// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb — offline_pdp.go is the DDIL P3.1 governed-degrade
// layer for the authorization PDP. Today a SpiceDB outage fails closed
// at t=0 (the CachedClient.Check error path). This file adds a signed,
// time-boxed, revocation-aware last-known-good decision cache built on
// hexx-pep-core/pkg/govdecision: when SpiceDB is unreachable, Talon
// serves the cached decision WITHIN a short budget (operating-spec:
// 15m standard, 5m privileged/step-up routes), then fails closed.
//
// Trust model. Every cached decision is signed by a per-process Ed25519
// issuer key and verified before it is served, so an in-memory-corrupted
// or forged entry can never be honoured (no unsigned local trust — the
// operating-spec "signed budgets" principle). The keypair is ephemeral
// and never leaves the process: it signs on the live path and verifies
// on the degraded path, both in-process, and a restart naturally voids
// the whole cache (there is nothing durable to serve stale from a dead
// key). That is the most fail-closed-biased default for the per-pod,
// in-memory decision cache; it is NOT an operator credential, so it is
// not persisted to Vault. A pre-provisioned key (island/emergency tier,
// cross-pod decision sharing) can be injected via OfflinePDPConfig.
//
// Revocation offline. A monotonic per-subject epoch is bumped on every
// session-kill / CAEP revoke / role loss (CachedClient.InvalidateBySubject
// → Revoke). A decision issued under an epoch older than the subject's
// current known epoch is denied EVEN with no connectivity — this is how
// "revoke online AND offline" (a hard DDIL requirement) holds.
package spicedb

import (
	"container/list"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// DefaultOfflineStandardBudget / DefaultOfflinePrivilegedBudget are the
// operating-spec baselines (2026-07-19-ddil-degraded-mode-operating-spec.md
// §1): a cached SpiceDB decision is honoured offline for at most 15m on a
// standard route, 5m on a privileged/step-up route. Shorter is more
// adversary-aware; more-privileged access gets the shorter window.
const (
	DefaultOfflineStandardBudget   = 15 * time.Minute
	DefaultOfflinePrivilegedBudget = 5 * time.Minute
	// defaultOfflineCacheMax bounds the signed-decision cache so a
	// long-lived process cannot grow it without limit across many
	// (subject, route) pairs. LRU eviction past this ceiling.
	defaultOfflineCacheMax = 4096
)

// OfflinePDPMetrics is the optional observability sink for governed-degrade
// events at the SpiceDB PDP. Implementations are Prom-backed in production;
// nil is tolerated (no-op).
type OfflinePDPMetrics interface {
	// OnOfflineServed fires when a cached decision is served during a
	// SpiceDB outage (within budget). allowed is the served verdict.
	OnOfflineServed(allowed bool)
	// OnOfflineDenied fires when no valid cached decision was available
	// (absent / expired-past-budget / epoch-revoked / bad-signature) so
	// the PDP falls through to fail-closed.
	OnOfflineDenied()
}

// OfflinePDP caches signed last-known-good SpiceDB authorization decisions
// and serves them within budget when SpiceDB is unreachable.
type OfflinePDP struct {
	ev      *govdecision.CachedEvaluator
	epochs  *govdecision.MemoryEpochStore
	signer  govdecision.Signer
	budgets govdecision.Budgets
	clock   resilient.Clock
	metrics OfflinePDPMetrics
	logger  *slog.Logger
}

// OfflinePDPConfig parameterises NewOfflinePDP.
type OfflinePDPConfig struct {
	// StandardBudget / PrivilegedBudget bound how long a cached decision
	// is honoured offline per tier. <=0 uses the operating-spec defaults.
	StandardBudget   time.Duration
	PrivilegedBudget time.Duration
	// MaxEntries bounds the signed-decision LRU. <=0 uses the default.
	MaxEntries int
	// Clock is the time source (testability + trusted-time seam). nil =
	// resilient.SystemClock.
	Clock resilient.Clock
	// Metrics is the optional governed-degrade sink. nil = no-op.
	Metrics OfflinePDPMetrics
	// Logger, if set, emits a WARN per governed-degrade serve. nil = none.
	Logger *slog.Logger
	// Signer / Verifier optionally inject a pre-provisioned issuer keypair
	// (island/emergency tier, cross-pod decision sharing). Both nil (the
	// default) generates an ephemeral per-process Ed25519 keypair.
	Signer   govdecision.Signer
	Verifier govdecision.Verifier
}

// NewOfflinePDP builds an OfflinePDP. When no keypair is injected it
// generates an ephemeral per-process Ed25519 issuer key (see the package
// doc for why that is the most fail-closed default here).
func NewOfflinePDP(cfg OfflinePDPConfig) (*OfflinePDP, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = resilient.SystemClock{}
	}
	signer, verifier := cfg.Signer, cfg.Verifier
	if signer == nil || verifier == nil {
		s, v, err := govdecision.GenerateEd25519()
		if err != nil {
			return nil, fmt.Errorf("spicedb offline pdp: generate issuer key: %w", err)
		}
		signer, verifier = s, v
	}
	std := cfg.StandardBudget
	if std <= 0 {
		std = DefaultOfflineStandardBudget
	}
	priv := cfg.PrivilegedBudget
	if priv <= 0 {
		priv = DefaultOfflinePrivilegedBudget
	}
	budgets := govdecision.Budgets{
		govdecision.TierStandard:   std,
		govdecision.TierPrivileged: priv,
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultOfflineCacheMax
	}
	epochs := govdecision.NewMemoryEpochStore()
	ev := govdecision.NewCachedEvaluator(verifier,
		govdecision.WithEpochStore(epochs),
		govdecision.WithBudgets(budgets),
		govdecision.WithCache(newBoundedDecisionCache(maxEntries)),
	)
	return &OfflinePDP{
		ev:      ev,
		epochs:  epochs,
		signer:  signer,
		budgets: budgets,
		clock:   clock,
		metrics: cfg.Metrics,
		logger:  cfg.Logger,
	}, nil
}

// Record stores a signed, time-boxed last-known-good decision after a
// successful LIVE SpiceDB check. The decision is stamped with the
// subject's current known revocation epoch so a later revoke voids it.
// An un-budgeted tier is NOT cached (fail-closed bias — never an
// unbounded offline window).
func (o *OfflinePDP) Record(host, subject, permission string, privileged, allowed bool) {
	now := o.clock.Now()
	tier := tierFor(privileged)
	validUntil, err := o.budgets.ValidUntil(tier, now)
	if err != nil {
		return
	}
	verdict := govdecision.Deny
	if allowed {
		verdict = govdecision.Allow
	}
	d := govdecision.Decision{
		Subject:    subject,
		Resource:   resourceID(host, permission),
		Verdict:    verdict,
		IssuedAt:   now,
		ValidUntil: validUntil,
		Epoch:      o.epochs.Epoch(subject),
	}
	signed, err := govdecision.Sign(o.signer, d)
	if err != nil {
		return
	}
	// IngestDecision verifies the signature before caching and advances
	// the subject's known epoch monotonically (a no-op here since we
	// stamped the current epoch).
	_ = o.ev.IngestDecision(signed)
}

// Serve returns a cached last-known-good decision for the request as of
// now, or (false, false) when none is valid (absent / past budget /
// epoch-revoked / bad signature). It never fails open. Used by the
// CachedClient.Check error path when SpiceDB is unreachable.
func (o *OfflinePDP) Serve(host, subject, permission string, privileged bool) (allowed, ok bool) {
	now := o.clock.Now()
	d, ok := o.ev.EvaluateCached(context.Background(), govdecision.Request{
		Subject:  subject,
		Resource: resourceID(host, permission),
		Tier:     tierFor(privileged),
	}, now)
	if !ok {
		if o.metrics != nil {
			o.metrics.OnOfflineDenied()
		}
		return false, false
	}
	allowed = d.Verdict == govdecision.Allow
	if o.metrics != nil {
		o.metrics.OnOfflineServed(allowed)
	}
	if o.logger != nil {
		o.logger.Warn("spicedb: serving cached authorization decision (DDIL P3.1 governed-degrade) — SpiceDB unreachable, within budget",
			"host", host, "sub", subject, "perm", permission,
			"verdict", d.Verdict.String(), "issued_at", d.IssuedAt.Format(time.RFC3339),
			"valid_until", d.ValidUntil.Format(time.RFC3339))
	}
	return allowed, true
}

// Revoke bumps the subject's known revocation epoch so every cached
// decision issued before this point is denied — even offline. Wired to
// every Talon revoke path via CachedClient.InvalidateBySubject.
func (o *OfflinePDP) Revoke(subject string) {
	if subject == "" {
		return
	}
	o.epochs.Observe(subject, o.epochs.Epoch(subject)+1)
}

// KnownEpoch exposes the current known revocation epoch (diagnostics/tests).
func (o *OfflinePDP) KnownEpoch(subject string) uint64 { return o.epochs.Epoch(subject) }

// tierFor maps route privilege to a govdecision staleness tier: privileged/
// step-up routes get the shorter (5m) budget, everything else the 15m
// standard budget.
func tierFor(privileged bool) govdecision.Tier {
	if privileged {
		return govdecision.TierPrivileged
	}
	return govdecision.TierStandard
}

// resourceID is the govdecision resource identity for a (host, permission)
// pair. The '|' separator cannot appear in a DNS host or a schema
// permission name, so the encoding is unambiguous.
func resourceID(host, permission string) string { return host + "|" + permission }

// boundedDecisionCache is an LRU that satisfies govdecision.Cache, keyed
// by (subject, resource). It bounds memory for a long-lived process; the
// govdecision default MemoryCache is unbounded. Decisions are still
// gated by signature + budget + epoch at serve time — the LRU only caps
// footprint, it is not a security boundary.
type boundedDecisionCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
}

type decisionEntry struct {
	key string
	d   govdecision.Decision
}

func newBoundedDecisionCache(max int) *boundedDecisionCache {
	if max <= 0 {
		max = defaultOfflineCacheMax
	}
	return &boundedDecisionCache{
		max:   max,
		ll:    list.New(),
		items: make(map[string]*list.Element, max),
	}
}

func decisionKey(subject, resource string) string { return subject + "\x00" + resource }

// Get returns the cached Decision for (subject, resource).
func (c *boundedDecisionCache) Get(subject, resource string) (govdecision.Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[decisionKey(subject, resource)]
	if !ok {
		return govdecision.Decision{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*decisionEntry).d, true
}

// Put stores d keyed by its Subject/Resource, evicting the LRU tail past
// capacity.
func (c *boundedDecisionCache) Put(d govdecision.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := decisionKey(d.Subject, d.Resource)
	if el, ok := c.items[k]; ok {
		el.Value.(*decisionEntry).d = d
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&decisionEntry{key: k, d: d})
	c.items[k] = el
	for c.ll.Len() > c.max {
		victim := c.ll.Back()
		if victim == nil {
			break
		}
		c.ll.Remove(victim)
		delete(c.items, victim.Value.(*decisionEntry).key)
	}
}
