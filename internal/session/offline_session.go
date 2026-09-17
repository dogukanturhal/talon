// SPDX-License-Identifier: AGPL-3.0-or-later

// offline_session.go is the DDIL P3.1 governed-degrade layer for the
// session-store read on the request hot path. Today a Redis outage fails
// the per-request session Read closed at t=0 (Store.Read → router 503).
// That is correct for a genuine miss/revoke/expiry, but for a pure
// INFRASTRUCTURE outage it collapses every already-authenticated session
// the instant Redis blips — and it makes the SpiceDB offline PDP (which
// already grants critical/high routes a 5m authz budget) unreachable,
// because the session read happens FIRST.
//
// This file closes that gap with the SAME primitive the SpiceDB offline
// PDP uses (hexx-pep-core/pkg/govdecision): on each SUCCESSFUL live Read
// the manager signs a short-TTL, revocation-aware last-known-good
// "session-valid" decision that carries the whole session blob; when
// Redis is unreachable the router serves that cached session WITHIN a
// budget (operating-spec: 15m standard, 5m privileged/step-up routes),
// then fails closed. It is a direct mirror of internal/spicedb/offline_pdp.go.
//
// Trust model (identical to the SpiceDB offline PDP). Every cached decision
// is signed by a per-process Ed25519 issuer key and verified before it is
// served, so an in-memory-corrupted or forged entry can never be honoured
// (no unsigned local trust — the operating-spec "signed budgets" principle).
// The keypair is ephemeral and never leaves the process; a restart voids
// the whole cache (nothing durable to serve stale from a dead key), the
// most fail-closed default for a per-pod in-memory cache. A pre-provisioned
// key (island/emergency tier, cross-pod session sharing) can be injected.
//
// Revocation offline. The subject's monotonic epoch (shared shape with the
// SpiceDB PDP) is bumped on every session-kill / CAEP revoke / role loss
// via the SubjectInvalidator fan-out; a session decision issued under an
// epoch older than the subject's current known epoch is denied EVEN with
// no connectivity — "revoke online AND offline". Note the inherent DDIL
// limit: a revoke that arrives DURING a full Redis outage cannot be written
// to Redis at all, so the short budget (≤15m) is the exposure bound.
//
// Tiering. One recorded decision serves both tiers: it is stamped with the
// STANDARD (longer) ValidUntil, and the PRIVILEGED tightening (IssuedAt +
// 5m) is applied at SERVE time from the signed IssuedAt, keyed by the
// sensitivity of the route hit during the outage. So the same session gets
// a shorter offline window on a critical route than on a standard one,
// without recording two decisions.
package session

import (
	"container/list"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// DefaultOfflineSessionStandardBudget / DefaultOfflineSessionPrivilegedBudget
// are the operating-spec baselines (2026-07-19-ddil-degraded-mode-operating-spec.md
// §1), identical to the SpiceDB PDP: a cached session is honoured offline for
// at most 15m on a standard route, 5m on a privileged/step-up route.
const (
	DefaultOfflineSessionStandardBudget   = 15 * time.Minute
	DefaultOfflineSessionPrivilegedBudget = 5 * time.Minute
	// defaultOfflineSessionCacheMax bounds the signed-decision LRU so a
	// long-lived process cannot grow it without limit across many active
	// cookies. Sized above the SpiceDB decision cap because the key space
	// here is per-session (one entry per live cookie), not per (subject,
	// route). LRU eviction past this ceiling.
	defaultOfflineSessionCacheMax = 8192
	// defaultOfflineSessionRecordInterval throttles re-signing on the
	// read-hot path: a cookie's last-known-good decision is refreshed at
	// most once per interval, so a busy session does not pay an Ed25519
	// sign + blob-marshal on every request (mirrors the SlidingRefresh
	// throttle). The served window still slides forward each interval.
	defaultOfflineSessionRecordInterval = 60 * time.Second
	// offlineSessionBlobClaim is the Decision.Claims key under which the
	// base64(JSON) session blob is carried. Claims are inside SigningBytes,
	// so the served session is covered by the issuer signature.
	offlineSessionBlobClaim = "blob"
)

// OfflineSessionMetrics is the optional observability sink for session-store
// governed-degrade events. Method names are session-scoped so a single
// Prometheus adapter can implement BOTH this and spicedb.OfflinePDPMetrics
// (whose OnOfflineServed takes a bool) without a signature clash. nil is
// tolerated (no-op).
type OfflineSessionMetrics interface {
	// OnSessionOfflineServed fires when a cached session is served during a
	// Redis outage (within budget).
	OnSessionOfflineServed()
	// OnSessionOfflineDenied fires when no valid cached session was available
	// (absent / past budget / epoch-revoked / bad-signature / past hard
	// expiry) so the read falls through to fail-closed.
	OnSessionOfflineDenied()
}

// OfflineSessionCache caches signed last-known-good sessions and serves them
// within budget when the Redis session store is unreachable. Concurrency-safe.
type OfflineSessionCache struct {
	verifier govdecision.Verifier
	signer   govdecision.Signer
	epochs   *govdecision.MemoryEpochStore

	stdBudget      time.Duration
	privBudget     time.Duration
	recordInterval time.Duration
	leeway         time.Duration

	clock   resilient.Clock
	metrics OfflineSessionMetrics
	logger  *slog.Logger

	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element // cookieID -> *list.Element(*offlineSessionEntry)
}

type offlineSessionEntry struct {
	cookieID string
	d        govdecision.Decision
}

// OfflineSessionConfig parameterises NewOfflineSessionCache.
type OfflineSessionConfig struct {
	// StandardBudget / PrivilegedBudget bound how long a cached session is
	// honoured offline per tier. <=0 uses the operating-spec defaults.
	StandardBudget   time.Duration
	PrivilegedBudget time.Duration
	// RecordInterval throttles re-signing on the read-hot path. <=0 uses the
	// 60s default.
	RecordInterval time.Duration
	// Leeway widens the offline time-window symmetrically to absorb bounded
	// clock skew between the recording and serving instant (single-process
	// here, so 0 is correct; a small value only matters for injected
	// cross-pod keys). Default 0 (strict).
	Leeway time.Duration
	// MaxEntries bounds the signed-decision LRU. <=0 uses the default.
	MaxEntries int
	// Clock is the time source (testability + trusted-time seam). nil =
	// resilient.SystemClock.
	Clock resilient.Clock
	// Metrics is the optional governed-degrade sink. nil = no-op.
	Metrics OfflineSessionMetrics
	// Logger, if set, emits a WARN per governed-degrade serve. nil = none.
	Logger *slog.Logger
	// Signer / Verifier optionally inject a pre-provisioned issuer keypair
	// (island/emergency tier, cross-pod session sharing). Both nil (the
	// default) generates an ephemeral per-process Ed25519 keypair.
	Signer   govdecision.Signer
	Verifier govdecision.Verifier
}

// NewOfflineSessionCache builds an OfflineSessionCache. When no keypair is
// injected it generates an ephemeral per-process Ed25519 issuer key (see the
// package doc for why that is the most fail-closed default here).
func NewOfflineSessionCache(cfg OfflineSessionConfig) (*OfflineSessionCache, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = resilient.SystemClock{}
	}
	signer, verifier := cfg.Signer, cfg.Verifier
	if signer == nil || verifier == nil {
		s, v, err := govdecision.GenerateEd25519()
		if err != nil {
			return nil, err
		}
		signer, verifier = s, v
	}
	std := cfg.StandardBudget
	if std <= 0 {
		std = DefaultOfflineSessionStandardBudget
	}
	priv := cfg.PrivilegedBudget
	if priv <= 0 {
		priv = DefaultOfflineSessionPrivilegedBudget
	}
	// A privileged budget must never exceed the standard one — the tighter
	// tier is a floor, not a ceiling. Clamp defensively so a misconfiguration
	// cannot widen the privileged window.
	if priv > std {
		priv = std
	}
	interval := cfg.RecordInterval
	if interval <= 0 {
		interval = defaultOfflineSessionRecordInterval
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultOfflineSessionCacheMax
	}
	return &OfflineSessionCache{
		verifier:       verifier,
		signer:         signer,
		epochs:         govdecision.NewMemoryEpochStore(),
		stdBudget:      std,
		privBudget:     priv,
		recordInterval: interval,
		leeway:         cfg.Leeway,
		clock:          clock,
		metrics:        cfg.Metrics,
		logger:         cfg.Logger,
		max:            maxEntries,
		ll:             list.New(),
		items:          make(map[string]*list.Element, maxEntries),
	}, nil
}

// Record stores a signed, time-boxed last-known-good session after a
// successful LIVE Redis read. It is a no-op when the manager is nil, the
// blob has no subject, or a fresh-enough decision already exists for this
// cookie (the record-interval throttle). The decision is stamped with the
// subject's current known revocation epoch so a later revoke voids it.
func (c *OfflineSessionCache) Record(cookieID string, b *Blob) {
	if c == nil || cookieID == "" || b == nil || b.Sub == "" {
		return
	}
	now := c.clock.Now()

	// Throttle: skip re-signing if the existing decision is younger than the
	// record interval. Read under the lock so we observe a consistent entry.
	c.mu.Lock()
	if el, ok := c.items[cookieID]; ok {
		if now.Sub(el.Value.(*offlineSessionEntry).d.IssuedAt) < c.recordInterval {
			c.mu.Unlock()
			return
		}
	}
	c.mu.Unlock()

	raw, err := json.Marshal(b)
	if err != nil {
		return
	}
	d := govdecision.Decision{
		Subject:    b.Sub,
		Resource:   cookieID,
		Verdict:    govdecision.Allow,
		IssuedAt:   now,
		ValidUntil: now.Add(c.stdBudget),
		Epoch:      c.epochs.Epoch(b.Sub),
		Claims:     map[string]string{offlineSessionBlobClaim: base64.StdEncoding.EncodeToString(raw)},
	}
	signed, err := govdecision.Sign(c.signer, d)
	if err != nil {
		return
	}
	c.put(cookieID, signed)
}

// Serve returns the cached last-known-good session for cookieID as of now, or
// (nil, false) when none is valid. It never fails open. Used by the router's
// session-read error path when Redis is unreachable. `privileged` selects the
// tighter (5m-from-issue) budget for critical/high routes.
//
// Order of checks (each a hard gate, mirroring govdecision.EvaluateCached):
//  1. present in cache,
//  2. issuer signature valid (no unsigned local trust),
//  3. within [IssuedAt, effective-deadline] widened by leeway, where the
//     effective deadline is min(ValidUntil, IssuedAt+privBudget) for a
//     privileged route,
//  4. Decision.Epoch >= the subject's known revocation epoch (offline revoke),
//  5. the session's own hard expiry (Blob.Exp) has not passed — grace must
//     never resurrect a session past its natural lifetime.
func (c *OfflineSessionCache) Serve(cookieID string, privileged bool) (*Blob, bool) {
	if c == nil || cookieID == "" {
		return nil, false
	}
	now := c.clock.Now()

	c.mu.Lock()
	el, ok := c.items[cookieID]
	if ok {
		c.ll.MoveToFront(el)
	}
	c.mu.Unlock()
	if !ok {
		c.denied()
		return nil, false
	}
	d := el.Value.(*offlineSessionEntry).d

	// 2. signature — an unsigned or forged entry is never trusted.
	if err := govdecision.Verify(c.verifier, d); err != nil {
		c.denied()
		return nil, false
	}
	// 3. budget window (tiered): privileged tightens to IssuedAt+privBudget.
	deadline := d.ValidUntil
	if privileged {
		if pd := d.IssuedAt.Add(c.privBudget); pd.Before(deadline) {
			deadline = pd
		}
	}
	if now.After(deadline.Add(c.leeway)) || now.Before(d.IssuedAt.Add(-c.leeway)) {
		c.denied()
		return nil, false
	}
	// 4. revocation epoch — a decision older than the subject's known epoch is
	// revoked even offline.
	if d.Epoch < c.epochs.Epoch(d.Subject) {
		c.denied()
		return nil, false
	}
	// 5. decode the carried session and honour its own hard expiry.
	enc := d.Claims[offlineSessionBlobClaim]
	rawBlob, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		c.denied()
		return nil, false
	}
	b := &Blob{}
	if err := json.Unmarshal(rawBlob, b); err != nil {
		c.denied()
		return nil, false
	}
	if b.Exp != 0 && now.Unix() >= b.Exp {
		c.denied()
		return nil, false
	}

	if c.metrics != nil {
		c.metrics.OnSessionOfflineServed()
	}
	if c.logger != nil {
		c.logger.Warn("session: serving cached session (DDIL P3.1 governed-degrade) — Redis unreachable, within budget",
			"sub", b.Sub, "privileged", privileged,
			"issued_at", d.IssuedAt.Format(time.RFC3339),
			"valid_until", d.ValidUntil.Format(time.RFC3339))
	}
	return b, true
}

// Revoke bumps the subject's known revocation epoch so every cached session
// issued before this point is denied — even offline. Wired to every Talon
// revoke path via InvalidateBySubject (the SubjectInvalidator fan-out).
func (c *OfflineSessionCache) Revoke(subject string) {
	if c == nil || subject == "" {
		return
	}
	c.epochs.Observe(subject, c.epochs.Epoch(subject)+1)
}

// InvalidateBySubject satisfies SubjectInvalidator so the OfflineSessionCache
// can be wired into the Store's revoke fan-out alongside the SpiceDB cache
// (see MultiInvalidator). reason is accepted for the interface but only the
// subject drives the epoch bump. Returns 1 (a subject-scoped invalidation
// always "counts") so a composite can sum fan-out results meaningfully.
func (c *OfflineSessionCache) InvalidateBySubject(subject, reason string) int {
	if c == nil || subject == "" {
		return 0
	}
	_ = reason
	c.Revoke(subject)
	return 1
}

// KnownEpoch exposes the current known revocation epoch (diagnostics/tests).
func (c *OfflineSessionCache) KnownEpoch(subject string) uint64 {
	if c == nil {
		return 0
	}
	return c.epochs.Epoch(subject)
}

// denied records an offline-denied outcome (helper to keep Serve tidy).
func (c *OfflineSessionCache) denied() {
	if c.metrics != nil {
		c.metrics.OnSessionOfflineDenied()
	}
}

// put stores d keyed by cookieID, evicting the LRU tail past capacity.
func (c *OfflineSessionCache) put(cookieID string, d govdecision.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[cookieID]; ok {
		el.Value.(*offlineSessionEntry).d = d
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&offlineSessionEntry{cookieID: cookieID, d: d})
	c.items[cookieID] = el
	for c.ll.Len() > c.max {
		victim := c.ll.Back()
		if victim == nil {
			break
		}
		c.ll.Remove(victim)
		delete(c.items, victim.Value.(*offlineSessionEntry).cookieID)
	}
}

// IsUnavailable reports whether a Store.Read error is an INFRASTRUCTURE
// unavailability (Redis transport error or breaker-open) rather than a
// genuine session outcome (not-found / revoked / expired / AEAD-auth-fail).
// Only the former is eligible for governed offline-serve; the latter must
// stay fail-closed. It is the inverse of the session sentinels, so any
// wrapped/unknown error is treated as unavailability (matches the router's
// ReasonInternal → 503 classification).
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, ErrNotFound),
		errors.Is(err, ErrRevoked),
		errors.Is(err, ErrExpired),
		errors.Is(err, ErrAuthFailed):
		return false
	default:
		return true
	}
}

// MultiInvalidator fans a subject invalidation out to several
// SubjectInvalidators (e.g. the SpiceDB decision cache AND the offline
// session cache), so a single Store.SetSubjectInvalidator call keeps every
// per-subject cache honest. Returns the sum of the fan-out counts.
type MultiInvalidator []SubjectInvalidator

// InvalidateBySubject invokes every non-nil member and sums their counts.
func (m MultiInvalidator) InvalidateBySubject(subject, reason string) int {
	total := 0
	for _, inv := range m {
		if inv == nil {
			continue
		}
		total += inv.InvalidateBySubject(subject, reason)
	}
	return total
}
