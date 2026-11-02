// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit emits the structured per-decision events Talon's
// security posture depends on. Every auth decision (allow / deny /
// error), every session lifecycle transition, and every continuous-
// verification invalidation lands as a JSON line on stdout, picked up
// by the cluster's log shipper (Loki today; Wazuh-indexer in Phase 4
// per ADR 0001 §10).
//
// Wire shape (one event per line):
//
//	{
//	  "ts": "2026-04-26T12:34:56Z",
//	  "event": "request.allow" | "request.deny" | ...,
//	  "sub": "<falcon-id sub>",
//	  "email": "alice@example.com",
//	  "route": "prometheus.internal.example.com",
//	  "method": "GET",
//	  "path": "/graph",
//	  "decision": "allow",
//	  "reason": "ok",
//	  "src_ip": "203.0.113.45",
//	  "ua_hash": "sha256:9f86…",
//	  "session_id": "<uuid>",
//	  "permission": "viewer",
//	  "mfa": false,
//	  "iss": "https://id.example.com",
//	  "talon_version": "<commit>"
//	}
//
// Discriminator is `event`; consumers (Wazuh rules) match on it.
package audit

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/chain"

	tlog "github.com/dogukanturhal/talon/internal/log"
)

// Event is the discriminator field on every audit record.
type Event string

const (
	EventAuthStart          Event = "auth.start"
	EventAuthCallback       Event = "auth.callback"
	EventAuthLogout         Event = "auth.logout"
	EventBackchannelLogout  Event = "auth.backchannel_logout"
	EventFrontchannelLogout Event = "auth.frontchannel_logout"
	EventRequestAllow       Event = "request.allow"
	EventRequestDeny        Event = "request.deny"
	EventRequestError       Event = "request.error"
	EventSessionCreate      Event = "session.create"
	EventSessionRevoke      Event = "session.revoke"
	EventCVInvalidate       Event = "cv.invalidate"
	EventAdminRevoke        Event = "admin.revoke"
	EventMFAChallenge       Event = "auth.mfa_challenge"

	// EventIAPMintFailed records every failure of the per-request
	// X-Talon-Identity-Token signing path (internal/identityjwt). Talon
	// is the SOLE minter, so a failure here always means either (a) the
	// session blob became unparseable, (b) the signing key was misloaded
	// at startup, or (c) the audience binding was lost — all
	// security-relevant. When this fires Talon falls back to unsigned
	// X-Talon-* headers so requests still proxy (Phase A), but an
	// upstream running Phase B verifier-required mode WILL refuse the
	// request — SOC must triage every occurrence.
	//
	// Emitted at WARN severity (see IAPMintFailed): a mint failure is
	// always security-relevant, and on a route still in the default
	// fail-open posture it is ALSO the signal operators watch to drive the
	// downstream SDK-verifier migration (every occurrence is a request
	// that proxied with unsigned X-Talon-* headers instead of the signed
	// token).
	EventIAPMintFailed Event = "iap.token.mint_failed"

	// EventIAPMintDenied records a request that was FAIL-CLOSED denied at
	// the IAP mint path because the route has RequireSignedIdentityToken
	// enabled and Talon could not stamp a signed X-Talon-Identity-Token
	// (either the signer was not wired, or Sign() returned an error). The
	// user's session + policy decision had already ALLOWED — this event is
	// the enforcement action that overrides that allow because the signed
	// identity assertion the route contractually requires was unavailable.
	// Distinct from EventIAPMintFailed (which fires on every mint failure,
	// fail-open OR fail-closed) so SOC can alert specifically on the
	// enforcement denials. Emitted at WARN severity.
	EventIAPMintDenied Event = "iap.token.mint_denied"
)

// Record is a single audit event. Fields are optional unless marked
// required; consumers MUST tolerate missing fields. The TalonVersion
// field is filled from the binary's main.commit so per-event triage
// can correlate with a specific build.
//
// The embedded chain.Stamp adds tamper-evident seq + prev_hash on every
// emission via the chain.JSONLChain sink (ADR 0031). slog emission is
// unaffected — slog only sees the explicit attrs we hand it below; the
// embedded fields are part of the JSON-marshaled shape consumed by
// chain.JSONLChain.
type Record struct {
	chain.Stamp
	Event     Event     `json:"event"`
	Timestamp time.Time `json:"ts"`
	Sub       string    `json:"sub,omitempty"`
	Email     string    `json:"email,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Route     string    `json:"route,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Decision  string    `json:"decision,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	// DenyReason is the concrete, operator-authored cause a ZTNA policyRego
	// surfaces via `data.talon.route.deny_reason` (e.g. "ztna: AAL3
	// required"). Reason stays the coarse category ("rego_denied") for
	// dashboard continuity; DenyReason carries the granular why so a
	// SOC analyst / operator can tell AAL from posture-staleness from tier
	// without re-deriving the Rego by hand.
	DenyReason   string `json:"deny_reason,omitempty"`
	SrcIP        string `json:"src_ip,omitempty"`
	UAHash       string `json:"ua_hash,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	Permission   string `json:"permission,omitempty"`
	MFA          *bool  `json:"mfa,omitempty"`
	Issuer       string `json:"iss,omitempty"`
	Err          string `json:"err,omitempty"`
	TalonVersion string `json:"talon_version,omitempty"`

	// DecisionID — per-request correlation handle (boot prompt §4 Gap 4).
	// Auto-populated from ctx via Emit if unset by the caller; the
	// SOC analyst greps Wazuh on this field to reconstruct everything
	// that happened during one auth decision.
	DecisionID string `json:"decision_id,omitempty"`

	// SSOChainID — per-session correlation handle that spans Talon ↔
	// Falcon-ID ↔ upstream-app logs. Generated at /auth/start, persisted
	// in the session blob, replayed onto every audit event for the
	// session's lifetime. Auto-populated from ctx via Emit if unset.
	SSOChainID string `json:"sso_chain_id,omitempty"`

	// IAPKid — RFC 7517 key-id of the IAP identity-token signing key the
	// request was minted with (or attempted to be — see
	// EventIAPMintFailed). Lets SOC pin every audit record to a specific
	// key generation during a rotation window, and lets verifier-side
	// failure reports (from downstream SDKs) be joined back to Talon's
	// view of which key signed which JWT.
	IAPKid string `json:"iap_kid,omitempty"`

	// IAPAudience — the per-host audience claim the JWT was minted for
	// (typically the protected host). Populated on iap.token.mint_failed.
	IAPAudience string `json:"iap_audience,omitempty"`
}

// Emitter wraps a *slog.Logger with the standard audit prefix so audit
// records are filterable by handler downstream (Wazuh rule: where
// log.attr.subsystem == "audit").
//
// During the ADR 0031 dual-emit window, every Emit also writes the same
// Record to an optional chain.JSONLChain sink — same payload, tamper-
// evident hash chain on top. SOC tooling can grep the chain stream for
// NIST AU-9 evidence while existing log shippers keep ingesting the
// slog stream. When confidence accumulates the slog stream becomes
// optional; the chain stream stays.
type Emitter struct {
	logger       *slog.Logger
	talonVersion string
	chain        chain.Sink // optional — nil disables chain emission
}

// New returns an Emitter that writes to the package's stdout JSON sink
// (slog default in cmd/talon). The chain sink is unset; use NewDual to
// also write a tamper-evident hash-chained stream.
func New(logger *slog.Logger, version string) *Emitter {
	return &Emitter{
		logger:       logger.With("subsystem", "audit"),
		talonVersion: version,
	}
}

// NewDual returns an Emitter that writes to BOTH the slog handler (for
// existing log-shipper consumers) AND a chain.JSONLChain backed by w
// (typically os.Stdout, picked up by the same shipper that ingests slog).
// Two JSON lines per audit event; consumers that want the integrity
// guarantee read the line carrying `seq` + `prev_hash`. ADR 0031.
func NewDual(logger *slog.Logger, version string, w io.Writer) *Emitter {
	return &Emitter{
		logger:       logger.With("subsystem", "audit"),
		talonVersion: version,
		chain:        chain.NewJSONLChain(w),
	}
}

// StampTime implements chain.TimeStamper so the shared sink fills
// Timestamp only when the caller didn't already set it (the same
// "callers may set Timestamp explicitly for replay/backfill" semantics
// the slog path already preserves).
func (r *Record) StampTime(t time.Time) {
	if r.Timestamp.IsZero() {
		r.Timestamp = t
	}
}

// Emit records r. Convenience methods below set Event + Timestamp
// automatically. DecisionID + SSOChainID auto-populate from ctx if the
// caller didn't set them explicitly.
//
// When the chain sink is configured (NewDual), the SAME populated
// record is emitted via chain.JSONLChain.Emit BEFORE the slog handler
// path runs. The chain sink owns its own mutex + seq counter, so its
// hash chain stays consistent regardless of how often slog is invoked
// (or skipped) afterward.
func (e *Emitter) Emit(ctx context.Context, r Record) {
	e.emitLevel(ctx, r, slog.LevelInfo)
}

// emitLevel is the shared emission core behind Emit and the WARN-level
// convenience wrappers (IAPMintFailed, IAPMintDenied). The chain sink is
// severity-agnostic — it records the same tamper-evident line regardless
// of level — but the slog stream honours the requested level so
// security-relevant events (mint failures / fail-closed denials) surface
// above the INFO firehose in Loki/Wazuh without a separate rule.
func (e *Emitter) emitLevel(ctx context.Context, r Record, level slog.Level) {
	r.TalonVersion = e.talonVersion
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	if r.DecisionID == "" {
		r.DecisionID = tlog.DecisionIDFrom(ctx)
	}
	if r.SSOChainID == "" {
		r.SSOChainID = tlog.SSOChainIDFrom(ctx)
	}
	if e.chain != nil {
		// chain.JSONLChain.Emit stamps Stamp{seq, prev_hash} and writes
		// one JSON line. Failure is non-fatal (audit MUST NOT crash the
		// request path); log via the slog handler so the operator sees
		// the chain regression without losing the underlying event.
		if err := e.chain.Emit(ctx, &r); err != nil {
			e.logger.With("subsystem", "audit").Warn("audit-chain emit failed", "err", err.Error())
		}
	}
	// Use slog's structured logging so JSON shape is consistent with
	// the rest of Talon's stdout. Each Record field becomes a slog
	// attribute via its json tag.
	logger := tlog.From(ctx).With("subsystem", "audit")
	attrs := []any{
		"event", string(r.Event),
		"ts", r.Timestamp.Format(time.RFC3339Nano),
		"talon_version", r.TalonVersion,
	}
	if r.Sub != "" {
		attrs = append(attrs, "sub", r.Sub)
	}
	if r.Email != "" {
		attrs = append(attrs, "email", r.Email)
	}
	if r.TenantID != "" {
		attrs = append(attrs, "tenant_id", r.TenantID)
	}
	if r.Route != "" {
		attrs = append(attrs, "route", r.Route)
	}
	if r.Method != "" {
		attrs = append(attrs, "method", r.Method)
	}
	if r.Path != "" {
		attrs = append(attrs, "path", r.Path)
	}
	if r.Decision != "" {
		attrs = append(attrs, "decision", r.Decision)
	}
	if r.Reason != "" {
		attrs = append(attrs, "reason", r.Reason)
	}
	if r.DenyReason != "" {
		attrs = append(attrs, "deny_reason", r.DenyReason)
	}
	if r.SrcIP != "" {
		attrs = append(attrs, "src_ip", r.SrcIP)
	}
	if r.UAHash != "" {
		attrs = append(attrs, "ua_hash", r.UAHash)
	}
	if r.SessionID != "" {
		attrs = append(attrs, "session_id", r.SessionID)
	}
	if r.Permission != "" {
		attrs = append(attrs, "permission", r.Permission)
	}
	if r.MFA != nil {
		attrs = append(attrs, "mfa", *r.MFA)
	}
	if r.Issuer != "" {
		attrs = append(attrs, "iss", r.Issuer)
	}
	if r.Err != "" {
		attrs = append(attrs, "err", r.Err)
	}
	if r.DecisionID != "" {
		attrs = append(attrs, "decision_id", r.DecisionID)
	}
	if r.SSOChainID != "" {
		attrs = append(attrs, "sso_chain_id", r.SSOChainID)
	}
	if r.IAPKid != "" {
		attrs = append(attrs, "iap_kid", r.IAPKid)
	}
	if r.IAPAudience != "" {
		attrs = append(attrs, "iap_audience", r.IAPAudience)
	}
	logger.Log(ctx, level, "audit", attrs...)
}

// Allow emits a request.allow event. Convenience wrapper around Emit.
func (e *Emitter) Allow(ctx context.Context, r Record) {
	r.Event = EventRequestAllow
	r.Decision = "allow"
	e.Emit(ctx, r)
}

// Deny emits a request.deny event.
func (e *Emitter) Deny(ctx context.Context, r Record) {
	r.Event = EventRequestDeny
	r.Decision = "deny"
	e.Emit(ctx, r)
}

// Error emits a request.error event.
func (e *Emitter) Error(ctx context.Context, r Record) {
	r.Event = EventRequestError
	r.Decision = "error"
	e.Emit(ctx, r)
}

// SessionCreate emits a session.create event.
func (e *Emitter) SessionCreate(ctx context.Context, r Record) {
	r.Event = EventSessionCreate
	e.Emit(ctx, r)
}

// SessionRevoke emits a session.revoke event.
func (e *Emitter) SessionRevoke(ctx context.Context, r Record) {
	r.Event = EventSessionRevoke
	e.Emit(ctx, r)
}

// CVInvalidate emits a cv.invalidate event from the continuous-verification
// goroutine.
func (e *Emitter) CVInvalidate(ctx context.Context, r Record) {
	r.Event = EventCVInvalidate
	e.Emit(ctx, r)
}

// AdminRevoke emits a admin.revoke event for the DELETE /admin/sessions API.
func (e *Emitter) AdminRevoke(ctx context.Context, r Record) {
	r.Event = EventAdminRevoke
	e.Emit(ctx, r)
}

// BackchannelLogout emits an auth.backchannel_logout event for sessions
// invalidated via OIDC Back-Channel Logout 1.0 receipt at
// POST /auth/backchannel-logout. Distinct from EventSessionRevoke in
// reason field: SOC analysts grep this event to attribute a session
// teardown to an upstream OP-driven cascade (Sign Out elsewhere) vs an
// admin-driven revocation, expiry, or local /auth/logout.
func (e *Emitter) BackchannelLogout(ctx context.Context, r Record) {
	r.Event = EventBackchannelLogout
	e.Emit(ctx, r)
}

// FrontchannelLogout emits an auth.frontchannel_logout event per session
// invalidated via OIDC Front-Channel Logout 1.0 iframe receipt at
// GET /auth/frontchannel-logout. Distinct from EventBackchannelLogout
// because the cascade trigger is browser-driven (parent OP page renders
// an iframe pointing here) rather than server-to-server: SOC analysts
// use the event-name split to tell whether the user's browser was alive
// at logout time (FCL fired) or whether only the OP could see them
// signed out (BCL fired).
func (e *Emitter) FrontchannelLogout(ctx context.Context, r Record) {
	r.Event = EventFrontchannelLogout
	e.Emit(ctx, r)
}

// MFAChallenge emits an event when Talon redirects for step-up MFA.
func (e *Emitter) MFAChallenge(ctx context.Context, r Record) {
	r.Event = EventMFAChallenge
	e.Emit(ctx, r)
}

// IAPMintFailed records a failed Sign() at the IAP identity-token mint
// path. Always rare — Sign() failure indicates either a corrupted
// session blob or an unloaded signer. SOC triage: correlate iap_kid +
// iap_audience + sub + err.
//
// Emitted at WARN: on a fail-open route (RequireSignedIdentityToken=false,
// the default) every occurrence is a request that fell back to unsigned
// X-Talon-* headers, so ops watch the WARN rate to drive the downstream
// SDK-verifier migration. The proxy sets r.Reason to "fail_open_unsigned_
// fallback" or "fail_closed_denied" so the two postures are distinguishable
// on the same event.
func (e *Emitter) IAPMintFailed(ctx context.Context, r Record) {
	r.Event = EventIAPMintFailed
	e.emitLevel(ctx, r, slog.LevelWarn)
}

// IAPMintDenied records a fail-closed denial: the route has
// RequireSignedIdentityToken enabled and Talon could not stamp a signed
// identity token, so the request was refused (5xx) instead of proxying
// with unsigned headers. SOC triage: correlate iap_audience + sub +
// reason (err="signer not wired" vs the propagated Sign() error).
func (e *Emitter) IAPMintDenied(ctx context.Context, r Record) {
	r.Event = EventIAPMintDenied
	r.Decision = "deny"
	e.emitLevel(ctx, r, slog.LevelWarn)
}
