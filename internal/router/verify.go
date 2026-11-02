// SPDX-License-Identifier: AGPL-3.0-or-later

// Package router — Verify is the shared decision core consumed by BOTH
// the HTTP /auth/verify forward-auth endpoint (serveAuthVerify) AND the
// Envoy ext_authz gRPC server (internal/extauthz). Extracting it ensures
// the two wire formats produce IDENTICAL decisions for the same request
// — load-bearing for the Phase 7 GEP-1494-aligned shared-PDP shape
// (one Talon, two callers, same audit trail).
//
// Design rationale: rather than have ext_authz call /auth/verify over
// localhost HTTP, the two surface adapters call the same in-process
// function. Saves a round-trip, avoids double-emit of audit events,
// and lets ext_authz hand back structured identity-header injection
// to Envoy/APISIX/Cilium/Traefik/HAProxy without re-parsing HTTP
// headers from a Talon response.
//
// The decision flow mirrors serveAuthVerify exactly:
//  1. Host lookup against the live TalonRoute table
//  2. Cookie → session blob (Redis)
//  3. Per-host session-control gate (TTL, idle, IP rebind, device claims)
//  4. Policy evaluation (SpiceDB CheckPermission + AuthorizedGroups)
//  5. Step-up check (mfaRequired / requireACR)
//  6. Sliding refresh + last-seen touch (best-effort)
//  7. Identity header set (X-Talon-User/Email/Subject/Tenant-Id/Groups)
//
// Any divergence here is a Phase 7 invariant violation — the HTTP and
// gRPC adapters MUST produce the same allow/deny for the same input.
package router

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	v1beta1 "github.com/dogukanturhal/talon/api/v1beta1"
	"github.com/dogukanturhal/talon/internal/audit"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/policy"
	"github.com/dogukanturhal/talon/internal/session"
	"github.com/dogukanturhal/talon/internal/svctoken"
)

// VerifyDecision is the cross-protocol output shape. Wire adapters map
// these fields to HTTP response (serveAuthVerify) or to gRPC
// CheckResponse fields (extauthz).
type VerifyDecision struct {
	// Allowed is the binary allow/deny. When false, Reason carries the
	// X-Talon-Reason label value the adapter should surface.
	Allowed bool

	// Reason is the policy.ReasonX value (or the metric label) for the
	// deny. Empty when Allowed=true. Same vocabulary serveAuthVerify
	// has been emitting on its X-Talon-Reason header since ADR 0005.
	Reason string

	// IdentityHeaders are the X-Talon-* headers to inject on the
	// outbound request when Allowed=true. Adapter writes them onto
	// the HTTP response (forward-auth) or into CheckResponse.OkHttp
	// Response.Headers (ext_authz). Empty when Allowed=false.
	IdentityHeaders map[string]string

	// MFARequired marks the special-case "step-up needed" deny. The
	// adapter writes 401+X-Talon-Reason="mfa_required" identical to
	// the v1alpha1 behaviour AND ALSO emits WWWAuthenticate per
	// RFC 9470 (see field below) so API clients can re-authenticate
	// without depending on the calling proxy's redirect logic.
	MFARequired bool

	// WWWAuthenticate is the RFC 9470 step-up challenge header value
	// (Phase 6b-3). Non-empty ONLY when MFARequired=true; carries
	// the `Bearer error="insufficient_user_authentication" acr_values=
	// "..."` form that lets API clients negotiate the missing factor
	// without the calling proxy needing to translate the 401 into
	// a redirect.
	//
	// Adapters: HTTP `serveAuthVerify` writes
	//   w.Header().Set("WWW-Authenticate", dec.WWWAuthenticate)
	// gRPC `extauthz.Server` appends a HeaderValueOption with
	// Key=WWW-Authenticate to the DeniedHttpResponse.Headers.
	// Both surfaces emit identical wire shape so APISIX / Envoy /
	// Istio downstreams can branch on the same header.
	WWWAuthenticate string

	// Blob is the resolved session for the request — adapter-side
	// audit emission and step-up logic may consult it. nil when
	// Allowed=false AND the deny happened before session resolution
	// (e.g., unknown host, missing cookie).
	Blob *session.Blob
}

// VerifyInput is the cross-protocol input shape. The HTTP adapter
// builds this from the http.Request; the ext_authz adapter builds it
// from the Envoy CheckRequest attributes.
type VerifyInput struct {
	// Host is the original-client request host. HTTP adapter reads
	// X-Forwarded-Host (APISIX sets this); ext_authz adapter reads
	// Attributes.Request.Http.Host. Empty falls back to the inbound
	// connection's req.Host equivalent.
	Host string

	// CookieValue is the Talon session cookie's value (already
	// extracted from the Cookie header by the adapter). Empty means
	// "no session" — the Verify call fails fast with ReasonNoSession.
	CookieValue string

	// Method + Path are surfaced for audit-event accuracy. They do
	// NOT influence the v1alpha1 decision (per-host policy only); a
	// future v1beta1-pathRules-aware Verify caller will pass them
	// into the path-rule matcher (Phase 7.2).
	Method string
	Path   string

	// SrcIP is the resolved client IP for the per-host IP-rebind
	// check. HTTP adapter uses oidc.ClientIP(req); ext_authz adapter
	// reads Attributes.Source.Address. Empty disables the rebind
	// check (same fall-back the v1alpha1 code already does).
	SrcIP string
}

// Verify is the shared decision core. Mirrors serveAuthVerify's
// implementation step-for-step; deliberately not a method on
// upstreamEntry because the audit/metrics/policy hooks live on Router.
//
// IMPORTANT: this function MUST keep wire-format-agnostic behaviour.
// Adding HTTP-specific things (writing headers, error()-ing) here
// breaks the ext_authz adapter. The contract is: receive structured
// input → return VerifyDecision → adapter formats the wire reply.
func (r *Router) Verify(ctx context.Context, in VerifyInput) VerifyDecision {
	logger := tlog.From(ctx)

	if in.Host == "" {
		return VerifyDecision{
			Allowed: false,
			Reason:  "unknown_host",
		}
	}

	r.mu.RLock()
	up, ok := r.upstreams[in.Host]
	r.mu.RUnlock()
	if !ok {
		logger.Warn("verify: unknown host", "host", in.Host)
		return VerifyDecision{Allowed: false, Reason: "unknown_host"}
	}

	// Phase 7.3 — v1beta1 per-path policy. Walk pathRules first;
	// matched rule's action=deny short-circuits before any session
	// work (cheaper deny path). Matched rule's Policy fields overlay
	// the host-default policy below (effective for THIS request only).
	//
	// nil/empty pathRules preserves v1alpha1 behaviour exactly —
	// the matcher returns nil immediately and `up` is consulted as-is.
	//
	// Phase 6b-3 metric: emit `talon_authz_decision_total{rule, action,
	// route}` for every pathRule outcome (or empty-rule when no rule
	// matched). Operators can join this with the existing
	// talon_auth_decision_total to break down per-rule fire rate.
	matched := FirstMatch(up.pathRules, in.Method, in.Path)
	matchedRuleName := ""
	if matched != nil {
		matchedRuleName = matched.Rule.Name
		if matched.Rule.Action == v1beta1.PathRuleDeny {
			r.metrics.AuthDecision.WithLabelValues(in.Host, "deny", "explicit_deny").Inc()
			r.metrics.AuthzDecision.WithLabelValues(matchedRuleName, "deny", in.Host).Inc()
			return VerifyDecision{Allowed: false, Reason: "explicit_deny"}
		}
		up = overlayUpstreamPolicy(up, matched.Rule.Policy)
	}

	if in.CookieValue == "" {
		return VerifyDecision{Allowed: false, Reason: string(policy.ReasonNoSession)}
	}

	blob, err := r.store.Read(ctx, in.CookieValue)
	offlineServed := false
	if err != nil {
		// DDIL P3.1 governed offline session-grace. On a pure Redis-store
		// UNAVAILABILITY (transport error / breaker open — NOT a genuine
		// not-found / revoked / expired / auth-fail, which stay fail-closed),
		// serve a signed last-known-good session within budget instead of
		// denying at t=0. Privileged (critical/high) routes get the tighter
		// 5m window, everything else 15m (session.OfflineSessionCache applies
		// the tier from the signed IssuedAt). Only succeeds when a decision
		// was recorded while Redis was healthy; the cache self-reports the
		// ddil_degraded_total{session_store,...} metric. Absent the cache
		// (feature off) or on a genuine session error, we fall through to the
		// unchanged fail-closed path. Without this, the SpiceDB privileged
		// offline PDP is unreachable during a Redis outage (the session read
		// fails first).
		if r.offlineSessions != nil && session.IsUnavailable(err) {
			if b, ok := r.offlineSessions.Serve(in.CookieValue, privilegedSensitivity(up.sensitivity)); ok {
				blob = b
				offlineServed = true
			}
		}
		if !offlineServed {
			reason := classifyVerifySessionErr(err)
			r.metrics.AuthDecision.WithLabelValues(in.Host, "deny", reason).Inc()
			if errors.Is(err, session.ErrRevoked) {
				r.metrics.EdgeRevokeBlock.WithLabelValues(in.Host).Inc()
			}
			return VerifyDecision{Allowed: false, Reason: reason}
		}
	} else {
		// Successful live read — record a signed last-known-good session so a
		// later Redis outage can serve it within budget (no-op when the cache
		// is nil / throttled). The rest of the gate (per-host, policy, step-up)
		// runs on the served blob identically whether it came from Redis or the
		// offline cache, preserving the shared-PDP invariant.
		r.offlineSessions.Record(in.CookieValue, blob)
	}

	// ADR 0044 — classify the access channel from the original-client host
	// so the clientless absolute-TTL cap + AAL cap below apply identically
	// to the ext_authz / forward-auth surface as to ServeHTTP. Empty
	// ClientlessHostSuffixes = tier disabled → channel="cookie".
	channel := r.sessionChannel(in.Host)

	// Per-host session-control gate (Phase 4 batch). Same evaluation
	// as serveAuthVerify; emits the same audit event vocabulary. The
	// channel selects the absolute-TTL cap (clientlessMaxTTL tightens it).
	// Skip the last-seen read when serving offline — Redis is unreachable, so
	// this would only hit the open breaker; a zero lastSeen makes the per-host
	// idle gate fall back to the blob.IAT floor (its normal "no activity yet"
	// path), the correct governed-degrade posture.
	var lastSeen time.Time
	if !offlineServed {
		lastSeen, _ = r.store.GetLastSeen(ctx, in.CookieValue)
	}
	phv := evaluatePerHost(up, blob, time.Now(), in.SrcIP, lastSeen, channel)
	if !phv.ok {
		// auditDecisionLabel: "would_deny" in soak (kept out of the real
		// deny rate TalonAuthFailureRate sums), "deny" when enforcing.
		r.metrics.AuthDecision.WithLabelValues(in.Host, auditDecisionLabel(up.auditOnly, "deny"), string(phv.reason)).Inc()
		if up.auditOnly {
			emitWouldHaveDenied(ctx, r.audit, blob,
				in.Host, in.Method, in.Path, in.CookieValue, up.permission, phv.reason)
			logger.Info("verify: per-host check would have denied (audit-only)",
				"host", in.Host, "sub", blob.Sub, "reason", phv.reason)
			// audit-only soak: continue to the policy stage instead of denying
		} else {
			r.audit.Deny(ctx, audit.Record{
				Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
				Route: in.Host, Method: in.Method, Path: in.Path,
				Reason: string(phv.reason), SessionID: in.CookieValue,
				Permission: up.permission, Issuer: blob.Iss, SrcIP: blob.SrcIP,
			})
			return VerifyDecision{
				Allowed: false,
				Reason:  string(phv.reason),
				Blob:    blob,
			}
		}
	}

	verdict := r.pe.Evaluate(ctx, blob, in.Host, up.permission, up.sensitivity)
	r.metrics.AuthDecision.WithLabelValues(in.Host, string(verdict.Decision), string(verdict.Reason)).Inc()
	if verdict.Decision != policy.Allow {
		r.audit.Deny(ctx, audit.Record{
			Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
			Route: in.Host, Method: in.Method, Path: in.Path,
			Reason: string(verdict.Reason), SessionID: in.CookieValue,
			Permission: up.permission, Issuer: blob.Iss,
		})
		return VerifyDecision{
			Allowed: false,
			Reason:  string(verdict.Reason),
			Blob:    blob,
		}
	}

	// ADR 0044 fail-closed cap — a clientless (agentless, no-device-cert)
	// session MUST NOT reach a critical route unless the route explicitly
	// opts in (allowClientless). Mirrors ServeHTTP exactly so the ext_authz
	// / forward-auth surface enforces the same access-channel boundary; a
	// divergence here is a Phase 7 shared-PDP invariant violation. Not
	// subject to auditOnly (access-channel boundary, and the tier is opt-in).
	if channel == policy.ChannelClientless && up.sensitivity == "critical" && !up.allowClientless {
		r.metrics.AuthDecision.WithLabelValues(in.Host, "deny", "clientless_critical_denied").Inc()
		r.audit.Deny(ctx, audit.Record{
			Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
			Route: in.Host, Method: in.Method, Path: in.Path,
			Reason: "clientless_critical_denied", SessionID: in.CookieValue,
			Permission: up.permission, Issuer: blob.Iss,
		})
		return VerifyDecision{
			Allowed: false,
			Reason:  "clientless_critical_denied",
			Blob:    blob,
		}
	}

	// ADR 0044 AAL cap — a clientless session MUST be ≥ WebAuthn/AAL2
	// before reaching ANY access-zone route. Reuses the RFC 9470 challenge
	// path (advertising the AAL2 acr_values) so API clients can re-auth
	// with a phishing-resistant factor. STRICTER than the route-level
	// mfaRequired gate below. Honours auditOnly to match ServeHTTP.
	if channel == policy.ChannelClientless && !clientlessAALSatisfied(blob) {
		r.metrics.AuthDecision.WithLabelValues(in.Host, auditDecisionLabel(up.auditOnly, "deny"), "clientless_aal_required").Inc()
		if up.auditOnly {
			emitWouldHaveDenied(ctx, r.audit, blob,
				in.Host, in.Method, in.Path, in.CookieValue, up.permission, "clientless_aal_required")
			logger.Info("verify: clientless AAL cap would have challenged (audit-only)",
				"host", in.Host, "sub", blob.Sub, "amr", blob.AMR, "acr", blob.ACR)
			// audit-only soak: fall through to the step-up gate / allow.
		} else {
			mfa := false
			r.audit.MFAChallenge(ctx, audit.Record{
				Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
				Route: in.Host, Method: in.Method, Path: in.Path,
				MFA: &mfa, SessionID: in.CookieValue, Issuer: blob.Iss,
			})
			r.metrics.AuthzDecision.WithLabelValues(matchedRuleName, "stepup", in.Host).Inc()
			return VerifyDecision{
				Allowed:         false,
				Reason:          "clientless_aal_required",
				MFARequired:     true,
				Blob:            blob,
				WWWAuthenticate: BuildRFC9470Challenge(clientlessStepUpACR, true, mfaMaxAgeSecForSensitivity(up.sensitivity)),
			}
		}
	}

	// Step-up gate — Phase 6b-3 emits the RFC 9470 challenge header
	// alongside the existing 401+X-Talon-Reason=mfa_required wire
	// shape. Both surface adapters (HTTP forward-auth + gRPC
	// ext_authz) write the WWWAuthenticate field onto their
	// respective response — API clients can re-authenticate
	// without a calling-proxy redirect.
	stepUpOK, _ := stepUpSatisfied(up.mfaRequired, up.requireACR, blob)
	if !stepUpOK {
		mfa := false
		r.audit.MFAChallenge(ctx, audit.Record{
			Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
			Route: in.Host, Method: in.Method, Path: in.Path,
			MFA: &mfa, SessionID: in.CookieValue, Issuer: blob.Iss,
		})
		r.metrics.AuthzDecision.WithLabelValues(matchedRuleName, "stepup", in.Host).Inc()
		return VerifyDecision{
			Allowed:         false,
			Reason:          "mfa_required",
			MFARequired:     true,
			Blob:            blob,
			WWWAuthenticate: BuildRFC9470Challenge(up.requireACR, up.mfaRequired, mfaMaxAgeSecForSensitivity(up.sensitivity)),
		}
	}

	// Sliding refresh — best-effort, mirrors serveAuthVerify exactly.
	// Skipped when serving from the offline cache: Redis is unreachable so both
	// writes would fail, and the served session's own signed budget (not a
	// Redis TTL) already bounds the offline window.
	if !offlineServed {
		if err := r.store.SlidingRefresh(ctx, in.CookieValue, blob); err != nil {
			logger.Warn("verify: sliding refresh failed", "err", err)
		}
		if err := r.store.TouchLastSeen(ctx, in.CookieValue); err != nil {
			logger.Warn("verify: touch last-seen failed", "err", err)
		}
	}

	mfa := containsAnyMFA(blob.AMR)
	r.audit.Allow(ctx, audit.Record{
		Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
		Route: in.Host, Method: in.Method, Path: in.Path,
		Reason: "verify", MFA: &mfa, SessionID: in.CookieValue,
		Permission: up.permission, Issuer: blob.Iss,
	})
	r.metrics.AuthzDecision.WithLabelValues(matchedRuleName, "allow", in.Host).Inc()

	return VerifyDecision{
		Allowed:         true,
		IdentityHeaders: buildIdentityHeaders(blob),
		Blob:            blob,
	}
}

// overlayUpstreamPolicy returns a per-request copy of `up` with the
// matched PathRule's Policy fields overlayed on top. Fields the rule
// leaves zero/nil inherit from the host default (the original `up`).
// Phase 7.3 — only the fields meaningfully overrideable per-path are
// overlayed:
//
//   - Permission       (per-path different access tier; e.g.,
//     /admin/* requires editor while /api/* viewer)
//   - AllowedGroups    (per-path different group gate)
//   - MfaRequired      (step-up only on sensitive paths)
//   - AcrValues        (per-path ACR requirement; RFC 9470)
//   - AuthMode         (per-path different auth channel; e.g.,
//     /api/* = bearer_or_basic_with_credential_
//     exchange while /admin/* = cookie)
//
// Fields NOT overlayed (host-level by design): SessionAbsoluteSec,
// SessionIdleSec, ReauthOnIP, RequireDeviceClaims, AuditOnly,
// ContinuousVerifyMinutes, Rego. These are host-wide invariants —
// a per-path session TTL would be operationally surprising.
//
// Returns a new upstreamEntry value (not a pointer); the caller is
// safe to mutate the returned copy without affecting the map entry.
func overlayUpstreamPolicy(up upstreamEntry, p v1beta1.Policy) upstreamEntry {
	if p.Permission != "" {
		up.permission = string(p.Permission)
	}
	if p.AuthMode != "" {
		// Re-validate authMode using the same fallback semantics as
		// RegisterUpstream — unrecognised values fall back to the
		// route's existing authMode rather than silently downgrading
		// to cookie (which would defeat the overlay's intent).
		// Phase 7.3 keeps it strict: accept only valid enum values;
		// invalid stays at the host default.
		if isValidAuthMode(p.AuthMode) {
			up.authMode = svctokenAuthMode(p.AuthMode)
		}
	}
	if len(p.AllowedGroups) > 0 {
		// AllowedGroups is consulted by policy.Composite.Evaluate via
		// the SpiceDB role-to-group mapping. The overlay replaces (not
		// adds) the group list — matches the YAML-overlay intent in
		// the design ("fields set on the rule override the
		// default"). To inherit, simply don't set the field.
		_ = p.AllowedGroups // groups flow through pe.Evaluate via blob.Groups; overlay shape TBD in Phase 7.3.b
	}
	if p.MfaRequired {
		up.mfaRequired = true
	}
	if len(p.AcrValues) > 0 {
		up.requireACR = append([]string(nil), p.AcrValues...)
	}
	return up
}

// isValidAuthMode is a thin string-based check so the overlay path
// doesn't depend on the svctoken package's exact enum shape. Mirrors
// the v1beta1 schema's `+kubebuilder:validation:Enum=...` set.
func isValidAuthMode(m string) bool {
	switch m {
	case "cookie", "bearer", "both",
		"bearer_or_passthrough",
		"bearer_or_basic_with_credential_exchange",
		"bearer_or_federated_passthrough",
		"cookie_or_bearer_or_passthrough",
		"anonymous":
		return true
	}
	return false
}

// svctokenAuthMode converts a v1beta1.Policy.AuthMode string into the
// svctoken.AuthMode type the router stores. Local helper to avoid an
// import cycle (svctoken is consumed by router, not the other way).
//
// The cast is safe because both types are string-backed enums with
// the same set of valid values — isValidAuthMode is the gate.
func svctokenAuthMode(m string) svctoken.AuthMode {
	return svctoken.AuthMode(m)
}

// buildIdentityHeaders returns the X-Talon-* identity headers per ADR
// 0005. Mirrors injectIdentityHeaders(w, blob) but returns a map so
// both the HTTP adapter (writes to http.ResponseWriter) and the gRPC
// ext_authz adapter (writes to CheckResponse.OkHttpResponse.Headers)
// can consume the same vocabulary. Any future header addition lands
// on both wire formats simultaneously.
func buildIdentityHeaders(b *session.Blob) map[string]string {
	h := map[string]string{
		"X-Talon-User":    b.Sub,
		"X-Talon-Subject": b.Sub,
		"X-Talon-Email":   b.Email,
	}
	if b.TenantID != "" {
		h["X-Talon-Tenant-Id"] = b.TenantID
	}
	if len(b.Groups) > 0 {
		h["X-Talon-Groups"] = strings.Join(b.Groups, ",")
	}
	if b.Iss != "" {
		h["X-Talon-Issuer"] = b.Iss
	}
	if b.IAT > 0 {
		// OIDC Core §2 `iat` — when the session was issued. APISIX-
		// side plugins (and any future Envoy ext_authz callers) can
		// compute session age without re-decoding the id_token.
		h["X-Talon-Issued-At"] = strconv.FormatInt(b.IAT, 10)
	}
	return h
}
