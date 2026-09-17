// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers — backchannel_logout.go is the OIDC Back-Channel
// Logout 1.0 receiver per
// https://openid.net/specs/openid-connect-backchannel-1_0.html.
//
// Falcon-ID's BackchannelLogoutService.NotifyLogout (in falcon-id) POSTs
// a signed `logout_token` to this endpoint whenever a user signs out at
// any registered RP. Without this receiver, Talon's session at
// internal.example.com would stay alive for up to 8h (SessionHardTTL)
// after Sign Out at accounts.hexxlock.com — the gap that closed in this
// MR (gap SLO-01 of
// <gitops-bootstrap-repo>/docs/audits/2026-Q2-tier1-iam-iap-audit.md).
//
// AUTHENTICATION
//
// The signed JWT IS the authentication for this endpoint per spec §2.6.
// Defense-in-depth comes from three additional layers configured at the
// platform level:
//   - Linkerd Server CR + AuthorizationPolicy + MeshTLSAuthentication on
//     the Talon Pod gates the wire-level path to a SPIFFE-identity
//     allow-list. No mesh, no POST.
//   - The Talon AuthorizationPolicy listed in deploy/helm/talon/templates/
//     authorizationpolicy.yaml restricts callers to falcon-id's SA.
//   - The handler validates the JWT signature against Falcon-ID's JWKS,
//     iss, aud, exp, iat skew, the spec-required `events` map shape,
//     and the absence of a `nonce`. A `jti`-keyed Redis SETNX provides
//     replay defense (spec §2.6 fourth bullet).
//
// SESSION RESOLUTION
//
// The handler scopes the cascade to `sub` (fan out via the existing
// talon:revoke-by-sub:<sub> ZRange index). Per-`sid` resolution would
// require capturing the OP's session UUID into Blob — tracked as a
// follow-up. Per-sub matches both the spec semantics (§2.5: "the RP
// MUST then perform the corresponding logout action(s)") and the
// existing /admin/revoke fan-out shape, so the audit trail stays
// uniform across cascade triggers.
//
// AUDIT
//
// Each revoked session emits an auth.backchannel_logout event. The
// `reason` field carries the originating logout_token's jti for forensic
// correlation back to the upstream OP log line.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	xoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/talon/internal/audit"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
)

// backchannelLogoutEventClaim is the OIDC-mandated key in the `events`
// claim that distinguishes a logout token from any other event token
// shape (RFC 8417 / SET).
const backchannelLogoutEventClaim = "http://schemas.openid.net/event/backchannel-logout"

// BackchannelLogout is the spec-§2.6 receiver for OIDC Back-Channel
// Logout 1.0. Mounted on the auth host at POST /auth/backchannel-logout.
type BackchannelLogout struct {
	// Verifier validates logout_token signature against the OP's JWKS,
	// `iss == OP issuer`, `aud == Talon client_id`, and `exp > now`.
	// Falcon-ID emits exp=iat+2min so default expiry checking is fine;
	// IAT skew is enforced separately so a logout_token without exp
	// (allowed by spec) still gets a freshness bound.
	Verifier *xoidc.IDTokenVerifier
	// Store is the session store; Read + Revoke both run through it.
	Store *session.Store
	// Redis is the same client that backs Store; used for the
	// per-`sub` revocation index ZRange and the jti replay-defense
	// SETNX.
	Redis *redis.Client
	// Audit emits the auth.backchannel_logout event per revoked session.
	Audit *audit.Emitter
	// MaxIATSkew bounds how stale an incoming logout_token can be.
	// Default 5 minutes — generous enough to absorb clock drift in a
	// single-cluster deployment but tight enough to make a captured
	// token replay-class attack window finite. The same value drives
	// the jti SETNX TTL.
	MaxIATSkew time.Duration
	// IssuerURL is the expected OP issuer; surfaced in error responses
	// and audit logs so operators don't have to cross-reference
	// Verifier internals.
	IssuerURL string
}

// logoutClaims is the spec-§2.4 shape of the JWT body. Required: iss,
// aud, iat, jti, events, and (sub or sid). MUST NOT include `nonce`.
type logoutClaims struct {
	Issuer   string                 `json:"iss"`
	Audience interface{}            `json:"aud"` // string OR []string per RFC 7519
	IssuedAt int64                  `json:"iat"`
	JTI      string                 `json:"jti"`
	Subject  string                 `json:"sub,omitempty"`
	SID      string                 `json:"sid,omitempty"`
	Events   map[string]interface{} `json:"events"`
	Nonce    string                 `json:"nonce,omitempty"` // MUST be empty per spec
}

// ServeHTTP implements POST /auth/backchannel-logout per
// OIDC Back-Channel Logout 1.0 §2.6.
//
// Response codes:
//
//	200  logout processed (or no sessions found — both spec-OK)
//	400  malformed token or replay
//	405  non-POST
//	500  internal store error
//
// Every non-200 response carries an X-Talon-Reason header so an
// operator can grep Falcon-ID's BackchannelLogout delivery logs against
// it without parsing the body (which is intentionally empty per spec).
func (h *BackchannelLogout) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())
	w.Header().Set("Cache-Control", "no-store")

	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("X-Talon-Reason", "method_not_allowed")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	if h.Verifier == nil || h.Store == nil || h.Redis == nil || h.Audit == nil {
		// Mis-wired build — fail closed and log so the next deploy fixes
		// it. Spec compliance MUST NOT be optional at runtime.
		logger.Error("backchannel logout: handler missing dependency")
		w.Header().Set("X-Talon-Reason", "handler_not_ready")
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}

	maxSkew := h.MaxIATSkew
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}

	// Cap the form body before ParseForm. A spec-conformant logout_token
	// is well under 8 KiB even with extension claims; 64 KiB leaves
	// generous headroom while making memory-exhaustion DoS infeasible
	// (gosec G120). The ParseForm + PostFormValue pair below both pull
	// from req.Body, so the cap MUST be set on the same Body reader
	// before either touches it.
	req.Body = http.MaxBytesReader(w, req.Body, 64*1024)

	if err := req.ParseForm(); err != nil {
		w.Header().Set("X-Talon-Reason", "malformed_form")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	rawToken := strings.TrimSpace(req.PostFormValue("logout_token"))
	if rawToken == "" {
		w.Header().Set("X-Talon-Reason", "missing_logout_token")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// Spec §2.6 step 1+2 — signature, iss, aud, exp via go-oidc
	// IDTokenVerifier (Falcon-ID emits exp on the logout_token; default
	// expiry check is correct).
	idToken, err := h.Verifier.Verify(req.Context(), rawToken)
	if err != nil {
		w.Header().Set("X-Talon-Reason", "verify_failed")
		logger.Warn("backchannel logout: token verify failed", "err", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// Spec §2.6 step 3 — extract + validate claims body.
	var claims logoutClaims
	if err := idToken.Claims(&claims); err != nil {
		w.Header().Set("X-Talon-Reason", "claims_parse")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if err := validateLogoutClaims(&claims, h.IssuerURL, maxSkew); err != nil {
		w.Header().Set("X-Talon-Reason", reasonFromValidationErr(err))
		logger.Warn("backchannel logout: claims invalid",
			"err", err, "jti_prefix", safePrefix(claims.JTI),
			"iat_age", time.Since(time.Unix(claims.IssuedAt, 0)).String())
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// Spec §2.6 fifth bullet — replay defense via jti.
	jtiKey := "talon:slo:jti:" + claims.JTI
	jtiTTL := 2*maxSkew + time.Minute
	set, err := h.Redis.SetNX(req.Context(), jtiKey, "1", jtiTTL).Result()
	if err != nil {
		// Redis is required for replay defense; fail closed rather than
		// silently accept potential replays.
		logger.Error("backchannel logout: redis setnx failed", "err", err)
		w.Header().Set("X-Talon-Reason", "replay_check_failed")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	if !set {
		w.Header().Set("X-Talon-Reason", "replayed_jti")
		logger.Warn("backchannel logout: replayed jti rejected",
			"jti_prefix", safePrefix(claims.JTI))
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	revoked := h.cascade(req.Context(), claims.Subject, claims.JTI, claims.Issuer)

	logger.Info("backchannel logout processed",
		"sub", claims.Subject, "sid", claims.SID,
		"jti_prefix", safePrefix(claims.JTI), "revoked", revoked)

	// Spec §2.6: success returns 200 with no body. Talon adds an
	// internal-only debug header so e2e harnesses can assert the
	// fan-out count without screen-scraping logs.
	w.Header().Set("X-Talon-Revoked", fmt.Sprintf("%d", revoked))
	w.WriteHeader(http.StatusOK)
}

// cascade fans out the revocation across all Talon sessions for sub.
// Per-`sid` resolution would require capturing the OP's session UUID
// into the session blob — tracked as a follow-up. Per-sub matches the
// existing streaming-revocation fan-out at /admin/revoke for audit
// uniformity.
//
// Returns the number of sessions actually revoked. Sessions that were
// already gone (race with /admin/revoke or natural expiry) get pruned
// from the per-sub index in passing.
func (h *BackchannelLogout) cascade(ctx context.Context, sub, jti, iss string) int {
	logger := tlog.From(ctx)

	if sub == "" {
		// Spec §2.5 allows sid-only logout tokens; without sub we'd
		// need OP-sid → cookieID resolution which Talon does not yet
		// support. Surfacing this as a "no-op" event keeps audit trail
		// honest until follow-up SLO-02 lands.
		logger.Warn("backchannel logout: sub-less token; cascade skipped pending sid index")
		return 0
	}

	cookieIDs, err := h.Redis.ZRange(ctx, "talon:revoke-by-sub:"+sub, 0, -1).Result()
	if err != nil {
		logger.Error("backchannel logout: ZRange revoke-by-sub failed",
			"sub", sub, "err", err)
		return 0
	}
	if len(cookieIDs) == 0 {
		// User has no Talon sessions — also spec-OK. The OP doesn't
		// know which RPs the user has sessions at, so a best-effort
		// fan-out is expected to find empty for some receivers.
		return 0
	}

	revoked := 0
	for _, cookieID := range cookieIDs {
		blob, err := h.Store.Read(ctx, cookieID)
		if err != nil {
			// Already gone — prune the index entry and move on.
			h.Redis.ZRem(ctx, "talon:revoke-by-sub:"+sub, cookieID)
			continue
		}
		if err := h.Store.Revoke(ctx, cookieID, blob); err != nil {
			logger.Warn("backchannel logout: revoke failed",
				"cookie_id_prefix", safePrefix(cookieID), "err", err)
			continue
		}
		revoked++
		h.Audit.BackchannelLogout(ctx, audit.Record{
			Sub:       sub,
			Email:     blob.Email,
			TenantID:  blob.TenantID,
			SessionID: cookieID,
			Issuer:    iss,
			Reason:    "logout_token_jti=" + safePrefix(jti),
		})
	}
	return revoked
}

// validateLogoutClaims enforces the spec-§2.4 + §2.6 invariants the
// underlying *xoidc.IDTokenVerifier doesn't cover (verifier handles
// signature + iss + aud + exp; everything else lives here).
func validateLogoutClaims(c *logoutClaims, expectedIss string, maxSkew time.Duration) error {
	if c.Issuer == "" || (expectedIss != "" && c.Issuer != expectedIss) {
		return errIssuerMismatch
	}
	if c.JTI == "" {
		return errMissingJTI
	}
	if c.IssuedAt == 0 {
		return errMissingIAT
	}
	now := time.Now().Unix()
	if c.IssuedAt > now+int64(maxSkew.Seconds()) {
		return errIATFuture
	}
	if c.IssuedAt < now-int64(maxSkew.Seconds()) {
		return errIATTooOld
	}
	if c.Nonce != "" {
		return errForbiddenNonce
	}
	if c.Subject == "" && c.SID == "" {
		return errMissingSubAndSID
	}
	if len(c.Events) == 0 {
		return errMissingEvents
	}
	ev, ok := c.Events[backchannelLogoutEventClaim]
	if !ok {
		return errMissingLogoutEvent
	}
	// Spec §2.4: the value MUST be the empty JSON object `{}`. Permit
	// both `map[string]interface{}{}` and explicit nil for tolerance —
	// any non-empty payload (a non-empty map, a non-object value)
	// signals a misformed token.
	switch v := ev.(type) {
	case nil:
		// Some marshalers serialise the empty struct{} as null.
		return nil
	case map[string]interface{}:
		if len(v) != 0 {
			return errMalformedLogoutEvent
		}
	default:
		return errMalformedLogoutEvent
	}
	return nil
}

// reasonFromValidationErr maps validation-error sentinels to the
// X-Talon-Reason header value so operators can grep delivery logs
// without parsing the response body.
func reasonFromValidationErr(err error) string {
	switch {
	case errors.Is(err, errIssuerMismatch):
		return "issuer_mismatch"
	case errors.Is(err, errMissingJTI):
		return "missing_jti"
	case errors.Is(err, errMissingIAT):
		return "missing_iat"
	case errors.Is(err, errIATFuture):
		return "iat_future"
	case errors.Is(err, errIATTooOld):
		return "iat_too_old"
	case errors.Is(err, errForbiddenNonce):
		return "forbidden_nonce"
	case errors.Is(err, errMissingSubAndSID):
		return "missing_sub_and_sid"
	case errors.Is(err, errMissingEvents):
		return "missing_events"
	case errors.Is(err, errMissingLogoutEvent):
		return "missing_logout_event"
	case errors.Is(err, errMalformedLogoutEvent):
		return "malformed_logout_event"
	default:
		return "claims_invalid"
	}
}

var (
	errIssuerMismatch       = errors.New("iss claim mismatch")
	errMissingJTI           = errors.New("missing jti claim")
	errMissingIAT           = errors.New("missing iat claim")
	errIATFuture            = errors.New("iat claim is in the future beyond clock skew")
	errIATTooOld            = errors.New("iat claim is older than max clock skew")
	errForbiddenNonce       = errors.New("logout_token MUST NOT carry a nonce claim")
	errMissingSubAndSID     = errors.New("logout_token MUST contain sub and/or sid")
	errMissingEvents        = errors.New("missing events claim")
	errMissingLogoutEvent   = errors.New("events claim missing backchannel-logout event")
	errMalformedLogoutEvent = errors.New("backchannel-logout event value MUST be an empty object")
)

// _ keeps json.Marshal in scope for tests that build JWTs by hand.
var _ = json.Marshal
