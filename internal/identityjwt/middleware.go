// SPDX-License-Identifier: AGPL-3.0-or-later

// middleware.go — drop-in net/http middleware that mounts the
// Verifier in front of an upstream's handler chain. Lets a Go service
// behind Talon adopt cryptographic IAP trust with one line:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/", identityjwt.Middleware(verifier)(apiHandler))
//
// Behaviour matches the Phase B contract documented in ADR 0005:
//   - X-Talon-Identity-Token absent OR verify fails → 401.
//   - Verify succeeds → claims are stashed in request context; the
//     downstream handler reads them via ClaimsFromContext(ctx).
//   - JWKS unreachable → 401 with a different code so ops dashboards
//     can distinguish "client sent bad token" from "Talon is down"
//     (the same fail-closed posture Cloudflare Access / Google IAP /
//     AWS ALB OIDC have shipped for years).
//
// The 401 body is JSON with a `code` field upstream client SDKs can
// branch on, mirroring the Falcon-ID client's iap_event taxonomy:
//
//	{"error":"...","code":"iap_token_missing"}
//	{"error":"...","code":"iap_token_invalid","reason":"audience_mismatch"}
//	{"error":"...","code":"iap_jwks_unavailable"}
//
// Reason codes match the SDK side (signature_failed, expired,
// issuer_mismatch, audience_mismatch, not_yet_valid, alg_not_allowed,
// jwt_invalid, unknown) so SOC dashboards correlate both verifier
// dialects on a single discriminator.
package identityjwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// MiddlewareOptions tunes the middleware's failure policy. Zero-value
// is the safe Phase B default: fail closed on every verify failure +
// always 401 with a JSON body. Operators dial it back via these
// fields for narrow cases (a metrics endpoint that needs to stay
// open, a maintenance route that accepts cookie-only auth, etc.).
type MiddlewareOptions struct {
	// OnUnverified replaces the default 401-JSON response. Useful for
	// services that want to render an HTML login redirect, plumb a
	// custom code field, or log additional context. Receives the
	// classified failure (reason) so the handler can branch without
	// re-parsing.
	OnUnverified func(w http.ResponseWriter, r *http.Request, failure VerifyFailure)

	// AllowMissing keeps the request flowing when no token is present.
	// The downstream handler can detect this via
	// ClaimsFromContext == nil + fall back to its own auth path
	// (cookie, API key, etc.). Phase A behaviour; defaults to false
	// (= Phase B fail-closed) since that's the tier-1 default.
	AllowMissing bool
}

// VerifyFailure carries the classification of the verify failure
// passed to OnUnverified callbacks. Reason mirrors the SDK's
// IapVerifyReason enum verbatim so Loki / Wazuh rules treat both
// sides as one taxonomy.
type VerifyFailure struct {
	// Code is the high-level discriminator. One of:
	//   iap_token_missing
	//   iap_token_invalid
	//   iap_jwks_unavailable
	Code string

	// Reason is the fine-grained verify-failure category for
	// iap_token_invalid; empty for the other two codes. Same enum as
	// the SDK side: signature_failed, expired, issuer_mismatch,
	// audience_mismatch, not_yet_valid, alg_not_allowed, jwt_invalid,
	// unknown.
	Reason string

	// Err is the wrapped verifier error — preserved for logging /
	// optional surfacing in a custom OnUnverified handler. NEVER
	// returned to the client; the error message can leak details
	// useful only to an attacker probing for misconfiguration.
	Err error
}

// claimsContextKey is the typed key under which verified IdentityClaims
// land on the request context. Typed (not string) per the standard
// net/http guideline to defeat accidental collisions.
type claimsContextKey struct{}

// ClaimsFromContext returns the verified IdentityClaims stashed by
// Middleware on the request context, or nil if no claims were
// verified (= the middleware let the request through under
// AllowMissing, or the request wasn't routed through Middleware at
// all).
func ClaimsFromContext(ctx context.Context) *IdentityClaims {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(claimsContextKey{}).(*IdentityClaims)
	return v
}

// withClaims returns ctx with the given claims attached. Exported for
// test rigs that need to simulate "verified" requests without the
// full mint+verify round-trip; production callers always reach this
// path via Middleware().
func withClaims(ctx context.Context, claims *IdentityClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// Middleware returns an http.Handler middleware that verifies the
// X-Talon-Identity-Token JWT on every request before delegating to
// next. See MiddlewareOptions for failure-policy knobs.
//
// Threading semantics: the verifier is safe for concurrent calls and
// caches JWKS internally, so one middleware instance scales across
// the upstream's full request volume.
func Middleware(v *Verifier, opts ...MiddlewareOptions) func(http.Handler) http.Handler {
	var opt MiddlewareOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.OnUnverified == nil {
		opt.OnUnverified = defaultOnUnverified
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v == nil {
				// Verifier was never wired — protect against accidental
				// passthrough in production by failing closed. Matches
				// the no-token path semantically (= Phase B).
				opt.OnUnverified(w, r, VerifyFailure{
					Code: "iap_token_missing",
					Err:  errors.New("identityjwt: nil verifier"),
				})
				return
			}
			claims, err := v.VerifyRequest(r)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
				return
			}
			if errors.Is(err, ErrNoToken) {
				if opt.AllowMissing {
					next.ServeHTTP(w, r)
					return
				}
				opt.OnUnverified(w, r, VerifyFailure{Code: "iap_token_missing", Err: err})
				return
			}
			if errors.Is(err, ErrJWKSUnavailable) {
				opt.OnUnverified(w, r, VerifyFailure{Code: "iap_jwks_unavailable", Err: err})
				return
			}
			opt.OnUnverified(w, r, VerifyFailure{
				Code:   "iap_token_invalid",
				Reason: classifyReason(err),
				Err:    err,
			})
		})
	}
}

// classifyReason maps a verifier error to the SDK-shared reason enum.
// Lives here for historical reasons (middleware was first consumer);
// also used by the verifier itself for metrics labelling. Single
// taxonomy across middleware response bodies + metrics + audit so
// SOC dashboards correlate on one set of strings.
func classifyReason(err error) string {
	switch {
	case errors.Is(err, ErrSignatureInvalid):
		return "signature_failed"
	case errors.Is(err, ErrTokenExpired):
		return "expired"
	case errors.Is(err, ErrTokenNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrIssuerMismatch):
		return "issuer_mismatch"
	case errors.Is(err, ErrAudienceMismatch):
		return "audience_mismatch"
	case errors.Is(err, ErrAlgNotAllowed):
		return "alg_not_allowed"
	case errors.Is(err, ErrTokenMalformed):
		return "jwt_invalid"
	case errors.Is(err, ErrReplay):
		return "replay"
	}
	return "unknown"
}

// defaultOnUnverified writes a JSON 401 body matching the SDK side's
// error-code taxonomy. Operators can override via
// MiddlewareOptions.OnUnverified.
func defaultOnUnverified(w http.ResponseWriter, _ *http.Request, f VerifyFailure) {
	type body struct {
		Error  string `json:"error"`
		Code   string `json:"code"`
		Reason string `json:"reason,omitempty"`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	msg := "Not authenticated"
	switch f.Code {
	case "iap_jwks_unavailable":
		msg = "Identity verification temporarily unavailable"
	case "iap_token_invalid":
		msg = "Identity token invalid"
	}
	_ = json.NewEncoder(w).Encode(body{Error: msg, Code: f.Code, Reason: f.Reason})
}
