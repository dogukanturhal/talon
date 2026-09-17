// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"errors"
	"net/http"
)

// claimsCtxKey is the private type used to thread verified Claims
// through the request context to the downstream proxy. Downstream
// code retrieves with ClaimsFromContext.
type claimsCtxKey struct{}

// ClaimsFromContext returns the verified Claims previously attached
// by Middleware, or nil if the request was not authenticated via the
// bearer path (e.g., the cookie path served this request).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsCtxKey{}).(*Claims)
	return c
}

// WithClaims attaches Claims to ctx. Exported for tests + for
// upstreams that synthesise claims for replay/dev scenarios.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

// AuthMode controls how a single host treats incoming requests.
// Configured per Server CR (`authMode` field).
type AuthMode string

const (
	// AuthModeCookie — only cookie-session requests are accepted.
	// Bearer headers are ignored (no machine path for this host).
	// Default for back-compat with existing browser-only Server CRs.
	AuthModeCookie AuthMode = "cookie"

	// AuthModeBearer — only Bearer-token requests are accepted.
	// Missing/invalid Bearer → 401 (no OIDC dance for this host).
	// Use for machine-only endpoints (e.g., a dedicated API host).
	AuthModeBearer AuthMode = "bearer"

	// AuthModeBoth — Bearer-first, cookie fallback. The mixed-traffic
	// mode for hosts that serve both human browsers + machine clients
	// (github.com, registry.example.com).
	AuthModeBoth AuthMode = "both"

	// AuthModeBearerOrPassthrough — Bearer-first; when Bearer header is
	// absent, proxy the request to upstream with the original Authorization
	// header intact and skip the OIDC dance entirely. This is the
	// enterprise BeyondCorp pattern Cloudflare Access, Pomerium, Boundary,
	// and Teleport use for hosts that mix Bearer-authenticated machine
	// consumers with native-auth legacy callers on the SAME hostname.
	//
	// Concrete example — github.com:
	//   - ArgoCD repo-server (canary)   sends Authorization: Bearer <jwt>
	//                                   -> svctoken verify + proxy with claims
	//   - Atlantis (legacy PAT caller)  sends Authorization: Basic oauth2:<PAT>
	//                                   -> no Bearer header -> passthrough
	//                                      to GitLab which handles the PAT
	//                                      natively
	//   - Human browser                 -> no Bearer -> passthrough; GitLab
	//                                      serves its native /users/sign_in
	//                                      page (no Talon IAP gate for this
	//                                      mode by design)
	//
	// Distinction from AuthModeBoth: this mode never runs the cookie
	// path. Hosts that want IAP for browsers AND Bearer for machines on
	// the same name still use AuthModeBoth.
	//
	// Distinction from AuthModeBearer: this mode tolerates absent Bearer
	// (proxies through). Bearer-only hosts 401 in that case.
	AuthModeBearerOrPassthrough AuthMode = "bearer_or_passthrough" //nolint:gosec // G101 false positive — AuthMode discriminator string, not a credential

	// AuthModeBearerOrBasicWithCredentialExchange — the Phase 4.5
	// credential-exchange mode. Accepts the svctoken via EITHER:
	//   - Authorization: Bearer <jwt>, or
	//   - Authorization: Basic base64(<anything>:<jwt>)
	// the latter being the wire shape ArgoCD's go-git produces from a
	// repoCreds Secret (username slot ignored, password is the JWT).
	// On successful verify, the router strips the inbound Authorization
	// and substitutes a per-host upstream credential (PAT / robot
	// account) sourced from a Kubernetes Secret in the talon ns. The
	// substitution closes the gap where a legacy upstream (self-hosted
	// GitLab, JFrog Artifactory, etc.) cannot validate Falcon-ID-issued
	// JWTs natively.
	//
	// On absent Bearer + absent svctoken-shape Basic password (e.g.
	// `Basic oauth2:glpat-xxx`, a legacy PAT call): falls through to
	// OutcomePassthrough — Talon forwards the request with the original
	// Authorization intact, preserving existing PAT-based workflows.
	// This is identical to AuthModeBearerOrPassthrough's no-Bearer
	// behaviour and is the property that lets a host roll out
	// credential exchange WITHOUT breaking pre-existing legacy callers.
	//
	// On present-but-broken JWT (sig fail / iss / aud / exp / scope):
	// 401 with the canonical Bearer WWW-Authenticate hint, same as
	// AuthModeBearerOrPassthrough. A present-but-broken token is an
	// explicit identity assertion that didn't verify; silently
	// downgrading to passthrough would mask the security event.
	//
	// Architecturally mirrors Envoy ext_authz's allowed_upstream_headers
	// override semantics + Ory Oathkeeper's verify-then-mutate pipeline
	// (research synthesis 2026-05-29).
	AuthModeBearerOrBasicWithCredentialExchange AuthMode = "bearer_or_basic_with_credential_exchange" //nolint:gosec // G101 false positive — AuthMode discriminator string, not a credential

	// AuthModeBearerOrFederatedPassthrough — Bearer-first, with
	// secondary trust for federated issuers.
	//
	// Same wire shape as AuthModeBearerOrPassthrough on the
	// no-Bearer + primary-issuer paths:
	//   - no Authorization header           -> OutcomePassthrough
	//   - Bearer present, primary verify ok -> OutcomeAuthorised (claims)
	//
	// NEW on the primary-iss-mismatch path:
	//   - Bearer present, iss does NOT match primary ExpectedIssuer,
	//     iss IS in the FederatedIssuers registry AND federated verify
	//     (sig + exp + per-issuer AllowedHosts) succeeds
	//                                      -> OutcomePassthrough
	//     (Bearer header preserved; upstream re-validates with its own
	//     authz; no Talon claims attached — Falcon-ID's Claims shape
	//     does not apply to foreign issuers)
	//
	// PRESERVED REJECT PATHS (Envoy CVE-2021-21378 invariant — never
	// silently downgrade a present-but-broken Bearer):
	//   - Bearer present, primary verify fails for any reason OTHER
	//     than iss-mismatch (signature / aud / exp / scope / replay /
	//     revoked) -> OutcomeRejected
	//   - Bearer present, iss NEITHER matches primary NOR any
	//     federated issuer                  -> OutcomeRejected
	//   - Bearer present, iss matches federated registry but the
	//     federated verify itself fails (sig / exp / host-not-allowed)
	//                                       -> OutcomeRejected
	//
	// CANONICAL USE CASE — Harbor v2 Docker registry.
	//
	// Harbor implements the Docker Registry v2 token spec: GET /v2/
	// returns a Bearer-realm challenge, client fetches a Harbor-
	// ISSUED JWT from /service/token, then retries /v2/<repo>/
	// manifests/<tag> with `Authorization: Bearer <harbor-jwt>`.
	// Harbor's JWTs are signed by Harbor's own key (NOT Falcon-ID's
	// JWKS). Without federated trust, Talon's standard verify would
	// 401 every Docker pull cluster-wide. With this mode AND a
	// FederatedIssuerConfig{Issuer: "harbor-token-issuer",
	// StaticPublicKey: <Harbor pubkey>, AllowedHosts: ["registry.example.com"]},
	// Talon confirms the Harbor-Bearer is signed by the trusted key
	// and proxies as-is. Harbor itself enforces per-repo authz via
	// its `access` claim.
	//
	// Architecturally mirrors:
	//   - Envoy jwt_authn map<provider, JwtProvider> with requires_any
	//   - Istio RequestAuthentication.jwtRules[]
	//   - Ory Oathkeeper trusted_issuers[]
	// per 2026-05-30 deep-research synthesis (workflow wf_36f4dd00-d01,
	// 105 agents, adversarially verified against Envoy/Istio CVEs).
	AuthModeBearerOrFederatedPassthrough AuthMode = "bearer_or_federated_passthrough"

	// AuthModeCookieOrBearerOrPassthrough — Path B unified mode
	// (Talon!#### / 2026-06-09). Combines cookie/OIDC SSO + Bearer-or-
	// Basic credential exchange + legacy Basic passthrough + federated
	// Bearer trust on a SINGLE hostname.
	//
	// Wire dispatch is shape-driven:
	//   - no Authorization header        -> OutcomeNotAttempted (cookie
	//                                       path runs; defense-in-depth
	//                                       posture enforcement before
	//                                       upstream)
	//   - Bearer<svctoken> verified      -> OutcomeAuthorised (claims
	//                                       attached; credential-exchange
	//                                       substitution happens at the
	//                                       router layer)
	//   - Basic<*:svctoken> verified     -> same
	//   - Basic<*:legacy-PAT> (no svctoken
	//     shape extractable)             -> OutcomePassthrough (upstream
	//                                       handles native PAT auth)
	//   - Bearer<federated-iss> valid    -> OutcomePassthrough (Bearer
	//                                       preserved; upstream re-
	//                                       validates with its own
	//                                       claim shape)
	//   - Bearer present but broken     -> OutcomeRejected (Envoy
	//                                       CVE-2021-21378 invariant:
	//                                       never silently downgrade a
	//                                       present-but-broken identity
	//                                       assertion)
	//
	// CANONICAL USE CASE — github.com. Three classes of
	// caller share the same hostname after Path B migration:
	//   - human browsers (cookie SSO with device-posture pre-check)
	//   - argocd-repo-server (Bearer svctoken -> credential-exchange ->
	//     upstream PAT)
	//   - Atlantis legacy PAT callers (Basic oauth2:<PAT> -> passthrough)
	//
	// DISTINCTION from AuthModeBoth: this mode adds credential-exchange
	// + Basic JWT-in-password extraction + federated trust on top of the
	// cookie+Bearer dual path. AuthModeBoth is Bearer-only on the
	// machine path, no credential substitution, no federated trust.
	//
	// DISTINCTION from AuthModeBearerOrBasicWithCredentialExchange:
	// that mode passes through no-auth requests (Basic with non-JWT
	// password). This mode runs the cookie path on no-auth, then
	// passes through only on Basic-with-non-JWT-password. Suitable for
	// a hostname where no-auth is overwhelmingly browser traffic.
	//
	// NOT SUITABLE FOR DOCKER REGISTRY V2 surfaces (Harbor) — Docker
	// clients send GET /v2/ with no Authorization expecting a
	// 401 + WWW-Authenticate Bearer-realm reply; routing that to the
	// cookie/OIDC dance would return HTML/302 and break the dance.
	// Harbor stays on AuthModeBearerOrFederatedPassthrough.
	AuthModeCookieOrBearerOrPassthrough AuthMode = "cookie_or_bearer_or_passthrough" //nolint:gosec // G101 false positive — AuthMode discriminator string, not a credential
)

// IsValid reports whether m is a recognised AuthMode value.
func (m AuthMode) IsValid() bool {
	switch m {
	case AuthModeCookie, AuthModeBearer, AuthModeBoth, AuthModeBearerOrPassthrough,
		AuthModeBearerOrBasicWithCredentialExchange,
		AuthModeBearerOrFederatedPassthrough,
		AuthModeCookieOrBearerOrPassthrough, "":
		return true
	default:
		return false
	}
}

// SupportsCredentialExchange reports whether m is a mode on which the
// router should substitute the per-host upstream credential after a
// successful svctoken verification.
//
// Both modes that return true document credential exchange as part of
// their contract:
//
//   - AuthModeBearerOrBasicWithCredentialExchange — the original
//     Phase 4.5 mode; credential exchange IS the mode.
//   - AuthModeCookieOrBearerOrPassthrough — the Path B unified mode,
//     whose doc comment above states it "adds credential-exchange +
//     Basic JWT-in-password extraction + federated trust on top of the
//     cookie+Bearer dual path".
//
// The second was previously absent from the router's guard, which
// checked the first constant by direct equality. The result was a
// silent, confusing failure rather than an error: on a
// cookie_or_bearer_or_passthrough route Talon would verify the caller's
// Falcon-ID token, authorise the request, and forward it WITHOUT
// substituting the upstream credential — so an upstream that cannot
// validate Falcon-ID JWTs saw an unauthenticated request and refused
// it. Caught 2026-08-14 on internal.example.com (Verdaccio), where a
// correctly-scoped token produced `GET /-/whoami -> 200 {}` with an
// empty body and 401 on every private package.
//
// Keeping this as a predicate rather than an inline disjunction means
// the next mode that needs exchange is added in one place, next to the
// doc comments that promise it.
func (m AuthMode) SupportsCredentialExchange() bool {
	switch m {
	case AuthModeBearerOrBasicWithCredentialExchange,
		AuthModeCookieOrBearerOrPassthrough:
		return true
	default:
		return false
	}
}

// Outcome describes what the middleware decided. The router uses this
// to choose the next step (proxy with synthesised blob / fall through
// to cookie path / 401).
type Outcome int

const (
	// OutcomeNotAttempted — the host's AuthMode forbade the bearer path
	// OR no Authorization header was present and the mode allows cookie
	// fallback. Router should run the cookie path next.
	OutcomeNotAttempted Outcome = iota

	// OutcomeAuthorised — Bearer verified, Claims attached to ctx,
	// router should proxy.
	OutcomeAuthorised

	// OutcomeFallthrough — Bearer present but verification failed in
	// a way that's compatible with cookie fallback (AuthModeBoth).
	// Router should run the cookie path next.
	OutcomeFallthrough

	// OutcomeRejected — Bearer present but verification failed AND
	// the host's AuthMode is bearer-only. Router should 401.
	OutcomeRejected

	// OutcomePassthrough — AuthModeBearerOrPassthrough decided no Bearer
	// header is present. Router should proxy DIRECTLY to upstream
	// without OIDC dance, with the request's original Authorization
	// header preserved so the upstream can do its native auth (Basic
	// PAT, session cookie etc.). No Talon claims attached.
	OutcomePassthrough
)

// Decision is the per-request output of Decide. Carries the Outcome
// plus, on success, the verified Claims and the new request bound to
// a context carrying those Claims.
type Decision struct {
	Outcome Outcome
	Claims  *Claims
	Request *http.Request
	Err     error
}

// Decide runs the bearer path for one request. The router calls this
// BEFORE its cookie/session lookup. It does NOT write to w on its own
// — the router decides what to write based on Outcome + the host's
// AuthMode. This separation keeps the middleware pure (testable) and
// the router authoritative on HTTP response shape.
//
// Contract:
//   - mode==AuthModeCookie → always returns OutcomeNotAttempted, regardless
//     of headers. Bearer headers are ignored to avoid surprising
//     mixed-cookie+bearer behaviour on browser-only hosts.
//   - mode==AuthModeBearer → no header → OutcomeRejected. Header present
//     but verification fails → OutcomeRejected.
//   - mode==AuthModeBoth → no header → OutcomeNotAttempted (cookie path).
//     Header present + verified → OutcomeAuthorised. Header present but
//     verification fails → OutcomeFallthrough (cookie path tried;
//     audit-funnel sees both attempts).
//   - mode==AuthModeBearerOrPassthrough → no header → OutcomePassthrough
//     (router proxies to upstream with original Authorization header
//     intact, no OIDC dance). Header present + verified → OutcomeAuthorised.
//     Header present but verification fails → OutcomeRejected (a present-
//     but-broken Bearer is an explicit identity assertion that didn't
//     verify; passthrough in that case would silently downgrade
//     security).
//   - mode==AuthModeCookieOrBearerOrPassthrough → no header →
//     OutcomeNotAttempted (cookie/OIDC path). Header present + svctoken
//     Bearer-or-Basic verified → OutcomeAuthorised. Header present but
//     unparseable as svctoken (e.g. `Basic oauth2:<legacy-PAT>`) →
//     OutcomePassthrough. Header present + foreign-issuer Bearer
//     federated-verified → OutcomePassthrough. Header present + svctoken
//     parsed but verification failed → OutcomeRejected (Envoy
//     CVE-2021-21378 invariant: never silently downgrade).
//
// In all cases, the middleware emits exactly one metric sample per
// Decide call (via the verifier's Metrics sink for bearer attempts;
// noop for cookie-only hosts).
func (v *Verifier) Decide(r *http.Request, mode AuthMode) Decision {
	if !mode.IsValid() {
		// Defensive: unrecognised mode → treat as bearer-only deny.
		// Surfaces operator misconfig at the request layer rather than
		// silently downgrading security.
		return Decision{Outcome: OutcomeRejected, Err: errors.New("svctoken: invalid AuthMode")}
	}

	// Cookie-only hosts: skip entirely. Saves verifier work + avoids
	// any chance of accidental machine-path activation on a
	// browser-only host.
	if mode == AuthModeCookie {
		return Decision{Outcome: OutcomeNotAttempted}
	}

	// AuthModeCookieOrBearerOrPassthrough: if no Authorization header
	// at all, route directly to the cookie/OIDC path. This is the
	// browser branch — defense-in-depth posture enforcement runs in
	// the cookie path before any request reaches the upstream. Only
	// requests that DO carry an Authorization header proceed into the
	// credential-exchange + federated-trust dispatch below.
	if mode == AuthModeCookieOrBearerOrPassthrough && r.Header.Get("Authorization") == "" {
		return Decision{Outcome: OutcomeNotAttempted}
	}

	// Bearer attempt. Modes that accept the credential-exchange wire
	// shape also try the JWT-in-Basic-password extraction; all other
	// modes are Bearer-only as before.
	var (
		claims *Claims
		err    error
	)
	if mode == AuthModeBearerOrBasicWithCredentialExchange ||
		mode == AuthModeCookieOrBearerOrPassthrough {
		claims, err = v.VerifyRequestBearerOrBasic(r)
	} else {
		claims, err = v.VerifyRequest(r)
	}
	if err == nil {
		return Decision{
			Outcome: OutcomeAuthorised,
			Claims:  claims,
			Request: r.WithContext(WithClaims(r.Context(), claims)),
		}
	}

	// Distinguish "no header" from "bad header" for the right fallback.
	if errors.Is(err, ErrNoToken) {
		switch mode {
		case AuthModeBearer:
			return Decision{Outcome: OutcomeRejected, Err: err}
		case AuthModeBearerOrPassthrough, AuthModeBearerOrBasicWithCredentialExchange, AuthModeBearerOrFederatedPassthrough:
			// No Bearer (or Basic-as-Bearer) header → proxy directly.
			// Upstream handles its own auth (PAT, Basic, native
			// session, etc.). For the credential-exchange mode this
			// preserves the existing legacy-PAT path so a host can
			// roll out the new mode without breaking pre-existing
			// callers. For the federated mode this is the path that
			// serves the FIRST leg of Harbor's Docker Registry v2
			// challenge — GET /v2/ with no auth flows through to
			// Harbor which returns the WWW-Authenticate Bearer-realm.
			return Decision{Outcome: OutcomePassthrough, Err: err}
		case AuthModeCookieOrBearerOrPassthrough:
			// We only reached the Bearer attempt because an
			// Authorization header was present (the no-header early-
			// return above handled the cookie/OIDC branch). ErrNoToken
			// here means VerifyRequestBearerOrBasic could not extract
			// a svctoken-shape Bearer or Basic JWT — i.e. the request
			// carries a legacy native-auth header (e.g.
			// `Basic oauth2:<glpat-PAT>` from Atlantis, or
			// `Authorization: Token <gitlab-personal-token>`). Pass
			// through so the upstream handles its own native auth.
			return Decision{Outcome: OutcomePassthrough, Err: err}
		default:
			// AuthModeBoth / "" → cookie path next.
			return Decision{Outcome: OutcomeNotAttempted, Err: err}
		}
	}

	// Header present but primary verify failed. For
	// AuthModeBearerOrFederatedPassthrough, the failure may be because
	// the token was minted by a TRUSTED FEDERATED issuer (Harbor, etc.)
	// whose key is not in the primary Falcon-ID JWKS — so primary
	// verify returns ErrSignatureInvalid (kid not in JWKS) or
	// ErrIssuerMismatch depending on which check trips first. Try
	// the federated verifier; its own iss-must-be-in-registry guard
	// blocks any token whose iss isn't a configured federated
	// issuer (so a Falcon-ID JWT with bad sig that was rejected by
	// primary won't be silently admitted here — iss=primary is
	// explicitly NOT in the federated registry, enforced at
	// NewVerifier time).
	//
	// This is the Harbor-Bearer-passthrough path. Preserves the
	// no-silent-downgrade-on-forged-Bearer invariant: only KNOWN-
	// federated-issuer signed-and-fresh tokens are admitted;
	// unknown iss / failed sig / expired / wrong-host federated all
	// still reject below.
	if (mode == AuthModeBearerOrFederatedPassthrough || mode == AuthModeCookieOrBearerOrPassthrough) && v.HasFederatedIssuers() {
		if raw, ok := extractBearer(r.Header.Get("Authorization")); ok {
			_, fedErr := v.VerifyFederated(r.Context(), raw, r.Host)
			if fedErr == nil {
				// Federated verify ok → proxy as-is with original
				// Authorization header intact. No Talon Claims attached
				// (foreign issuer's claim shape is upstream-defined).
				return Decision{Outcome: OutcomePassthrough, Err: nil}
			}
			// Federated verify failed (signature / exp / host-not-
			// allowed / iss-not-in-registry) — fall through to
			// OutcomeRejected. Keep the primary err for audit (it
			// carries the original kid / aud / scope context that
			// helps operators diagnose); the federated leg's err is
			// only informative when the JWT was clearly federated-
			// shaped, which we can't tell here without inspecting iss.
			_ = fedErr
		}
	}

	// Header present but verify failed (sig / iss / aud / exp / scope /
	// replay / revoked). A present-but-broken Bearer is an explicit
	// identity assertion; never silently downgrade to passthrough or
	// cookie — security-relevant rejects must surface as rejects.
	switch mode {
	case AuthModeBearer, AuthModeBearerOrPassthrough, AuthModeBearerOrBasicWithCredentialExchange, AuthModeBearerOrFederatedPassthrough,
		AuthModeCookieOrBearerOrPassthrough:
		// CookieOrBearerOrPassthrough joins the reject set: an
		// Authorization header that PARSED as svctoken-Bearer or
		// svctoken-Basic but failed verification (bad sig, wrong iss,
		// expired, replay) is a present-but-broken identity
		// assertion. Silently downgrading to cookie or passthrough
		// would mask the security event. Envoy CVE-2021-21378 invariant.
		return Decision{Outcome: OutcomeRejected, Err: err}
	default:
		// AuthModeBoth → cookie path may still serve a stale-Bearer +
		// valid-cookie browser session.
		return Decision{Outcome: OutcomeFallthrough, Err: err}
	}
}
