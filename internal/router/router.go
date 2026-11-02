// SPDX-License-Identifier: AGPL-3.0-or-later

// Package router wires Talon's HTTP routes:
//
//   - /auth/start     — OIDC kickoff (HTML-redirect to IdP)
//   - /auth/callback  — OIDC callback (HTML-redirect to original URL)
//   - /auth/logout    — RP-initiated logout
//   - /auth/logged-out — landing page after logout
//   - /healthz, /readyz — kubelet probes
//
// Plus the catch-all that resolves the session, applies policy, and
// proxies to the upstream registered for the request Host header.
package router

import (
	"bufio"
	"context"
	"errors"
	"io"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/config"
	"github.com/dogukanturhal/talon/internal/credexchange"
	"github.com/dogukanturhal/talon/internal/devicemtls"
	"github.com/dogukanturhal/talon/internal/handlers"
	"github.com/dogukanturhal/talon/internal/identityjwt"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/observability"
	"github.com/dogukanturhal/talon/internal/oidc"
	"github.com/dogukanturhal/talon/internal/policy"
	"github.com/dogukanturhal/talon/internal/posture"
	"github.com/dogukanturhal/talon/internal/proxy"
	"github.com/dogukanturhal/talon/internal/session"
	"github.com/dogukanturhal/talon/internal/svctoken"
)

// CVRunner is the subset of cv.Runner the router calls for inline
// continuous-verification (per-route override). Defined as an interface
// so the router doesn't import internal/cv directly — keeps the package
// graph one-way and lets unit tests stub the runner.
type CVRunner interface {
	VerifyOneInline(ctx context.Context, cookieID string) bool
}

// Router is the top-level HTTP handler. Implements http.Handler.
type Router struct {
	cfg   *config.Config
	rp    *oidc.RP
	store *session.Store
	pe    *policy.CompositePolicy
	// offlineSessions is the DDIL P3.1 governed offline session-grace cache.
	// On a successful live session Read the router records a signed
	// last-known-good session here; when Redis is unreachable it serves that
	// cached session within budget instead of failing closed at t=0. nil
	// (default) keeps the pre-P3.1 fail-closed behaviour. Set via
	// SetOfflineSessions during startup when cfg.DDILOfflineSessionEnabled.
	offlineSessions *session.OfflineSessionCache
	// defaultRego is the global ZTNA baseline applied to any route whose
	// own up.rego is nil (secure-by-default). Wired via
	// SetDefaultPolicyRego at startup from cfg.DefaultPolicyRego; nil keeps
	// the legacy opt-in-per-route behaviour.
	defaultRego        *policy.RegoEvaluator
	metrics            *observability.Metrics
	health             *handlers.Health
	audit              *audit.Emitter
	admin              *handlers.Admin
	cv                 CVRunner                     // optional; when nil, per-route inline CV is disabled
	revoke             *handlers.RevokeWebhook      // optional; nil = streaming endpoint disabled
	frontchannelLogout *handlers.FrontchannelLogout // optional; nil = FCL receiver disabled
	backchannelLogout  *handlers.BackchannelLogout  // optional; nil = SLO receiver disabled
	// iapSigner mints the X-Talon-Identity-Token RS256 JWT on every
	// proxied request. Set via SetIAPSigner during startup; nil keeps
	// the legacy unsigned-headers-only path during Phase A pre-rollout.
	// Also serves the JWKS endpoint at /.well-known/jwks.json on the
	// auth host so SDK verifiers can fetch the public key.
	iapSigner *identityjwt.Signer
	// svctokenVerifier verifies Falcon-ID-issued client_credentials
	// JWTs presented as Authorization: Bearer on protected routes
	// (talon-service-tokens Phase 3). Set via SetSvctokenVerifier
	// during startup when cfg.SvctokenEnabled=true. nil keeps the
	// legacy cookie-only path active for every host — bearer headers
	// are not consulted at all when nil.
	svctokenVerifier *svctoken.Verifier
	// credLoader resolves per-host upstream credentials for routes in
	// AuthModeBearerOrBasicWithCredentialExchange (talon-service-tokens
	// Phase 4.5). Set via SetCredentialExchangeLoader during startup;
	// nil keeps every credential-exchange route at OutcomePassthrough
	// (legacy behaviour, no header substitution) which is the safe
	// default before the operator-side Vault/ExternalSecret wiring
	// lands.
	credLoader credexchange.Loader
	// caepHandler is the POST /caep/events handler for OpenID CAEP 1.0
	// Security Event Tokens (session-revoked, credential-change, etc.).
	// Scoped to the auth host (same as /auth/*) — only the IdP
	// transmitter posts SETs to Talon. Wired via SetCAEPHandler; nil
	// keeps the legacy "no CAEP receiver" path active (sessions revoke
	// only on TTL or manual /admin/revoke).
	caepHandler http.Handler
	// postureVerifier validates X-Talon-Posture headers against a
	// separately-trusted posture issuer trust chain (NOT the Falcon-ID
	// OIDC keypair — see ADR 0011 trust-isolation rationale). Set via
	// SetPostureVerifier; nil disables the posture path entirely.
	// When non-nil, routes that declare `requirePosture` consult this
	// verifier on every Verify; routes without that requirement are
	// unaffected.
	postureVerifier *posture.Verifier
	// deviceMTLS configures the XFCC device-identity path; nil = off (XFCC
	// is left untouched).
	deviceMTLS *devicemtls.Config
	mu              sync.RWMutex
	upstreams       map[string]upstreamEntry // host → proxy handler + permission
}

type upstreamEntry struct {
	handler     *proxy.Handler
	permission  string
	mfaRequired bool
	// authMode controls which authentication channels this host accepts.
	// Empty = svctoken.AuthModeCookie (default — browser-only, OIDC dance).
	// "bearer" = machine-only; missing/invalid Bearer → 401, no OIDC dance.
	// "both" = Bearer-first with cookie fallback for mixed-traffic hosts.
	// See svctoken/middleware.go for the full state machine.
	authMode svctoken.AuthMode
	// requireACR — when non-empty, the step-up gate REQUIRES blob.ACR
	// to match one of the listed Authentication Context Class
	// References (RFC 8176 §1 / OIDC Core §2). Supersedes mfaRequired
	// for the routes that opt in. Empty list (default) keeps the
	// legacy amr-based path with the new permissive containsAnyMFA
	// fallback (see internal/router/stepup.go).
	requireACR              []string
	continuousVerifyMinutes int32                 // 0 = inherit cluster default; > 0 = per-route override
	rego                    *policy.RegoEvaluator // nil = no narrowing (most routes); set = compiled per-route Rego
	sensitivity             string                // ZTNA route-sensitivity (ADR 0040 Phase 5). Defaults to "medium" via routerBuildRegoPosture.
	allowClientless         bool                  // ADR 0044: lift the clientless-on-critical hard deny for this route
	clientlessMaxTTL        int32                 // ADR 0044: absolute TTL cap (sec) for clientless sessions; 0 = cluster default
	// Phase 4 per-host session-control fields. See perhost.go for the
	// industry-parity references and evaluation order.
	sessionAbsoluteSec int32                                    // 0 = use cluster default
	sessionIdleSec     int32                                    // 0 = no idle limit
	reauthOnIP         bool                                     // /24 rebind triggers fresh OIDC handshake
	deviceClaims       []gatewayv1alpha1.DeviceClaimRequirement // AND-combined; empty = no device gate
	auditOnly          bool                                     // soak mode: emit "would_have_denied_X" but allow
	// Phase 7.3 — v1beta1 per-path policy. nil/empty preserves the
	// v1alpha1 host-only behaviour. When non-empty, router.Verify
	// matches the request against these rules first (first-match-
	// wins) and overlays the matched rule's Policy on top of the
	// fields above.
	pathRules []CompiledRule
	// publicPaths bypass the session gate entirely (ZTNA enrollment-bootstrap
	// carve-out). Matched method+exact-path in ServeHTTP BEFORE any
	// svctoken/cookie/session evaluation; the upstream self-authenticates.
	publicPaths []config.PublicRoute
}

// RegisterUpstreamParams bundles the per-route knobs the router needs to
// enforce a TalonRoute. Replaces the older positional signature once the
// per-host session-control batch took the parameter list past 6 entries.
// Callers must set Handler + Permission; everything else is optional and
// safely defaults to the existing cluster behaviour when zero/nil.
type RegisterUpstreamParams struct {
	Handler     *proxy.Handler
	Permission  string
	MfaRequired bool
	// RequireACR — when non-empty, the step-up gate REQUIRES the
	// session's id_token-sourced `acr` claim to match one of these
	// Authentication Context Class References (OIDC Core §2 / RFC 8176
	// §1). Per RFC 8176 §1 this is the RECOMMENDED gate shape because
	// `acr` is a stable business-rule reference, not a brittle method
	// enumeration. Typical values for HexxLock: ["urn:hexxlock:aal2"]
	// or ["urn:hexxlock:aal2","urn:hexxlock:aal3"]. Empty list (the
	// default) keeps the legacy MfaRequired path active with a
	// permissive amr fallback (any RFC 8176 §2 multi-factor signal
	// satisfies the gate).
	RequireACR              []string
	ContinuousVerifyMinutes int32
	Rego                    *policy.RegoEvaluator
	// Per-host session-control knobs (Phase 4 batch).
	SessionAbsoluteSec    int32
	SessionIdleSec        int32
	ReauthOnNetworkChange bool
	RequireDeviceClaims   []gatewayv1alpha1.DeviceClaimRequirement
	AuditOnly             bool
	// Phase C: per-route opt-in to ALSO inject the signed IAP JWT into
	// Authorization: Bearer for stock OAuth2/OIDC upstreams. Pushed
	// onto the proxy.Handler in RegisterUpstream.
	InjectAuthorizationBearer bool
	// RequireSignedIdentityToken makes a signed-identity-token mint failure
	// FAIL CLOSED for this route (deny 5xx) instead of the default
	// fail-open unsigned-header fallback (ASVS 5.0 V9). Per-route opt-in an
	// operator flips as each downstream finishes verifying the signed
	// X-Talon-Identity-Token. The effective value pushed onto the handler
	// is OR'd with the global TALON_REQUIRE_SIGNED_IDENTITY_TOKEN floor in
	// RegisterUpstream, so a route can only tighten, never drop below it.
	RequireSignedIdentityToken bool
	// AuthMode — per-host accepted authentication channels. See
	// svctoken.AuthMode values; empty defaults to AuthModeCookie.
	// talon-service-tokens Phase 3.
	AuthMode svctoken.AuthMode
	// PathRules — Phase 7.3 per-path policy overlays from v1beta1
	// TalonRoute.spec.pathRules. Each rule is precompiled (regex
	// compiled once, methods set, match-kind cached) by
	// router.CompileRules(...) at reconcile time. nil/empty = no
	// per-path policy (v1alpha1-compatible behaviour). When non-empty,
	// router.Verify consults them via FirstMatch BEFORE applying
	// the host-default policy fields above; matched rule's Policy
	// overlays selected default fields (Permission, AuthMode,
	// AllowedGroups, MfaRequired, AcrValues) for the request.
	PathRules []CompiledRule
	// Sensitivity is the ZTNA route-sensitivity class (ADR 0040 Phase
	// 5). Operator-declared in TalonRouteSpec.Sensitivity; projected
	// into `RegoInputPosture.Compliance["route_sensitivity"]` by the
	// router so the ZTNA Rego baseline (docs/policy/ztna/
	// ztna_baseline.rego) can apply the tier × AAL × sensitivity
	// matrix. Empty string defaults to "medium" (Rego baseline's own
	// default). Reconciler enum-validates {"low","medium","high",
	// "critical"} so typos surface at reconcile time, not at request
	// time.
	Sensitivity string
	// AllowClientless (ADR 0044) lifts the clientless-on-critical hard deny.
	AllowClientless bool
	// ClientlessMaxTTL (ADR 0044) absolute TTL cap (sec) for clientless
	// sessions on this route; 0 = cluster default.
	ClientlessMaxTTL int32
	// PublicPaths — method+exact-path routes that bypass the Talon session
	// gate (enrollment-bootstrap carve-out); the upstream self-authenticates.
	PublicPaths []config.PublicRoute
}

// New builds a Router with no upstreams registered. Phase 1 wires the
// pilot host (prometheus.ops) here once the chart's protectedHosts list
// is non-empty; for the auth host (auth.internal.example.com) only the
// /auth/* + health endpoints serve.
func New(cfg *config.Config, rp *oidc.RP, store *session.Store, pe *policy.CompositePolicy, metrics *observability.Metrics, health *handlers.Health, audit *audit.Emitter, admin *handlers.Admin) *Router {
	return &Router{
		cfg:       cfg,
		rp:        rp,
		store:     store,
		pe:        pe,
		metrics:   metrics,
		health:    health,
		audit:     audit,
		admin:     admin,
		upstreams: map[string]upstreamEntry{},
	}
}

// SetCVRunner wires the continuous-verification runner so per-route
// inline checks (TalonRoute.spec.continuousVerifyMinutes) can fire.
// Optional; nil keeps the legacy global-cadence-only behaviour.
func (r *Router) SetCVRunner(cv CVRunner) {
	r.cv = cv
}

// SetOfflineSessions wires the DDIL P3.1 governed offline session-grace
// cache. When set, Verify records a signed last-known-good session after
// each successful live Read and serves it within budget when Redis is
// unreachable (instead of failing closed at t=0). Optional; nil keeps the
// pre-P3.1 fail-closed behaviour. Wired at startup when
// cfg.DDILOfflineSessionEnabled.
func (r *Router) SetOfflineSessions(c *session.OfflineSessionCache) {
	r.offlineSessions = c
}

// SetDefaultPolicyRego wires the global ZTNA baseline Rego applied to
// every protected route that does NOT declare its own policyRego, so
// device-posture enforcement is secure-by-default rather than opt-in
// per app. Optional; nil keeps the legacy per-route opt-in. A route
// opts OUT of the baseline by declaring an explicit permissive
// policyRego (`default allow := true`). Compiled + wired at startup
// from cfg.DefaultPolicyRego (see cmd/talon/main.go).
func (r *Router) SetDefaultPolicyRego(re *policy.RegoEvaluator) {
	r.defaultRego = re
}

// SetSvctokenVerifier wires the Falcon-ID service-token Bearer
// verifier (talon-service-tokens Phase 3). After this call, every
// protected-route request whose Server CR sets authMode=bearer or
// authMode=both is consulted through the verifier BEFORE the cookie
// path; AuthModeCookie (default) hosts are unaffected so existing
// browser-only routes keep behaving identically.
//
// Optional; nil keeps the legacy cookie-only path active for every
// host — bearer headers are not consulted at all when nil. The
// cluster default is OFF (cfg.SvctokenEnabled=false); the operator
// flips it per-deployment.
func (r *Router) SetSvctokenVerifier(v *svctoken.Verifier) {
	r.svctokenVerifier = v
}

// SetCredentialExchangeLoader wires the per-host upstream credential
// loader used by AuthModeBearerOrBasicWithCredentialExchange routes.
// After this call the router will, on every successful svctoken
// verify on a credential-exchange route, look up the upstream
// credential and substitute Authorization before forwarding.
//
// nil keeps every credential-exchange route at the same behaviour as
// AuthModeBearerOrPassthrough — Bearer is verified + claims attached
// + the original Authorization is preserved. This is the safe state
// to deploy the binary in BEFORE the operator-side Vault and
// ExternalSecret manifests land.
func (r *Router) SetCredentialExchangeLoader(l credexchange.Loader) {
	r.credLoader = l
}

// SetCAEPHandler wires the OpenID CAEP 1.0 SET receiver. The supplied
// handler must implement POST /caep/events; typically constructed via
// caep.HTTPHandler(receiver). After this call, the auth host responds
// to POST requests on /caep/events with the receiver's outcome (202
// on success, 401/400/429 per RFC 8935 Push Delivery).
//
// Scoped to the auth host so only the IdP transmitter posts here —
// downstream protected hosts cannot accidentally receive CAEP traffic.
//
// Optional; nil keeps the legacy "no CAEP receiver" behavior (sessions
// revoke only on TTL or via /admin/revoke).
func (r *Router) SetCAEPHandler(h http.Handler) {
	r.caepHandler = h
}

// SetPostureVerifier wires the X-Talon-Posture JWS verifier. Optional;
// nil disables the posture-check code path entirely. When non-nil,
// future TalonRoute path-rule evaluation that declares
// `requirePosture` will consult this verifier on every Verify call;
// routes without that requirement are unaffected.
//
// Trust chain is INTENTIONALLY DISTINCT from Falcon-ID OIDC keys —
// see ADR 0011. A posture-issuer compromise must not yield user-
// identity-token mint capability and vice versa.
func (r *Router) SetPostureVerifier(v *posture.Verifier) {
	r.postureVerifier = v
}

type deviceIdentityCtxKey struct{}

// deviceIdentity returns the device-mTLS identity resolved at the start of
// ServeHTTP (zero value, present=false, when unavailable).
func deviceIdentity(ctx context.Context) devicemtls.Identity {
	if id, ok := ctx.Value(deviceIdentityCtxKey{}).(devicemtls.Identity); ok {
		return id
	}
	return devicemtls.Identity{Channel: devicemtls.ChannelDeviceMTLS}
}

// SetDeviceMTLS wires the device-mTLS edge config (XFCC trust + audit/enforce
// mode). Optional; nil keeps the pre-existing behaviour.
func (r *Router) SetDeviceMTLS(c *devicemtls.Config) {
	r.deviceMTLS = c
}

// SetIAPSigner wires the IAP identity-JWT signer. After this call:
//
//   - Every proxy.Handler subsequently registered via RegisterUpstream
//     receives the same signer instance (the router pushes it onto each
//     handler — handlers are constructed before the router but signer
//     wiring is centralised here for symmetry with CVRunner).
//   - The auth host (cfg.ExternalURL) starts serving the matching JWKS
//     at /.well-known/jwks.json so SDK verifiers can fetch the public
//     key. Cache-Control: public, max-age=300.
//
// Optional; nil keeps the legacy unsigned-X-Talon-* path (Phase A
// pre-rollout, or single-binary tests).
func (r *Router) SetIAPSigner(signer *identityjwt.Signer) {
	r.iapSigner = signer
	r.mu.Lock()
	for _, entry := range r.upstreams {
		entry.handler.SetSigner(signer)
		// Audit emitter is held on the Router struct, set in New(); push
		// it onto each handler so iap.token.mint_failed records carry the
		// canonical Loki shape (subsystem=audit, decision_id, sso_chain_id).
		entry.handler.SetAudit(r.audit)
	}
	r.mu.Unlock()
}

// RegisterUpstream maps a host header to a proxy handler. Permission is
// the SpiceDB relation name (viewer|editor|admin) — empty string means
// the role filter is the only gate (Phase 1 fallback). MfaRequired
// triggers step-up MFA per ADR 0001 §6 / boot prompt §4. ContinuousVerifyMinutes
// (0 = cluster default) drives the per-route inline CV check; values
// less than the global runner's Interval activate the inline path.
// Rego is the compiled per-route Rego escape hatch — nil = no
// narrowing; non-nil = evaluate after CompositePolicy.Allow, deny on
// false return (Tier-1 Gap 5).
//
// The Phase 4 per-host session-control fields (SessionAbsoluteSec,
// SessionIdleSec, ReauthOnNetworkChange, RequireDeviceClaims, AuditOnly)
// are evaluated by perhost.evaluatePerHost before the composite policy
// runs; see perhost.go for industry-parity references.
func (r *Router) RegisterUpstream(host string, p RegisterUpstreamParams) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Push the IAP signer onto newly-registered handlers so routes added
	// AFTER SetIAPSigner ran (TalonRoute reconcile churn) also stamp the
	// signed identity token. If SetIAPSigner has not been called yet
	// (Phase A pre-rollout) r.iapSigner is nil → handler keeps the
	// unsigned-only path, which is correct.
	if r.iapSigner != nil {
		p.Handler.SetSigner(r.iapSigner)
		p.Handler.SetAudit(r.audit)
	}
	// Phase C: per-route opt-in to also inject Authorization: Bearer for
	// stock OAuth2 upstreams (Grafana, Argo CD, etc.). No-op when the
	// signer isn't wired — you need a JWT to inject.
	p.Handler.SetInjectAuthorizationBearer(p.InjectAuthorizationBearer)
	// ASVS 5.0 V9 — fail-closed identity-token minting. Effective = global
	// floor OR per-route opt-in: enabling either tightens the route, and a
	// route can never fall below the fleet-wide TALON_REQUIRE_SIGNED_IDENTITY_TOKEN
	// default. This also applies the floor to the static TALON_PROTECTED_HOSTS_JSON
	// routes, which do not carry the per-route knob. Default (both false)
	// keeps the legacy fail-open unsigned-header fallback. r.cfg is nil in
	// some unit-test constructions (Router built as a struct literal), so
	// the global floor is only consulted when cfg is wired.
	requireSigned := p.RequireSignedIdentityToken
	if r.cfg != nil {
		requireSigned = requireSigned || r.cfg.RequireSignedIdentityToken
	}
	p.Handler.SetRequireSignedIdentityToken(requireSigned)
	// Normalise authMode: empty / unrecognised → cookie (back-compat).
	// Phase 3 hosts opting into bearer must set explicitly via Server CR.
	authMode := p.AuthMode
	if !authMode.IsValid() || authMode == "" {
		authMode = svctoken.AuthModeCookie
	}
	r.upstreams[host] = upstreamEntry{
		handler:                 p.Handler,
		permission:              p.Permission,
		mfaRequired:             p.MfaRequired,
		requireACR:              append([]string(nil), p.RequireACR...),
		continuousVerifyMinutes: p.ContinuousVerifyMinutes,
		rego:                    p.Rego,
		authMode:                authMode,
		sessionAbsoluteSec:      p.SessionAbsoluteSec,
		sessionIdleSec:          p.SessionIdleSec,
		reauthOnIP:              p.ReauthOnNetworkChange,
		deviceClaims:            deviceClaimsFromSpec(p.RequireDeviceClaims),
		auditOnly:               p.AuditOnly,
		pathRules:               p.PathRules,
		sensitivity:             p.Sensitivity,
		allowClientless:         p.AllowClientless,
		clientlessMaxTTL:        p.ClientlessMaxTTL,
		publicPaths:             append([]config.PublicRoute(nil), p.PublicPaths...),
	}
}

// sessionChannel classifies the request's access channel (ADR 0044). A
// request whose host matches a configured access-zone suffix
// (TALON_CLIENTLESS_HOST_SUFFIXES, e.g. ".access.example.com") is the
// agentless "clientless" channel — no device cert, browser-attestable signals
// only. Everything else is the default agent "cookie" channel. Empty suffix
// list disables the clientless tier, so every session stays "cookie".
func (r *Router) sessionChannel(host string) string {
	h := strings.ToLower(host)
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i] // strip :port
	}
	for _, suf := range r.cfg.ClientlessHostSuffixes {
		if suf != "" && strings.HasSuffix(h, strings.ToLower(suf)) {
			return policy.ChannelClientless
		}
	}
	return policy.ChannelCookie
}

// isPublicRoute reports whether req matches one of up's configured public
// (unauthenticated) routes: case-insensitive method + EXACT normalized path.
// It reuses the same hardened NormalizePath as the path-rule engine so encoded
// slashes / path params / traversal can't smuggle a gated path through the
// carve-out. Fail-closed: an un-normalizable path never matches.
func (r *Router) isPublicRoute(up upstreamEntry, req *http.Request) bool {
	if len(up.publicPaths) == 0 {
		return false
	}
	norm, err := NormalizePath(req.URL.Path)
	if err != nil {
		return false
	}
	for _, pr := range up.publicPaths {
		if strings.EqualFold(pr.Method, req.Method) && pr.Path == norm {
			return true
		}
	}
	return false
}

// SetRevokeWebhook wires the streaming-revocation handler so
// `POST /admin/revoke` (mTLS+SPIFFE-authenticated, distinct from
// the cookie-authenticated operator endpoint) becomes available.
// Optional; nil keeps the endpoint disabled.
func (r *Router) SetRevokeWebhook(h *handlers.RevokeWebhook) {
	r.revoke = h
}

// SetBackchannelLogout wires the OIDC Back-Channel Logout 1.0 receiver
// at POST /auth/backchannel-logout (auth-host-scoped). The JWT itself
// authenticates the request per spec §2.6; Linkerd MTA + AuthorizationPolicy
// at the platform layer add defense-in-depth. Optional; nil keeps the
// endpoint at 404.
func (r *Router) SetBackchannelLogout(h *handlers.BackchannelLogout) {
	r.backchannelLogout = h
}

// SetFrontchannelLogout wires the OIDC Front-Channel Logout 1.0 receiver
// at GET /auth/frontchannel-logout (auth-host-scoped). The iss query
// parameter validates the request per spec §5.4; CSP frame-ancestors
// at the response layer prevents hostile sites embedding the iframe.
// Optional; nil keeps the endpoint at 404.
func (r *Router) SetFrontchannelLogout(h *handlers.FrontchannelLogout) {
	r.frontchannelLogout = h
}

// UnregisterUpstream removes a host's proxy handler. Called by the
// reconciler on TalonRoute deletion.
func (r *Router) UnregisterUpstream(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.upstreams, host)
}

// ServeHTTP routes the request.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// talon_request_total wiring (audit internal engineering notes
	// oidc_handshake_never_incremented_2026_05_30) — wrap the writer so
	// the final status can be observed, and emit RequestTotal on
	// function exit. SLO alerts (TalonSLOFastBurn/SlowBurn,
	// TalonUpstreamErrorRate) depend on this single emit. The
	// decision label is derived from final status — `allow` when
	// <400 (proxied successfully or 30x redirect), `deny` for 4xx
	// (auth/policy reject), `error` for 5xx (Talon/upstream failure).
	// Per-AuthDecision-call wiring would be more precise but is too
	// invasive (17 call sites scattered across helpers); this gate
	// captures the SLO surface accurately while staying contained.
	recw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
	w = recw
	defer func() {
		if r.metrics == nil {
			return
		}
		decision := "allow"
		switch {
		case recw.status >= 500:
			decision = "error"
		case recw.status >= 400:
			decision = "deny"
		}
		r.metrics.RequestTotal.WithLabelValues(
			req.Host, req.Method, decision, strconv.Itoa(recw.status),
		).Inc()
	}()

	// Per-request decision_id (boot prompt §4 Gap 4) — populated on every
	// audit event emitted during this request via tlog.DecisionIDFrom in
	// audit.Emitter. UUIDv4 because the existing import set already has it;
	// monotonic ULIDs would be nicer for sort-by-time but the audit pipeline
	// already records ts so the difference doesn't matter for grep.
	ctx := tlog.WithDecisionID(req.Context(), uuid.NewString())

	// Per-request logger with method/path/host. decision_id rides along
	// the ctx so logs and audit emit can both pick it up.
	logger := tlog.From(ctx).With(
		"method", req.Method, "path", req.URL.Path, "host", req.Host,
	)
	ctx = tlog.Into(ctx, logger)
	// Device-mTLS edge: XFCC is believed only from the configured Envoy
	// identity and is ALWAYS stripped from the request so no later reader or
	// upstream can see a client-supplied value.
	ctx = context.WithValue(ctx, deviceIdentityCtxKey{},
		devicemtls.Resolve(r.deviceMTLS, req.Header, time.Now()))
	req = req.WithContext(ctx)

	// Always-public probe endpoints — host-agnostic by design (kube
	// probes hit the pod directly via PodIP, no Host header).
	switch req.URL.Path {
	case "/healthz":
		r.health.Liveness(w, req)
		return
	case "/readyz":
		r.health.Readiness(w, req)
		return
	}

	// Talon-owned OIDC RP endpoints are SCOPED TO THE AUTH HOST ONLY.
	//
	// Why: every protected host runs through Talon, but downstream apps
	// like ArgoCD ship their own OIDC Relying Party that uses the same
	// `/auth/callback` path on their own hostname (e.g.
	// argocd.internal.example.com/auth/callback). If Talon claimed
	// /auth/callback for every host, the IdP's 302 back to argocd's
	// callback would be intercepted by Talon, fail the handshake-state
	// check (the state cookie belongs to argocd, not Talon), and
	// surface to the user as "invalid or expired token".
	//
	// Talon's RP redirect_uri is registered at Falcon-ID exactly as
	// `https://<auth-host>/auth/callback` — by spec the IdP will never
	// redirect anywhere else, so scoping to the auth host loses nothing
	// for Talon's own flow. Downstream apps can use `/auth/start`,
	// `/auth/callback`, `/auth/logout`, `/auth/logged-out`,
	// `/auth/verify` freely on their own hostnames; Talon falls through
	// to the proxy upstream below.
	//
	// `/auth/verify` is the forward-auth subrequest endpoint (Gap 7).
	// External proxies (APISIX, etc.) call `<auth-host>/auth/verify`
	// explicitly, never a protected host, so it's grouped here.
	if req.Host == r.cfg.ExternalURL.Hostname() {
		switch req.URL.Path {
		case "/auth/start":
			// talon_oidc_handshake_total{step="start",outcome} — the
			// HandleStart handler always renders a 302 to the IdP on
			// success and a 4xx HTML page on failure (bad redirect_uri,
			// state-cookie write failure, etc). Map response status to
			// outcome label here so the alert TalonSessionStoreRedisDown
			// (which gates on "OIDC start happens AND no allow follows")
			// has both halves of the predicate. Same statusCapturingRW
			// pattern as the top-level wrap; nested is fine because the
			// outer one just records the FINAL status which is whatever
			// the inner writes.
			innerw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			r.rp.HandleStart(innerw, req)
			if r.metrics != nil {
				outcome := "success"
				if innerw.status >= 400 {
					outcome = "fail"
				}
				r.metrics.OIDCHandshake.WithLabelValues("start", outcome).Inc()
			}
			return
		case "/auth/callback":
			innerw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			r.rp.HandleCallback(innerw, req)
			if r.metrics != nil {
				outcome := "success"
				if innerw.status >= 400 {
					outcome = "fail"
				}
				r.metrics.OIDCHandshake.WithLabelValues("callback", outcome).Inc()
			}
			return
		case "/auth/logout":
			innerw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			r.rp.HandleLogout(innerw, req)
			if r.metrics != nil {
				outcome := "success"
				if innerw.status >= 400 {
					outcome = "fail"
				}
				r.metrics.OIDCHandshake.WithLabelValues("logout", outcome).Inc()
			}
			return
		case "/auth/logged-out":
			r.serveLoggedOutPage(w, req)
			return
		case "/auth/verify":
			r.serveAuthVerify(w, req)
			return
		case "/caep/events":
			// OpenID CAEP 1.0 SET receiver. RFC 8935 Push Delivery.
			// Wired via SetCAEPHandler; when nil, return 503 to make
			// the disabled state explicit (vs falling through to the
			// proxy upstream that doesn't exist on the auth host).
			if r.caepHandler == nil {
				http.Error(w, "caep receiver disabled", http.StatusServiceUnavailable)
				return
			}
			r.caepHandler.ServeHTTP(w, req)
			return
		case "/.well-known/jwks.json":
			// IAP identity-token JWKS — published on the auth host so
			// SDK verifiers fetch it from the same origin that mints
			// the JWT. 5-minute Cache-Control matches Cloudflare Access
			// / Google IAP defaults. nil signer (Phase A pre-rollout)
			// yields a clean 503 — verifier libraries treat it as
			// "no keyset, fall back to unsigned" until the operator
			// finishes the key provisioning.
			//
			// Metrics wrap (Item 3): a tiny statusCapturingResponseWriter
			// records the outcome label (success / unconfigured / error)
			// so dashboards can alert on sustained 503s = upstream
			// Vault/ESO pipeline broken.
			recw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			identityjwt.JWKSHandler(r.iapSigner).ServeHTTP(recw, req)
			if r.metrics != nil {
				result := "success"
				switch {
				case recw.status == http.StatusServiceUnavailable:
					result = "unconfigured"
				case recw.status >= 400:
					result = "error"
				}
				r.metrics.IAPJWKSRequest.WithLabelValues(result).Inc()
			}
			return
		case "/auth/backchannel-logout":
			// OIDC Back-Channel Logout 1.0 receiver — server-to-server
			// from Falcon-ID. The JWT authenticates per spec §2.6;
			// Linkerd MTA + AuthorizationPolicy at the platform layer
			// add defense-in-depth. Auth-host-scoped to avoid colliding
			// with downstream RPs that ship their own /auth/* handlers
			// (memory internal engineering notes).
			if r.backchannelLogout != nil {
				r.backchannelLogout.ServeHTTP(w, req)
				return
			}
			// nil handler = endpoint disabled; fall through to 404
		case "/auth/frontchannel-logout":
			// OIDC Front-Channel Logout 1.0 receiver — browser iframe
			// from Falcon-ID's RP-initiated logout page. The iss query
			// parameter authenticates per spec §5.4; CSP frame-ancestors
			// in the response prevents hostile sites embedding the iframe.
			// Auth-host-scoped to avoid colliding with downstream RPs.
			if r.frontchannelLogout != nil {
				r.frontchannelLogout.ServeHTTP(w, req)
				return
			}
			// nil handler = endpoint disabled; fall through to 404
		}
	}
	// Admin API — caller authenticated via session cookie + role check
	// inside Admin.RevokeUser. Mounted before the protected-host
	// catch-all so it works on the auth host.
	if strings.HasPrefix(req.URL.Path, "/admin/sessions/") && r.admin != nil {
		r.admin.RevokeUser(w, req)
		return
	}
	// Streaming revocation webhook — mTLS+SPIFFE auth at the network
	// layer (Linkerd Server CR + AuthorizationPolicy + MeshTLS) plus
	// l5d-client-id allow-list assertion in the handler. Distinct from
	// /admin/sessions/{sub} which is the operator break-glass.
	if req.URL.Path == "/admin/revoke" && r.revoke != nil {
		r.revoke.ServeHTTP(w, req)
		return
	}

	// Auth host has no protected upstreams of its own; only /auth/* + health
	// + /readyz serve. Anything else is 404.
	if req.Host == r.cfg.ExternalURL.Hostname() {
		http.NotFound(w, req)
		return
	}

	// Protected route — find the upstream registered for this Host.
	r.mu.RLock()
	up, ok := r.upstreams[req.Host]
	r.mu.RUnlock()
	if !ok {
		// No upstream registered for this host → 404 (Talon doesn't know
		// what to proxy to). Operator misconfig — surfaces in audit log.
		logger.Warn("unknown host, no upstream registered")
		http.NotFound(w, req)
		return
	}

	// Public bootstrap routes (e.g. the ZTNA device-enrollment endpoint):
	// forward to the upstream WITHOUT a Talon session, BEFORE the svctoken
	// Bearer and cookie/session gates. Allow-listed per host (method+exact-
	// path) in config; the upstream self-authenticates (jess verifies the
	// WebAuthn witness JWS on /device-cert/attest). A not-yet-enrolled device
	// has no session/posture, so the endpoint that ESTABLISHES them cannot
	// itself require them. ServeUnauthenticated strips spoofable identity
	// headers so the carve-out can't be used to forge a Talon identity.
	if r.isPublicRoute(up, req) {
		r.metrics.AuthDecision.WithLabelValues(req.Host, "allow", "public_route").Inc()
		r.audit.Allow(req.Context(), audit.Record{
			Route: req.Host, Method: req.Method, Path: req.URL.Path, Reason: "public_route",
		})
		up.handler.ServeUnauthenticated(w, req)
		return
	}

	// talon-service-tokens Phase 3 — try the Falcon-ID Bearer JWT path
	// BEFORE the cookie path. The Decide call is a no-op when:
	//   - svctokenVerifier is nil (cluster default off, or test fakes)
	//   - the upstream's authMode is "cookie" (browser-only hosts)
	// so existing browser-only routes pay zero extra latency. For
	// machine consumers, a verified Bearer skips Redis + OIDC entirely
	// and proxies directly with synthesised claims attached to ctx.
	//
	// Outcome handling:
	//   OutcomeAuthorised  — Bearer verified; proxy via the upstream's
	//                        handler with the Claims-bearing request.
	//                        We DON'T run the per-host session-control
	//                        gate (mfa/acr/idle/IP-rebind) because those
	//                        are user-session concepts that don't apply
	//                        to machine identities. Scope enforcement
	//                        already happened inside svctoken.Verify.
	//   OutcomeRejected    — authMode=bearer + Bearer absent/invalid;
	//                        no OIDC dance, return 401 with the
	//                        canonical "WWW-Authenticate: Bearer" hint.
	//   OutcomeFallthrough — authMode=both + Bearer present but failed;
	//                        try the cookie path so a stale Bearer
	//                        doesn't lock out a human-using-browser
	//                        operator on the same hostname.
	//   OutcomeNotAttempted — cookie-only host OR authMode=both + no
	//                         Bearer header; run cookie path.
	//   OutcomePassthrough — authMode=bearer_or_passthrough + no Bearer
	//                        header; proxy DIRECTLY to upstream with
	//                        the original Authorization header intact
	//                        (Atlantis/Renovate/legacy-PAT pattern).
	//                        No OIDC, no claims, no policy evaluation.
	//                        Upstream is the auth authority for these
	//                        requests.
	if r.svctokenVerifier != nil && up.authMode != "" && up.authMode != svctoken.AuthModeCookie {
		dec := r.svctokenVerifier.Decide(req, up.authMode)
		switch dec.Outcome {
		case svctoken.OutcomeAuthorised:
			// END-USER BEARER TOKENS GET THE FULL AUTHORISATION DECISION
			// ==========================================================
			// The block comment above ("we DON'T run the per-host
			// session-control gate") is about SESSION LIFECYCLE — absolute
			// TTL, idle timeout, IP rebind, device claims. Those genuinely
			// have no meaning for a stateless token and stay skipped.
			//
			// AUTHORISATION is a different question. A TalonRoute's
			// allowedGroups (which the controller projects into SpiceDB via
			// WriteRouteRelationships) is a statement about WHO may reach
			// the host, and a human arriving over a CLI is the same
			// principal as that human arriving in a browser. Before this
			// block, a user token was authorised on scope + audience alone,
			// so allowedGroups silently did not apply to ANY non-browser
			// client — the route looked gated and was not.
			//
			// Machine identities keep the fast path: their authority is the
			// scope inside the token, already enforced by svctoken.Verify,
			// and they have no groups to evaluate.
			//
			// NOT subject to up.auditOnly, deliberately — the cookie path's
			// own pe.Evaluate verdict is not either. auditOnly softens the
			// posture / per-host-TTL / Rego soak gates; it has never
			// softened the core authz decision, and making the Bearer path
			// the one exception would let a soaking route hand a CLI
			// stronger access than a browser gets.
			//
			// Step-up (MFA/ACR) is NOT evaluated here yet. dec.Claims now
			// carries AMR/ACR so the gate has its evidence, but wiring it
			// needs a claims-based equivalent of evaluatePerHost's step-up
			// branch rather than the session-shaped one. Tracked as the
			// follow-up to this change; today's behaviour for user tokens
			// is strictly more checked than before, never less.
			machine := dec.Claims.IsMachine()
			if !machine {
				blob := blobFromSvctokenClaims(dec.Claims)
				verdict := r.pe.Evaluate(req.Context(), blob, req.Host, up.permission, up.sensitivity)
				if verdict.Decision != policy.Allow {
					// Emitted only on the deny/error branch. The allow
					// branch falls through to the single allow counter
					// below — incrementing here too would double-count
					// every authorised user request against the SLO.
					r.metrics.AuthDecision.WithLabelValues(req.Host,
						string(verdict.Decision), string(verdict.Reason)).Inc()
					logger.Warn("user bearer token denied",
						"host", req.Host, "sub", blob.Sub,
						"client_id", dec.Claims.ClientID,
						"jti", dec.Claims.JTI,
						"reason", verdict.Reason)
					r.audit.Deny(req.Context(), audit.Record{
						Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
						Route: req.Host, Method: req.Method, Path: req.URL.Path,
						Reason: string(verdict.Reason), Permission: up.permission,
						Issuer: blob.Iss,
					})
					// Plain text, not serveAccessDenied's HTML page: the
					// caller on this path is a CLI, and an HTML body is
					// exactly what makes npm/git report an opaque JSON
					// parse error instead of the actual reason.
					w.Header().Set("WWW-Authenticate",
						`Bearer realm="`+r.cfg.SvctokenIssuer+`", error="insufficient_scope"`)
					http.Error(w, "forbidden: "+string(verdict.Reason), http.StatusForbidden)
					return
				}
			}
			// One counter per authorised request, with the identity kind
			// in the reason label so machine and human Bearer traffic stay
			// distinguishable on the dashboards.
			allowReason := "svctoken"
			if !machine {
				allowReason = "svctoken_user"
			}
			r.metrics.AuthDecision.WithLabelValues(req.Host, "allow", allowReason).Inc()
			logger.Info("svctoken authorised",
				"host", req.Host,
				"client_id", dec.Claims.ClientID,
				"sub", dec.Claims.Subject,
				"machine", machine,
				"jti", dec.Claims.JTI)
			// Credential-exchange wire shape (Phase 4.5): on every mode
			// whose contract includes credential exchange (see
			// AuthMode.SupportsCredentialExchange), strip the inbound
			// (verified-svctoken) Authorization and
			// substitute the per-host upstream credential before
			// forwarding. The verify-then-substitute order is critical:
			// no substitution can happen until svctoken.Verify has
			// confirmed the inbound JWT, otherwise any caller could
			// trigger the swap. See internal/credexchange package
			// documentation for the cited industry-pattern references.
			outReq := dec.Request
			if up.authMode.SupportsCredentialExchange() && r.credLoader != nil {
				// Pass the verified JWT's client_id so the loader can
				// resolve a per-client upstream credential (Phase 5+
				// per-consumer differentiation, 2026-05-30). When the
				// per-client Secret is absent, the loader falls back
				// to the host-default — matches existing Phase 4.5
				// behaviour for routes whose consumers all share the
				// same upstream privilege scope.
				cred, err := r.credLoader.Load(req.Context(), req.Host, dec.Claims.ClientID)
				switch {
				case err == nil:
					credexchange.Apply(outReq, cred)
					r.metrics.AuthDecision.WithLabelValues(req.Host,
						"allow", "svctoken_credential_exchange").Inc()
					logger.Info("svctoken credential exchange applied",
						"host", req.Host,
						"client_id", dec.Claims.ClientID,
						"jti", dec.Claims.JTI,
						"cred_format", string(cred.Format))
				case errors.Is(err, credexchange.ErrNoCredential):
					// Route opted in but no Secret yet — preserve the
					// verified-svctoken Authorization (passthrough-like
					// behaviour). Counted distinctly so the operator
					// can alert on opt-in-without-secret drift.
					r.metrics.AuthDecision.WithLabelValues(req.Host,
						"allow", "svctoken_credential_exchange_uncfg").Inc()
					logger.Warn("svctoken credential exchange enabled but no upstream credential for host",
						"host", req.Host,
						"secret_name", credexchange.SecretNameForHost(req.Host))
				default:
					// Real error reading the Secret. Fail closed: 502.
					// The operator must see this in the audit funnel.
					r.metrics.AuthDecision.WithLabelValues(req.Host,
						"error", "svctoken_credential_exchange_load").Inc()
					logger.Error("svctoken credential exchange load failed",
						"host", req.Host, "err", err)
					http.Error(w, "credential exchange unavailable", http.StatusBadGateway)
					return
				}
			}
			up.handler.ServeHTTP(w, outReq)
			return
		case svctoken.OutcomeRejected:
			reason := "svctoken_rejected"
			if dec.Err != nil {
				logger.Warn("svctoken rejected (bearer-only host)",
					"host", req.Host, "err", dec.Err)
			}
			r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", reason).Inc()
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+r.cfg.SvctokenIssuer+`", error="invalid_token"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		case svctoken.OutcomeFallthrough:
			// Bearer present + failed but authMode=both lets the cookie
			// path try next. Log the failed bearer attempt for forensics
			// but DON'T return — fall through to the existing flow.
			logger.Info("svctoken fell through to cookie path",
				"host", req.Host, "err", dec.Err)
			r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", "svctoken_fallthrough").Inc()
		case svctoken.OutcomePassthrough:
			// authMode=bearer_or_passthrough + no Bearer header. Proxy
			// directly to upstream — upstream handles its own auth.
			// Skip the cookie path entirely (no OIDC dance for these
			// hosts; they're machine-traffic-tolerant by design).
			r.metrics.AuthDecision.WithLabelValues(req.Host, "allow", "svctoken_passthrough").Inc()
			up.handler.ServeHTTP(w, req)
			return
		case svctoken.OutcomeNotAttempted:
			// No bearer header, or cookie-only host — silent fall through.
		}
	}

	// Resolve session → run PE → proxy or redirect to /auth/start.
	cookie, _ := req.Cookie(oidc.SessionCookieName)
	if cookie == nil || cookie.Value == "" {
		r.startAuth(w, req)
		return
	}
	blob, err := r.store.Read(req.Context(), cookie.Value)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrRevoked):
			// BCL/FCL cascade hit: Falcon-ID's NotifyLogout reached
			// Talon's receiver, which wrote a per-cookie tombstone via
			// revoke-by-sub / revoke-by-sid fan-out. The next request
			// from the user-agent now blocks at the edge — the
			// load-bearing property of the SLO cascade. Phase 5b adds
			// this metric so the post-Sign-Out E2E synthetic can
			// assert per-host fan-out timing without scraping logs.
			r.metrics.EdgeRevokeBlock.WithLabelValues(req.Host).Inc()
			r.startAuth(w, req)
			return
		case errors.Is(err, session.ErrNotFound),
			errors.Is(err, session.ErrExpired):
			r.startAuth(w, req)
			return
		case errors.Is(err, session.ErrAuthFailed):
			logger.Warn("session AEAD failed — possible tamper or stale rotation key")
			r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", string(policy.ReasonAuthTagFailed)).Inc()
			r.startAuth(w, req)
			return
		default:
			logger.Error("session read", "err", err)
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
	}

	// Promote the session's SSO chain ID into the request ctx so any
	// audit event emitted further down (deny, MFA challenge, allow,
	// inline CV invalidate) carries it without each callsite needing
	// to know about Blob.SSOChainID. Boot prompt §4 Gap 4.
	if blob.SSOChainID != "" {
		ctx = tlog.WithSSOChainID(req.Context(), blob.SSOChainID)
		req = req.WithContext(ctx)
	}

	// ADR 0044 — classify the access channel BEFORE the per-host gate so
	// the clientless absolute-TTL cap (clientlessMaxTTL) can time-box
	// agentless sessions tighter than the same route's agent sessions.
	// Empty ClientlessHostSuffixes = tier disabled → channel="cookie" for
	// every host, so existing deployments are unchanged on upgrade.
	channel := r.sessionChannel(req.Host)

	// Per-host session-control gate (Phase 4 batch). Runs BEFORE the
	// inline CV check so an expired-by-per-host or idle-out session
	// doesn't trigger a wasted Falcon-ID userinfo round-trip.
	// Enforces unless up.auditOnly is set, in which case the deny
	// emits as "would_have_denied_X" and the request continues —
	// soak mode for the one-week pre-enforce window.
	currentIP := oidc.ClientIP(req)
	lastSeen, _ := r.store.GetLastSeen(req.Context(), cookie.Value)
	phv := evaluatePerHost(up, blob, time.Now(), currentIP, lastSeen, channel)
	if !phv.ok {
		// auditDecisionLabel: "would_deny" in soak (kept out of the real
		// deny rate TalonAuthFailureRate sums), "deny" when enforcing.
		r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "deny"), string(phv.reason)).Inc()
		if up.auditOnly {
			emitWouldHaveDenied(req.Context(), r.audit, blob,
				req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, phv.reason)
			logger.Info("per-host check would have denied (audit-only)",
				"host", req.Host, "sub", blob.Sub, "reason", phv.reason)
		} else {
			logger.Info("per-host check denied, restarting auth",
				"host", req.Host, "sub", blob.Sub, "reason", phv.reason)
			r.audit.Deny(req.Context(), audit.Record{
				Sub: blob.Sub, Email: blob.Email, TenantID: blob.TenantID,
				Route: req.Host, Method: req.Method, Path: req.URL.Path,
				Reason: string(phv.reason), SessionID: cookie.Value,
				Permission: up.permission, Issuer: blob.Iss, SrcIP: blob.SrcIP,
			})
			// All four per-host failure modes need a fresh OIDC handshake
			// (the cookie is no longer valid for THIS host); /auth/start is
			// the canonical re-auth bounce. Same as the session-not-found
			// branch above.
			r.startAuth(w, req)
			return
		}
	}

	// Per-route inline continuous verification — if the TalonRoute has
	// a continuousVerifyMinutes override tighter than the global runner's
	// cadence, force a synchronous CV check when this session's last CV
	// timestamp is older than the route's window. Catches a disabled or
	// group-changed user on the very next request to a high-privilege
	// route (vault.ops, argocd.ops) instead of waiting up to 5 min for
	// the global tick.
	if r.cv != nil && up.continuousVerifyMinutes > 0 {
		threshold := time.Duration(up.continuousVerifyMinutes) * time.Minute
		lastCV, _ := r.store.GetLastCV(req.Context(), cookie.Value)
		if lastCV.IsZero() || time.Since(lastCV) > threshold {
			if !r.cv.VerifyOneInline(req.Context(), cookie.Value) {
				// Session was invalidated by CV. Re-read the cookie to confirm
				// it's gone, then force a fresh OIDC handshake.
				logger.Info("inline CV invalidated session, restarting auth",
					"host", req.Host, "sub", blob.Sub, "threshold", threshold)
				r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", "cv_invalidated").Inc()
				r.startAuth(w, req)
				return
			}
			// verifyOne marks LastCV on success; nothing more to do here.
		}
	}

	verdict := r.pe.Evaluate(req.Context(), blob, req.Host, up.permission, up.sensitivity)
	if verdict.Decision == policy.Error {
		// Transient authz backend error (e.g. cold SpiceDB conn): retry once
		// before surfacing a retryable 503.
		verdict = r.pe.Evaluate(req.Context(), blob, req.Host, up.permission, up.sensitivity)
	}
	r.metrics.AuthDecision.WithLabelValues(req.Host, string(verdict.Decision), string(verdict.Reason)).Inc()
	if verdict.Decision != policy.Allow {
		logger.Warn("denied", "reason", verdict.Reason, "sub", blob.Sub)
		r.audit.Deny(req.Context(), audit.Record{
			Sub: blob.Sub, Email: blob.Email, Route: req.Host,
			Method: req.Method, Path: req.URL.Path, Reason: string(verdict.Reason),
			SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
		})
		r.serveVerdictDenied(w, req, verdict)
		return
	}

	// Fail-closed cap: an agentless session MUST NOT reach a critical route
	// unless the route explicitly opts in (allowClientless). The access zone
	// is opt-in, so this only fires once an operator routes clientless traffic
	// at a critical target without opting in — deny it. Not subject to the
	// auditOnly soak (it is an access-channel boundary, not a posture/TTL
	// check, and the clientless tier is itself opt-in).
	if channel == policy.ChannelClientless && up.sensitivity == "critical" && !up.allowClientless {
		logger.Warn("clientless denied on critical route", "host", req.Host, "sub", blob.Sub)
		r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", "clientless_critical_denied").Inc()
		r.audit.Deny(req.Context(), audit.Record{
			Sub: blob.Sub, Email: blob.Email, Route: req.Host,
			Method: req.Method, Path: req.URL.Path, Reason: "clientless_critical_denied",
			SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
		})
		r.serveAccessDenied(w, req, http.StatusForbidden, "clientless_critical_denied")
		return
	}

	// ADR 0044 AAL cap — a clientless (agentless, no-device-cert) session
	// MUST be ≥ WebAuthn/AAL2 before reaching ANY access-zone route. This
	// is STRICTER than (and orthogonal to) the route-level mfaRequired gate
	// below: it applies to every clientless route, and demands a phishing-
	// resistant factor (hwk/swk or an AAL2+ acr) rather than any RFC 8176
	// second factor. Reuses the RFC 9470 step-up path (startAuthWithMFA) so
	// browser navigation 302s to a WebAuthn re-auth and XHR/asset requests
	// get the insufficient_user_authentication challenge header. Honours
	// up.auditOnly identically to the MFA gate so a soak window stays
	// permissive while operators watch the audit stream.
	if channel == policy.ChannelClientless && !clientlessAALSatisfied(blob) {
		r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "deny"), "clientless_aal_required").Inc()
		if up.auditOnly {
			emitWouldHaveDenied(req.Context(), r.audit, blob,
				req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, "clientless_aal_required")
			logger.Info("clientless AAL cap would have challenged (audit-only)",
				"host", req.Host, "sub", blob.Sub, "amr", blob.AMR, "acr", blob.ACR)
			// Fall through to the rest of the gate chain (still allow).
		} else {
			mfa := true
			logger.Info("clientless AAL step-up required (WebAuthn/AAL2)",
				"host", req.Host, "sub", blob.Sub, "amr", blob.AMR, "acr", blob.ACR)
			r.audit.MFAChallenge(req.Context(), audit.Record{
				Sub: blob.Sub, Email: blob.Email, Route: req.Host,
				Method: req.Method, Path: req.URL.Path, MFA: &mfa,
				SessionID: cookie.Value, Issuer: blob.Iss,
			})
			r.startAuthWithMFA(w, req)
			return
		}
	}

	// Per-route Rego escape hatch (Tier-1 Gap 5). Runs ONLY after the
	// composite policy ALLOWs, so Rego can narrow but never broaden.
	// ZTNA baseline: prefer the route's own Rego; otherwise fall back to
	// the global default (SetDefaultPolicyRego) so device posture is
	// enforced SECURE-BY-DEFAULT on every route instead of opt-in per app.
	// A route opts OUT by declaring an explicit permissive policyRego
	// (`default allow := true`), per the baseline's documented public-
	// surface carve-out. nil rego + no global default is a no-op (legacy
	// opt-in). Eval errors fail-closed.
	effRego := up.rego
	if effRego == nil {
		effRego = r.defaultRego
	}
	if effRego != nil {
		// Per Phase K self-audit H-1 (2026-06-14): project
		// `time.Since(LastWebAuthnAt)` into AMRRecencySeconds so the Rego
		// baseline's `webauthn_fresh_1h` gate works. Zero LastWebAuthnAt
		// (no recent hardware-factor assertion) leaves AMRRecencySeconds
		// at 0 which the Rego module treats as fresh — safe because the
		// AAL3 rules separately require "hwk" in amr.
		var amrRecencySec int64
		if blob.LastWebAuthnAt > 0 {
			amrRecencySec = time.Now().Unix() - blob.LastWebAuthnAt
			if amrRecencySec < 0 {
				amrRecencySec = 0
			}
		}
		regoIn := &policy.RegoInput{
			User: policy.RegoInputUser{
				Sub: blob.Sub, Email: blob.Email,
				Groups: blob.Groups, Roles: blob.Roles,
				TenantID: blob.TenantID, AMR: blob.AMR,
				AMRRecencySeconds: amrRecencySec,
			},
			Route: policy.RegoInputRoute{
				Host: req.Host, Permission: up.permission,
			},
			Request: policy.RegoInputRequest{
				Method: req.Method, Path: req.URL.Path,
				SrcIP: blob.SrcIP,
			},
			Session: policy.RegoInputSession{Channel: channel},
		}
		devID := deviceIdentity(req.Context())
		if r.deviceMTLS.Enabled() {
			regoIn.DeviceMTLS = &policy.RegoInputDeviceMTLS{
				Present: devID.Present, Valid: devID.Valid, DeviceID: devID.DeviceID,
				Kind: devID.Kind, Channel: devID.Channel,
			}
		}

		// Project the verified X-Talon-Posture claim into RegoInput.Posture
		// so the ZTNA baseline Rego bundle (docs/policy/ztna/ztna_baseline.rego)
		// has tier / device_cert_valid / iat / etc. Without this the Rego
		// matrix falls through to TIER_BYOD + posture-stale defaults and
		// every request denies — even a legitimate hardware-key-bound
		// operator. Per Phase K self-audit C-1 (2026-06-14).
		//
		// Verification is best-effort: if posture is missing or invalid we
		// proceed WITHOUT setting regoIn.Posture, which forces the Rego
		// policy to use its fallback defaults (deny for routes that require
		// posture, allow for routes that don't). This is the same shape the
		// composite policy upstream already enforces, so we don't double-
		// gate here — Rego decides the final answer.
		var postureClaims *posture.Claims
		if r.postureVerifier != nil {
			if tok := strings.TrimSpace(req.Header.Get(posture.HeaderName)); tok != "" {
				pc, perr := r.postureVerifier.Verify(req.Context(), tok, blob.Sub)
				if perr != nil {
					// Log + metric but DO NOT block here — the Rego policy
					// fail-closes on missing posture for routes that need
					// it. Audit-only soak windows get visibility this way.
					logger.Warn("posture verify failed",
						"err", perr, "host", req.Host, "sub", blob.Sub)
					r.metrics.AuthDecision.WithLabelValues(req.Host, "warn", "posture_invalid").Inc()
					// DDIL P3.10 — a posture rejected because it is past its
					// governed grace budget (or hard expiry) is a fail-closed
					// governed-degrade event; count it distinctly so operators
					// can see grace exhaustion apart from other invalidity.
					if errors.Is(perr, posture.ErrExpired) {
						r.metrics.DDILDegraded.WithLabelValues(observability.DDILDepPosture, observability.DDILOutcomeFailClosed).Inc()
					}
				} else {
					postureClaims = pc
				}
			}
		}

		// Device-mTLS check (cert device <-> posture JWS sub binding). Audit
		// mode (default) only logs/counts would_deny; enforce denies.
		if r.deviceMTLS.Enabled() {
			postureSub := ""
			if postureClaims != nil {
				postureSub = postureClaims.Subject
			}
			if dd := devicemtls.Decide(r.deviceMTLS, devID, postureSub, req.Host); dd.Reason != "" {
				if dd.Deny {
					r.metrics.AuthDecision.WithLabelValues(req.Host, "deny", dd.Reason).Inc()
					r.audit.Deny(req.Context(), audit.Record{
						Sub: blob.Sub, Email: blob.Email, Route: req.Host,
						Method: req.Method, Path: req.URL.Path, Reason: dd.Reason,
						SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
					})
					r.serveAccessDenied(w, req, http.StatusForbidden, dd.Reason)
					return
				}
				r.metrics.AuthDecision.WithLabelValues(req.Host, "would_deny", dd.Reason).Inc()
				logger.Warn("device mTLS would_deny (audit mode)",
					"reason", dd.Reason, "host", req.Host, "sub", blob.Sub,
					"cert_present", devID.Present, "cert_valid", devID.Valid,
					"cert_device", devID.DeviceID, "cert_kind", devID.Kind,
					"posture_sub", postureSub)
			}
		}
		if postureClaims != nil {
			compliance := map[string]any{}
			for k, v := range postureClaims.Compliance {
				compliance[k] = v
			}
			var graceUntilUnix int64
			if !postureClaims.GraceUntil.IsZero() {
				graceUntilUnix = postureClaims.GraceUntil.Unix()
			}
			regoIn.Posture = &policy.RegoInputPosture{
				Issuer:     postureClaims.Issuer,
				Subject:    postureClaims.Subject,
				IssuedAt:   postureClaims.IssuedAt.Unix(),
				ExpiresAt:  postureClaims.ExpiresAt.Unix(),
				Degraded:   postureClaims.Degraded,
				GraceUntil: graceUntilUnix,
				Compliance: compliance,
			}
		}

		// DDIL P3.10 governed posture-grace — graceful downgrade at the
		// CONSUMER. A posture that verified (signature/attestation intact)
		// but is past its hard exp/MaxAge is served DEGRADED within Talon's
		// governed grace budget (posture.Verifier GraceCorp/GraceByod).
		// Talon — the PEP — decides the degraded SCOPE: a degraded device
		// posture is admissible for low/medium-sensitivity routes but MUST
		// be denied on critical/high (privileged) routes, mirroring the
		// offline session/PDP privileged tiering (privilegedSensitivity).
		// The device NEVER self-grants this grace (any device-claimed grace
		// field is ignored — the budget is Talon config only) and grace
		// NEVER bypasses attestation (Verify rejects a bad signature before
		// it can be degraded). This Go gate is authoritative + defense-in-
		// depth for the Degraded/GraceUntil facts also surfaced into the
		// Rego input above, so a custom Rego cannot widen access past it.
		if postureClaims != nil && postureClaims.Degraded {
			if postureDegradedDeny(up.sensitivity) {
				r.metrics.DDILDegraded.WithLabelValues(observability.DDILDepPosture, observability.DDILOutcomeOfflineDenied).Inc()
				r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "deny"), "posture_degraded").Inc()
				logger.Warn("posture degraded past exp — denied on privileged route (DDIL P3.10 governed grace)",
					"host", req.Host, "sub", blob.Sub, "sensitivity", up.sensitivity,
					"grace_until", postureClaims.GraceUntil.Format(time.RFC3339))
				if up.auditOnly {
					emitWouldHaveDenied(req.Context(), r.audit, blob,
						req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, "posture_degraded")
					logger.Info("posture-degraded would have denied (audit-only)",
						"host", req.Host, "sub", blob.Sub, "sensitivity", up.sensitivity)
					// fall through to allow + sliding-refresh below.
				} else {
					r.audit.Deny(req.Context(), audit.Record{
						Sub: blob.Sub, Email: blob.Email, Route: req.Host,
						Method: req.Method, Path: req.URL.Path, Reason: "posture_degraded",
						SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
					})
					r.serveAccessDenied(w, req, http.StatusForbidden, "posture_degraded")
					return
				}
			} else {
				// Low/medium route — served within grace, governed-degraded.
				r.metrics.DDILDegraded.WithLabelValues(observability.DDILDepPosture, observability.DDILOutcomeStaleServed).Inc()
				logger.Warn("posture degraded past exp — served within governed grace on non-privileged route (DDIL P3.10)",
					"host", req.Host, "sub", blob.Sub, "sensitivity", up.sensitivity,
					"grace_until", postureClaims.GraceUntil.Format(time.RFC3339))
			}
		}

		// Project the operator-declared route sensitivity into the
		// posture compliance map so the ZTNA baseline Rego bundle
		// (docs/policy/ztna/ztna_baseline.rego) can apply the tier ×
		// AAL × sensitivity matrix without operators having to encode
		// it in every per-host posture. Empty Sensitivity defaults via
		// the Rego baseline's own `route_sensitivity := s if {...} else
		// := "medium"` fallback, so this projection is purely a hint —
		// the Rego policy still owns the semantics.
		//
		// IMPORTANT: this runs AFTER the posture projection above so the
		// route-sensitivity hint overlays the verified posture compliance
		// map (the route operator owns sensitivity classification, not
		// the posture-signer).
		if up.sensitivity != "" {
			if regoIn.Posture == nil {
				regoIn.Posture = &policy.RegoInputPosture{Compliance: map[string]any{}}
			} else if regoIn.Posture.Compliance == nil {
				regoIn.Posture.Compliance = map[string]any{}
			}
			regoIn.Posture.Compliance["route_sensitivity"] = up.sensitivity
		}
		regoAllow, regoDenyReason, regoErr := effRego.EvaluateWithReason(req.Context(), regoIn)
		if regoErr != nil {
			logger.Error("rego eval failed (fail-closed)", "err", regoErr, "host", req.Host, "sub", blob.Sub)
			r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "error"), "rego_error").Inc()
			// Honour up.auditOnly for the Rego ERROR path too. A policy
			// bundle compile error during a soak window should not
			// blackhole every request to the route — the operator wants
			// to see the error in the audit log and ship a fix without
			// breaking access.
			if up.auditOnly {
				emitWouldHaveDenied(req.Context(), r.audit, blob,
					req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, "rego_error")
				logger.Info("rego eval errored — audit-only fall-through",
					"host", req.Host, "sub", blob.Sub, "err", regoErr)
				// fall through to allow + sliding-refresh below.
			} else {
				r.audit.Deny(req.Context(), audit.Record{
					Sub: blob.Sub, Email: blob.Email, Route: req.Host,
					Method: req.Method, Path: req.URL.Path, Reason: "rego_error",
					SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
					Err: regoErr.Error(),
				})
				http.Error(w, "forbidden: policy error", http.StatusForbidden)
				return
			}
		} else if !regoAllow {
			logger.Warn("rego denied", "host", req.Host, "sub", blob.Sub, "deny_reason", regoDenyReason)
			r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "deny"), "rego_denied").Inc()
			// AUDIT-ONLY: honour up.auditOnly identically to the per-host
			// gate (~L801) and the MFA step-up gate (~L940). Prior to this
			// fix the Rego deny ALWAYS short-circuited to 403, regardless
			// of auditOnly — so every route with a policyRego module and
			// auditOnly:true silently became enforce-mode the moment the
			// Rego said deny (caught live 2026-06-14 on argocd-ops: the
			// ZTNA baseline correctly denied no-posture requests, but the
			// audit-only soak window the operator declared was being
			// ignored). Matches the existing emitWouldHaveDenied pattern
			// used by per-host + MFA so dashboards see a unified
			// "would_have_denied_rego_denied" metric label.
			if up.auditOnly {
				emitWouldHaveDenied(req.Context(), r.audit, blob,
					req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, "rego_denied", regoDenyReason)
				logger.Info("rego would have denied (audit-only)",
					"host", req.Host, "sub", blob.Sub, "deny_reason", regoDenyReason)
				// fall through to allow + sliding-refresh below.
			} else {
				r.audit.Deny(req.Context(), audit.Record{
					Sub: blob.Sub, Email: blob.Email, Route: req.Host,
					Method: req.Method, Path: req.URL.Path, Reason: "rego_denied",
					DenyReason: regoDenyReason,
					SessionID:  cookie.Value, Permission: up.permission, Issuer: blob.Iss,
				})
				r.serveAccessDenied(w, req, http.StatusForbidden, "rego_denied")
				return
			}
		}
	}

	// Step-up gate per ADR 0001 §6 / boot prompt §4. The check follows
	// the RFC 8176 §1-recommended layering — acr first (stable LoA
	// reference), permissive amr fallback otherwise. See
	// internal/router/stepup.go for the decision table.
	//
	// Honours up.auditOnly: when true, log+audit the would-have-
	// challenged event and FALL THROUGH to allow. This matches the
	// per-host gate's behaviour at L348-380 and is what operators
	// expect when they set auditOnly=true on a route with
	// mfaRequired=true (e.g. for a soak window after a Falcon-ID amr
	// rollout). Pre-fix the MFA gate ALWAYS redirected, regardless
	// of auditOnly — operators set auditOnly=true thinking the route
	// would be permissive and got a hard MFA gate anyway. The
	// vault.ops blank-UI episode on 2026-05-08 was the visible
	// symptom (compounded by talon#1 — Accept-aware redirect — which
	// has its own MR).
	stepUpOK, _ := stepUpSatisfied(up.mfaRequired, up.requireACR, blob)
	if !stepUpOK {
		mfa := true
		if up.auditOnly {
			r.metrics.AuthDecision.WithLabelValues(req.Host, auditDecisionLabel(up.auditOnly, "deny"), "would_have_denied_mfa_required").Inc()
			emitWouldHaveDenied(req.Context(), r.audit, blob,
				req.Host, req.Method, req.URL.Path, cookie.Value, up.permission, "mfa_required")
			logger.Info("MFA gate would have challenged (audit-only)",
				"host", req.Host, "sub", blob.Sub, "amr", blob.AMR, "acr", blob.ACR)
			// Fall through to allow + sliding-refresh below.
		} else {
			logger.Info("step-up MFA required", "host", req.Host, "sub", blob.Sub, "amr", blob.AMR, "acr", blob.ACR)
			r.audit.MFAChallenge(req.Context(), audit.Record{
				Sub: blob.Sub, Email: blob.Email, Route: req.Host,
				Method: req.Method, Path: req.URL.Path, MFA: &mfa,
				SessionID: cookie.Value, Issuer: blob.Iss,
			})
			r.startAuthWithMFA(w, req)
			return
		}
	}

	// Sliding refresh — best-effort, errors logged but not fatal.
	if err := r.store.SlidingRefresh(req.Context(), cookie.Value, blob); err != nil {
		logger.Warn("sliding refresh failed", "err", err)
	}
	// TouchLastSeen on every successful protected hit so the per-route
	// idle-timeout check above (sessionIdleSec) has a fresh floor for
	// the next request. Best-effort; a Redis blip just delays the
	// idle-out by one request, which is the same behavior as a SlidingRefresh
	// failure. Touching on allow only (not deny) so an attacker
	// can't keep an idle session warm by spamming denied requests.
	if err := r.store.TouchLastSeen(req.Context(), cookie.Value); err != nil {
		logger.Warn("touch last-seen failed", "err", err)
	}

	mfa := containsAnyMFA(blob.AMR)
	r.audit.Allow(req.Context(), audit.Record{
		Sub: blob.Sub, Email: blob.Email, Route: req.Host,
		Method: req.Method, Path: req.URL.Path, Reason: "ok", MFA: &mfa,
		SessionID: cookie.Value, Permission: up.permission, Issuer: blob.Iss,
	})
	up.handler.ServeAuthenticated(w, req, blob)
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func (r *Router) startAuth(w http.ResponseWriter, req *http.Request) {
	// Accept-aware: 302 to /auth/start for browser navigation, 401 for
	// XHR/fetch/asset requests. Same rationale as startAuthWithMFA —
	// browsers don't follow 302 chains on fetch()/XHR or asset GETs,
	// so a redirect to an asset endpoint dies silently with empty body
	// (the SPA-bootstrap blank-page failure mode). 401 lets fetch()
	// callers detect the auth challenge and either retry after a top-
	// level reauth or fall through to user-visible error.
	if isXHROrAssetRequest(req) {
		w.Header().Set("WWW-Authenticate",
			`Bearer error="invalid_token", `+
				`error_description="session expired or missing", `+
				`max_age=0`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Talon-Reason", "auth_required")
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	rd := "https://" + req.Host + req.URL.RequestURI()
	target := r.cfg.ExternalURL.String() + "/auth/start?rd=" + urlQueryEscape(rd)
	oidc.WriteHTMLRedirect(w, target)
}

// startAuthWithMFA is like startAuth but appends mfa=1 so /auth/start
// adds acr_values=mfa to the OIDC authorize URL — Falcon-ID's step-up
// flow per ADR 0001 §6.
//
// Accept-aware response (RFC 9470 OAuth Step-Up Challenge):
//
//   - Browser navigation (Accept: text/html or no Accept):
//     302 + HTML-scaffolded body (Talon's canonical cross-origin
//     redirect — see oidc.WriteHTMLRedirect).
//   - XHR / asset request (Accept: application/json, OR
//     X-Requested-With: XMLHttpRequest, OR Sec-Fetch-Mode: cors,
//     OR Accept lacks text/html):
//     401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="mfa", max_age=0`.
//     Browsers follow 302 on document-level navigation but NOT on
//     fetch()/XHR — so a 302 to an asset GET dies silently with an
//     opaque-redirect or empty-body fetch error, which is exactly
//     why the Vault UI was blank pre-fix on 2026-05-08: every
//     /ui/assets/*.{js,css} request got 302→302→302 and the SPA
//     never bootstrapped because the asset bytes were the redirect
//     HTML body, not JS/CSS.
//
// References:
//
//   - RFC 9470 OAuth 2.0 Step-Up Authentication Challenge Protocol
//     https://www.rfc-editor.org/rfc/rfc9470.html
//   - oauth2-proxy#1393 — same 302-vs-XHR pitfall.
//   - oauth2-proxy#2725 — open feature gap upstream.
func (r *Router) startAuthWithMFA(w http.ResponseWriter, req *http.Request) {
	if isXHROrAssetRequest(req) {
		// RFC 9470 §3 challenge.
		w.Header().Set("WWW-Authenticate",
			`Bearer error="insufficient_user_authentication", `+
				`error_description="MFA required for this resource", `+
				`acr_values="mfa", max_age=0`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Talon-Reason", "mfa_required")
		http.Error(w, "MFA required", http.StatusUnauthorized)
		return
	}
	rd := "https://" + req.Host + req.URL.RequestURI()
	target := r.cfg.ExternalURL.String() + "/auth/start?mfa=1&rd=" + urlQueryEscape(rd)
	oidc.WriteHTMLRedirect(w, target)
}

// isXHROrAssetRequest reports whether the request is an in-page
// fetch/XHR (or an asset like a stylesheet, script, image) that
// will NOT follow a 302 redirect chain reliably. We detect this via
// any of:
//
//   - Sec-Fetch-Mode: cors|no-cors  (browsers set this on fetch/XHR)
//   - Sec-Fetch-Dest: script|style|image|font|empty (asset / XHR)
//   - X-Requested-With: XMLHttpRequest (legacy XHR)
//   - Accept doesn't list text/html anywhere (e.g. application/json,
//     application/javascript, image/*, */*; q=0.5 patterns from
//     fetch() default Accept)
//
// Conservative: when in doubt (no Sec-Fetch-* and Accept includes
// text/html) we return false so the caller does the document-level
// 302. False negatives = browser navigation gets a redirect (works).
// False positives = top-level navigation gets a 401 challenge — also
// recoverable by the user, just less seamless. The asymmetry is OK.
func isXHROrAssetRequest(req *http.Request) bool {
	// Sec-Fetch-Mode is the most reliable signal — sent by all modern
	// browsers (Chrome 76+, Firefox 90+, Safari 16.4+) on fetch + img
	// + script + link, but NOT on top-level navigation.
	switch req.Header.Get("Sec-Fetch-Mode") {
	case "cors", "no-cors", "websocket":
		return true
	case "navigate":
		return false
	}
	// Sec-Fetch-Dest: anything other than `document` is an asset.
	dest := req.Header.Get("Sec-Fetch-Dest")
	if dest != "" && dest != "document" {
		return true
	}
	// Legacy XHR signal — jQuery + axios + Fetch polyfills set this.
	if strings.EqualFold(req.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	// Accept-based fallback. text/html ANYWHERE in Accept => browser
	// page navigation. Otherwise (application/json, application/
	// javascript, image/*, etc.) we treat as XHR/asset.
	accept := req.Header.Get("Accept")
	if accept == "" {
		return false
	}
	return !strings.Contains(strings.ToLower(accept), "text/html")
}

// serveAuthVerify implements the GET /auth/verify forward-auth endpoint per
// ADR 0005. APISIX (or any peer that authenticates over Linkerd mTLS to a
// Talon ServiceAccount allow-list) calls this for each customer-tier
// request. Returns 200 + identity headers when the session is valid and
// the active TalonRoute permits access; 401 with X-Talon-Reason on any
// failure mode. Never fails open.
//
// The host the original client requested is read from X-Forwarded-Host
// (APISIX forward-auth plugin sets this); req.Host is the Talon Service's
// own DNS name on the cluster-internal mTLS hop. Cache-Control: no-store
// on every response — APISIX caches by default and a 200 cached after
// session revocation would defeat the gap-2 streaming-revocation point.
func (r *Router) serveAuthVerify(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if req.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.Header().Set("X-Talon-Reason", "method_not_allowed")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}

	cookieValue := ""
	if c, _ := req.Cookie(oidc.SessionCookieName); c != nil {
		cookieValue = c.Value
	}

	// Delegate the decision to the shared Verify core — the gRPC
	// ext_authz adapter (internal/extauthz) consumes the same
	// function so the two wire formats produce identical decisions.
	// See internal/router/verify.go for the contract.
	dec := r.Verify(req.Context(), VerifyInput{
		Host:        host,
		CookieValue: cookieValue,
		Method:      "GET",
		Path:        "/auth/verify",
		SrcIP:       oidc.ClientIP(req),
	})

	if !dec.Allowed {
		w.Header().Set("X-Talon-Reason", dec.Reason)
		if dec.WWWAuthenticate != "" {
			// RFC 9470 step-up challenge — API clients negotiate the
			// missing factor without depending on the calling proxy's
			// redirect logic. Phase 6b-3.
			w.Header().Set("WWW-Authenticate", dec.WWWAuthenticate)
		}
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	for k, v := range dec.IdentityHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
}

// classifyVerifySessionErr maps session.Read errors into the
// X-Talon-Reason header values forward-auth callers can branch on.
// Mirrors the protected-host catch-all's switch in ServeHTTP, but
// returns a string value (the metric label form) instead of a Reason
// type, since the verify endpoint is also writing the value to a
// response header.
func classifyVerifySessionErr(err error) string {
	switch {
	case errors.Is(err, session.ErrNotFound):
		return string(policy.ReasonNoSession)
	case errors.Is(err, session.ErrRevoked):
		return string(policy.ReasonRevokedSession)
	case errors.Is(err, session.ErrExpired):
		return string(policy.ReasonExpiredSession)
	case errors.Is(err, session.ErrAuthFailed):
		return string(policy.ReasonAuthTagFailed)
	default:
		return string(policy.ReasonInternal)
	}
}

// privilegedSensitivity reports whether a route's sensitivity class selects
// the tighter (5m) DDIL offline session-grace budget. Mirrors the SpiceDB
// PDP's privileged tiering (critical/high == privileged/step-up) so the
// offline session window and the offline authz window agree on what
// "privileged" means for the same route.
func privilegedSensitivity(sensitivity string) bool {
	return sensitivity == "critical" || sensitivity == "high"
}

// postureDegradedDeny reports whether a governed-degraded device posture
// (DDIL P3.10 — past its hard exp but within Talon's grace budget) must be
// DENIED on a route of the given sensitivity. A degraded posture is a
// graceful-downgrade, not a full pass: it is admissible for low/medium routes
// and denied on critical/high (privileged) ones — the SAME privileged split
// the offline session/PDP budgets use (privilegedSensitivity), so a decayed
// device-trust claim can never reach the most sensitive resources. Talon (the
// consumer/PEP) is the sole authority on this scope; the device never widens it.
func postureDegradedDeny(sensitivity string) bool {
	return privilegedSensitivity(sensitivity)
}

// serveAccessDenied renders Talon's access-denied response for a policy /
// device-posture block (ADR 0044 §UX). The user is AUTHENTICATED (this is not
// a login prompt) but policy refused the resource. Machine clients (XHR / asset
// / non-text/html API callers) get the plain status + an X-Talon-Reason header,
// unchanged. Browser NAVIGATION gets a branded HTML page that explains WHY and
// how to remediate (enroll / enable Access Agent) instead of a bare
// "forbidden" string — so a user whose device isn't enrolled sees actionable
// guidance, not a dead page. Always sets X-Talon-Reason + Cache-Control.
func (r *Router) serveVerdictDenied(w http.ResponseWriter, req *http.Request, v policy.Verdict) {
	if v.Decision == policy.Error {
		r.serveAuthzUnavailable(w, req, string(v.Reason))
		return
	}
	r.serveAccessDenied(w, req, http.StatusForbidden, string(v.Reason))
}

// serveAuthzUnavailable answers a policy Error (authz backend failure) with a
// retryable 503 instead of a misleading 403. Browser navigations get a page
// that auto-refreshes.
func (r *Router) serveAuthzUnavailable(w http.ResponseWriter, req *http.Request, reason string) {
	w.Header().Set("X-Talon-Reason", reason)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "2")
	if isXHROrAssetRequest(req) {
		http.Error(w, "temporary authorization error, retry", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="2"><title>Retrying…</title></head><body style="font-family:system-ui,sans-serif;text-align:center;margin-top:20vh"><h1>Temporary authorization error</h1><p>Retrying…</p></body></html>`)
}

func (r *Router) serveAccessDenied(w http.ResponseWriter, req *http.Request, status int, reason string) {
	w.Header().Set("X-Talon-Reason", reason)
	w.Header().Set("Cache-Control", "no-store")
	if isXHROrAssetRequest(req) {
		http.Error(w, "forbidden: "+reason, status)
		return
	}
	title, remedy := friendlyDeny(reason)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = denyTpl.Execute(w, struct {
		Host    string
		Title   string
		Remedy  string
		Reason  string
		HelpURL string
	}{
		Host:    req.Host,
		Title:   title,
		Remedy:  remedy,
		Reason:  reason,
		HelpURL: r.cfg.AccessHelpURL,
	})
}

// friendlyDeny maps an internal deny reason to a human title + remediation
// paragraph for the branded access-denied page. Unknown reasons fall back to a
// generic "not permitted" message (never leak internal detail beyond the
// reason code already in the X-Talon-Reason header).
func friendlyDeny(reason string) (title, remedy string) {
	switch reason {
	case "rego_denied":
		return "Your device isn’t reporting a valid security posture",
			"This resource requires Access Agent to be installed and running so your device can prove its security posture (disk encryption, screen lock, device certificate). Enable Access Agent and reload. If your device is enrolled but access is still blocked, this resource may require a managed corporate device."
	case "clientless_critical_denied":
		return "This resource requires a managed corporate device",
			"You’re reaching this over agentless browser access, which cannot reach the most sensitive resources. Use an Access Agent–enrolled corporate device, or contact your administrator."
	default:
		return "You don’t have permission to access this resource",
			"Your session is valid, but policy does not permit access here. If you believe this is an error, contact your administrator."
	}
}

// denyTpl renders the branded access-denied page (ADR 0044 §UX). iOS-safe full
// <html> shape per ADR 0001 §5.d. Shows the title + remediation + an optional
// "Enable Access Agent" CTA when AccessHelpURL is configured.
var denyTpl = template.Must(template.New("access_denied").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access denied — HexxLock</title>
  <style>
    :root { color-scheme: dark; }
    body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
           background:#0f1419; color:#e4e7eb;
           font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
    .card { max-width:520px; margin:24px; padding:32px; background:#1a2028; border:1px solid #2a3340;
            border-radius:12px; }
    .badge { display:inline-flex; align-items:center; gap:8px; color:#f1c40f; font-size:12px;
             text-transform:uppercase; letter-spacing:.06em; margin-bottom:14px; }
    .dot { width:9px; height:9px; border-radius:50%; background:#f1c40f; box-shadow:0 0 0 4px rgba(241,196,15,.15); }
    h1 { font-size:19px; margin:0 0 10px; }
    p { font-size:14px; line-height:1.55; color:#b9c2cc; margin:0 0 16px; }
    .cta { display:inline-block; background:#4a9eff; color:#0c1116; font-weight:600; font-size:14px;
           text-decoration:none; padding:10px 18px; border-radius:7px; }
    .meta { margin-top:18px; font-size:12px; color:#6b7682; word-break:break-all; }
    code { background:#0f1419; padding:1px 6px; border-radius:4px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge"><span class="dot"></span> Access denied</div>
    <h1>{{.Title}}</h1>
    <p>{{.Remedy}}</p>
    {{if .HelpURL}}<a class="cta" href="{{.HelpURL}}">Enable Access Agent</a>{{end}}
    <div class="meta">Resource: <code>{{.Host}}</code> &middot; Reason: <code>{{.Reason}}</code></div>
  </div>
</body>
</html>`))

func (r *Router) serveLoggedOutPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = loggedOutTpl.Execute(w, struct{ AuthURL string }{
		AuthURL: r.cfg.ExternalURL.String() + "/auth/start",
	})
}

// loggedOutTpl renders Talon's /auth/logged-out landing page —
// shown after the full SSO logout chain (Talon → Falcon-ID
// /oauth/logout → bounce back here). Auto-redirects to the sign-in
// flow after 5 seconds; provides a no-JS fallback link plus a manual
// "Sign in now" button. Keeps the iOS-safe HTML shape required by
// ADR 0001 §5.d (full <html><head><body> with content; no bare-anchor
// regression).
var loggedOutTpl = template.Must(template.New("logged_out").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no">
  <meta http-equiv="refresh" content="5;url={{.AuthURL}}">
  <meta name="theme-color" content="#0071e3">
  <title>Signed out — HexxLock</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; height: 100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
        'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg,#f5f5f7 0%,#fff 50%,#eef2ff 100%);
      color: #1d1d1f;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 16px;
    }
    @media (prefers-color-scheme: dark) {
      body { background: linear-gradient(135deg,#0a0a0a 0%,#111827 60%,#0f172a 100%); color:#f5f5f7; }
      .card { background:#1c1c1e; box-shadow:0 4px 24px rgba(0,0,0,0.5); }
      .muted { color:#a1a1a6; }
      .countdown { background:#2c2c2e; color:#f5f5f7; }
      .signin { background:#0a84ff; }
      .signin:hover, .signin:focus { background:#3395ff; }
    }
    .card {
      background: #fff;
      border-radius: 14px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      padding: 40px 32px;
      max-width: 420px; width: 100%;
      text-align: center;
    }
    .badge {
      width: 64px; height: 64px; border-radius: 50%;
      background: rgba(0,113,227,0.10);
      color: #0071e3;
      display: inline-flex; align-items: center; justify-content: center;
      margin-bottom: 20px;
    }
    .badge svg { width: 28px; height: 28px; }
    h1 { font-size: 22px; font-weight: 600; margin: 0 0 8px; letter-spacing: -0.01em; }
    .muted { color: #6e6e73; font-size: 14.5px; margin: 0 0 24px; line-height: 1.45; }
    .signin {
      display: inline-block;
      background: #0071e3; color: #fff;
      font-size: 15px; font-weight: 500;
      padding: 11px 22px;
      border-radius: 9px;
      text-decoration: none;
      transition: background 0.15s ease;
    }
    .signin:hover, .signin:focus { background: #0077ed; outline: none; }
    .countdown {
      margin-top: 18px;
      font-size: 13px;
      color: #6e6e73;
      background: rgba(0,0,0,0.04);
      border-radius: 8px;
      padding: 8px 12px;
      display: inline-block;
    }
    .countdown b { color: #0071e3; font-variant-numeric: tabular-nums; }
  </style>
</head>
<body>
  <main class="card" role="main">
    <div class="badge" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round">
        <path d="M9 12l2 2 4-4"/>
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <h1>You're signed out</h1>
    <p class="muted">Your session has been ended across HexxLock. We'll redirect you back to sign in shortly, or you can continue manually.</p>
    <a class="signin" href="{{.AuthURL}}">Sign in now</a>
    <div class="countdown" aria-live="polite">
      Redirecting in <b id="t">5</b>s…
    </div>
  </main>
  <script>
    // html/template's context-aware escaper sees JS string context
    // and auto-quotes + JS-escapes the substitution. Don't add a
    // printf "%q" pipe here — that wraps the value in extra quotes
    // that html/template escapes a second time, producing literal
    // double-quoted string in JS. The browser then treats the
    // outer-quoted string as a relative URL and resolves it to
    // /auth/%22https%3A...%22 — broken.
    (function () {
      var t = 5;
      var url = {{.AuthURL}};
      var el = document.getElementById('t');
      var iv = setInterval(function () {
        t -= 1;
        if (el) el.textContent = String(Math.max(t, 0));
        if (t <= 0) {
          clearInterval(iv);
          window.location.replace(url);
        }
      }, 1000);
    })();
  </script>
</body>
</html>
`))

// urlQueryEscape lets us avoid importing net/url just for QueryEscape;
// keeps router.go's import set minimal.
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			out = append(out, c)
		} else {
			out = append(out, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}

// statusCapturingResponseWriter is a minimal http.ResponseWriter wrapper
// that records the status code passed to WriteHeader so the JWKS metric
// label (success / unconfigured / error) can be derived from the
// outcome without re-implementing the JWKS handler. The wrapped writer
// transparently passes WriteHeader + Write through; we only intercept
// to remember the code.
type statusCapturingResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCapturingResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Hijack passes through to the underlying writer so HTTP/1.1
// connection upgrades (WebSocket, SPDY) keep working when this
// wrapper is in the chain. Required since the wrap was extended from
// the narrow /jwks branch to wrap every request in ServeHTTP — the
// upstream proxy uses httputil.ReverseProxy which needs Hijacker for
// WebSocket. Without this passthrough every upgrade fails with
// `http.Hijacker not implemented`.
func (w *statusCapturingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush passes through so chunked / SSE responses keep flushing
// through the wrapper. Same reasoning as Hijack: required once the
// wrapper covers every request, not just the JSON jwks handler.
func (w *statusCapturingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time guards.
var _ http.Handler = (*Router)(nil)
var _ http.ResponseWriter = (*statusCapturingResponseWriter)(nil)
var _ http.Hijacker = (*statusCapturingResponseWriter)(nil)
var _ http.Flusher = (*statusCapturingResponseWriter)(nil)
var _ = context.Background
