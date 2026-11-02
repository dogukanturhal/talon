// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy is Talon's PEP — the reverse-proxy that forwards admin
// browser requests to upstream services after the PE authorises. Identity
// is injected as X-Talon-* headers; any incoming X-Talon-* on the request
// is stripped first to defeat header-spoofing (ADR 0001 §7.a).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/identityjwt"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/observability"
	"github.com/dogukanturhal/talon/internal/session"
)

// Upstream describes a backend the Talon PEP forwards to.
type Upstream struct {
	// Host:port of the upstream Service (cluster-internal).
	Service string
	// Optional URL scheme; defaults to http.
	Scheme string
}

// URL builds the upstream base URL.
func (u Upstream) URL() *url.URL {
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return &url.URL{Scheme: scheme, Host: u.Service}
}

// Handler is a reverse-proxy bound to one Upstream and decorated with
// identity injection + metrics.
type Handler struct {
	rp       *httputil.ReverseProxy
	upstream Upstream
	metrics  *observability.Metrics
	route    string // for metrics labels (typically the public host)
	// signer mints the per-request X-Talon-Identity-Token JWT (RFC 7519,
	// RS256). Optional — nil keeps the legacy unsigned-header-only path
	// for backwards compatibility during the Phase A rollout. Once every
	// downstream SDK is verifying the JWT (Phase B), the unsigned
	// X-Talon-User et al. become convenience-only and the signer becomes
	// the authoritative identity surface. See internal/identityjwt for
	// the full trust model + threat analysis.
	signer *identityjwt.Signer
	// injectAuthorizationBearer additionally stamps the signed JWT into
	// the canonical Authorization: Bearer header for upstreams that
	// consume stock OAuth2 / OIDC middleware (Grafana, Argo CD,
	// generic Go services). Opt-in per route — see Phase C in
	// docs/architecture/0005-iap-identity-token.md. Requires signer.
	injectAuthorizationBearer bool
	// requireSignedIdentityToken flips the mint-failure posture from
	// FAIL-OPEN (proxy anyway with unsigned X-Talon-* headers, the Phase
	// A/B transitional default) to FAIL-CLOSED (deny with a 5xx). When
	// true, ServeAuthenticated refuses any request for which a signed
	// X-Talon-Identity-Token could not be stamped — either because the
	// signer is not wired or because Sign() returned an error. Default
	// false so nothing breaks for downstreams that have not yet finished
	// the SDK-verifier migration; an operator enables it per route (or
	// fleet-wide via TALON_REQUIRE_SIGNED_IDENTITY_TOKEN) as each
	// downstream starts verifying the signed token. The effective value is
	// the OR of the global default and the per-route knob (see
	// router.RegisterUpstream) — enabling either tightens the route, and
	// a route can never drop below the global floor. See
	// docs/architecture/0005-iap-identity-token.md §"Fail-closed minting".
	requireSignedIdentityToken bool
	// auditEmitter records iap.token.mint_failed records when the
	// signer's Sign() returns a non-nil error. Optional; nil-safe at
	// the call site so unit tests and the no-signer path don't have to
	// pre-wire an emitter. Production wires it via router → SetAudit.
	auditEmitter *audit.Emitter
}

// NewHandler returns a Handler for the given upstream.
//
// Header-injection ordering contract: the Rewrite callback intentionally
// does NOT strip X-Talon-* on pr.Out. ServeAuthenticated has already (1)
// stripped any client-supplied X-Talon-* headers BEFORE injection and
// (2) set authoritative X-Talon-* values on the inbound request. By the
// time Rewrite fires, pr.Out carries trusted X-Talon-* headers — stripping
// them here (the pre-2026-05-12 behaviour) silently broke every
// downstream consumer of the IAP-trust identity (notably the
// @hexxlock/falcon-id-client/nextjs middleware, which short-circuits on
// X-Talon-User to skip the redirect-to-/login dance). Live repro
// 2026-05-12 ~16:10Z: Talon audit logged decision=allow + permission=admin
// + mfa=true (audit reads from session blob, not outbound headers), but
// upstream frontend-falcon-admin saw zero X-Talon-* headers and bounced
// every authenticated user to accounts.example.com.
//
// Rewrite stays as the canonical place to rewrite the URL + the
// X-Forwarded-* family (those originate from the inbound transport,
// not the application layer). X-Talon-* is fully owned by
// ServeAuthenticated.
func NewHandler(route string, up Upstream, m *observability.Metrics) *Handler {
	target := up.URL()
	rp := &httputil.ReverseProxy{
		// Use Rewrite (Go 1.20+) instead of the deprecated Director.
		// Rewrite gives us the inbound + outbound request as a pair,
		// making it explicit which fields we mutate vs which we copy.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			// Pin X-Forwarded-Host to the original public host so
			// upstreams (e.g. Grafana) generate routable URLs.
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			// Preserve the original Host header on the outbound
			// request. SetURL above rewrites pr.Out.Host to the
			// upstream Service name (e.g. harbor.monitoring.svc),
			// which is the default httputil.ReverseProxy behaviour;
			// restore it to the public Host the client requested so
			// upstreams that compute response URLs from the Host
			// header (Harbor's Docker Registry v2 Bearer-realm,
			// GitLab's OmniAuth callback URLs, OAuth2 redirect_uris,
			// any upstream that emits self-referential absolute
			// URLs) return EXTERNALLY-resolvable URLs instead of
			// internal Service DNS.
			//
			// Live trigger 2026-05-30 — Harbor activation Gate D:
			// before this fix, GET /v2/ through Talon returned
			//   WWW-Authenticate: Bearer realm=
			//     "https://harbor.monitoring.svc.cluster.local:80/service/token"
			// which is unreachable from external Docker clients. With
			// preserved Host:
			//   WWW-Authenticate: Bearer realm=
			//     "https://registry.example.com/service/token"
			// matching the pre-Talon direct path exactly.
			//
			// This is the canonical IAP behaviour — Envoy
			// (auto_host_rewrite=false default), NGINX
			// (proxy_set_header Host $host default in plus modules),
			// HAProxy (http-request set-header Host pattern), and
			// Pomerium (preserve_host_header=true default) all
			// preserve the inbound Host on outbound. Talon was the
			// outlier.
			//
			// Compatible with all existing routes: every Talon
			// upstream has been receiving the upstream Service name
			// as Host since launch, AND the X-Forwarded-Host header
			// was already pinned to the public host above, so any
			// upstream that already uses X-Forwarded-Host is
			// unaffected. Upstreams that ignore X-Forwarded-Host
			// AND emit Host-based URLs (Harbor v2 token realm,
			// future MinIO presigned URLs, Vault redirects) start
			// emitting correctly-public URLs which is the desired
			// behaviour. The only risk is an upstream with vhost
			// routing that switches based on Host header — none of
			// our current upstreams do this (Linkerd mTLS bound
			// each to a single Service).
			pr.Out.Host = pr.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			tlog.From(r.Context()).Error("upstream error", "err", err, "route", route, "upstream", up.Service)
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
	// HTTPS upstreams use a Transport that skips x509 cert verification.
	// Rationale: in-cluster upstreams typically present self-signed certs
	// (SafeLine mgt nginx, Harbor core, etc.) and the actual transport-
	// security boundary is Linkerd mTLS, not the upstream's leaf cert.
	// Requiring valid PKI would force every upstream to ship a cert from
	// our internal CA, which is operationally heavier than the mesh trust
	// already established. http upstreams keep the default Transport.
	if target.Scheme == "https" {
		rp.Transport = &http.Transport{
			//nolint:gosec // see comment above — Linkerd mTLS is the boundary
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &Handler{rp: rp, upstream: up, metrics: m, route: route}
}

// ServeAuthenticated handles the request after the session has been
// resolved + the policy decision has passed. It performs the canonical
// IAP header-injection ceremony:
//
//  1. Strip any client-supplied X-Talon-* / spoofable identity headers
//     so they can't slip past the trust boundary.
//  2. Inject authoritative X-Talon-* values from the validated session.
//  3. Proxy upstream.
//
// Steps 1 and 2 MUST run BEFORE the proxy's Rewrite callback fires —
// otherwise the inbound request (and the proxy's clone of it) wouldn't
// carry the trusted headers when the upstream connection is built. The
// Rewrite callback no longer touches X-Talon-* (see NewHandler doc).
func (h *Handler) ServeAuthenticated(w http.ResponseWriter, req *http.Request, b *session.Blob) {
	stripSpoofableIdentityHeaders(req)
	// Phase C: when this route is in Authorization-Bearer-injection mode,
	// also strip any client-supplied Authorization so a spoofed token
	// cannot ride through to the upstream. Routes WITHOUT Bearer injection
	// leave Authorization alone — many upstreams use it for their own
	// auth flows and we don't want to break that.
	if h.injectAuthorizationBearer {
		req.Header.Del("Authorization")
	}
	injectIdentityHeaders(req, b)
	if !h.injectSignedIdentityToken(req, b) {
		// Fail-closed (RequireSignedIdentityToken): the signed identity
		// assertion this route contractually requires could not be
		// produced, so refuse rather than proxy with unsigned headers.
		// injectSignedIdentityToken has already emitted the WARN audit
		// (iap.token.mint_denied) + metric. 503 Service Unavailable is the
		// honest code: the failure is Talon-internal (not the client's
		// authz — the session already ALLOWED, and not the upstream —
		// which we never contacted), and it is retryable for the transient
		// key-load race. Body is generic to avoid leaking signer internals.
		http.Error(w, "identity assertion unavailable", http.StatusServiceUnavailable)
		return
	}
	start := time.Now()
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.rp.ServeHTTP(rw, req)
	h.observeUpstreamLatency(rw, start)
}

// ServeUnauthenticated forwards a request to the upstream WITHOUT a Talon
// session, for explicitly config-allow-listed public/bootstrap routes (e.g. the
// ZTNA device-enrollment endpoint, which self-authenticates via a WebAuthn
// witness JWS). It still strips spoofable identity headers so a client cannot
// forge a Talon identity through the carve-out, but — unlike ServeAuthenticated
// — it injects NO X-Talon-* identity and leaves the client's Authorization
// header and body intact so the self-authenticating upstream can verify them.
func (h *Handler) ServeUnauthenticated(w http.ResponseWriter, req *http.Request) {
	stripSpoofableIdentityHeaders(req)
	start := time.Now()
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.rp.ServeHTTP(rw, req)
	h.observeUpstreamLatency(rw, start)
}

// stripSpoofableIdentityHeaders removes any X-Talon-* / oauth2-proxy
// X-Auth-Request-* / X-Forwarded-User-style header a client may have set;
// the PEP injects authoritative replacements via injectIdentityHeaders.
//
// X-Forwarded-* base headers (Host, Proto, For) are left alone here —
// they are owned by Traefik and the proxy's SetXForwarded callback.
func stripSpoofableIdentityHeaders(req *http.Request) {
	for k := range req.Header {
		ku := strings.ToLower(k)
		if strings.HasPrefix(ku, "x-talon-") {
			req.Header.Del(k)
		}
	}
	// The signed identity-token header is also Talon-namespaced (sits
	// outside the X-Talon-* prefix on purpose so SDKs can grep just the
	// token without matching the convenience headers). Strip the
	// inbound version explicitly so a client-supplied forged token can
	// never reach upstream — only ServeAuthenticated's Sign() output
	// is authoritative.
	req.Header.Del(identityjwt.HeaderName)
	for _, k := range []string{
		"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Groups",
		"X-Forwarded-Preferred-Username", "X-Auth-Request-User",
		"X-Auth-Request-Email", "X-Auth-Request-Groups",
		"X-Auth-Request-Preferred-Username",
	} {
		req.Header.Del(k)
	}
}

// SetSigner wires the IAP identity-JWT signer. After this call,
// ServeAuthenticated will stamp X-Talon-Identity-Token on every
// proxied request. Optional; leave unset to keep the legacy
// unsigned-header-only path (used in tests + during the Phase A
// rollout before the matching SDK verifier is deployed).
func (h *Handler) SetSigner(s *identityjwt.Signer) {
	h.signer = s
}

// SetInjectAuthorizationBearer enables Phase C: in addition to the
// dedicated X-Talon-Identity-Token header, ServeAuthenticated will
// also stamp the same JWT into the Authorization: Bearer header for
// upstreams that consume stock OAuth2 / OIDC middleware. Opt-in
// per-route (set from TalonRoute.spec.injectAuthorizationBearer).
// No-op when the signer isn't wired (you need a JWT to inject).
func (h *Handler) SetInjectAuthorizationBearer(on bool) {
	h.injectAuthorizationBearer = on
}

// SetRequireSignedIdentityToken toggles fail-closed identity-token minting
// for this route (ASVS 5.0 V9 — signed-identity minting must be able to
// fail closed). When on, a request whose signed X-Talon-Identity-Token
// cannot be produced is denied with a 5xx instead of proxying unsigned.
// Default off preserves the legacy fail-open fallback. Wired per route from
// the OR of the global TALON_REQUIRE_SIGNED_IDENTITY_TOKEN default and the
// TalonRoute.spec.requireSignedIdentityToken knob; see router.RegisterUpstream.
func (h *Handler) SetRequireSignedIdentityToken(on bool) {
	h.requireSignedIdentityToken = on
}

// SetAudit wires the audit emitter the handler uses to record
// iap.token.mint_failed events when JWT signing fails. Optional; when
// unset the failure is logged via slog only (legacy behaviour). Router
// wires this at startup alongside the signer.
func (h *Handler) SetAudit(a *audit.Emitter) {
	h.auditEmitter = a
}

func injectIdentityHeaders(req *http.Request, b *session.Blob) {
	req.Header.Set("X-Talon-User", b.Email)
	req.Header.Set("X-Talon-Email", b.Email)
	req.Header.Set("X-Talon-Subject", b.Sub)
	if len(b.Groups) > 0 {
		req.Header.Set("X-Talon-Groups", strings.Join(b.Groups, ","))
	}
	if b.TenantID != "" {
		req.Header.Set("X-Talon-Tenant", b.TenantID)
	}
	// Cross-system correlation handle. Upstream apps that emit their own
	// audit log should echo this into their event records so the SOC
	// analyst can grep one ID across Talon, Falcon-ID and the upstream's
	// log streams.
	if b.SSOChainID != "" {
		req.Header.Set("X-Talon-Sso-Chain-Id", b.SSOChainID)
	}
}

// injectSignedIdentityToken mints the RS256-signed JWT carrying the
// blob's identity scoped to the route's public host (= audience) and
// stamps it on X-Talon-Identity-Token.
//
// Return value is the proceed decision: true = the caller may forward the
// request upstream; false = the caller MUST deny (fail closed). It returns
// false ONLY when the route has requireSignedIdentityToken enabled AND a
// signed token could not be stamped. In every other case it returns true.
//
// Mint-failure posture (ASVS 5.0 V9):
//   - Default (requireSignedIdentityToken=false): FAIL OPEN. A signing
//     failure — or an unwired signer (Phase A pre-rollout / single-binary
//     tests) — is logged and the request still proxies with the unsigned
//     X-Talon-* fallback. Tier-1 enforcement then happens upstream-side:
//     the SDK refuses requests without a verified token. Every fail-open
//     fallback now emits a WARN audit (iap.token.mint_failed,
//     reason=fail_open_unsigned_fallback) so operators can measure how
//     often it happens and drive the downstream SDK-verifier migration.
//   - requireSignedIdentityToken=true: FAIL CLOSED. A signing failure or an
//     unwired signer denies the request (WARN audit iap.token.mint_denied);
//     the caller returns 5xx instead of leaking an unsigned identity. This
//     is the per-route opt-in an operator flips as each downstream finishes
//     verifying the signed token.
//
// When the route has injectAuthorizationBearer enabled (Phase C), the
// JWT is ALSO stamped into the canonical Authorization: Bearer header.
// The inbound Authorization is stripped first (via
// stripSpoofableIdentityHeaders) so a client-supplied header can never
// reach the upstream in that mode.
func (h *Handler) injectSignedIdentityToken(req *http.Request, b *session.Blob) bool {
	if h.signer == nil {
		if h.requireSignedIdentityToken {
			// The route demands a signed token but no signer is wired —
			// we can never satisfy the contract, so deny loudly rather
			// than silently proxy unsigned. No Sign() was attempted, so
			// there is no kid/IAPTokenSign sample to record here; the
			// mint_denied audit + the 5xx (request_total) carry the signal.
			tlog.From(req.Context()).Warn("iap identity jwt required but signer not wired; failing closed",
				"route", h.route, "sub", b.Sub,
			)
			if h.auditEmitter != nil {
				h.auditEmitter.IAPMintDenied(req.Context(), audit.Record{
					Sub:         b.Sub,
					Email:       b.Email,
					TenantID:    b.TenantID,
					Route:       h.route,
					Method:      req.Method,
					Path:        req.URL.Path,
					SessionID:   b.SID,
					SSOChainID:  b.SSOChainID,
					IAPAudience: h.route,
					Reason:      "signer_not_wired",
					Err:         "signer not wired",
				})
			}
			return false
		}
		return true
	}
	token, err := h.signer.Sign(b, h.route)
	if err != nil {
		failClosed := h.requireSignedIdentityToken
		reason := "fail_open_unsigned_fallback"
		if failClosed {
			reason = "fail_closed_denied"
		}
		tlog.From(req.Context()).Warn("iap identity jwt sign failed",
			"err", err, "route", h.route, "sub", b.Sub,
			"require_signed", failClosed, "outcome", reason,
		)
		if h.auditEmitter != nil {
			rec := audit.Record{
				Sub:         b.Sub,
				Email:       b.Email,
				TenantID:    b.TenantID,
				Route:       h.route,
				Method:      req.Method,
				Path:        req.URL.Path,
				SessionID:   b.SID,
				SSOChainID:  b.SSOChainID,
				IAPKid:      h.signer.Kid(),
				IAPAudience: h.route,
				Reason:      reason,
				Err:         err.Error(),
			}
			// Always record the mint failure (the migration-driving signal);
			// additionally record the enforcement action when failing closed.
			h.auditEmitter.IAPMintFailed(req.Context(), rec)
			if failClosed {
				h.auditEmitter.IAPMintDenied(req.Context(), rec)
			}
		}
		if h.metrics != nil {
			h.metrics.IAPTokenSign.WithLabelValues(h.route, "fail", h.signer.Kid()).Inc()
		}
		return !failClosed
	}
	req.Header.Set(identityjwt.HeaderName, token)
	if h.injectAuthorizationBearer {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if h.metrics != nil {
		h.metrics.IAPTokenSign.WithLabelValues(h.route, "success", h.signer.Kid()).Inc()
	}
	return true
}

// observeUpstreamLatency records upstream latency as TIME-TO-FIRST-BYTE — the
// interval from dispatching the request to the upstream's response headers
// arriving — NOT the wall time of ServeHTTP.
//
// httputil.ReverseProxy.ServeHTTP blocks for the entire lifetime of the
// response, including the body. For a streaming upstream that is the lifetime
// of the STREAM, not any measure of how quickly the upstream answered. ArgoCD's
// UI holds gRPC server-streams (Watch, WatchResourceTree) open for ~60s at a
// time; each completed with grpc.code=OK, and each was being recorded here as
// a 60-second "latency" observation. On 2026-08-05 that pushed
// talon:upstream_latency_seconds:p99:30m:cluster to >=10s (the +Inf bucket)
// and fired TalonLatencyP99HighCluster, whose SLO is 500ms, while nothing was
// actually slow: 91.7% of requests completed under 0.5s and the route's
// success ratio was 100%. Normal p99 on days with no UI session open is
// 9-100ms. Long-lived streams also produced the paired TalonUpstreamErrorRate
// 502s when the proxy cut them.
//
// TTFB is the standard proxy-side definition and the one this SLO was written
// against (the Pomerium admin-tier session-validation budget, ~400ms p99).
// nginx and Envoy draw the same distinction — nginx splits
// upstream_header_time from upstream_response_time; Envoy splits
// upstream_rq_time from the response-complete duration — precisely so
// streaming and websocket traffic cannot swamp a latency SLO.
//
// If the upstream never responded (dial failure, timeout before headers) there
// is no first byte, so the full elapsed time IS the latency and is recorded as
// such — those are exactly the slow failures the SLO should catch.
func (h *Handler) observeUpstreamLatency(rw *statusWriter, start time.Time) {
	if h.metrics == nil {
		return
	}
	d := time.Since(start)
	if at := rw.HeaderAt(); !at.IsZero() {
		d = at.Sub(start)
	}
	h.metrics.UpstreamLatency.WithLabelValues(h.route).Observe(d.Seconds())
}

// statusWriter records the status, and when the upstream's response
// headers reached the client, for metrics.
type statusWriter struct {
	http.ResponseWriter
	status int
	// headerAt is when the upstream's response headers were written —
	// i.e. time-to-first-byte. Zero until the upstream actually responds.
	// See Handler.observeUpstreamLatency for why this, and not the duration of
	// ServeHTTP, is what upstream_latency_seconds must observe.
	headerAt time.Time
}

func (s *statusWriter) WriteHeader(c int) {
	s.markResponded()
	s.status = c
	s.ResponseWriter.WriteHeader(c)
}

// Write records TTFB for handlers that never call WriteHeader explicitly —
// net/http emits an implicit 200 on the first Write.
func (s *statusWriter) Write(b []byte) (int, error) {
	s.markResponded()
	return s.ResponseWriter.Write(b)
}

// markResponded stamps the moment the upstream first produced a response.
// Only the FIRST call counts; a streaming body writes many times.
func (s *statusWriter) markResponded() {
	if s.headerAt.IsZero() {
		s.headerAt = time.Now()
	}
}

// Status returns the recorded status code (defaulting to 200).
func (s *statusWriter) Status() int { return s.status }

// HeaderAt returns when the upstream's response headers reached the client,
// or the zero time if the upstream never responded at all.
func (s *statusWriter) HeaderAt() time.Time { return s.headerAt }

// Hijack lets WebSocket / SPDY connection upgrades flow through this
// wrapper. httputil.ReverseProxy needs the ResponseWriter to be an
// http.Hijacker to switch protocols (e.g. the jess RDP/SSH/DB console
// WS at /ws/*); without it every upgrade fails with "can't switch
// protocols using non-Hijacker ResponseWriter type *proxy.statusWriter".
// Mirrors internal/router's statusCapturingResponseWriter.
func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		c, rw, err := h.Hijack()
		if err == nil {
			// A successful hijack means the upgrade negotiation with the
			// upstream completed, so the "response" has effectively arrived.
			// Stamp it here because a hijacked connection never calls
			// WriteHeader — without this a WebSocket session that stays open
			// for an hour would be recorded as an hour of upstream latency.
			s.markResponded()
		}
		return c, rw, err
	}
	return nil, nil, http.ErrNotSupported
}

// Flush passes through so chunked / SSE / streaming responses keep
// flushing through this wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time guards.
var _ http.Handler = (*Handler)(nil)
var _ http.Hijacker = (*statusWriter)(nil)
var _ http.Flusher = (*statusWriter)(nil)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.rp.ServeHTTP(w, r) }

// Ensure context use is recorded (silences linter on context import).
var _ = context.Background
