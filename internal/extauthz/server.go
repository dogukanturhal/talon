// SPDX-License-Identifier: AGPL-3.0-or-later

// Package extauthz implements the Envoy ext_authz gRPC server
// (service.auth.v3.Authorization) backed by Talon's shared Verify
// decision core (internal/router.Router.Verify).
//
// Why this exists — Phase 7 / GEP-1494 alignment
// ==============================================
// Phase 6 shipped Talon as an IAP with rich per-host (and post-Phase-6b
// per-path) policy. Phase 7 makes Talon a SHARED PDP that multiple
// data planes consume:
//
//   - Talon's own HTTP data plane (admin tier internal.example.com)
//   - APISIX (customer tier *.hexxlock.com + api.example.app)
//   - Future: Envoy Gateway, Istio, Cilium, HAProxy, Traefik, ingress-nginx
//
// The wire contract is Envoy ext_authz v3 — the cross-implementation
// forward-auth primitive standardized by Gateway API GEP-1494
// (HTTPRoute ExternalAuth Filter, Experimental in v1.4.0). KubeCon
// London 2025 reached multi-dataplane consensus: every major data
// plane either already speaks ext_authz natively (Envoy, Envoy Gateway,
// Istio) or has a near-identical method that GEP-1494 maps onto
// (HAProxy, Traefik, Cilium, ingress-nginx).
//
// Adopting ext_authz as Talon's PDP wire format means:
//   - The current HTTP /auth/verify forward-auth (ADR 0005) stays for
//     backward-compat during transition; new callers should use gRPC.
//   - APISIX migrates from `forward-auth` plugin (HTTP) to `ext-plugin`
//     or a custom plugin that speaks ext_authz gRPC.
//   - Identity headers (X-Talon-User/Email/Subject/Tenant-Id/Groups)
//     are injected via CheckResponse.OkHttpResponse.Headers — same
//     vocabulary HTTP forward-auth uses. Callers don't re-parse.
//
// Decision core sharing
// =====================
// This server is a thin wire-format adapter. It builds a router.
// VerifyInput from the Envoy CheckRequest attributes, calls
// router.Verify(), and formats the response. ALL audit emission,
// metric instrumentation, session lifecycle, per-host gates, policy
// evaluation, and step-up logic live in router.Verify — guaranteeing
// the gRPC and HTTP adapters produce IDENTICAL decisions for the
// same request.
package extauthz

import (
	"context"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	codes "google.golang.org/grpc/codes"

	"github.com/hexxlock/talon/internal/oidc"
	"github.com/hexxlock/talon/internal/router"
)

// Verifier is the subset of router.Router this package depends on.
// Kept as an interface so tests can substitute a fake without
// constructing the full Router (which needs session.Store + SpiceDB
// client + audit emitter + Falcon-ID RP — all the usual integration
// machinery). Production wiring passes a *router.Router directly.
type Verifier interface {
	Verify(ctx context.Context, in router.VerifyInput) router.VerifyDecision
}

// Server implements the Envoy ext_authz Authorization service. Embeds
// the generated UnimplementedAuthorizationServer for forward-compat
// per the standard gRPC-Go server-skeleton pattern — when Envoy adds
// a new RPC to the service definition, we don't break the build.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	verifier Verifier
}

// NewServer wires the ext_authz adapter to a Verifier (typically the
// *router.Router instance the main HTTP data plane also uses). The
// gRPC server registration happens in cmd/talon/main.go alongside
// the existing HTTP listeners.
func NewServer(v Verifier) *Server {
	return &Server{verifier: v}
}

// Check is the single ext_authz RPC. Envoy / Envoy Gateway / Istio /
// APISIX / Cilium / Traefik / HAProxy / etc. call this per inbound
// request. The handler:
//
//  1. Extracts request shape from CheckRequest.Attributes.Request.Http
//     (host from :authority or x-forwarded-host header; cookie from
//     the cookie header; method + path verbatim; source IP from
//     Attributes.Source.Address).
//  2. Builds a router.VerifyInput.
//  3. Calls the shared Verify core.
//  4. Maps the VerifyDecision into a CheckResponse:
//     - Allow → status.OK + OkHttpResponse with identity headers to
//       inject onto the upstream request (override semantics —
//       AppendAction=OVERWRITE_IF_EXISTS_OR_ADD per RFC-style
//       intent; matches Envoy ext_authz `allowed_upstream_headers`
//       behaviour).
//     - Deny → status.PERMISSION_DENIED + DeniedHttpResponse with
//       status=401 (Unauthorized) + X-Talon-Reason header so callers
//       can branch (redirect-to-login vs hard-fail vs RFC 9470
//       step-up challenge per Phase 6b).
//
// Cache-Control: no-store equivalent — Envoy ext_authz responses are
// not cached by the filter by default (no `disable_request_body_buffering`
// caching equivalent for the decision itself). Callers MUST NOT cache
// the CheckResponse — every request gets a fresh decision per the
// session-revocation invariant (ADR 0001 §7.b / Gap 2 streaming
// revocation).
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	in := buildVerifyInput(req)
	dec := s.verifier.Verify(ctx, in)

	if !dec.Allowed {
		return denyResponse(dec.Reason, dec.WWWAuthenticate), nil
	}
	return okResponse(dec.IdentityHeaders), nil
}

// buildVerifyInput maps the Envoy CheckRequest into a router.VerifyInput.
// The mapping mirrors the HTTP forward-auth adapter (serveAuthVerify)
// so the two surfaces are decision-equivalent.
//
// Header lookup is case-insensitive in HTTP, but the Envoy proto
// guarantees lower-cased keys: "All header keys must be lower-cased,
// because HTTP header keys are case-insensitive." We rely on that
// guarantee for direct map lookups.
func buildVerifyInput(req *authv3.CheckRequest) router.VerifyInput {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()
	headers := httpReq.GetHeaders()

	// Host — APISIX preserves x-forwarded-host on the ext_authz call
	// (mirroring the existing HTTP forward-auth behaviour). Fall back
	// to the :authority pseudo-header which Envoy normalises into
	// httpReq.Host on HTTP/1.1 connections.
	host := headers["x-forwarded-host"]
	if host == "" {
		host = httpReq.GetHost()
	}

	// Cookie — Envoy concatenates multi-cookie headers per RFC 6265
	// §5.4 ("when the user agent generates an HTTP request, the user
	// agent MUST NOT attach more than one Cookie header field"). Parse
	// once using net/http's cookie parser (oidc.SessionCookieName is
	// the constant the HTTP adapter also reads).
	cookieValue := extractCookieValue(headers["cookie"], oidc.SessionCookieName)

	// Source IP — Envoy populates Attributes.Source.Address; APISIX
	// sets x-forwarded-for from CF-Connecting-IP. Prefer x-forwarded-for
	// for parity with the HTTP adapter (oidc.ClientIP reads it).
	srcIP := firstIPFromHeader(headers["x-forwarded-for"])
	if srcIP == "" {
		if src := attrs.GetSource().GetAddress().GetSocketAddress(); src != nil {
			srcIP = src.GetAddress()
		}
	}

	return router.VerifyInput{
		Host:        host,
		CookieValue: cookieValue,
		Method:      httpReq.GetMethod(),
		Path:        httpReq.GetPath(),
		SrcIP:       srcIP,
	}
}

// extractCookieValue parses the inbound Cookie header for the named
// session cookie. Returns empty string if absent — Verify maps that
// to ReasonNoSession.
//
// Implementation: net/http's http.ParseCookie would be the canonical
// path but it requires building a *http.Request. Instead, hand-parse
// the "k=v; k2=v2" form — same shape Envoy's HTTP/1.1 parser hands us
// and identical to what oidc.SessionCookieName lookup does on the
// HTTP forward-auth path.
func extractCookieValue(header, name string) string {
	for _, kv := range strings.Split(header, ";") {
		kv = strings.TrimSpace(kv)
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		if kv[:eq] == name {
			return kv[eq+1:]
		}
	}
	return ""
}

// firstIPFromHeader returns the first comma-separated IP from an
// X-Forwarded-For header value. RFC 7239 / X-Forwarded-For ordering
// puts the original client first. Empty input → empty output.
func firstIPFromHeader(h string) string {
	if h == "" {
		return ""
	}
	if comma := strings.IndexByte(h, ','); comma >= 0 {
		return strings.TrimSpace(h[:comma])
	}
	return strings.TrimSpace(h)
}

// okResponse builds the allow CheckResponse with identity headers
// injected onto the upstream request. AppendAction=OVERWRITE_IF_
// EXISTS_OR_ADD ensures a client-supplied X-Talon-* header cannot
// spoof the trusted identity (same intent as the HTTP forward-auth
// adapter's w.Header().Set overwrite semantics).
//
// Envoy's ext_authz filter passes these headers to the upstream via
// `allowed_upstream_headers` (the upstream-side filter config lists
// them) — but using HeadersToRemove / Headers in CheckResponse means
// we don't need APISIX/Envoy-side per-header allow-listing; the
// CheckResponse itself authoritatively names what to inject. Cleaner
// for operators.
func okResponse(identityHeaders map[string]string) *authv3.CheckResponse {
	hs := make([]*corev3.HeaderValueOption, 0, len(identityHeaders))
	for k, v := range identityHeaders {
		hs = append(hs, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: k, Value: v},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: hs},
		},
	}
}

// denyResponse builds the deny CheckResponse with HTTP 401 and the
// X-Talon-Reason header carrying the policy decision label. Status
// code is PERMISSION_DENIED at the gRPC layer (mapping to Envoy's
// "deny" outcome) and 401 Unauthorized at the HTTP layer (matching
// the HTTP forward-auth adapter's behaviour exactly — APISIX clients
// branching on the response status see the same 401 from both
// adapters).
//
// Phase 6b RFC 9470 step-up note: when dec.MFARequired is true, this
// function STILL returns a 401 with X-Talon-Reason="mfa_required" —
// matches Phase 6a.1 wire behaviour. Phase 6b's matcher engine will
// emit the full WWW-Authenticate challenge format
// (`Bearer error="insufficient_user_authentication" acr_values=...`)
// once the per-path ACR requirement plumbing is wired through Verify.
func denyResponse(reason, wwwAuthenticate string) *authv3.CheckResponse {
	headers := []*corev3.HeaderValueOption{
		{
			Header: &corev3.HeaderValue{Key: "X-Talon-Reason", Value: reason},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
		{
			Header: &corev3.HeaderValue{Key: "Cache-Control", Value: "no-store"},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
	}
	if wwwAuthenticate != "" {
		// RFC 9470 step-up challenge — same wire shape the HTTP
		// adapter emits. APISIX / Envoy / Istio downstreams branch
		// on the WWW-Authenticate header to drive API-client step-up
		// without the calling proxy translating 401 → redirect.
		headers = append(headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: "WWW-Authenticate", Value: wwwAuthenticate},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
				Headers: headers,
			},
		},
	}
}
