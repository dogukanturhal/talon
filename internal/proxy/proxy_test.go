// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/identityjwt"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/observability"
	"github.com/dogukanturhal/talon/internal/session"
)

// TestServeAuthenticated_InjectsXTalonHeadersToUpstream is the regression
// test for the 2026-05-12 silent-header-strip bug.
//
// Pre-fix behaviour: ServeAuthenticated injected X-Talon-* on the inbound
// request, then the proxy's Rewrite callback ran stripIncomingTalonHeaders
// on pr.Out — deleting the very headers ServeAuthenticated had just
// stamped. Upstream consumers (notably @hexxlock/falcon-id-client/nextjs
// which short-circuits on X-Talon-User to skip the redirect-to-/login
// dance) saw zero X-Talon-* headers and bounced authenticated users to
// accounts.example.com. Talon's audit log still read decision=allow
// because it reads from the session blob, not the outbound headers —
// masking the breakage.
//
// Post-fix: strip runs BEFORE injection in ServeAuthenticated; Rewrite
// no longer touches X-Talon-*. Upstream sees the trusted identity
// headers.
//
// This test captures the headers the proxy actually delivers to the
// upstream socket and asserts each X-Talon-* value, plus asserts that
// spoofable client-supplied X-Talon-* / X-Auth-Request-* are stripped
// regardless of how the client tried to inject them.
func TestServeAuthenticated_InjectsXTalonHeadersToUpstream(t *testing.T) {
	var (
		mu              sync.Mutex
		capturedHeaders http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHeaders = r.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	handler := NewHandler("test-route", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)

	blob := &session.Blob{
		Sub:        "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:      "dogukanturhal@example.com",
		Groups:     []string{"platform_admin", "iam_admin"},
		TenantID:   "00000000-0000-0000-0000-000000000002",
		SSOChainID: "test-chain-id",
	}

	// Inbound request carries spoofable headers the client should not be
	// able to influence — fix asserts these get stripped before the
	// authoritative values are injected.
	req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
	req.Host = "falcon.internal.example.com"
	req.Header.Set("X-Talon-User", "attacker@evil.com")
	req.Header.Set("X-Talon-Subject", "spoofed-subject")
	req.Header.Set("X-Auth-Request-User", "spoofed-oauth2proxy-user")
	req.Header.Set("X-Forwarded-User", "spoofed-forwarded-user")
	req.Header.Set("Cookie", "talon_session=opaque")

	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200; body=%q", rr.Code, rr.Body.String())
	}

	mu.Lock()
	got := capturedHeaders
	mu.Unlock()
	if got == nil {
		t.Fatal("upstream never captured headers — proxy did not forward")
	}

	// Authoritative X-Talon-* values reach upstream.
	wantTalon := map[string]string{
		"X-Talon-User":         blob.Email,
		"X-Talon-Email":        blob.Email,
		"X-Talon-Subject":      blob.Sub,
		"X-Talon-Groups":       strings.Join(blob.Groups, ","),
		"X-Talon-Tenant":       blob.TenantID,
		"X-Talon-Sso-Chain-Id": blob.SSOChainID,
	}
	for k, want := range wantTalon {
		if got.Get(k) != want {
			t.Errorf("upstream header %q = %q, want %q (regression of the 2026-05-12 silent-header-strip bug)", k, got.Get(k), want)
		}
	}

	// Spoofable client-supplied identity headers MUST NOT reach upstream
	// (oauth2-proxy / X-Forwarded family).
	for _, k := range []string{"X-Auth-Request-User", "X-Forwarded-User"} {
		if v := got.Get(k); v != "" {
			t.Errorf("spoofable header %q reached upstream with value %q — security regression", k, v)
		}
	}
}

// TestStripSpoofableIdentityHeaders_RemovesXTalonPrefix asserts the strip
// helper actually deletes every X-Talon-* header regardless of casing,
// since strings.ToLower is the canonical comparison.
func TestStripSpoofableIdentityHeaders_RemovesXTalonPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Talon-User", "v1")
	req.Header.Set("x-talon-email", "v2")
	req.Header.Set("X-TALON-SUBJECT", "v3")
	req.Header.Set("X-Auth-Request-User", "v4")
	req.Header.Set("X-Talon-Identity-Token", "spoofed-jwt-from-client")
	req.Header.Set("X-Forwarded-Host", "preserved.example.com") // must NOT be stripped

	stripSpoofableIdentityHeaders(req)

	for _, k := range []string{"X-Talon-User", "x-talon-email", "X-TALON-SUBJECT", "X-Auth-Request-User", "X-Talon-Identity-Token"} {
		if v := req.Header.Get(k); v != "" {
			t.Errorf("header %q still set after strip: %q", k, v)
		}
	}
	if got := req.Header.Get("X-Forwarded-Host"); got != "preserved.example.com" {
		t.Errorf("X-Forwarded-Host was wrongly stripped: %q", got)
	}
}

// TestServeAuthenticated_InjectsSignedIAPToken — Phase A tier-1 signed
// IAP. Asserts that when a Signer is wired, ServeAuthenticated stamps
// a verifiable X-Talon-Identity-Token JWT alongside the unsigned
// X-Talon-* headers, scoped to the correct audience (the public route
// host), and that the token verifies against the signer's public key.
// Companion to TestServeAuthenticated_InjectsXTalonHeadersToUpstream.
func TestServeAuthenticated_InjectsSignedIAPToken(t *testing.T) {
	// Generate a test RSA key + signer.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test rsa key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.internal.example.com")
	if err != nil {
		t.Fatalf("NewSignerFromPEM: %v", err)
	}

	var (
		mu              sync.Mutex
		capturedHeaders http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHeaders = r.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	handler := NewHandler("falcon.internal.example.com", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)
	handler.SetSigner(signer)

	blob := &session.Blob{
		Sub:        "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:      "dogukanturhal@example.com",
		Groups:     []string{"platform_admin", "iam_admin"},
		TenantID:   "00000000-0000-0000-0000-000000000002",
		SSOChainID: "chain-id-1",
		SID:        "sid-1",
	}

	req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
	req.Host = "falcon.internal.example.com"
	// Spoof attempt — must be stripped before authoritative injection.
	req.Header.Set("X-Talon-Identity-Token", "attacker-supplied-token")

	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}

	mu.Lock()
	got := capturedHeaders
	mu.Unlock()
	if got == nil {
		t.Fatal("upstream never captured headers")
	}

	token := got.Get("X-Talon-Identity-Token")
	if token == "" {
		t.Fatal("upstream did not receive X-Talon-Identity-Token — signer integration broken")
	}
	if token == "attacker-supplied-token" {
		t.Fatal("upstream received the SPOOFED client-supplied token — security regression in stripSpoofableIdentityHeaders")
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("upstream JWT parse: %v", err)
	}
	pub := signer.PublicKey()
	var claims identityjwt.IdentityClaims
	if err := parsed.Claims(&pub, &claims); err != nil {
		t.Fatalf("upstream JWT signature verify: %v", err)
	}
	if claims.Issuer != "https://auth.internal.example.com" {
		t.Errorf("iss = %q, want https://auth.internal.example.com", claims.Issuer)
	}
	if claims.Subject != blob.Sub {
		t.Errorf("sub = %q, want %q", claims.Subject, blob.Sub)
	}
	if claims.Audience != "falcon.internal.example.com" {
		t.Errorf("aud = %q, want falcon.internal.example.com (per-route binding)", claims.Audience)
	}
	if claims.Email != blob.Email {
		t.Errorf("email = %q, want %q", claims.Email, blob.Email)
	}
}

// TestServeAuthenticated_InjectsAuthorizationBearer_OptIn — Phase C.
// When SetInjectAuthorizationBearer(true) is called AND a signer is
// wired, the same RS256 JWT lands in BOTH X-Talon-Identity-Token AND
// the canonical Authorization: Bearer header. A client-supplied
// Authorization header is stripped before authoritative injection so
// upstream cannot be tricked into accepting a forged Bearer token.
func TestServeAuthenticated_InjectsAuthorizationBearer_OptIn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.internal.example.com")
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu              sync.Mutex
		capturedHeaders http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHeaders = r.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("grafana.internal.example.com", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)
	handler.SetSigner(signer)
	handler.SetInjectAuthorizationBearer(true)

	blob := &session.Blob{
		Sub:    "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:  "dogukanturhal@example.com",
		Groups: []string{"platform_admin"},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal.example.com"
	// Client tries to spoof Authorization — must be stripped before
	// authoritative injection.
	req.Header.Set("Authorization", "Bearer attacker-supplied-token")

	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	mu.Lock()
	got := capturedHeaders
	mu.Unlock()

	dedicated := got.Get(identityjwt.HeaderName)
	if dedicated == "" {
		t.Fatal("upstream missing dedicated X-Talon-Identity-Token")
	}
	authz := got.Get("Authorization")
	if authz == "" {
		t.Fatal("upstream missing Authorization (Phase C inject failed)")
	}
	if authz == "Bearer attacker-supplied-token" {
		t.Fatal("upstream received SPOOFED Authorization — strip-then-inject ordering broken")
	}
	if !strings.HasPrefix(authz, "Bearer ") {
		t.Errorf("Authorization should start with Bearer, got %q", authz)
	}
	if dedicated != strings.TrimPrefix(authz, "Bearer ") {
		t.Error("X-Talon-Identity-Token and Authorization Bearer payload must be the same JWT")
	}

	// JWT validates against the signer's public key + has correct aud.
	pub := signer.PublicKey()
	parsed, err := jwt.ParseSigned(dedicated, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims identityjwt.IdentityClaims
	if err := parsed.Claims(&pub, &claims); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Audience != "grafana.internal.example.com" {
		t.Errorf("aud = %q, want grafana.internal.example.com", claims.Audience)
	}
}

// TestServeAuthenticated_BearerNotInjectedByDefault — Phase C is opt-in.
// Routes that don't set InjectAuthorizationBearer keep Authorization
// untouched (upstreams that use their own auth flow stay unbroken).
func TestServeAuthenticated_BearerNotInjectedByDefault(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, _ := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.ops")

	var (
		mu              sync.Mutex
		capturedHeaders http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHeaders = r.Header.Clone()
		mu.Unlock()
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("falcon.internal.example.com", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)
	handler.SetSigner(signer)
	// NOT calling SetInjectAuthorizationBearer — default is false.

	blob := &session.Blob{Sub: "s", Email: "e"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "falcon.internal.example.com"
	// Existing Authorization (e.g. an upstream's own service token)
	// must be PRESERVED when this route doesn't opt into Bearer mode.
	req.Header.Set("Authorization", "Bearer upstream-private-token")
	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	mu.Lock()
	got := capturedHeaders
	mu.Unlock()
	if got.Get(identityjwt.HeaderName) == "" {
		t.Error("dedicated X-Talon-Identity-Token still expected")
	}
	if got := got.Get("Authorization"); got != "Bearer upstream-private-token" {
		t.Errorf("Authorization should pass through unchanged when Bearer mode is off, got %q", got)
	}
}

// TestServeAuthenticated_IncrementsIAPSignMetric — Item 3 (Prometheus
// metric wiring). Every successful IAP sign must increment
// talon_iap_token_sign_total{route,result="success",kid=…}.
func TestServeAuthenticated_IncrementsIAPSignMetric(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.ops")
	if err != nil {
		t.Fatalf("NewSignerFromPEM: %v", err)
	}
	reg := prometheus.NewRegistry()
	metrics := observability.New(reg)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("falcon.internal.example.com", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, metrics)
	handler.SetSigner(signer)

	blob := &session.Blob{Sub: "u1", Email: "u1@ex.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "falcon.internal.example.com"
	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	got := testutil.ToFloat64(metrics.IAPTokenSign.WithLabelValues("falcon.internal.example.com", "success", signer.Kid()))
	if got != 1 {
		t.Errorf("talon_iap_token_sign_total{result=success,kid=%s} = %v, want 1", signer.Kid(), got)
	}
}

// TestServeAuthenticated_EmitsAuditOnSignFailure — Item 2 (tier-1
// observability). When Sign() fails, the handler MUST log an
// iap.token.mint_failed audit record carrying iap_kid + iap_audience +
// sub + err so SOC can pin the failure to a specific key generation /
// route binding without having to grep the slog stream.
//
// The test forces a failure by constructing a Handler with route="" —
// signer.Sign rejects empty audiences per RFC 8725 §3.1, which is the
// only programmatic Sign-failure mode in production.
func TestServeAuthenticated_EmitsAuditOnSignFailure(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.internal.example.com")
	if err != nil {
		t.Fatalf("NewSignerFromPEM: %v", err)
	}

	// Capture slog output the audit emitter writes into. The Emitter
	// pulls its logger from request context via tlog.From, so we inject
	// our capture logger into the request below.
	var auditBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&auditBuf, nil))
	emitter := audit.New(logger, "test-version")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)

	// route="" — empty audience triggers signer.Sign error.
	handler := NewHandler("", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)
	handler.SetSigner(signer)
	handler.SetAudit(emitter)

	blob := &session.Blob{
		Sub: "u1", Email: "u1@ex.com",
		TenantID: "tenant-1", SID: "sid-1", SSOChainID: "chain-1",
	}
	req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
	req.Host = "falcon.internal.example.com"
	req = req.WithContext(tlog.Into(req.Context(), logger))
	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	// Request still succeeds — Phase A fallback to unsigned headers.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unsigned fallback)", rr.Code)
	}

	// Audit line must be present. (Note: audit's Emit derives its
	// logger from request context via tlog.From, then attaches
	// subsystem=audit; the captured logger above is what it uses.)
	out := auditBuf.String()
	if !strings.Contains(out, `"event":"iap.token.mint_failed"`) {
		t.Fatalf("audit stream missing iap.token.mint_failed event: %s", out)
	}
	if !strings.Contains(out, `"iap_kid":"`+signer.Kid()+`"`) {
		t.Errorf("audit missing iap_kid=%q in: %s", signer.Kid(), out)
	}
	if !strings.Contains(out, `"sub":"u1"`) {
		t.Errorf("audit missing sub: %s", out)
	}
	if !strings.Contains(out, `"err":"`) {
		t.Errorf("audit missing err field: %s", out)
	}
}

// TestServeAuthenticated_NoSignerKeepsUnsignedFallback — Phase A
// backwards-compat. When the signer is not wired (single-binary tests,
// pre-rollout config), the proxy still injects unsigned X-Talon-*
// headers but skips X-Talon-Identity-Token cleanly without panicking.
func TestServeAuthenticated_NoSignerKeepsUnsignedFallback(t *testing.T) {
	var (
		mu              sync.Mutex
		capturedHeaders http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHeaders = r.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("falcon.internal.example.com", Upstream{Service: upstreamURL.Host, Scheme: upstreamURL.Scheme}, nil)
	// NOTE: SetSigner deliberately not called.

	blob := &session.Blob{Sub: "u1", Email: "u1@ex.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "falcon.internal.example.com"
	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	mu.Lock()
	got := capturedHeaders
	mu.Unlock()
	if got.Get("X-Talon-Email") != "u1@ex.com" {
		t.Error("unsigned X-Talon-Email missing — fallback path broken")
	}
	if got.Get("X-Talon-Identity-Token") != "" {
		t.Error("X-Talon-Identity-Token should be absent when signer is unwired")
	}
	if !strings.Contains(strings.ToLower(rr.Body.String()), "ok") && rr.Code != http.StatusOK {
		t.Errorf("upstream not reached; status=%d body=%q", rr.Code, rr.Body.String())
	}
}

// TestNewHandler_HTTPSUpstreamSkipsCertVerify — HTTPS upstreams use a
// Transport that skips x509 verification because Linkerd mTLS is the
// in-cluster transport-security boundary (ADR 0007). Without this,
// SafeLine mgt's nginx-on-1443 self-signed cert would fail TLS handshake
// and Talon would return 502. Documented trust decision.
func TestNewHandler_HTTPSUpstreamSkipsCertVerify(t *testing.T) {
	// httptest.NewTLSServer presents a self-signed cert generated at
	// test-time — exactly the SafeLine-mgt failure mode.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("safeline.internal.example.com",
		Upstream{Service: upstreamURL.Host, Scheme: "https"}, nil)

	blob := &session.Blob{Sub: "u1", Email: "u1@ex.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "safeline.internal.example.com"
	rr := httptest.NewRecorder()
	handler.ServeAuthenticated(rr, req, blob)

	if rr.Code != http.StatusOK {
		t.Fatalf("HTTPS upstream returned %d (body=%q) — cert verification likely NOT skipped", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("response body mismatch: %q", rr.Body.String())
	}
}

// TestNewHandler_HTTPUpstreamDefaultTransport — HTTP upstreams use the
// default Transport (no skip-verify). Verifies the scheme switch in
// NewHandler isn't a one-way toggle that affects http upstreams too.
func TestNewHandler_HTTPUpstreamDefaultTransport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("grafana.internal.example.com",
		Upstream{Service: upstreamURL.Host}, nil) // Scheme empty → defaults to http

	if handler.rp.Transport != nil {
		t.Errorf("HTTP upstream should use default Transport (nil), got %T", handler.rp.Transport)
	}
}

// TestNewHandler_PreservesInboundHostOnOutbound — regression guard
// for the Harbor activation Gate D incident 2026-05-30. Without
// Host preservation, httputil.ReverseProxy's SetURL rewrites the
// outbound Host header to the upstream Service name, breaking any
// upstream that uses the Host header for self-referential URL
// generation (Harbor v2 Bearer-realm, OAuth2 redirect_uris, etc.).
// This test pins the canonical IAP behaviour (preserve inbound Host)
// by capturing the Host the upstream actually receives.
func TestNewHandler_PreservesInboundHostOnOutbound(t *testing.T) {
	var seenHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	handler := NewHandler("registry.example.com",
		Upstream{Service: upstreamURL.Host}, nil)

	// Simulate Traefik routing registry.example.com to Talon: the
	// inbound HTTP request carries Host=registry.example.com even
	// though the connection is opened against upstreamURL.Host
	// (Talon's listener) via --resolve.
	req := httptest.NewRequest(http.MethodGet, "http://registry.example.com/v2/", nil)
	req.Host = "registry.example.com"
	rec := httptest.NewRecorder()
	handler.rp.ServeHTTP(rec, req)

	if seenHost != "registry.example.com" {
		t.Errorf("upstream saw Host=%q, want registry.example.com (Host header was rewritten to upstream Service name — regression of the 2026-05-30 Harbor activation fix)", seenHost)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status got %d want 200", rec.Code)
	}
}
