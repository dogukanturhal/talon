// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/config"
	"github.com/dogukanturhal/talon/internal/observability"
	"github.com/dogukanturhal/talon/internal/proxy"
)

// newPublicRouteTestRouter builds a minimally-wired Router whose only job
// is to exercise the ServeHTTP enrollment-bootstrap carve-out. It wires a
// fresh metrics registry + a discard-logger audit emitter (both consulted
// by the carve-out path and the top-level RequestTotal defer) and registers
// one upstream for jess.test that proxies POST /device-cert/attest to a
// recording backend WITHOUT a Talon session.
//
// The auth host is set to auth.test so it never collides with jess.test.
func newPublicRouteTestRouter(t *testing.T, backend http.Handler) (*Router, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)

	// httptest.Server.URL is http://127.0.0.1:PORT — strip the scheme to
	// get the host:port the proxy.Upstream.Service expects.
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	metrics := observability.New(prometheus.NewRegistry())
	auditEmitter := audit.New(slog.New(slog.NewTextHandler(io.Discard, nil)), "test")

	rt := &Router{
		cfg:       &config.Config{ExternalURL: &url.URL{Scheme: "https", Host: "auth.test"}},
		metrics:   metrics,
		audit:     auditEmitter,
		upstreams: map[string]upstreamEntry{},
	}
	rt.RegisterUpstream("jess.test", RegisterUpstreamParams{
		Handler:     proxy.NewHandler("jess.test", proxy.Upstream{Service: u.Host}, metrics),
		Permission:  "viewer",
		PublicPaths: []config.PublicRoute{{Method: "POST", Path: "/device-cert/attest"}},
	})
	return rt, srv
}

// TestServeHTTP_PublicRoute_BypassesSessionGate is the core security test:
// the ZTNA device-enrollment endpoint must be reachable by a not-yet-
// enrolled device (no Talon session cookie) — the carve-out forwards it
// to the self-authenticating upstream — while every other method/path on
// the same host stays gated.
func TestServeHTTP_PublicRoute_BypassesSessionGate(t *testing.T) {
	var upstreamHits int
	var sawTalonUser, sawAuthz string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		sawTalonUser = r.Header.Get("X-Talon-User")
		sawAuthz = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "attested")
	})
	rt, _ := newPublicRouteTestRouter(t, backend)

	t.Run("allow-listed POST reaches upstream with no cookie", func(t *testing.T) {
		upstreamHits = 0
		req := httptest.NewRequest(http.MethodPost, "https://jess.test/device-cert/attest", nil)
		req.Host = "jess.test"
		// A client tries to forge identity + carries a self-auth bearer.
		req.Header.Set("X-Talon-User", "attacker@evil.test")
		req.Header.Set("Authorization", "Bearer witness-jws")
		rec := httptest.NewRecorder()

		rt.ServeHTTP(rec, req)

		if upstreamHits != 1 {
			t.Fatalf("upstream hit %d times, want 1 (carve-out should forward)", upstreamHits)
		}
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("status = 401, want it NOT gated (got through to upstream → %d)", rec.Code)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 from recording upstream", rec.Code)
		}
		// Spoofable identity header must be stripped before forwarding.
		if sawTalonUser != "" {
			t.Errorf("upstream saw forged X-Talon-User=%q, want it stripped", sawTalonUser)
		}
		// The client's Authorization (witness JWS) MUST survive so the
		// self-authenticating upstream can verify it.
		if sawAuthz != "Bearer witness-jws" {
			t.Errorf("upstream saw Authorization=%q, want it preserved intact", sawAuthz)
		}
	})

	t.Run("non-allow-listed path stays gated (401)", func(t *testing.T) {
		upstreamHits = 0
		req := httptest.NewRequest(http.MethodPost, "https://jess.test/other", nil)
		req.Host = "jess.test"
		// XHR markers so the gated path returns a deterministic 401 instead
		// of a browser 302 to /auth/start.
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Accept", "*/*")
		rec := httptest.NewRecorder()

		rt.ServeHTTP(rec, req)

		if upstreamHits != 0 {
			t.Fatalf("upstream hit %d times for /other, want 0 (must stay gated)", upstreamHits)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d for gated /other, want 401", rec.Code)
		}
	})

	t.Run("wrong method on allow-listed path stays gated (method-scoped)", func(t *testing.T) {
		upstreamHits = 0
		// Carve-out is POST-only; a GET on the same path must NOT bypass.
		req := httptest.NewRequest(http.MethodGet, "https://jess.test/device-cert/attest", nil)
		req.Host = "jess.test"
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Accept", "*/*")
		rec := httptest.NewRecorder()

		rt.ServeHTTP(rec, req)

		if upstreamHits != 0 {
			t.Fatalf("upstream hit %d times for GET, want 0 (carve-out is POST-only)", upstreamHits)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d for GET on allow-listed path, want 401", rec.Code)
		}
	})
}

// TestIsPublicRoute_MatchMatrix pins the method/path matching semantics of
// the carve-out, including the hardened-NormalizePath properties that stop
// a gated path being smuggled through via a trailing slash, traversal, or
// an encoded slash. Fail-closed: anything that isn't an EXACT normalized
// match must NOT be public.
func TestIsPublicRoute_MatchMatrix(t *testing.T) {
	up := upstreamEntry{
		publicPaths: []config.PublicRoute{{Method: "POST", Path: "/device-cert/attest"}},
	}
	r := &Router{}

	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"exact match", http.MethodPost, "/device-cert/attest", true},
		{"method case-insensitive", "post", "/device-cert/attest", true},
		{"wrong method", http.MethodGet, "/device-cert/attest", false},
		{"trailing slash is a different path", http.MethodPost, "/device-cert/attest/", false},
		{"unrelated path", http.MethodPost, "/other", false},
		{"prefix is not exact", http.MethodPost, "/device-cert/attest/extra", false},
		// NormalizePath resolves "." segments → still the gated path, but it
		// is the SAME canonical path so it correctly matches. (Defensive:
		// the carve-out allow-listed it, so resolving to it is fine.)
		{"dot-segment normalizes to the allow-listed path", http.MethodPost, "/device-cert/./attest", true},
		// Encoded slash makes NormalizePath return an error → fail-closed,
		// never matches, so a smuggled gated path can't ride the carve-out.
		{"encoded-slash traversal fails closed", http.MethodPost, "/device-cert/%2e%2e/attest", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://jess.test"+tc.path, nil)
			got := r.isPublicRoute(up, req)
			if got != tc.want {
				t.Errorf("isPublicRoute(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}

	t.Run("empty publicPaths never matches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "https://jess.test/device-cert/attest", nil)
		if (&Router{}).isPublicRoute(upstreamEntry{}, req) {
			t.Error("isPublicRoute with no publicPaths matched, want false")
		}
	})
}

// TestServeUnauthenticated_StripsIdentity_PreservesAuthz verifies the
// proxy-layer guarantee independently of the router: a forged X-Talon-*
// header is stripped before forwarding, but the client's Authorization
// (the self-auth witness JWS) is left intact for the upstream to verify.
func TestServeUnauthenticated_StripsIdentity_PreservesAuthz(t *testing.T) {
	var sawTalonUser, sawTalonGroups, sawAuthz string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTalonUser = r.Header.Get("X-Talon-User")
		sawTalonGroups = r.Header.Get("X-Talon-Groups")
		sawAuthz = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(backend)
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	h := proxy.NewHandler("jess.test", proxy.Upstream{Service: u.Host}, nil)

	req := httptest.NewRequest(http.MethodPost, "https://jess.test/device-cert/attest", nil)
	req.Host = "jess.test"
	req.Header.Set("X-Talon-User", "attacker@evil.test")
	req.Header.Set("X-Talon-Groups", "platform_admin")
	req.Header.Set("Authorization", "Bearer witness-jws")
	rec := httptest.NewRecorder()

	h.ServeUnauthenticated(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 from upstream (request should have proxied)", rec.Code)
	}
	if sawTalonUser != "" {
		t.Errorf("upstream saw forged X-Talon-User=%q, want stripped", sawTalonUser)
	}
	if sawTalonGroups != "" {
		t.Errorf("upstream saw forged X-Talon-Groups=%q, want stripped", sawTalonGroups)
	}
	if sawAuthz != "Bearer witness-jws" {
		t.Errorf("upstream saw Authorization=%q, want preserved intact", sawAuthz)
	}
}
