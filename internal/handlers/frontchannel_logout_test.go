// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/hexxlock/talon/internal/audit"
	"github.com/hexxlock/talon/internal/session"
)

// These tests cover the spec-§3 / §5.4 request-validation invariants and
// the response-shape contract (PNG body + Cache-Control + CSP). The
// per-sid cascade itself rides on the same Redis ZRange shape as the
// BCL cascade (covered by integration tests in the BCL package); we
// deliberately don't spin up an in-process Redis here because the
// cascade exercises store.Read/Revoke which already have dedicated
// store-level coverage.

// newTestFCL returns a handler with non-nil Store/Redis stubs so the
// dependency-check passes; tests that don't exercise the cascade never
// touch the underlying clients. Use newTestFCLNoDeps to drive the
// dependency-check fail-closed path explicitly.
func newTestFCL(t *testing.T) *FrontchannelLogout {
	t.Helper()
	return &FrontchannelLogout{
		Store:         &session.Store{},
		Redis:         &redis.Client{},
		Audit:         audit.New(slog.Default(), "test"),
		IssuerURL:     "https://id.hexxlock.com",
		FrameAncestor: "https://id.hexxlock.com",
	}
}

func newTestFCLNoDeps(t *testing.T) *FrontchannelLogout {
	t.Helper()
	return &FrontchannelLogout{
		Audit:         audit.New(slog.Default(), "test"),
		IssuerURL:     "https://id.hexxlock.com",
		FrameAncestor: "https://id.hexxlock.com",
	}
}

func TestFrontchannelLogout_RejectsNonGET(t *testing.T) {
	h := newTestFCL(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/frontchannel-logout?iss=https://id.hexxlock.com&sid=11111111-1111-1111-1111-111111111111", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "method_not_allowed" {
		t.Fatalf("X-Talon-Reason=%q, want method_not_allowed", got)
	}
	if rec.Header().Get("Allow") != "GET" {
		t.Fatalf("Allow header missing")
	}
}

func TestFrontchannelLogout_MissingDependenciesReturns503(t *testing.T) {
	h := newTestFCLNoDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?iss=https://id.hexxlock.com&sid=11111111-1111-1111-1111-111111111111", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 — handler must fail closed when Store/Redis nil", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "handler_not_ready" {
		t.Fatalf("X-Talon-Reason=%q, want handler_not_ready", got)
	}
}

func TestFrontchannelLogout_MissingIssReturns400(t *testing.T) {
	h := newTestFCL(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?sid=11111111-1111-1111-1111-111111111111", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "missing_iss" {
		t.Fatalf("X-Talon-Reason=%q, want missing_iss", got)
	}
}

func TestFrontchannelLogout_IssMismatchReturns400(t *testing.T) {
	h := newTestFCL(t)
	cases := []struct{ name, iss string }{
		{"different host", "https://attacker.example.com"},
		{"different scheme", "http://id.hexxlock.com"},
		{"host suffix attack", "https://id.hexxlock.com.attacker.example"},
		{"path injection", "https://id.hexxlock.com/admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?iss="+tc.iss+"&sid=11111111-1111-1111-1111-111111111111", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("iss=%q: got %d, want 400", tc.iss, rec.Code)
			}
			if got := rec.Header().Get("X-Talon-Reason"); got != "iss_mismatch" {
				t.Fatalf("iss=%q: X-Talon-Reason=%q, want iss_mismatch", tc.iss, got)
			}
		})
	}
}

func TestFrontchannelLogout_MissingSIDReturns400(t *testing.T) {
	h := newTestFCL(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?iss=https://id.hexxlock.com", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "missing_sid" {
		t.Fatalf("X-Talon-Reason=%q, want missing_sid", got)
	}
}

func TestFrontchannelLogout_NonUUIDSidReturns400(t *testing.T) {
	h := newTestFCL(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout?iss=https://id.hexxlock.com&sid=not-a-uuid", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "malformed_sid" {
		t.Fatalf("X-Talon-Reason=%q, want malformed_sid", got)
	}
}

func TestFrontchannelLogout_ResponseHeaders_AlwaysSet(t *testing.T) {
	// Even on a 400/503 path the cache + CSP headers MUST be present
	// so a hostile cache can't store an "iss missing" response and
	// replay it on a subsequent valid request.
	h := newTestFCLNoDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	cache := rec.Header().Get("Cache-Control")
	for _, want := range []string{"no-store", "no-cache", "must-revalidate", "max-age=0"} {
		if !contains(cache, want) {
			t.Errorf("Cache-Control=%q missing %q", cache, want)
		}
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q, want no-cache", got)
	}
	if got := rec.Header().Get("Expires"); got != "0" {
		t.Errorf("Expires=%q, want 0", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors https://id.hexxlock.com" {
		t.Errorf("CSP=%q, want frame-ancestors https://id.hexxlock.com", got)
	}
}

func TestFrontchannelLogout_FrameAncestorEmpty_FallsBackToDefault(t *testing.T) {
	h := newTestFCLNoDeps(t)
	h.FrameAncestor = ""
	req := httptest.NewRequest(http.MethodGet, "/auth/frontchannel-logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'self' https:" {
		t.Errorf("CSP=%q, want frame-ancestors 'self' https:", got)
	}
}

func TestFrontchannelLogout_PNGPayloadIsValid(t *testing.T) {
	// Sanity-check the embedded base64 payload decodes to a real PNG
	// (8-byte signature) so a copy-paste mistake doesn't ship a broken
	// iframe response that crashes browser image decoders.
	pixel, err := base64.StdEncoding.DecodeString(fclPixelPNG)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pixel) < 8 {
		t.Fatalf("payload too short: %d bytes", len(pixel))
	}
	wantSig := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	for i := range wantSig {
		if pixel[i] != wantSig[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x — PNG signature corrupt", i, pixel[i], wantSig[i])
		}
	}
}

func TestIssuerMatches(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
		ok   bool
	}{
		{"exact match", "https://id.hexxlock.com", "https://id.hexxlock.com", true},
		{"got with trailing slash", "https://id.hexxlock.com/", "https://id.hexxlock.com", true},
		{"want with trailing slash", "https://id.hexxlock.com", "https://id.hexxlock.com/", true},
		{"both with trailing slash", "https://id.hexxlock.com/", "https://id.hexxlock.com/", true},
		{"different scheme rejected", "http://id.hexxlock.com", "https://id.hexxlock.com", false},
		{"different host rejected", "https://other.example.com", "https://id.hexxlock.com", false},
		{"host suffix attack rejected", "https://id.hexxlock.com.attacker.example", "https://id.hexxlock.com", false},
		{"path mismatch rejected", "https://id.hexxlock.com/admin", "https://id.hexxlock.com", false},
		{"empty want rejects everything", "https://id.hexxlock.com", "", false},
		{"unparseable got rejected", "::not-a-url", "https://id.hexxlock.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := issuerMatches(tc.got, tc.want); got != tc.ok {
				t.Fatalf("issuerMatches(%q, %q) = %v, want %v", tc.got, tc.want, got, tc.ok)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// readAll is a small wrapper retained for future cascade-test additions
// (when miniredis lands in go.mod via Phase 1.1, the body assertions
// below will need to read the response body to verify the PNG bytes
// arrived intact).
var _ = io.ReadAll
