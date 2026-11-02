// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeaders_Defaults(t *testing.T) {
	h := Headers(Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	want := map[string]string{
		"Strict-Transport-Security":  "max-age=31536000; includeSubDomains; preload",
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin-allow-popups",
		"Permissions-Policy":         "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s: got %q, want %q", k, got, v)
		}
	}
}

func TestHeaders_SkipCOOPHosts(t *testing.T) {
	h := Headers(Options{
		SkipCOOPHosts: []string{"vault.internal.example.com", "  Other.Host  "},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	cases := []struct {
		name string
		host string
		want string // expected COOP header value
	}{
		{"listed host omits COOP", "vault.internal.example.com", ""},
		{"listed host with port omits COOP", "vault.internal.example.com:443", ""},
		{"case-insensitive match", "VAULT.INTERNAL.EXAMPLE.COM", ""},
		{"second listed host (whitespace + case normalized)", "other.host", ""},
		{"unlisted host still gets COOP", "argocd.internal.example.com", "same-origin-allow-popups"},
		{"unlisted host with port", "argocd.internal.example.com:8443", "same-origin-allow-popups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.Host = tc.host
			h.ServeHTTP(rec, req)
			if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != tc.want {
				t.Errorf("host %q: COOP got %q, want %q", tc.host, got, tc.want)
			}
			// Sanity: HSTS + frame-options always present regardless of host
			if rec.Header().Get("Strict-Transport-Security") == "" {
				t.Errorf("host %q: HSTS should still be present", tc.host)
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf("host %q: X-Frame-Options should still be DENY", tc.host)
			}
		})
	}
}

func TestHeaders_DisableHSTS(t *testing.T) {
	h := Headers(Options{DisableHSTS: true}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS should be absent, got %q", v)
	}
}

func TestHeaders_HSTSMaxAgeOverride(t *testing.T) {
	h := Headers(Options{HSTSMaxAge: 600}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	got := rec.Header().Get("Strict-Transport-Security")
	if !strings.HasPrefix(got, "max-age=600;") {
		t.Errorf("expected max-age=600 prefix, got %q", got)
	}
}

func TestHeaders_HSTSNoPreload(t *testing.T) {
	h := Headers(Options{HSTSNoPreload: true}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	got := rec.Header().Get("Strict-Transport-Security")
	if strings.Contains(got, "preload") {
		t.Errorf("preload should be absent, got %q", got)
	}
	if !strings.Contains(got, "includeSubDomains") {
		t.Errorf("includeSubDomains should remain, got %q", got)
	}
}

func TestHeaders_HSTSNoSubdomains_ImpliesNoPreload(t *testing.T) {
	// hstspreload.org requires includeSubDomains; preload directive
	// without includeSubDomains is invalid → middleware drops both.
	h := Headers(Options{HSTSNoSubdomains: true}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	got := rec.Header().Get("Strict-Transport-Security")
	if strings.Contains(got, "includeSubDomains") {
		t.Errorf("includeSubDomains should be absent, got %q", got)
	}
	if strings.Contains(got, "preload") {
		t.Errorf("preload should be absent (implied by NoSubdomains), got %q", got)
	}
}

func TestHeaders_OmitFrameOptions(t *testing.T) {
	h := Headers(Options{FrameOptions: "-"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("X-Frame-Options"); v != "" {
		t.Errorf("X-Frame-Options should be absent, got %q", v)
	}
}

func TestHeaders_OverrideFrameOptions(t *testing.T) {
	h := Headers(Options{FrameOptions: "SAMEORIGIN"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("X-Frame-Options"); v != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options: got %q, want SAMEORIGIN", v)
	}
}

func TestHeaders_DownstreamCanOverrideCSP(t *testing.T) {
	// FCL handler scenario: middleware sets defaults, downstream sets
	// CSP frame-ancestors. Verify Set semantics let the inner handler win.
	h := Headers(Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors https://id.example.com")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rec.Header().Get("Content-Security-Policy"); v != "frame-ancestors https://id.example.com" {
		t.Errorf("CSP override lost: got %q", v)
	}
	// Frame-Options still applied
	if v := rec.Header().Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options should still be DENY, got %q", v)
	}
}

func TestHeaders_DoesNotConsumeBody(t *testing.T) {
	h := Headers(Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "hello" {
		t.Errorf("body mutated: got %q", rec.Body.String())
	}
}

func TestItoa_Boundary(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{31536000, "31536000"},
		{-42, "-42"},
	}
	for _, c := range cases {
		if got := itoa(c.n); got != c.want {
			t.Errorf("itoa(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
