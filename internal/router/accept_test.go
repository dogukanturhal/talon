// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsXHROrAssetRequest covers the Accept-header / Sec-Fetch-* logic
// that decides whether Talon's auth-redirect path returns a 302 (top-
// level navigation) or a 401 with WWW-Authenticate per RFC 9470 (fetch/
// XHR/asset). The wrong choice on an asset GET is exactly what bricked
// the Vault UI on 2026-05-08 — every /ui/assets/*.{js,css} got 302→302
// and the SPA never bootstrapped because the asset bytes were the HTML
// of the redirect page, not JS/CSS.
func TestIsXHROrAssetRequest(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "browser top-level navigation — Sec-Fetch-Mode=navigate",
			headers: map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Accept": "text/html,application/xhtml+xml"},
			want:    false,
		},
		{
			name:    "fetch() default — Sec-Fetch-Mode=cors",
			headers: map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept": "*/*"},
			want:    true,
		},
		{
			name:    "asset GET — Sec-Fetch-Dest=script",
			headers: map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script", "Accept": "*/*"},
			want:    true,
		},
		{
			name:    "stylesheet — Sec-Fetch-Dest=style",
			headers: map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "style", "Accept": "text/css,*/*;q=0.1"},
			want:    true,
		},
		{
			name:    "image — Sec-Fetch-Dest=image",
			headers: map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image", "Accept": "image/*,*/*;q=0.8"},
			want:    true,
		},
		{
			name:    "service worker fetch — Sec-Fetch-Mode=cors no Accept text/html",
			headers: map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept": "*/*"},
			want:    true,
		},
		{
			name:    "websocket upgrade — Sec-Fetch-Mode=websocket",
			headers: map[string]string{"Sec-Fetch-Mode": "websocket"},
			want:    true,
		},
		{
			name:    "legacy XHR (jQuery / axios) — X-Requested-With set, no Sec-Fetch-*",
			headers: map[string]string{"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
			want:    true,
		},
		{
			name:    "API request explicit JSON — no Sec-Fetch-*",
			headers: map[string]string{"Accept": "application/json"},
			want:    true,
		},
		{
			name:    "image request explicit — no Sec-Fetch-*",
			headers: map[string]string{"Accept": "image/png,image/jpeg"},
			want:    true,
		},
		{
			name:    "browser navigation no Sec-Fetch-* — Accept includes text/html",
			headers: map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9"},
			want:    false,
		},
		{
			name:    "no headers at all — conservative, treat as nav",
			headers: map[string]string{},
			want:    false,
		},
		{
			name:    "wildcard accept only — treat as XHR (fetch() default)",
			headers: map[string]string{"Accept": "*/*"},
			want:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ui/sw.js", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got := isXHROrAssetRequest(req)
			if got != tc.want {
				t.Errorf("isXHROrAssetRequest()=%v, want %v (headers: %+v)", got, tc.want, tc.headers)
			}
		})
	}
}

// TestStartAuthWithMFA_AcceptAware verifies the Accept-aware branch
// of the MFA-required redirect path. RFC 9470 challenge for XHR/asset,
// 302 HTML-scaffolded for browser nav.
func TestStartAuthWithMFA_AcceptAware(t *testing.T) {
	r := &Router{}
	// We can't easily test full Router state here (cfg/ExternalURL path
	// requires more wiring), so we target only the branching logic.
	// Build the asset-style request and confirm we hit the 401 path
	// before the 302 codepath would dereference cfg.ExternalURL.
	req := httptest.NewRequest(http.MethodGet, "/ui/sw.js", nil)
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Host = "internal.example.com"

	rec := httptest.NewRecorder()
	// startAuthWithMFA's XHR branch returns BEFORE touching r.cfg, so
	// a zero-value Router suffices. (If we ever rearrange the function,
	// this test will catch the regression with a nil-pointer panic
	// instead of a silent 302 with empty Location.)
	r.startAuthWithMFA(rec, req)

	if got := rec.Code; got != http.StatusUnauthorized {
		t.Errorf("XHR branch: status=%d, want %d", got, http.StatusUnauthorized)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if wa == "" {
		t.Errorf("XHR branch: WWW-Authenticate header missing")
	}
	wantSubstrings := []string{
		`error="insufficient_user_authentication"`,
		`acr_values="mfa"`,
		`max_age=0`,
	}
	for _, ws := range wantSubstrings {
		if !contains([]string{wa}, wa) || !containsString(wa, ws) {
			t.Errorf("XHR branch: WWW-Authenticate=%q missing substring %q", wa, ws)
		}
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "mfa_required" {
		t.Errorf("XHR branch: X-Talon-Reason=%q, want mfa_required", got)
	}
}

// containsString — local helper. router.contains is for []string;
// here we want substring within a single string.
func containsString(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
