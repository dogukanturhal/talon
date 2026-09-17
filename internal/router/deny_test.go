// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hexxlock/talon/internal/config"
)

func newDenyRouter() *Router {
	return &Router{cfg: &config.Config{AccessHelpURL: "https://access.hexxlock.com/enroll"}}
}

func TestServeAccessDenied_BrowserGetsBrandedPage(t *testing.T) {
	r := newDenyRouter()
	req := httptest.NewRequest(http.MethodGet, "https://internal.example.com/applications", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := httptest.NewRecorder()

	r.serveAccessDenied(rec, req, http.StatusForbidden, "rego_denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	if rec.Header().Get("X-Talon-Reason") != "rego_denied" {
		t.Errorf("missing/wrong X-Talon-Reason: %q", rec.Header().Get("X-Talon-Reason"))
	}
	body := rec.Body.String()
	for _, want := range []string{"HexxLock Access", "https://access.hexxlock.com/enroll", "rego_denied", "internal.example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("branded page missing %q", want)
		}
	}
}

func TestServeAccessDenied_APIGetsPlain(t *testing.T) {
	r := newDenyRouter()
	req := httptest.NewRequest(http.MethodGet, "https://internal.example.com/api/v1/applications", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Mode", "cors") // XHR
	rec := httptest.NewRecorder()

	r.serveAccessDenied(rec, req, http.StatusForbidden, "rego_denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Fatalf("API client got HTML (%q); want plain", ct)
	}
	if rec.Header().Get("X-Talon-Reason") != "rego_denied" {
		t.Errorf("missing X-Talon-Reason")
	}
	if !strings.Contains(rec.Body.String(), "forbidden: rego_denied") {
		t.Errorf("plain body = %q", rec.Body.String())
	}
}

func TestFriendlyDeny(t *testing.T) {
	for _, reason := range []string{"rego_denied", "clientless_critical_denied", "something_else"} {
		title, remedy := friendlyDeny(reason)
		if title == "" || remedy == "" {
			t.Errorf("friendlyDeny(%q) returned empty title/remedy", reason)
		}
	}
}
