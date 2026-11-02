// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/talon/internal/config"
	"github.com/dogukanturhal/talon/internal/policy"
)

func newDenyRouter() *Router {
	return &Router{cfg: &config.Config{AccessHelpURL: "https://access.example.com/enroll"}}
}

func TestServeAccessDenied_BrowserGetsBrandedPage(t *testing.T) {
	r := newDenyRouter()
	req := httptest.NewRequest(http.MethodGet, "https://argocd.internal.example.com/applications", nil)
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
	for _, want := range []string{"Access Agent", "https://access.example.com/enroll", "rego_denied", "argocd.internal.example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("branded page missing %q", want)
		}
	}
}

func TestServeAccessDenied_APIGetsPlain(t *testing.T) {
	r := newDenyRouter()
	req := httptest.NewRequest(http.MethodGet, "https://argocd.internal.example.com/api/v1/applications", nil)
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

func TestServeVerdictDenied_InternalErrorIs503(t *testing.T) {
	r := newDenyRouter()
	v := policy.Verdict{Decision: policy.Error, Reason: policy.ReasonInternal}

	req := httptest.NewRequest(http.MethodGet, "https://argocd.internal.example.com/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := httptest.NewRecorder()
	r.serveVerdictDenied(rec, req, v)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec.Body.String(), `http-equiv="refresh" content="2"`) {
		t.Errorf("missing meta refresh: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Access denied") {
		t.Error("must not render Access denied")
	}

	api := httptest.NewRequest(http.MethodGet, "https://argocd.internal.example.com/api", nil)
	api.Header.Set("Sec-Fetch-Mode", "cors")
	rec = httptest.NewRecorder()
	r.serveVerdictDenied(rec, api, v)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("api: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}

	rec = httptest.NewRecorder()
	r.serveVerdictDenied(rec, req, policy.Verdict{Decision: policy.Deny, Reason: policy.ReasonNoPermission})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny: %d, want 403", rec.Code)
	}
}
