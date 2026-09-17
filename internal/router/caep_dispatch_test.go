// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/dogukanturhal/talon/internal/config"
)

// TestCAEPDispatch_Disabled_Returns503 — when SetCAEPHandler hasn't
// been called, /caep/events on the auth host returns 503 (explicit
// disabled state) so SIEM rules can distinguish "intentionally
// disabled" from "route-typo / not yet rolled out" (which would 404).
func TestCAEPDispatch_Disabled_Returns503(t *testing.T) {
	authURL := &url.URL{Scheme: "https", Host: "auth.test"}
	rt := &Router{
		cfg: &config.Config{ExternalURL: authURL},
	}
	req := httptest.NewRequest(http.MethodPost, "https://auth.test/caep/events", nil)
	req.Host = "auth.test"
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("nil caepHandler should return 503, got %d", rec.Code)
	}
}

// TestCAEPDispatch_Enabled_DelegatesToHandler — once SetCAEPHandler is
// wired, /caep/events on the auth host delegates to the handler.
// This test uses a stub handler that responds 202 to confirm the
// dispatch reaches it.
func TestCAEPDispatch_Enabled_DelegatesToHandler(t *testing.T) {
	authURL := &url.URL{Scheme: "https", Host: "auth.test"}
	rt := &Router{
		cfg: &config.Config{ExternalURL: authURL},
	}
	called := false
	rt.SetCAEPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://auth.test/caep/events", nil)
	req.Host = "auth.test"
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)

	if !called {
		t.Errorf("SetCAEPHandler handler should have been invoked")
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202 from stub handler, got %d", rec.Code)
	}
}

// TestCAEPDispatch_NonAuthHost_PassesThrough — confirms /caep/events
// on a non-auth host does NOT trigger the CAEP receiver (which would
// 503 mismatched). The path falls through to the normal upstream
// resolution which will deny (no upstream registered) or proxy as
// appropriate. This pins the auth-host-scoping invariant.
func TestCAEPDispatch_NonAuthHost_PassesThrough(t *testing.T) {
	authURL := &url.URL{Scheme: "https", Host: "auth.test"}
	rt := &Router{
		cfg:       &config.Config{ExternalURL: authURL},
		upstreams: map[string]upstreamEntry{},
	}
	// Set a handler — even though it's set, the auth-host switch
	// should not fire on a non-auth host.
	caepCalled := false
	rt.SetCAEPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caepCalled = true
	}))

	req := httptest.NewRequest(http.MethodPost, "https://other.test/caep/events", nil)
	req.Host = "other.test"
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)

	if caepCalled {
		t.Errorf("CAEP handler must NOT fire on non-auth host (%s)", req.Host)
	}
	// Without an upstream registered for other.test, the router's
	// catchall will eventually deny — we don't care about the exact
	// status here, just that the CAEP handler wasn't called.
	_ = rec.Code
}
