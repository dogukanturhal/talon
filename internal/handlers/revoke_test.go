// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/talon/internal/audit"
)

// Most of the validation surface of POST /admin/revoke runs BEFORE any
// Redis or session.Store call, so it can be exercised with a nil
// Store/Redis. Happy-path coverage that requires Redis ride a follow-up
// MR alongside the miniredis-based test harness (mirrors the deferred
// integration coverage noted in backchannel_logout_test.go).

const (
	testCaller = "wazuh-ar-reconciler.monitoring.serviceaccount.identity.linkerd.cluster.local"
)

func newTestRevokeWebhook() *RevokeWebhook {
	return &RevokeWebhook{
		Audit:             audit.New(slog.Default(), "test"),
		AllowedIdentities: []string{testCaller, "falcon-id.falcon-id.serviceaccount.identity.linkerd.cluster.local"},
		RateLimitPerSec:   100,
	}
}

func doRequest(h *RevokeWebhook, method, path string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRevoke_EndpointDisabledWhenAllowListEmpty(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()
	h.AllowedIdentities = nil

	rec := doRequest(h, http.MethodPost, "/admin/revoke", map[string]string{
		"l5d-client-id": testCaller,
	}, []byte(`{"sub":"u-1"}`))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "endpoint_disabled" {
		t.Fatalf("X-Talon-Reason=%q want endpoint_disabled", got)
	}
}

func TestRevoke_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()

	rec := doRequest(h, http.MethodGet, "/admin/revoke", map[string]string{
		"l5d-client-id": testCaller,
	}, nil)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "POST" {
		t.Fatalf("Allow=%q want POST", got)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "method_not_allowed" {
		t.Fatalf("X-Talon-Reason=%q want method_not_allowed", got)
	}
}

func TestRevoke_OffMesh(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()

	rec := doRequest(h, http.MethodPost, "/admin/revoke", nil, []byte(`{"sub":"u-1"}`))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "off_mesh" {
		t.Fatalf("X-Talon-Reason=%q want off_mesh", got)
	}
}

func TestRevoke_ForbiddenCaller(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()

	rec := doRequest(h, http.MethodPost, "/admin/revoke", map[string]string{
		"l5d-client-id": "evil.example.com",
	}, []byte(`{"sub":"u-1"}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "forbidden_caller" {
		t.Fatalf("X-Talon-Reason=%q want forbidden_caller", got)
	}
}

func TestRevoke_InvalidJSON(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()

	rec := doRequest(h, http.MethodPost, "/admin/revoke", map[string]string{
		"l5d-client-id": testCaller,
	}, []byte(`{not json`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "invalid_body" {
		t.Fatalf("X-Talon-Reason=%q want invalid_body", got)
	}
}

func TestRevoke_MissingSub(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()

	rec := doRequest(h, http.MethodPost, "/admin/revoke", map[string]string{
		"l5d-client-id": testCaller,
	}, []byte(`{"reason":"x"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "missing_sub" {
		t.Fatalf("X-Talon-Reason=%q want missing_sub", got)
	}
}

func TestRevoke_RateLimit(t *testing.T) {
	t.Parallel()
	h := newTestRevokeWebhook()
	// Tight bucket: 1/sec, burst 2 — third immediate hit fails.
	h.RateLimitPerSec = 1
	// Manually drain the bucket so the very first request hits the
	// rate-limit branch deterministically (no scheduler timing).
	h.mu.Lock()
	h.bucket = 0
	h.last = time.Now()
	h.mu.Unlock()

	rec := doRequest(h, http.MethodPost, "/admin/revoke", map[string]string{
		"l5d-client-id": testCaller,
	}, []byte(`{"sub":"u-1"}`))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After=%q want 1", got)
	}
	if got := rec.Header().Get("X-Talon-Reason"); got != "rate_limited" {
		t.Fatalf("X-Talon-Reason=%q want rate_limited", got)
	}
}

func TestRevoke_AllowRate_TokenBucketRefill(t *testing.T) {
	t.Parallel()
	h := &RevokeWebhook{RateLimitPerSec: 10}
	// Use the public allowRate via reflection-free path: drain then
	// inject elapsed time.
	h.mu.Lock()
	h.bucket = 0
	h.last = time.Now().Add(-time.Second)
	h.mu.Unlock()

	if !h.allowRate() {
		t.Fatalf("after 1s elapsed at rate=10/s, allowRate must succeed")
	}
}

func TestRevoke_AllowRate_DisabledByZero(t *testing.T) {
	t.Parallel()
	h := &RevokeWebhook{RateLimitPerSec: 0}
	for i := 0; i < 1000; i++ {
		if !h.allowRate() {
			t.Fatalf("allowRate must always return true when RateLimitPerSec=0")
		}
	}
}

func TestRevoke_BodySchema_DecisionIDAndSourceAreOptionalAndPreserved(t *testing.T) {
	t.Parallel()
	// Asserts the new SIEM-unification fields parse without rejection. End-to-end
	// audit propagation rides the deferred Redis-backed integration MR.
	body, err := json.Marshal(revokeReq{
		Sub:        "01234567-89ab-cdef-0123-456789abcdef",
		Reason:     "siem_ar:rule_id_31200",
		DecisionID: "01HZ9D6VPK7XBQK3WZ7WQXDGAF",
		Source:     "wazuh-ar",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"decision_id":`) {
		t.Fatalf("marshalled body missing decision_id key: %s", body)
	}
	if !strings.Contains(string(body), `"source":`) {
		t.Fatalf("marshalled body missing source key: %s", body)
	}

	// Round-trip via the same decoder the handler uses — JSON tags
	// must stay aligned.
	var got revokeReq
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.DecisionID != "01HZ9D6VPK7XBQK3WZ7WQXDGAF" {
		t.Fatalf("decision_id=%q want 01HZ9D6VPK7XBQK3WZ7WQXDGAF", got.DecisionID)
	}
	if got.Source != "wazuh-ar" {
		t.Fatalf("source=%q want wazuh-ar", got.Source)
	}
}

func TestContainsString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hay  []string
		need string
		want bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "z", false},
		{nil, "b", false},
		{[]string{}, "b", false},
	}
	for _, c := range cases {
		if got := containsString(c.hay, c.need); got != c.want {
			t.Fatalf("containsString(%v,%q)=%v want %v", c.hay, c.need, got, c.want)
		}
	}
}

func TestSafePrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"abcdefghij", "abcdefgh"},
		{"abc", "abc"},
		{"", ""},
		{"abcdefgh", "abcdefgh"},
	}
	for _, c := range cases {
		if got := safePrefix(c.in); got != c.want {
			t.Fatalf("safePrefix(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// Test that concurrent allowRate calls don't deadlock or panic.
func TestRevoke_AllowRate_Concurrent(t *testing.T) {
	t.Parallel()
	h := &RevokeWebhook{RateLimitPerSec: 1000}
	var wg sync.WaitGroup
	const callers = 50
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = h.allowRate()
			}
		}()
	}
	wg.Wait()
}
