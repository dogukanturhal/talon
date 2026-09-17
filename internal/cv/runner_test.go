// SPDX-License-Identifier: AGPL-3.0-or-later

package cv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRefreshAccessToken_Success — the IDP returns a fresh access token
// + a rotated refresh token; runner should propagate both.
func TestRefreshAccessToken_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected Content-Type: %s", got)
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "rt-old" {
			t.Errorf("expected refresh_token=rt-old, got %s", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-new","token_type":"Bearer","expires_in":300,"refresh_token":"rt-new"}`))
	}))
	defer srv.Close()

	r := &Runner{
		TokenURL:     srv.URL,
		ClientID:     "talon",
		ClientSecret: "shh",
		HTTPClient:   &http.Client{Timeout: 2 * time.Second},
	}
	at, rt, err := r.refreshAccessToken(context.Background(), "rt-old")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if at != "at-new" || rt != "rt-new" {
		t.Fatalf("unexpected tokens: %q %q", at, rt)
	}
}

// TestRefreshAccessToken_NoRotation — IdP doesn't rotate the refresh
// token; we should get newAccessToken with empty newRefreshToken.
func TestRefreshAccessToken_NoRotation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-new","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	r := &Runner{TokenURL: srv.URL, HTTPClient: srv.Client()}
	at, rt, err := r.refreshAccessToken(context.Background(), "rt-x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if at != "at-new" {
		t.Fatalf("at: %q", at)
	}
	if rt != "" {
		t.Fatalf("expected empty rt, got %q", rt)
	}
}

// TestRefreshAccessToken_Refused — 401 from token endpoint must surface
// as a NON-transient error so the caller invalidates the session.
func TestRefreshAccessToken_Refused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	r := &Runner{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, _, err := r.refreshAccessToken(context.Background(), "rt-bad")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, errTransient) {
		t.Fatalf("401 should NOT be transient: %v", err)
	}
}

// TestRefreshAccessToken_Transient5xx — 5xx must wrap errTransient
// so the caller leaves the session alone.
func TestRefreshAccessToken_Transient5xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	r := &Runner{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, _, err := r.refreshAccessToken(context.Background(), "rt-x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("5xx must be transient: %v", err)
	}
}

// TestRefreshAccessToken_TransientNetwork — unreachable token URL must
// wrap errTransient.
func TestRefreshAccessToken_TransientNetwork(t *testing.T) {
	t.Parallel()
	r := &Runner{
		TokenURL:   "http://127.0.0.1:1/oauth/token", // port 1 = ICMP echo, refused
		HTTPClient: &http.Client{Timeout: 200 * time.Millisecond},
	}
	_, _, err := r.refreshAccessToken(context.Background(), "rt-x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("network error must be transient: %v", err)
	}
}

// TestRefreshAccessToken_EmptyAccessToken — successful 200 but empty
// access_token must be transient (we can't proceed but it's not an
// auth refusal — IdP misbehaving).
func TestRefreshAccessToken_EmptyAccessToken(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	r := &Runner{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, _, err := r.refreshAccessToken(context.Background(), "rt-x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("empty access_token must be transient: %v", err)
	}
}

// TestFetchUserInfo_Success — happy path, claims decoded.
func TestFetchUserInfo_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer at-x" {
			t.Errorf("Authorization: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"user-123","email":"a@b","roles":["platform_admin"]}`))
	}))
	defer srv.Close()

	r := &Runner{UserInfoURL: srv.URL, HTTPClient: srv.Client()}
	uc, err := r.fetchUserInfo(context.Background(), "at-x")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if uc.Sub != "user-123" || uc.Email != "a@b" {
		t.Fatalf("decode: %+v", uc)
	}
	if !contains(uc.Roles, "platform_admin") {
		t.Fatalf("missing role: %+v", uc.Roles)
	}
}

// TestFetchUserInfo_Unauthorized — 401 must be NON-transient (caller
// invalidates).
func TestFetchUserInfo_Unauthorized(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	r := &Runner{UserInfoURL: srv.URL, HTTPClient: srv.Client()}
	_, err := r.fetchUserInfo(context.Background(), "at-bad")
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, errTransient) {
		t.Fatalf("401 must not be transient: %v", err)
	}
}

// TestFetchUserInfo_Transient5xx — 5xx must wrap errTransient.
func TestFetchUserInfo_Transient5xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := &Runner{UserInfoURL: srv.URL, HTTPClient: srv.Client()}
	_, err := r.fetchUserInfo(context.Background(), "at-x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("5xx must be transient: %v", err)
	}
}

// TestFetchUserInfo_GarbledJSON — 200 with non-JSON body must be
// transient (IdP misbehaving, not auth refusal).
func TestFetchUserInfo_GarbledJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>not json</html>`))
	}))
	defer srv.Close()

	r := &Runner{UserInfoURL: srv.URL, HTTPClient: srv.Client()}
	_, err := r.fetchUserInfo(context.Background(), "at-x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errTransient) {
		t.Fatalf("decode failure must be transient: %v", err)
	}
}

func TestContains(t *testing.T) {
	t.Parallel()
	if !contains([]string{"a", "b"}, "a") {
		t.Fatal("a should be present")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("c should not be present")
	}
	if contains(nil, "x") {
		t.Fatal("nil haystack must not match")
	}
}

func TestSafePrefix(t *testing.T) {
	t.Parallel()
	if got := safePrefix("abcdefghijkl"); got != "abcdefgh" {
		t.Fatalf("prefix: %q", got)
	}
	if got := safePrefix("ab"); got != "ab" {
		t.Fatalf("short: %q", got)
	}
}

// TestNeedLeaderElection asserts the controller-runtime contract.
func TestNeedLeaderElection(t *testing.T) {
	t.Parallel()
	r := &Runner{}
	if !r.NeedLeaderElection() {
		t.Fatal("CV must require leader election")
	}
}

// TestRefreshAccessToken_NoClientSecret — public client (PKCE-only)
// must not crash if ClientSecret is empty; form should omit the field.
func TestRefreshAccessToken_NoClientSecret(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if v, ok := r.Form["client_secret"]; ok && len(v) > 0 && v[0] != "" {
			t.Errorf("expected client_secret omitted, got %q", v[0])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	r := &Runner{
		TokenURL:   srv.URL,
		ClientID:   "talon-pkce",
		HTTPClient: srv.Client(),
	}
	if _, _, err := r.refreshAccessToken(context.Background(), "rt"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

// snippet must not panic on long bodies.
func TestSnippet_Truncation(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 1000)
	out := snippet([]byte(long))
	if len(out) > 250 {
		t.Fatalf("not truncated: %d", len(out))
	}
}

// extractAccessTokenRoles is the Phase 4.2 role-loss check input — any
// decoder regression invalidates every session on the next tick, so the
// round-trip cases are gated here.
func TestExtractAccessTokenRoles(t *testing.T) {
	t.Parallel()
	// Minimal fixture: header + payload + signature; we only inspect payload.
	// Payload JSON: {"sub":"u1","roles":["platform_admin","iam_admin"]}.
	raw := "eyJhbGciOiJSUzI1NiJ9." +
		"eyJzdWIiOiJ1MSIsInJvbGVzIjpbInBsYXRmb3JtX2FkbWluIiwiaWFtX2FkbWluIl19." +
		"signature-ignored"
	roles, err := extractAccessTokenRoles(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(roles) != 2 || roles[0] != "platform_admin" || roles[1] != "iam_admin" {
		t.Fatalf("unexpected roles: %v", roles)
	}

	// Token with no roles claim — caller distinguishes empty-but-decoded
	// from decode-error and must not invalidate on the empty case.
	rawNoRoles := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"
	roles, err = extractAccessTokenRoles(rawNoRoles)
	if err != nil {
		t.Fatalf("decode (no roles): %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected empty roles, got: %v", roles)
	}

	// Malformed: not a JWT.
	if _, err := extractAccessTokenRoles("not-a-jwt"); err == nil {
		t.Fatal("expected error on non-JWT input")
	}

	// Malformed payload (valid JWT shape, garbage payload).
	if _, err := extractAccessTokenRoles("hdr.@not-base64@.sig"); err == nil {
		t.Fatal("expected error on non-base64 payload")
	}
}
