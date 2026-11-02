// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests for the developer login flow. The fake authorization server
// verifies PKCE S256 for real rather than asserting on the request
// shape, so a regression that stopped sending code_verifier — or sent a
// verifier that does not hash to the challenge — fails here rather than
// at the IdP.

package clilogin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAS is a minimal authorization server: discovery + authorize +
// token, with real PKCE verification.
func fakeAS(t *testing.T, opts map[string]string) *httptest.Server {
	t.Helper()
	var gotChallenge, gotMethod, grantedScope string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		methods := []string{"S256"}
		if opts["no_s256"] == "1" {
			methods = []string{"plain"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/token",
			"code_challenge_methods_supported": methods,
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotChallenge, gotMethod = q.Get("code_challenge"), q.Get("code_challenge_method")
		// RFC 6749 §6: the refresh grant may narrow this set, never widen
		// it. Recording it here is what makes the refresh handler below a
		// faithful model instead of an echo chamber.
		grantedScope = q.Get("scope")
		state := q.Get("state")
		if opts["bad_state"] == "1" {
			state = "tampered"
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=THECODE&state="+state, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")

		if r.Form.Get("grant_type") == "refresh_token" {
			// Record what the CLI actually sent so the test can assert
			// the resource parameter is present.
			res := r.Form.Get("resource")
			// Intersect requested with granted — a real AS will not hand
			// back a scope that was never authorised.
			granted := map[string]bool{}
			for _, sc := range strings.Fields(grantedScope) {
				granted[sc] = true
			}
			var effective []string
			for _, sc := range strings.Fields(r.Form.Get("scope")) {
				if granted[sc] {
					effective = append(effective, sc)
				}
			}
			if len(effective) == 0 {
				effective = strings.Fields(grantedScope)
			}
			aud := res
			if opts["wrong_aud"] == "1" {
				aud = "https://api.example.com"
			}
			claims := base64.RawURLEncoding.EncodeToString([]byte(
				fmt.Sprintf(`{"aud":[%q,"other"],"sub":"user-uuid"}`, aud)))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "h." + claims + ".s",
				"expires_in":    3600,
				"scope":         strings.Join(effective, " "),
				"resource_seen": res,
			})
			return
		}

		// authorization_code: verify PKCE for real.
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if gotMethod != "S256" || want != gotChallenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PKCE mismatch"}`))
			return
		}
		rt := "REFRESH-1"
		if opts["no_refresh"] == "1" {
			rt = ""
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "refresh_token": rt,
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

// drive follows the authorize redirect the way a browser would.
func drive(t *testing.T) func(string) error {
	t.Helper()
	return func(u string) error {
		go func() {
			c := &http.Client{}
			resp, err := c.Get(u)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestLogin_PKCERoundTrip(t *testing.T) {
	srv := fakeAS(t, nil)
	ep, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	tok, err := Login(context.Background(), ep, "talon-cli", []string{"npm.internal.example.com"}, true, drive(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.RefreshToken != "REFRESH-1" {
		t.Fatalf("refresh token = %q", tok.RefreshToken)
	}
	t.Log("OK  full loopback PKCE round trip, S256 verified server-side")
}

func TestDiscover_RejectsIssuerWithoutS256(t *testing.T) {
	srv := fakeAS(t, map[string]string{"no_s256": "1"})
	if _, err := Discover(context.Background(), srv.URL); err == nil {
		t.Fatal("expected refusal when S256 is unsupported")
	} else {
		t.Logf("OK  refused non-S256 issuer: %v", err)
	}
}

func TestLogin_RejectsStateMismatch(t *testing.T) {
	srv := fakeAS(t, map[string]string{"bad_state": "1"})
	ep, _ := Discover(context.Background(), srv.URL)
	if _, err := Login(context.Background(), ep, "talon-cli", []string{"npm.internal.example.com"}, true, drive(t)); err == nil {
		t.Fatal("expected state-mismatch rejection")
	} else {
		t.Logf("OK  rejected tampered state: %v", err)
	}
}

func TestLogin_RequiresRefreshToken(t *testing.T) {
	srv := fakeAS(t, map[string]string{"no_refresh": "1"})
	ep, _ := Discover(context.Background(), srv.URL)
	if _, err := Login(context.Background(), ep, "talon-cli", []string{"npm.internal.example.com"}, true, drive(t)); err == nil {
		t.Fatal("expected failure when no refresh_token is returned")
	} else {
		t.Logf("OK  %v", err)
	}
}

func TestMintForHost_SendsResourceAndVerifiesAudience(t *testing.T) {
	srv := fakeAS(t, nil)
	ep, _ := Discover(context.Background(), srv.URL)
	tok, err := MintForHost(context.Background(), ep, "talon-cli", "REFRESH-1", "npm.internal.example.com")
	if err != nil {
		t.Fatalf("MintForHost: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("no access token")
	}
	t.Log("OK  mint sent resource= and the returned aud matched the host")

	bad := fakeAS(t, map[string]string{"wrong_aud": "1"})
	epBad, _ := Discover(context.Background(), bad.URL)
	_, err = MintForHost(context.Background(), epBad, "talon-cli", "R", "npm.internal.example.com")
	if err == nil {
		t.Fatal("expected audience-mismatch refusal")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("OK  refused a token Talon would reject: %v", err)
}

func TestWriteNpmrc_PreservesUnrelatedLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(p, []byte(
		"//registry.npmjs.org/:_authToken=KEEPME\n"+
			"@hexxlock:registry=https://npm.internal.example.com/\n"+
			"//npm.internal.example.com/:_authToken=STALE\n"+
			"prefer-offline=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNpmrc(p, "npm.internal.example.com", "@hexxlock", "FRESH"); err != nil {
		t.Fatalf("WriteNpmrc: %v", err)
	}
	out, _ := os.ReadFile(p)
	s := string(out)
	for _, must := range []string{"KEEPME", "prefer-offline=true", "_authToken=FRESH"} {
		if !strings.Contains(s, must) {
			t.Errorf("missing %q in:\n%s", must, s)
		}
	}
	if strings.Contains(s, "STALE") {
		t.Errorf("stale token survived:\n%s", s)
	}
	if n := strings.Count(s, "@hexxlock:registry="); n != 1 {
		t.Errorf("scope line count = %d, want 1:\n%s", n, s)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %04o, want 0600", fi.Mode().Perm())
	}
	t.Log("OK  unrelated lines preserved, stale token replaced, no duplicate scope, 0600")
}

func TestStore_RejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Path: filepath.Join(dir, "tokens.json")}
	if err := s.Save(&Tokens{RefreshToken: "R"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if err := os.Chmod(s.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("expected refusal to read a world-readable token file")
	} else {
		t.Logf("OK  %v", err)
	}
}

// TestLogin_RequestsPerHostTalonScopes pins the fix for the 2026-08-16
// live failure: talonctl logged in with only the OIDC base scopes, then
// asked the refresh grant for `talon:<host>:read`. RFC 6749 §6 allows a
// refresh to narrow scope but never to widen it, so the token came back
// without the per-host scopes — with a perfectly correct audience — and
// Talon rejected it at the gateway with `scope insufficient`.
//
// The authorize request is where the per-host scopes have to appear.
func TestLogin_RequestsPerHostTalonScopes(t *testing.T) {
	var authorizeScope string
	srv := fakeASCapturingScope(t, &authorizeScope)
	ep, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := Login(context.Background(), ep, "svc-talon-cli",
		[]string{"npm.internal.example.com"}, true, drive(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	for _, want := range []string{
		"talon:npm.internal.example.com:read",
		"talon:npm.internal.example.com:write",
		"offline_access", "groups", "roles",
	} {
		if !strings.Contains(authorizeScope, want) {
			t.Errorf("authorize scope %q missing %q", authorizeScope, want)
		}
	}
}

// TestScopesForLogin_MultipleHosts — a login can cover several hosts, and
// each contributes its own read/write pair. Adding a host later means
// logging in again; there is no way to widen an existing grant.
func TestScopesForLogin_MultipleHosts(t *testing.T) {
	got := strings.Join(scopesForLogin([]string{"a.ops", "", "b.ops"}, true), " ")
	for _, want := range []string{"talon:a.ops:read", "talon:a.ops:write", "talon:b.ops:read", "talon:b.ops:write"} {
		if !strings.Contains(got, want) {
			t.Errorf("scopes %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "talon::read") {
		t.Errorf("empty host produced a scope: %q", got)
	}
}

// fakeASCapturingScope records the scope presented at /authorize.
func fakeASCapturingScope(t *testing.T, out *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		*out = q.Get("scope")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=C&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "refresh_token": "rt",
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

// TestScopesForLogin_ReadOnlyByDefault is the least-privilege guard.
//
// Talon resolves the required verb from the request: `npm install` is a
// GET needing talon:<host>:read, `npm publish` is a PUT needing
// talon:<host>:write. So omitting :write from the grant is what actually
// stops a consumer from overwriting a package — there is no separate
// enforcement point to fall back on.
//
// A regression here is silent and dangerous: every developer's laptop
// credential would quietly regain publish rights, and nothing in the
// install path would look any different.
func TestScopesForLogin_ReadOnlyByDefault(t *testing.T) {
	got := strings.Join(scopesForLogin([]string{"npm.internal.example.com"}, false), " ")
	if !strings.Contains(got, "talon:npm.internal.example.com:read") {
		t.Errorf("default login must grant read: %q", got)
	}
	if strings.Contains(got, ":write") {
		t.Errorf("default login must NOT grant write (npm publish would become possible): %q", got)
	}
}

// TestScopesForLogin_PublishIsOptIn — the publisher case still works, and
// write is strictly additive to read (a publisher also installs).
func TestScopesForLogin_PublishIsOptIn(t *testing.T) {
	got := strings.Join(scopesForLogin([]string{"npm.internal.example.com"}, true), " ")
	for _, want := range []string{"talon:npm.internal.example.com:read", "talon:npm.internal.example.com:write"} {
		if !strings.Contains(got, want) {
			t.Errorf("--publish login missing %q: %q", want, got)
		}
	}
}
