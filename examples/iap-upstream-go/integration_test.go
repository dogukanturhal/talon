// SPDX-License-Identifier: AGPL-3.0-or-later

// integration_test.go — exercises the example service's full chain
// (Talon-mint → JWKS-serve → Middleware-verify → handler) so the
// reference example never silently rots when the underlying
// middleware contract changes. This file lives in the example
// directory deliberately: developers copying the example get the
// integration test pattern alongside it.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/talon/internal/identityjwt"
)

// rig stands up a Talon-side signer + JWKS server + an upstream
// httptest.Server running the example's handler chain. Returns a
// pair of helpers: sign() to mint tokens, call() to hit the upstream.
type rig struct {
	signer       *identityjwt.Signer
	upstreamURL  string
	close        func()
}

func setupRig(t *testing.T) *rig {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := identityjwt.NewSignerFromPEM(pemBytes, "https://auth.ops.example.test")
	if err != nil {
		t.Fatal(err)
	}

	// Mount the actual JWKS handler.
	jwksMux := http.NewServeMux()
	jwksMux.Handle("/.well-known/jwks.json", identityjwt.JWKSHandler(signer))
	jwksSrv := httptest.NewServer(jwksMux)

	verifier, err := identityjwt.NewVerifier(identityjwt.VerifierConfig{
		JWKSURL:          jwksSrv.URL + "/.well-known/jwks.json",
		ExpectedIssuer:   "https://auth.ops.example.test",
		ExpectedAudience: "myservice.ops.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mirror what main() builds — same handler topology so the test
	// covers the actual production wiring.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := verifier.HealthCheck(r.Context()); err != nil {
			http.Error(w, "iap verifier unhealthy: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
	api := http.NewServeMux()
	api.HandleFunc("/api/whoami", whoamiHandler)
	api.HandleFunc("/api/echo", echoHandler)
	mux.Handle("/api/", identityjwt.Middleware(verifier)(api))

	upstreamSrv := httptest.NewServer(mux)

	return &rig{
		signer:      signer,
		upstreamURL: upstreamSrv.URL,
		close: func() {
			upstreamSrv.Close()
			jwksSrv.Close()
		},
	}
}

func (r *rig) call(t *testing.T, method, path, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, r.upstreamURL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set(identityjwt.HeaderName, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestExample_Healthz_AlwaysOK(t *testing.T) {
	r := setupRig(t)
	defer r.close()
	resp := r.call(t, http.MethodGet, "/healthz", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestExample_Readyz_OKWhenJWKSReachable(t *testing.T) {
	r := setupRig(t)
	defer r.close()
	resp := r.call(t, http.MethodGet, "/readyz", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestExample_API_RejectsUnauthed(t *testing.T) {
	r := setupRig(t)
	defer r.close()
	resp := r.call(t, http.MethodGet, "/api/whoami", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "iap_token_missing") {
		t.Errorf("response should carry code=iap_token_missing, got %q", body)
	}
}

func TestExample_API_WhoamiSurfacesClaims(t *testing.T) {
	r := setupRig(t)
	defer r.close()
	// Mint a token shaped like a real Talon JWT.
	blob := mustBlob(t)
	token, err := r.signer.Sign(blob, "myservice.ops.example.test")
	if err != nil {
		t.Fatal(err)
	}
	resp := r.call(t, http.MethodGet, "/api/whoami", token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["sub"] != "u-1" {
		t.Errorf("sub = %v, want u-1", got["sub"])
	}
	if got["email"] != "user@example.test" {
		t.Errorf("email = %v", got["email"])
	}
	if got["jti"] == "" || got["jti"] == nil {
		t.Error("jti claim should propagate into whoami response")
	}
}

func TestExample_API_GroupGatingEnforced(t *testing.T) {
	r := setupRig(t)
	defer r.close()

	// Token without platform_admin must be rejected by /api/echo POST.
	tokNonAdmin := mustSign(t, r, mustBlobWithGroups(t, "viewer"))
	resp := r.call(t, http.MethodPost, "/api/echo", tokNonAdmin, strings.NewReader(""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin POST status = %d, want 403", resp.StatusCode)
	}

	// Token with platform_admin must pass.
	tokAdmin := mustSign(t, r, mustBlobWithGroups(t, "platform_admin"))
	resp2 := r.call(t, http.MethodPost, "/api/echo", tokAdmin, strings.NewReader(""))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("admin POST status = %d, want 200", resp2.StatusCode)
	}
}

func TestExample_API_RejectsWrongAudience(t *testing.T) {
	r := setupRig(t)
	defer r.close()
	// Mint for a different audience — must reject.
	tok, _ := r.signer.Sign(mustBlob(t), "OTHER.ops.example.test")
	resp := r.call(t, http.MethodGet, "/api/whoami", tok, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "audience_mismatch") {
		t.Errorf("response should narrow reason to audience_mismatch, got %q", body)
	}
}
