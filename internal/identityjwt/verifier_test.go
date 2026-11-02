// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/dogukanturhal/talon/internal/session"
)

// jwksTestServer returns an httptest.Server that publishes the given
// signer's JWKS at /.well-known/jwks.json plus a hit counter for the
// JWKS-refresh-on-unknown-kid tests.
func jwksTestServer(t *testing.T, s *Signer) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		JWKSHandler(s).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/.well-known/jwks.json", &hits
}

func TestNewVerifier_RejectsEmptyConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  VerifierConfig
	}{
		{"missing JWKSURL", VerifierConfig{ExpectedIssuer: "i", ExpectedAudience: "a"}},
		{"missing ExpectedIssuer", VerifierConfig{JWKSURL: "u", ExpectedAudience: "a"}},
		{"missing ExpectedAudience", VerifierConfig{JWKSURL: "u", ExpectedIssuer: "i"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewVerifier(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestVerifier_RoundtripMintAndVerify(t *testing.T) {
	signer, err := NewSignerFromPEM(genTestKey(t), "https://auth.internal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	jwksURL, _ := jwksTestServer(t, signer)

	v, err := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://auth.internal.example.com",
		ExpectedAudience: "registry.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	blob := &session.Blob{
		Sub:        "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:      "dogukanturhal@example.com",
		Groups:     []string{"platform_admin"},
		TenantID:   "tenant-1",
		SSOChainID: "chain-1",
		SID:        "sid-1",
	}
	token, err := signer.Sign(blob, "registry.example.com")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := v.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject != blob.Sub {
		t.Errorf("sub = %q, want %q", claims.Subject, blob.Sub)
	}
	if claims.Audience != "registry.example.com" {
		t.Errorf("aud = %q", claims.Audience)
	}
	if claims.Email != blob.Email {
		t.Errorf("email = %q", claims.Email)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "platform_admin" {
		t.Errorf("groups = %v", claims.Groups)
	}
}

func TestVerifier_VerifyRequest_NoToken(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := v.VerifyRequest(r)
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("got %v, want errors.Is(_, ErrNoToken)", err)
	}
}

func TestVerifier_RejectsAudienceMismatch(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "registry.example.com",
	})
	// Token minted for argocd, not harbor — must reject.
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "argocd.internal.example.com")
	_, err := v.VerifyToken(context.Background(), token)
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("got %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifier_RejectsIssuerMismatch(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://wrong.issuer")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.internal.example.com", ExpectedAudience: "a",
	})
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	_, err := v.VerifyToken(context.Background(), token)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("got %v, want ErrIssuerMismatch", err)
	}
}

func TestVerifier_RejectsExpired(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		ClockTolerance: time.Millisecond, // tight
	})
	// Mint a token with iat/exp in the past by directly hitting the
	// jose layer (Signer.Sign always stamps a fresh window).
	pub := signer.PublicKey()
	_ = pub
	now := time.Now().Add(-10 * time.Minute).Unix()
	claims := IdentityClaims{
		Issuer: "https://auth.ops", Subject: "u", Audience: "a",
		IssuedAt: now, ExpiresAt: now + 60,
	}
	raw, err := jwt.Signed(signer.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.VerifyToken(context.Background(), raw)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("got %v, want ErrTokenExpired", err)
	}
}

func TestVerifier_RejectsBadSignature(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	// Tamper the signature segment.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape: %q", token)
	}
	// Flip 10 middle bytes — base64url edges can no-op on a single char.
	sig := []byte(parts[2])
	mid := len(sig) / 2
	for i := 0; i < 10 && mid+i < len(sig); i++ {
		if sig[mid+i] == 'A' {
			sig[mid+i] = 'B'
		} else {
			sig[mid+i] = 'A'
		}
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	_, err := v.VerifyToken(context.Background(), tampered)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("got %v, want ErrSignatureInvalid", err)
	}
}

func TestVerifier_RejectsMalformedToken(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	_, err := v.VerifyToken(context.Background(), "not.a.jwt")
	if !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("got %v, want ErrTokenMalformed", err)
	}
}

func TestVerifier_JWKSCacheReusedWithinTTL(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, hits := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	for i := 0; i < 5; i++ {
		token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
		if _, err := v.VerifyToken(context.Background(), token); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("JWKS fetch hits = %d, want 1 (cache should serve 4 reads)", h)
	}
}

func TestVerifier_PrefetchJWKSFailsLoud(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: "http://127.0.0.1:1/unreachable", ExpectedIssuer: "i", ExpectedAudience: "a",
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := v.PrefetchJWKS(ctx)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable", err)
	}
}

func TestVerifier_JWKSEndpointReturnsBadStatus(t *testing.T) {
	// Sign a real token so the verifier reaches the JWKS-fetch step
	// (token parsing happens first; we want to exercise the 503 path).
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no key configured", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: srv.URL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	_, err := v.VerifyToken(context.Background(), token)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable", err)
	}
}

func TestVerifier_RotationOverlapBothKidsVerify(t *testing.T) {
	// Active signer (the new key after a rotation).
	active, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	// Retired key — what existed before the rotation; we publish it on
	// JWKS alongside the active so JWTs minted just before the rolling
	// restart still verify during the overlap window.
	retiredPEM := genTestKey(t)
	retired, _ := NewSignerFromPEM(retiredPEM, "https://auth.ops")
	if err := active.AddPreviousPublicKeyFromPEM(retiredPEM); err != nil {
		t.Fatal(err)
	}

	jwksURL, _ := jwksTestServer(t, active)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	// Token signed by RETIRED key must still verify (overlap window).
	oldToken, _ := retired.Sign(&session.Blob{Sub: "u-old"}, "a")
	if _, err := v.VerifyToken(context.Background(), oldToken); err != nil {
		t.Errorf("retired-key token must verify during overlap: %v", err)
	}
	// And a fresh token signed by the active key.
	newToken, _ := active.Sign(&session.Blob{Sub: "u-new"}, "a")
	if _, err := v.VerifyToken(context.Background(), newToken); err != nil {
		t.Errorf("active-key token must verify: %v", err)
	}
}

func TestVerifier_RejectsAlgOutsideWhitelist(t *testing.T) {
	// Build an HS256 token + publish a bogus JWKS — verifier MUST
	// refuse to parse the HS256 token regardless of whether a key
	// would verify it.
	bogusPub, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&bogusPub.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	_ = pubPEM

	// Mint an HS256 token manually.
	hsSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("secret-32-bytes-long-________________")},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(hsSigner).Claims(IdentityClaims{
		Issuer: "https://auth.ops", Subject: "u", Audience: "a",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 60,
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Use any reachable JWKS — the verifier never gets that far.
	dummySigner, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, dummySigner)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	_, err = v.VerifyToken(context.Background(), tok)
	if !errors.Is(err, ErrAlgNotAllowed) && !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("got %v, want ErrAlgNotAllowed or ErrTokenMalformed", err)
	}
}

func TestVerifier_HealthCheck_ReachableJWKS(t *testing.T) {
	s, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, s)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	if err := v.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck on reachable JWKS: %v", err)
	}
}

func TestVerifier_HealthCheck_UnreachableJWKS(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL:          "http://127.0.0.1:1/unreachable",
		ExpectedIssuer:   "i",
		ExpectedAudience: "a",
		HTTPClient:       &http.Client{Timeout: 50 * time.Millisecond},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := v.HealthCheck(ctx)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable", err)
	}
}

func TestVerifier_HealthCheck_RejectsJWKSWithNoRSAKeys(t *testing.T) {
	// JWKS structurally valid (empty array would already fail) but
	// containing only a non-RSA key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// minimal EC key shape — passes JSON decode but isn't *rsa.PublicKey
		_, _ = w.Write([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","kid":"ec-1"}]}`))
	}))
	t.Cleanup(srv.Close)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: srv.URL, ExpectedIssuer: "i", ExpectedAudience: "a",
	})
	err := v.HealthCheck(context.Background())
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable (no RSA keys)", err)
	}
}

func TestVerifier_EmptyJWKSReturnsUnavailable(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{})
	}))
	t.Cleanup(srv.Close)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: srv.URL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	_, err := v.VerifyToken(context.Background(), token)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable", err)
	}
}
