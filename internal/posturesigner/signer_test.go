// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/hexxlock/talon/internal/caep"
	"github.com/hexxlock/talon/internal/posture"
)

// testVaultTransit is an in-process httptest server that simulates Vault
// Transit. It holds a real RSA key and implements:
//   - POST /v1/transit/sign/<key> — signs with SHA-256+PKCS1v15
//   - GET  /v1/transit/keys/<key> — returns public key PEM
type testVaultTransit struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	pubPEM string
	token  string
}

func newTestVaultTransit(t *testing.T) *testVaultTransit {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	tv := &testVaultTransit{key: key, pubPEM: pubPEM, token: "test-vault-token"}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/sign/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != tv.token {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		var req struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		inputBytes, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			http.Error(w, "bad input base64", http.StatusBadRequest)
			return
		}
		// SHA-256 + PKCS1v15 (Vault `signature_algorithm: pkcs1v15`,
		// `hash_algorithm: sha2-256`). crypto.SHA256 = 5.
		digest := sha256.Sum256(inputBytes)
		sig, err := rsa.SignPKCS1v15(rand.Reader, tv.key, 5, digest[:])
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		// Vault returns "vault:v1:<standard_base64>".
		vaultSig := "vault:v1:" + base64.StdEncoding.EncodeToString(sig)
		resp := map[string]any{"data": map[string]string{"signature": vaultSig}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})
	mux.HandleFunc("/v1/transit/keys/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != tv.token {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"keys": map[string]any{
					"1": map[string]string{"public_key": pubPEM},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})
	tv.srv = httptest.NewServer(mux)
	t.Cleanup(tv.srv.Close)
	return tv
}

func newIssuerForTest(t *testing.T, tv *testVaultTransit) *JWSIssuer {
	t.Helper()
	// Inject a mock readFileOnce so the issuer reads our static token.
	orig := readFileOnce
	t.Cleanup(func() { readFileOnce = orig })
	readFileOnce = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "token") {
			return []byte(tv.token), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	}

	iss, err := NewJWSIssuer(JWSIssuerConfig{
		VaultAddr: tv.srv.URL,
		KeyName:   "posture-signer",
		Issuer:    "https://posture.hexxlock.com",
		Audience:  "https://internal.example.com",
		TokenPath: "/vault/secrets/token",
	})
	if err != nil {
		t.Fatalf("NewJWSIssuer: %v", err)
	}
	iss.httpCl = tv.srv.Client()

	ctx := context.Background()
	if err := iss.RefreshJWKS(ctx); err != nil {
		t.Fatalf("RefreshJWKS: %v", err)
	}
	return iss
}

// TestJWSIssuer_RoundTrip_PostureVerifier is the load-bearing cross-
// package integration test: it mints a JWS through IssueJWS and then
// verifies it through the production posture.Verifier. If the wire
// shapes diverge (e.g., a field renamed in heartbeat.go but not in
// posture.go's rawClaims), this test catches it.
func TestJWSIssuer_RoundTrip_PostureVerifier(t *testing.T) {
	tv := newTestVaultTransit(t)
	iss := newIssuerForTest(t, tv)

	req := &HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		UserSub:    "user-123",
		Tier:       TierCorp,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IAT:        time.Now().Unix(),
		Compliance: map[string]any{
			"disk_encrypted":  true,
			"edr_running":     true,
			"screen_lock_min": 5,
		},
		deviceCertThumbprint: "test-x5t-thumbprint-base64url-no-pad-32",
	}

	ctx := context.Background()
	jws, _, err := iss.IssueJWS(ctx, req)
	if err != nil {
		t.Fatalf("IssueJWS: %v", err)
	}
	if jws == "" {
		t.Fatal("IssueJWS returned empty JWS")
	}

	// Verify with production posture.Verifier using the test key as the
	// trusted JWKS. We wrap the RSA public key in a JWKSResolver.
	resolver := &staticKeyResolver{key: &tv.key.PublicKey}
	verifier, err := posture.NewVerifier(posture.VerifierConfig{
		TrustedIssuers:   []string{"https://posture.hexxlock.com"},
		ExpectedAudience: "https://internal.example.com",
		AllowedAlgs:      []jose.SignatureAlgorithm{jose.RS256},
		Resolver:         resolver,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	claims, err := verifier.Verify(ctx, jws, "user-123")
	if err != nil {
		t.Fatalf("posture.Verifier.Verify: %v", err)
	}

	// Validate the claims round-tripped correctly.
	wantSub := "device:" + req.DeviceUUID
	if claims.Subject != wantSub {
		t.Errorf("sub: want %q, got %q", wantSub, claims.Subject)
	}
	if claims.UserSub != req.UserSub {
		t.Errorf("user_sub: want %q, got %q", req.UserSub, claims.UserSub)
	}
	if claims.Issuer != "https://posture.hexxlock.com" {
		t.Errorf("iss: want https://posture.hexxlock.com, got %q", claims.Issuer)
	}
	if diskEnc, ok := claims.Compliance["disk_encrypted"].(bool); !ok || !diskEnc {
		t.Errorf("compliance.disk_encrypted: want true bool, got %v (%T)",
			claims.Compliance["disk_encrypted"], claims.Compliance["disk_encrypted"])
	}
}

// staticKeyResolver implements posture.JWKSResolver for tests, wrapping
// a single RSA public key.
type staticKeyResolver struct {
	key *rsa.PublicKey
}

func (r *staticKeyResolver) Keys(_ context.Context, _, _ string) ([]any, error) {
	return []any{r.key}, nil
}

func TestJWSIssuer_VaultSignError(t *testing.T) {
	// Vault returns 500 — IssueJWS must propagate the error.
	errKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	errDER, _ := x509.MarshalPKIXPublicKey(&errKey.PublicKey)
	errPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: errDER}))

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sign/") {
			http.Error(w, `{"errors":["internal error"]}`, http.StatusInternalServerError)
			return
		}
		// Allow keys endpoint for JWKS refresh.
		resp := map[string]any{
			"data": map[string]any{
				"keys": map[string]any{"1": map[string]string{"public_key": errPEM}},
			},
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer errSrv.Close()

	orig := readFileOnce
	defer func() { readFileOnce = orig }()
	readFileOnce = func(_ string) ([]byte, error) { return []byte("test-token"), nil }

	iss, _ := NewJWSIssuer(JWSIssuerConfig{
		VaultAddr: errSrv.URL, KeyName: "posture-signer",
		Issuer: "https://posture.hexxlock.com", Audience: "https://internal.example.com",
		TokenPath: "/vault/secrets/token",
	})
	iss.httpCl = errSrv.Client()
	_ = iss.RefreshJWKS(context.Background())

	req := &HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Compliance: map[string]any{},
	}
	_, _, err := iss.IssueJWS(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from vault 500, got nil")
	}
}

func TestJWSIssuer_JWKS_ContainsPubKey(t *testing.T) {
	tv := newTestVaultTransit(t)
	iss := newIssuerForTest(t, tv)

	jwks := iss.JWKS()
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("JWKS must have at least one key, got: %v", jwks)
	}
	entry, ok := keys[0].(jwkEntry)
	if !ok {
		t.Fatalf("expected jwkEntry, got %T", keys[0])
	}
	if entry.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %q", entry.Kty)
	}
	if entry.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %q", entry.Alg)
	}
}

func TestJWSIssuer_IsJWKSStale_BeforeRefresh(t *testing.T) {
	orig := readFileOnce
	defer func() { readFileOnce = orig }()
	readFileOnce = func(_ string) ([]byte, error) { return []byte("tok"), nil }

	iss, _ := NewJWSIssuer(JWSIssuerConfig{
		VaultAddr: "http://127.0.0.1:1", KeyName: "k",
		Issuer: "x", Audience: "y", TokenPath: "/tok",
	})
	if !iss.IsJWKSStale() {
		t.Fatal("JWKS should be stale before first refresh")
	}
}

// TestJWSIssuer_JWS_ThreeParts verifies the JWS compact serialization
// has exactly three dot-separated components (header.payload.signature).
func TestJWSIssuer_JWS_ThreeParts(t *testing.T) {
	tv := newTestVaultTransit(t)
	iss := newIssuerForTest(t, tv)

	jws, _, err := iss.IssueJWS(context.Background(), &HeartbeatRequest{
		DeviceUUID:           "550e8400-e29b-41d4-a716-446655440000",
		Compliance:           map[string]any{},
		deviceCertThumbprint: "fake-x5t-for-three-parts-test",
	})
	if err != nil {
		t.Fatalf("IssueJWS: %v", err)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part compact JWS, got %d parts: %v", len(parts), parts)
	}
	// Verify header decodes to a JSON object with alg=RS256.
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header base64url decode: %v", err)
	}
	var hdr map[string]string
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("header JSON unmarshal: %v", err)
	}
	if hdr["alg"] != "RS256" {
		t.Errorf("expected alg=RS256 in header, got %q", hdr["alg"])
	}
}

// TestJWSIssuer_SignSET verifies the CAEP SET signing path (ADR 0043):
// a 3-part compact JWS with header typ=secevent+jwt whose signature
// verifies against the issuer's Vault Transit public key.
func TestJWSIssuer_SignSET(t *testing.T) {
	tv := newTestVaultTransit(t)
	iss := newIssuerForTest(t, tv)

	// Build a well-formed SET via the transmitter (so `aud` is set by the
	// caep package's unexported audienceField), then sign it with the
	// Vault-Transit-backed issuer. iss implements caep.Signer.
	tx, err := caep.NewTransmitter(caep.TransmitterConfig{
		SetIssuer:     "https://posture.hexxlock.com",
		SubjectIssuer: "https://id.hexxlock.com",
		Audience:      "https://internal.example.com",
		ReceiverURL:   "https://example.invalid/caep/events",
	}, iss)
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}
	claims := tx.BuildDeviceComplianceChange("user-1", "550e8400-e29b-41d4-a716-446655440000", false)

	compact, err := iss.SignSET(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignSET: %v", err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part compact JWS, got %d: %v", len(parts), parts)
	}

	// Header must declare the SET media type (RFC 8417).
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	var hdr map[string]string
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("header unmarshal: %v", err)
	}
	if hdr["typ"] != "secevent+jwt" {
		t.Errorf("typ: want secevent+jwt, got %q", hdr["typ"])
	}
	if hdr["alg"] != "RS256" {
		t.Errorf("alg: want RS256, got %q", hdr["alg"])
	}

	// Signature must verify against the test Vault key (RS256 over the
	// signing input header.payload).
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature decode: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&tv.key.PublicKey, 5 /* crypto.SHA256 */, digest[:], sig); err != nil {
		t.Fatalf("SET signature does not verify against issuer key: %v", err)
	}

	// Payload round-trips the SET claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var rt caep.SETClaims
	if err := json.Unmarshal(payloadJSON, &rt); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if rt.JTI == "" {
		t.Error("payload missing jti")
	}
	if rt.Iss != "https://posture.hexxlock.com" {
		t.Errorf("iss: want https://posture.hexxlock.com, got %q", rt.Iss)
	}
	if _, ok := rt.Events[caep.EventDeviceComplianceChange]; !ok {
		t.Errorf("payload missing device-compliance-change event: %v", rt.Events)
	}
}

// TestPemToJWK ensures RSA-2048 PEM round-trips through pemToJWK correctly.
func TestPemToJWK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	entry, err := pemToJWK(pemStr, "test-kid")
	if err != nil {
		t.Fatalf("pemToJWK: %v", err)
	}
	if entry.KID != "test-kid" {
		t.Errorf("kid: want test-kid, got %q", entry.KID)
	}
	if entry.Kty != "RSA" {
		t.Errorf("kty: want RSA, got %q", entry.Kty)
	}
	// N must be non-empty base64url.
	if _, err := base64.RawURLEncoding.DecodeString(entry.N); err != nil {
		t.Errorf("N is not valid base64url: %v", err)
	}
}

// Ensure jwt and jose packages are referenced (compile-time import verification).
var (
	_ = jwt.Claims{}
	_ = jose.RS256
)
