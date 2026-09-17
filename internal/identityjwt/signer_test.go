// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/dogukanturhal/talon/internal/session"
)

// genTestKey returns a fresh 2048-bit RSA key encoded as PKCS#1 PEM —
// the shape Talon's TALON_IAP_SIGNING_KEY_PEM env var carries in prod.
func genTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test rsa key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// signClaimsViaJose is a test helper that bypasses Sign() so callers
// can inject custom claim shapes (e.g. with jti deliberately omitted,
// or with a specific exp in the past). Returns the compact JWS string.
func signClaimsViaJose(s *Signer, claims IdentityClaims) (string, error) {
	return jwt.Signed(s.signer).Claims(claims).Serialize()
}

func TestNewSignerFromPEM_PKCS1Roundtrip(t *testing.T) {
	pemBytes := genTestKey(t)
	signer, err := NewSignerFromPEM(pemBytes, "https://internal.example.com")
	if err != nil {
		t.Fatalf("NewSignerFromPEM: %v", err)
	}
	if signer.Kid() == "" {
		t.Error("Kid() empty — kid is required for JWKS rotation")
	}
	if signer.Issuer() != "https://internal.example.com" {
		t.Errorf("Issuer() = %q, want %q", signer.Issuer(), "https://internal.example.com")
	}
}

func TestNewSignerFromPEM_PKCS8Roundtrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := NewSignerFromPEM(pemBytes, "https://internal.example.com")
	if err != nil {
		t.Fatalf("NewSignerFromPEM PKCS#8: %v", err)
	}
	if signer.Kid() == "" {
		t.Error("Kid() empty")
	}
}

func TestNewSignerFromPEM_RejectsBelowTwoThousandForty_EightBitKey(t *testing.T) {
	// 1024-bit key — below NIST SP 800-131A's 2048-bit floor.
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(weakKey),
	})
	if _, err := NewSignerFromPEM(pemBytes, "https://internal.example.com"); err == nil {
		t.Fatal("expected error for sub-2048-bit key, got nil")
	}
}

func TestNewSignerFromPEM_RejectsEmptyIssuer(t *testing.T) {
	pemBytes := genTestKey(t)
	if _, err := NewSignerFromPEM(pemBytes, ""); err == nil {
		t.Fatal("expected error for empty issuer, got nil")
	}
}

func TestNewSignerFromPEM_RejectsMalformedPEM(t *testing.T) {
	if _, err := NewSignerFromPEM([]byte("not a pem"), "https://auth.ops"); err == nil {
		t.Fatal("expected error for malformed PEM, got nil")
	}
	if _, err := NewSignerFromPEM([]byte{}, "https://auth.ops"); err == nil {
		t.Fatal("expected error for empty PEM, got nil")
	}
}

func TestSign_ClaimsRoundtripAndVerify(t *testing.T) {
	pemBytes := genTestKey(t)
	signer, err := NewSignerFromPEM(pemBytes, "https://internal.example.com")
	if err != nil {
		t.Fatal(err)
	}

	blob := &session.Blob{
		Sub:        "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:      "dogukanturhal@example.com",
		Groups:     []string{"platform_admin", "iam_admin"},
		TenantID:   "00000000-0000-0000-0000-000000000002",
		SSOChainID: "test-chain-id",
		SID:        "test-sid",
	}

	rawJWT, err := signer.Sign(blob, "internal.example.com")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if rawJWT == "" {
		t.Fatal("Sign returned empty token")
	}
	if !strings.Contains(rawJWT, ".") || strings.Count(rawJWT, ".") != 2 {
		t.Errorf("Sign returned non-compact JWS: %q", rawJWT)
	}

	// Parse + verify against signer's public key.
	pub := signer.PublicKey()
	parsed, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	var out IdentityClaims
	if err := parsed.Claims(&pub, &out); err != nil {
		t.Fatalf("verify+extract claims: %v", err)
	}

	if out.Issuer != "https://internal.example.com" {
		t.Errorf("iss = %q, want https://internal.example.com", out.Issuer)
	}
	if out.Subject != blob.Sub {
		t.Errorf("sub = %q, want %q", out.Subject, blob.Sub)
	}
	if out.Audience != "internal.example.com" {
		t.Errorf("aud = %q, want internal.example.com", out.Audience)
	}
	if out.Email != blob.Email {
		t.Errorf("email = %q, want %q", out.Email, blob.Email)
	}
	if len(out.Groups) != 2 || out.Groups[0] != "platform_admin" {
		t.Errorf("groups = %v, want [platform_admin iam_admin]", out.Groups)
	}
	if out.TenantID != blob.TenantID {
		t.Errorf("tenant_id = %q, want %q", out.TenantID, blob.TenantID)
	}
	if out.SSOChainID != blob.SSOChainID {
		t.Errorf("sso_chain_id = %q, want %q", out.SSOChainID, blob.SSOChainID)
	}
	if out.SID != blob.SID {
		t.Errorf("sid = %q, want %q", out.SID, blob.SID)
	}
	// roles mirrors the X-Talon-Groups source (blob.Groups) verbatim.
	if len(out.Roles) != len(out.Groups) {
		t.Fatalf("roles = %v, want == groups %v", out.Roles, out.Groups)
	}
	for i := range out.Groups {
		if out.Roles[i] != out.Groups[i] {
			t.Errorf("roles[%d] = %q, want %q (== groups)", i, out.Roles[i], out.Groups[i])
		}
	}

	// iat / exp window.
	now := time.Now().Unix()
	if out.IssuedAt > now || now-out.IssuedAt > 5 {
		t.Errorf("iat %d not within 5s of now %d", out.IssuedAt, now)
	}
	if out.ExpiresAt-out.IssuedAt != int64(DefaultTokenLifetime.Seconds()) {
		t.Errorf("exp-iat = %d, want %d", out.ExpiresAt-out.IssuedAt, int64(DefaultTokenLifetime.Seconds()))
	}
}

// TestSign_RolesClaimMirrorsGroupsSource proves the signed JWT's `roles`
// claim carries the EXACT source that feeds the X-Talon-Groups header
// (blob.Groups) — verbatim, and NOT blob.Roles. This is the
// behavior-preserving contract for eyrie: when eyrie switches its authz
// derivation from `groups` to `roles`, it must read the identical slice.
//
// The blob deliberately sets Roles to a DIFFERENT value than Groups so a
// regression that (wrongly) sourced the claim from blob.Roles would fail.
func TestSign_RolesClaimMirrorsGroupsSource(t *testing.T) {
	signer, err := NewSignerFromPEM(genTestKey(t), "https://internal.example.com")
	if err != nil {
		t.Fatal(err)
	}

	blob := &session.Blob{
		Sub:    "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:  "dogukanturhal@example.com",
		Groups: []string{"/platform/admins", "/iam/admins"}, // X-Talon-Groups source
		Roles:  []string{"platform_admin", "iam_admin"},     // internal-only; must NOT leak into the claim
	}

	rawJWT, err := signer.Sign(blob, "internal.example.com")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := signer.PublicKey()
	parsed, err := jwt.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	var out IdentityClaims
	if err := parsed.Claims(&pub, &out); err != nil {
		t.Fatalf("verify+extract claims: %v", err)
	}

	// roles == blob.Groups (the header source), byte-for-byte.
	if len(out.Roles) != len(blob.Groups) {
		t.Fatalf("roles = %v, want == blob.Groups %v", out.Roles, blob.Groups)
	}
	for i := range blob.Groups {
		if out.Roles[i] != blob.Groups[i] {
			t.Errorf("roles[%d] = %q, want %q (blob.Groups)", i, out.Roles[i], blob.Groups[i])
		}
	}
	// roles must NOT be sourced from blob.Roles (the internal-only slice).
	if len(out.Roles) > 0 && out.Roles[0] == blob.Roles[0] {
		t.Errorf("roles[0] = %q leaked from blob.Roles; must mirror blob.Groups", out.Roles[0])
	}
	// groups claim unchanged — still the same source.
	if len(out.Groups) != len(blob.Groups) || out.Groups[0] != blob.Groups[0] {
		t.Errorf("groups = %v, want %v (unchanged)", out.Groups, blob.Groups)
	}
}

func TestSign_RejectsEmptyAudience(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	blob := &session.Blob{Sub: "s", Email: "e"}
	if _, err := signer.Sign(blob, ""); err == nil {
		t.Fatal("expected error for empty audience (per-host binding required), got nil")
	}
}

func TestSign_RejectsNilBlob(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if _, err := signer.Sign(nil, "internal.example.com"); err == nil {
		t.Fatal("expected error for nil blob, got nil")
	}
}

func TestSign_RejectsNilSigner(t *testing.T) {
	var s *Signer
	blob := &session.Blob{Sub: "s"}
	if _, err := s.Sign(blob, "internal.example.com"); err == nil {
		t.Fatal("expected error for nil signer, got nil")
	}
}

func TestJWKSHandler_ServesValidJWKS(t *testing.T) {
	signer, err := NewSignerFromPEM(genTestKey(t), "https://internal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	JWKSHandler(signer).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("content-type = %q, want application/jwk-set+json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("cache-control = %q, want public, max-age=300", got)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("jwks.keys = %d, want 1", len(set.Keys))
	}
	if set.Keys[0].KeyID != signer.Kid() {
		t.Errorf("kid = %q, want %q", set.Keys[0].KeyID, signer.Kid())
	}
	if set.Keys[0].Use != "sig" {
		t.Errorf("use = %q, want sig", set.Keys[0].Use)
	}
	if set.Keys[0].Algorithm != string(jose.RS256) {
		t.Errorf("alg = %q, want RS256", set.Keys[0].Algorithm)
	}

	// Public-key roundtrip: published key must verify a JWT we sign.
	blob := &session.Blob{Sub: "s", Email: "e"}
	raw, err := signer.Sign(blob, "test.audience")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	pubFromJWKS, ok := set.Keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("jwks key is not *rsa.PublicKey: %T", set.Keys[0].Key)
	}
	var claims IdentityClaims
	if err := parsed.Claims(pubFromJWKS, &claims); err != nil {
		t.Errorf("verify JWT against JWKS-published key: %v", err)
	}
}

func TestJWKSHandler_NilSigner503(t *testing.T) {
	rec := httptest.NewRecorder()
	JWKSHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (signing not configured)", rec.Code)
	}
}

func TestAddPreviousPublicKeyFromPEM_PrivatePKCS1(t *testing.T) {
	// Active signer.
	active, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	// Retired key — same shape we'd read from Vault's `key_previous`
	// field during a rotation overlap.
	prevPEM := genTestKey(t)
	if err := active.AddPreviousPublicKeyFromPEM(prevPEM); err != nil {
		t.Fatalf("AddPreviousPublicKeyFromPEM: %v", err)
	}
	prev := active.PreviousPublicKeys()
	if len(prev) != 1 {
		t.Fatalf("PreviousPublicKeys len = %d, want 1", len(prev))
	}
	if prev[0].Kid == "" {
		t.Error("retired kid empty")
	}
	if prev[0].Kid == active.Kid() {
		t.Error("retired kid == active kid — should differ on different keys")
	}
}

func TestAddPreviousPublicKeyFromPEM_PublicPKIX(t *testing.T) {
	active, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	// Generate a separate key, marshal ONLY the public half as PKIX.
	retired, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&retired.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := active.AddPreviousPublicKeyFromPEM(pubPEM); err != nil {
		t.Fatalf("AddPreviousPublicKeyFromPEM (PUBLIC KEY): %v", err)
	}
	if got := len(active.PreviousPublicKeys()); got != 1 {
		t.Errorf("PreviousPublicKeys len = %d, want 1", got)
	}
}

func TestAddPreviousPublicKeyFromPEM_RejectsWeakKey(t *testing.T) {
	active, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(weak),
	})
	if err := active.AddPreviousPublicKeyFromPEM(weakPEM); err == nil {
		t.Fatal("expected error registering 1024-bit retired key, got nil")
	}
}

func TestAddPreviousPublicKeyFromPEM_IdempotentSameKey(t *testing.T) {
	active, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	prevPEM := genTestKey(t)
	_ = active.AddPreviousPublicKeyFromPEM(prevPEM)
	// Second call with the same PEM must not double-publish.
	_ = active.AddPreviousPublicKeyFromPEM(prevPEM)
	if got := len(active.PreviousPublicKeys()); got != 1 {
		t.Errorf("retired key count = %d after duplicate registration, want 1", got)
	}
}

func TestAddPreviousPublicKeyFromPEM_SkipsActiveKey(t *testing.T) {
	pemBytes := genTestKey(t)
	active, err := NewSignerFromPEM(pemBytes, "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	// Registering the SAME key as previous is a no-op (same kid) — protects
	// operators who forget to swap the Vault field during a rotation.
	if err := active.AddPreviousPublicKeyFromPEM(pemBytes); err != nil {
		t.Fatalf("AddPreviousPublicKeyFromPEM with active key: %v", err)
	}
	if got := len(active.PreviousPublicKeys()); got != 0 {
		t.Errorf("retired keys = %d after registering active key as previous, want 0 (skipped)", got)
	}
}

func TestJWKSHandler_PublishesActiveAndRetiredKeys(t *testing.T) {
	active, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	// Retired signer — kept only so we can sign a JWT with the OLD key
	// and prove it verifies against the JWKS-published retired key.
	retiredPEM := genTestKey(t)
	retiredSigner, err := NewSignerFromPEM(retiredPEM, "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := active.AddPreviousPublicKeyFromPEM(retiredPEM); err != nil {
		t.Fatalf("AddPreviousPublicKeyFromPEM: %v", err)
	}

	rec := httptest.NewRecorder()
	JWKSHandler(active).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("jwks.keys = %d, want 2 (active + retired)", len(set.Keys))
	}

	// Verify a JWT signed by the RETIRED key against the JWKS-published
	// retired entry — exactly what a verifier with cached JWKS would do
	// during the overlap window when it sees an old-kid token.
	blob := &session.Blob{Sub: "s", Email: "e"}
	rawOld, err := retiredSigner.Sign(blob, "test.aud")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(rawOld, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	headerKid := parsed.Headers[0].KeyID
	var matched *jose.JSONWebKey
	for i := range set.Keys {
		if set.Keys[i].KeyID == headerKid {
			matched = &set.Keys[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("retired kid %q not found in JWKS — kids published: %v", headerKid, jwksKids(set))
	}
	pub, ok := matched.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("matched JWKS key is not *rsa.PublicKey: %T", matched.Key)
	}
	var claims IdentityClaims
	if err := parsed.Claims(pub, &claims); err != nil {
		t.Errorf("verify old-kid JWT against JWKS retired key: %v", err)
	}
}

func jwksKids(set jose.JSONWebKeySet) []string {
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

func TestSigner_HealthCheck_SuccessOnValidSigner(t *testing.T) {
	s, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HealthCheck(); err != nil {
		t.Errorf("HealthCheck on valid signer: %v", err)
	}
}

func TestSigner_HealthCheck_NilSafe(t *testing.T) {
	var s *Signer
	if err := s.HealthCheck(); err == nil {
		t.Error("HealthCheck on nil signer should error, not panic")
	}
}

func TestSigner_HealthCheck_DetectsKeyCorruption(t *testing.T) {
	// Construct a valid signer then deliberately corrupt the underlying
	// jose signer reference so Sign() fails. This simulates the
	// failure mode where the key is loaded but the joseSigner state
	// is somehow inconsistent (a bug, not a configuration defect, but
	// the probe should still catch it).
	s, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.signer = nil
	s.mu.Unlock()
	if err := s.HealthCheck(); err == nil {
		t.Error("HealthCheck should detect nil joseSigner state")
	}
}
