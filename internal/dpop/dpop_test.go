// SPDX-License-Identifier: AGPL-3.0-or-later

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// makeKey returns a P-256 keypair for DPoP proof signing.
func makeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

// mintProof signs a DPoP proof JWT with the test key.
func mintProof(t *testing.T, key *ecdsa.PrivateKey, method, urlStr string, opts ...func(*dpopClaims)) string {
	t.Helper()
	claims := dpopClaims{
		HTM: method,
		HTU: urlStr,
		IAT: time.Now().Unix(),
		JTI: uuid.NewString(),
	}
	for _, o := range opts {
		o(&claims)
	}

	// EmbedJWK: true tells go-jose to put the *signing key's* public
	// half into the protected header under "jwk" — which is exactly
	// what DPoP requires. WithHeader("jwk", ...) does not embed the
	// JWK in the standard slot; go-jose stores it specially.
	signerKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: key, Algorithm: string(jose.ES256), Use: "sig"},
	}
	opts2 := &jose.SignerOptions{EmbedJWK: true}
	opts2 = opts2.WithType("dpop+jwt")
	signer, err := jose.NewSigner(signerKey, opts2)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

func TestVerifier_HappyPath(t *testing.T) {
	v, err := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	key := makeKey(t)
	u, _ := url.Parse("https://api.example.app/v1/foo")
	proof := mintProof(t, key, "POST", u.String())
	req := httpReq("POST", u.String(), proof)

	jkt, err := v.VerifyRequest(req, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if jkt == "" {
		t.Errorf("expected non-empty thumbprint")
	}
}

func TestVerifier_MissingProof(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	req := httptestRequest("GET", "https://api.example.app/")
	_, err := v.VerifyRequest(req, "")
	if !errors.Is(err, ErrMissingProof) {
		t.Errorf("want ErrMissingProof, got %v", err)
	}
}

func TestVerifier_HTMMismatch(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	key := makeKey(t)
	u := "https://api.example.app/v1/foo"
	proof := mintProof(t, key, "GET", u) // signed claims GET
	req := httpReq("POST", u, proof)     // request method POST
	_, err := v.VerifyRequest(req, "")
	if !errors.Is(err, ErrInvalidProof) {
		t.Errorf("want ErrInvalidProof, got %v", err)
	}
}

func TestVerifier_HTUMismatch(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	key := makeKey(t)
	proof := mintProof(t, key, "GET", "https://api.example.app/v1/foo")
	req := httpReq("GET", "https://api.example.app/v1/bar", proof)
	_, err := v.VerifyRequest(req, "")
	if !errors.Is(err, ErrInvalidProof) {
		t.Errorf("want ErrInvalidProof on HTU mismatch, got %v", err)
	}
}

func TestVerifier_IATSkew(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{
		Replay:  NewMemoryCache(0),
		IATSkew: 5 * time.Second,
	})
	key := makeKey(t)
	u := "https://api.example.app/v1/foo"
	// Mint with iat 5 minutes in the past
	proof := mintProof(t, key, "GET", u, func(c *dpopClaims) {
		c.IAT = time.Now().Add(-5 * time.Minute).Unix()
	})
	req := httpReq("GET", u, proof)
	_, err := v.VerifyRequest(req, "")
	if !errors.Is(err, ErrIATSkew) {
		t.Errorf("want ErrIATSkew, got %v", err)
	}
}

func TestVerifier_Replay(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	key := makeKey(t)
	u := "https://api.example.app/v1/foo"
	// Use a fixed JTI so the second presentation is detected as replay.
	fixedJTI := "fixed-jti-for-replay-test"
	proof := mintProof(t, key, "GET", u, func(c *dpopClaims) { c.JTI = fixedJTI })

	req1 := httpReq("GET", u, proof)
	if _, err := v.VerifyRequest(req1, ""); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	req2 := httpReq("GET", u, proof)
	_, err := v.VerifyRequest(req2, "")
	if !errors.Is(err, ErrReplay) {
		t.Errorf("want ErrReplay on second presentation, got %v", err)
	}
}

func TestVerifier_ATHMismatch(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	key := makeKey(t)
	u := "https://api.example.app/v1/foo"
	proof := mintProof(t, key, "GET", u, func(c *dpopClaims) { c.ATH = HashAccessToken("real-token") })

	req := httpReq("GET", u, proof)
	_, err := v.VerifyRequest(req, HashAccessToken("different-token"))
	if !errors.Is(err, ErrATHMismatch) {
		t.Errorf("want ErrATHMismatch, got %v", err)
	}
}

func TestVerifier_ATHAccept(t *testing.T) {
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	key := makeKey(t)
	u := "https://api.example.app/v1/foo"
	tok := "real-access-token"
	proof := mintProof(t, key, "GET", u, func(c *dpopClaims) { c.ATH = HashAccessToken(tok) })
	req := httpReq("GET", u, proof)
	if _, err := v.VerifyRequest(req, HashAccessToken(tok)); err != nil {
		t.Errorf("ath should accept, got %v", err)
	}
}

func TestVerifier_RejectSymmetricAlg(t *testing.T) {
	// Trying to pass HS256 as an allowed alg at construction time
	// returns an error — symmetric keys have no usable jwk-public form.
	_, err := NewVerifier(VerifierConfig{
		Replay:      NewMemoryCache(0),
		AllowedAlgs: []jose.SignatureAlgorithm{jose.HS256},
	})
	if err == nil {
		t.Errorf("want symmetric-rejected error, got nil")
	}
}

func TestVerifier_NormalizeHTU(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://API.example.App/v1/foo", "https://api.example.app/v1/foo"},
		{"https://api.example.app:443/v1/foo", "https://api.example.app/v1/foo"},
		{"http://example.com:80/", "http://example.com/"},
		{"https://api.example.app/v1?a=1", "https://api.example.app/v1?a=1"},
		{"https://api.example.app/v1#frag", "https://api.example.app/v1"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVerifier_HashAccessToken(t *testing.T) {
	// Stable, length, base64url-no-pad. The hash of "test" using
	// SHA-256 then base64url(no-pad) is the canonical fixture.
	h := HashAccessToken("test")
	if len(h) != 43 {
		t.Errorf("expected 43 chars (base64url of 32B SHA-256), got %d (%q)", len(h), h)
	}
	if h != "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg" {
		t.Errorf("hash drift: got %q", h)
	}
}

func TestVerifier_RejectsHMACEmbeddedInJWK(t *testing.T) {
	// If a malicious proof embeds an HS256-keyed JWS (which would
	// permit a forged signature), it must be rejected at parse-time
	// because alg HS256 is not in the allowlist.
	v, _ := NewVerifier(VerifierConfig{Replay: NewMemoryCache(0)})
	// Construct a JWS manually w/ alg HS256 — ParseSigned will refuse
	// since v.permittedAlgs() excludes HS256.
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256, Key: []byte("symmetric-secret-key-32-bytes-long-XX"),
	}, (&jose.SignerOptions{}).WithType("dpop+jwt"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(dpopClaims{
		HTM: "GET", HTU: "https://x/", IAT: time.Now().Unix(), JTI: "x",
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	req := httpReq("GET", "https://x/", tok)
	_, err = v.VerifyRequest(req, "")
	if err == nil {
		t.Errorf("HS256-signed DPoP must be rejected, got accepted")
	}
}

// httpReq builds a request with the DPoP header populated. Uses
// Header.Set so the canonical MIME header key is "Dpop", which is
// what req.Header.Get("DPoP") looks up internally.
func httpReq(method, urlStr, proof string) *http.Request {
	u, _ := url.Parse(urlStr)
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: http.Header{},
	}
	req.Header.Set("DPoP", proof)
	return req
}

// httptestRequest is a header-less request (no DPoP).
func httptestRequest(method, urlStr string) *http.Request {
	u, _ := url.Parse(urlStr)
	return &http.Request{Method: method, URL: u, Header: http.Header{}}
}
