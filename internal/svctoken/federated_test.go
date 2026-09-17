// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// foreignSigner mints JWTs signed by a key NOT in the Falcon-ID JWKS
// — simulates Harbor's /service/token endpoint signing with its own
// internal RSA key. Yields the *rsa.PublicKey + a signer the test
// uses to mint sample tokens.
type foreignSigner struct {
	priv   *rsa.PrivateKey
	signer jose.Signer
}

func newForeignSigner(t *testing.T) *foreignSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "foreign-key-1"),
	)
	if err != nil {
		t.Fatalf("new foreign signer: %v", err)
	}
	return &foreignSigner{priv: priv, signer: signer}
}

func (s *foreignSigner) pubKey() *rsa.PublicKey { return &s.priv.PublicKey }

// mintForeign mints a Harbor-shaped JWT (iss + aud + exp, no
// Falcon-ID-specific extra claims). The audience is a label (not a
// URL) to mirror Harbor's "harbor-registry" convention. Optional
// overrides on issuer / aud / exp let tests drive sig-only-but-exp-
// expired / wrong-iss / etc. cases.
func (s *foreignSigner) mint(t *testing.T, issuer, audience string, exp time.Time) string {
	t.Helper()
	if exp.IsZero() {
		exp = time.Now().Add(5 * time.Minute)
	}
	std := jwt.Claims{
		Issuer:   issuer,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(exp),
		ID:       "foreign-jti-" + time.Now().Format("150405.000000000"),
	}
	tok, err := jwt.Signed(s.signer).Claims(std).Serialize()
	if err != nil {
		t.Fatalf("sign foreign jwt: %v", err)
	}
	return tok
}

// TestFederated_HappyPath — Harbor-shaped JWT signed by the federated
// issuer's key verifies successfully via VerifyFederated. Mirrors the
// canonical Harbor flow: docker client retries /v2/<repo>/manifests/
// <tag> with Authorization: Bearer <harbor-jwt>, Talon admits.
func TestFederated_HappyPath(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"ghcr.io/dogukanturhal"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier with federated: %v", err)
	}
	tok := fs.mint(t, "harbor-token-issuer", "harbor-registry", time.Time{})
	iss, err := v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if err != nil {
		t.Fatalf("VerifyFederated: %v", err)
	}
	if iss != "harbor-token-issuer" {
		t.Errorf("got iss=%q want harbor-token-issuer", iss)
	}
}

// TestFederated_UnknownIssuer_Rejected — the CVE-2021-21378 invariant.
// A JWT signed by an unknown issuer MUST be rejected, NEVER treated as
// missing-token-passthrough-eligible. Confirms Talon mirrors the
// Envoy/Istio tier-1 safety property.
func TestFederated_UnknownIssuer_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "some-other-issuer", "harbor-registry", time.Time{})
	_, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("unknown iss: want ErrIssuerMismatch, got %v", err)
	}
}

// TestFederated_WrongSigner_Rejected — a JWT claiming the federated
// issuer's iss but signed by a DIFFERENT key MUST 401. Defends against
// the attack "iss-claim-fake-out" where an attacker copies a victim's
// iss string into a forged token.
func TestFederated_WrongSigner_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	attacker := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Attacker mints a token CLAIMING harbor-token-issuer but signing
	// with their own key.
	tok := attacker.mint(t, "harbor-token-issuer", "harbor-registry", time.Time{})
	_, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("forged sig under known iss: want ErrSignatureInvalid, got %v", err)
	}
}

// TestFederated_Expired_Rejected — exp is the one universal claim
// every federated issuer must carry. A JWT with exp in the past MUST
// reject, even though audience + scope are not enforced.
func TestFederated_Expired_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "harbor-token-issuer", "harbor-registry", time.Now().Add(-1*time.Hour))
	_, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired federated: want ErrTokenExpired, got %v", err)
	}
}

// TestFederated_HostScopingEnforced — AllowedHosts confused-deputy
// guard. A federated issuer pinned to ghcr.io/dogukanturhal MUST NOT
// accept a token presented to a DIFFERENT route (vault.example.com,
// github.com, etc.). This is the mitigation against
// per-issuer scope bleed-across-vhosts called out in deep-research
// finding #10.
func TestFederated_HostScopingEnforced(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"ghcr.io/dogukanturhal"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "harbor-token-issuer", "harbor-registry", time.Time{})
	// Present a valid Harbor token to vault.example.com — must reject.
	_, err = v.VerifyFederated(context.Background(), tok, "vault.example.com")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("wrong-host federated: want ErrIssuerMismatch, got %v", err)
	}
	// Same token to the allowed host — must succeed.
	if _, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal"); err != nil {
		t.Errorf("right-host federated: want nil, got %v", err)
	}
}

// TestFederated_AllowedHostsEmpty_AcceptsAnyHost — when a federated
// issuer has no AllowedHosts (empty list), it applies to any route
// running AuthModeBearerOrFederatedPassthrough. Useful for issuers
// whose tokens are legitimately presented on multiple hosts.
func TestFederated_AllowedHostsEmpty_AcceptsAnyHost(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "wildcard-issuer",
			StaticPublicKey: fs.pubKey(),
			// AllowedHosts: nil — applies everywhere
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "wildcard-issuer", "any-aud", time.Time{})
	for _, h := range []string{"a.example.com", "b.example.com"} {
		if _, err := v.VerifyFederated(context.Background(), tok, h); err != nil {
			t.Errorf("empty AllowedHosts for host=%s: want nil, got %v", h, err)
		}
	}
}

// TestFederated_PrimaryStillVerifiesNormally — adding federated
// issuers MUST NOT change how the primary Falcon-ID verifier works
// for primary-issuer JWTs. Single-issuer regression guard for the
// 100% of existing routes that don't run the federated mode.
func TestFederated_PrimaryStillVerifiesNormally(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fid.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	claims, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if err != nil {
		t.Fatalf("primary verify of Falcon-ID JWT: %v", err)
	}
	if claims.ClientID != "svc-argocd-repo-server" {
		t.Errorf("claims.ClientID got %q want svc-argocd-repo-server", claims.ClientID)
	}
}

// TestFederated_PrimaryIssuerCollision_Rejected — operator misconfig
// guard. A FederatedIssuerConfig.Issuer that equals the primary
// ExpectedIssuer is rejected at construction time (NewVerifier
// returns error). Same iss with two different signers is undefined
// behaviour.
func TestFederated_PrimaryIssuerCollision_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	_, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "https://id.test", // collision with primary
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err == nil {
		t.Error("NewVerifier with primary-iss collision: want error, got nil")
	}
}

// TestFederated_DuplicateIssuersInList_Rejected — operator misconfig
// guard. Two FederatedIssuerConfig entries with the same iss is
// undefined; reject at construction.
func TestFederated_DuplicateIssuersInList_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	_, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{
			{Issuer: "dup", StaticPublicKey: fs.pubKey()},
			{Issuer: "dup", StaticPublicKey: fs.pubKey()},
		},
	})
	if err == nil {
		t.Error("NewVerifier with duplicate federated iss: want error, got nil")
	}
}

// TestFederated_MissingKey_Rejected — config validation: each
// federated issuer must have a StaticPublicKey (or JWKSURL once
// implemented).
func TestFederated_MissingKey_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	_, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer: "no-key",
		}},
	})
	if err == nil {
		t.Error("NewVerifier with federated issuer missing key: want error, got nil")
	}
}

// TestFederated_BothKeyAndJWKS_Rejected — config validation: not
// both static + JWKS-URL on the same federated issuer.
func TestFederated_BothKeyAndJWKS_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	_, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "both-keys",
			StaticPublicKey: fs.pubKey(),
			JWKSURL:         "https://example.com/jwks.json",
		}},
	})
	if err == nil {
		t.Error("NewVerifier with both StaticPublicKey + JWKSURL: want error, got nil")
	}
}

// TestFederated_JWKSURLOnly_NotYetSupported — JWKSURL-backed federated
// issuers are reserved for a follow-up MR. The current code path
// returns an explicit error so operators don't think a config typo
// is being silently accepted.
func TestFederated_JWKSURLOnly_NotYetSupported(t *testing.T) {
	fid := newTokenFactory(t)
	_, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:  "jwks-only-issuer",
			JWKSURL: "https://example.com/jwks.json",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "JWKSURL-backed federated issuers not yet supported") {
		t.Errorf("JWKSURL-only federated: want unsupported-yet error, got %v", err)
	}
}

// TestFederated_AlgNotRS256_Rejected — same RFC 8725 §3.3 alg
// whitelist as the primary verifier applies to federated. A token
// signed with HS256 (or none, or RS512) MUST reject.
func TestFederated_AlgNotRS256_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Sign with HS256 — not in allowedAlgorithms.
	hsSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("hs256 signer: %v", err)
	}
	std := jwt.Claims{
		Issuer:   "harbor-token-issuer",
		Audience: jwt.Audience{"harbor-registry"},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}
	tok, err := jwt.Signed(hsSigner).Claims(std).Serialize()
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	_, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("HS256 federated: want ErrAlgNotAllowed, got %v", err)
	}
}

// TestFederated_EmptyToken_Rejected — defense.
func TestFederated_EmptyToken_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err = v.VerifyFederated(context.Background(), "", "ghcr.io/dogukanturhal"); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("empty federated token: want ErrTokenMalformed, got %v", err)
	}
}

// TestFederated_NoIssuers_ReturnsConfigError — VerifyFederated with
// an empty registry returns ErrIssuerMismatch immediately so the
// middleware's iss-mismatch fallback doesn't accidentally admit
// anything.
func TestFederated_NoIssuers_ReturnsConfigError(t *testing.T) {
	fid := newTokenFactory(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		// no FederatedIssuers
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	fs := newForeignSigner(t)
	tok := fs.mint(t, "harbor-token-issuer", "harbor-registry", time.Time{})
	_, err = v.VerifyFederated(context.Background(), tok, "ghcr.io/dogukanturhal")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("empty federated registry: want ErrIssuerMismatch, got %v", err)
	}
	if v.HasFederatedIssuers() {
		t.Error("HasFederatedIssuers: want false on empty registry")
	}
}

// TestParseRSAPublicKeyPEM — round-trip operators' typical wire form
// (PEM string in Helm values) through the helper.
func TestParseRSAPublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	// Encode as PKIX (BEGIN PUBLIC KEY) — what `openssl rsa -pubout`
	// emits, the canonical wire form.
	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pkixPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixBytes})
	pub, err := ParseRSAPublicKeyPEM(pkixPEM)
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyPEM PKIX: %v", err)
	}
	if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Error("ParseRSAPublicKeyPEM PKIX: key mismatch")
	}
	// Also PKCS#1 (BEGIN RSA PUBLIC KEY).
	pkcs1Bytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1Bytes})
	pub2, err := ParseRSAPublicKeyPEM(pkcs1PEM)
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyPEM PKCS1: %v", err)
	}
	if pub2.N.Cmp(priv.N) != 0 {
		t.Error("ParseRSAPublicKeyPEM PKCS1: key mismatch")
	}
	// Garbage in → error out.
	if _, err := ParseRSAPublicKeyPEM([]byte("not a pem")); err == nil {
		t.Error("ParseRSAPublicKeyPEM(garbage): want error")
	}
}

// TestDecide_BearerOrFederatedPassthrough_HarborBearer_Passthrough —
// the end-to-end middleware test. Confirms the new AuthMode wires the
// federated-verify into the iss-mismatch fallback correctly.
func TestDecide_BearerOrFederatedPassthrough_HarborBearer_Passthrough(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"ghcr.io/dogukanturhal"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "harbor-token-issuer", "harbor-registry", time.Time{})
	r := httptest.NewRequest("GET", "https://ghcr.io/dogukanturhal/v2/platform/talon/manifests/latest", nil)
	r.Host = "ghcr.io/dogukanturhal"
	r.Header.Set("Authorization", "Bearer "+tok)
	d := v.Decide(r, AuthModeBearerOrFederatedPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("Harbor-Bearer federated: want OutcomePassthrough, got %v (err=%v)", d.Outcome, d.Err)
	}
	if d.Claims != nil {
		t.Errorf("federated passthrough: want nil Claims (foreign issuer shape), got %+v", d.Claims)
	}
}

// TestDecide_BearerOrFederatedPassthrough_UnknownIssuer_Rejected —
// CVE-2021-21378 invariant at the middleware layer. A Bearer whose iss
// is neither primary NOR federated MUST OutcomeRejected, never
// OutcomePassthrough — preserves the no-silent-downgrade property.
func TestDecide_BearerOrFederatedPassthrough_UnknownIssuer_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	attacker := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"ghcr.io/dogukanturhal"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Attacker mints a token claiming an issuer NOT in either set.
	tok := attacker.mint(t, "evil-issuer", "harbor-registry", time.Time{})
	r := httptest.NewRequest("GET", "https://ghcr.io/dogukanturhal/v2/", nil)
	r.Host = "ghcr.io/dogukanturhal"
	r.Header.Set("Authorization", "Bearer "+tok)
	d := v.Decide(r, AuthModeBearerOrFederatedPassthrough)
	if d.Outcome != OutcomeRejected {
		t.Errorf("unknown-iss federated: want OutcomeRejected, got %v (err=%v)", d.Outcome, d.Err)
	}
}

// TestDecide_BearerOrFederatedPassthrough_NoBearer_Passthrough — first
// leg of Docker Registry v2 challenge: GET /v2/ with no auth → Talon
// passes through, Harbor returns the Bearer-realm challenge.
func TestDecide_BearerOrFederatedPassthrough_NoBearer_Passthrough(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	r := httptest.NewRequest("GET", "https://ghcr.io/dogukanturhal/v2/", nil)
	r.Host = "ghcr.io/dogukanturhal"
	d := v.Decide(r, AuthModeBearerOrFederatedPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("no-Bearer federated: want OutcomePassthrough, got %v", d.Outcome)
	}
}

// TestDecide_BearerOrFederatedPassthrough_FalconIDBearer_Authorised —
// primary issuer still verified normally even when federated is also
// configured. Confirms the existing single-issuer path is untouched
// for backward compat.
func TestDecide_BearerOrFederatedPassthrough_FalconIDBearer_Authorised(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "harbor-token-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"ghcr.io/dogukanturhal"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fid.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-something",
		audience: "https://ghcr.io/dogukanturhal",
		clientID: "svc-something",
		// GET /v2/ classifies as VerbPull per VerbForRequest; scope
		// must be ":pull" not ":read" to match the Docker Registry v2
		// verb namespace.
		scope: "talon:ghcr.io/dogukanturhal:pull",
	})
	r := httptest.NewRequest("GET", "https://ghcr.io/dogukanturhal/v2/", nil)
	r.Host = "ghcr.io/dogukanturhal"
	r.Header.Set("Authorization", "Bearer "+tok)
	d := v.Decide(r, AuthModeBearerOrFederatedPassthrough)
	if d.Outcome != OutcomeAuthorised {
		t.Errorf("Falcon-ID-Bearer federated mode: want OutcomeAuthorised, got %v (err=%v)", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.ClientID != "svc-something" {
		t.Errorf("Falcon-ID-Bearer federated mode: missing/wrong Claims, got %+v", d.Claims)
	}
}

// TestAuthMode_BearerOrFederatedPassthrough_IsValid — guards the
// validator + ensures the new value doesn't coerce to an existing
// mode by accident.
func TestAuthMode_BearerOrFederatedPassthrough_IsValid(t *testing.T) {
	if !AuthModeBearerOrFederatedPassthrough.IsValid() {
		t.Error("AuthModeBearerOrFederatedPassthrough must be a recognised AuthMode")
	}
	if AuthMode("bearer_or_federated_passthrough").IsValid() == false {
		t.Error("string form of bearer_or_federated_passthrough must validate")
	}
}
