// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// tokenFactory is a self-contained Falcon-ID JWT issuer used by tests.
// Spins up a httptest server that serves a JWKS containing the test
// signing key, so a Verifier configured against it exercises the
// real JWKS-fetch + signature-verify path (not a mocked verifier).
type tokenFactory struct {
	t       *testing.T
	priv    *rsa.PrivateKey
	kid     string
	signer  jose.Signer
	jwksURL string
	server  *httptest.Server
}

func newTokenFactory(t *testing.T) *tokenFactory {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	kid := "test-key-1"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &tokenFactory{
		t:       t,
		priv:    priv,
		kid:     kid,
		signer:  signer,
		jwksURL: srv.URL + "/.well-known/jwks.json",
		server:  srv,
	}
}

type claimOpts struct {
	issuer    string
	subject   string
	audience  string
	clientID  string
	tenantID  string
	scope     string
	jti       string
	notBefore time.Time
	issuedAt  time.Time
	expiresAt time.Time
	signer    jose.Signer // override for alg/kid tests
}

func (f *tokenFactory) mint(t *testing.T, o claimOpts) string {
	t.Helper()
	if o.issuer == "" {
		o.issuer = "https://id.test"
	}
	if o.issuedAt.IsZero() {
		o.issuedAt = time.Now()
	}
	if o.expiresAt.IsZero() {
		o.expiresAt = o.issuedAt.Add(1 * time.Hour)
	}
	if o.jti == "" {
		o.jti = "jti-" + time.Now().Format("150405.000000000")
	}
	std := jwt.Claims{
		Issuer:   o.issuer,
		Subject:  o.subject,
		Audience: jwt.Audience{o.audience},
		IssuedAt: jwt.NewNumericDate(o.issuedAt),
		Expiry:   jwt.NewNumericDate(o.expiresAt),
		ID:       o.jti,
	}
	if !o.notBefore.IsZero() {
		std.NotBefore = jwt.NewNumericDate(o.notBefore)
	}
	extra := extraClaims{ClientID: o.clientID, TenantID: o.tenantID, Scope: o.scope}
	signer := o.signer
	if signer == nil {
		signer = f.signer
	}
	tok, err := jwt.Signed(signer).Claims(std).Claims(extra).Serialize()
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return tok
}

func newVerifierAgainst(t *testing.T, f *tokenFactory, issuer string, opts ...func(*VerifierConfig)) *Verifier {
	t.Helper()
	cfg := VerifierConfig{JWKSURL: f.jwksURL, ExpectedIssuer: issuer}
	for _, o := range opts {
		o(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerify_HappyPath(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		tenantID: "tenant-uuid",
		scope:    "talon:github.com:read",
	})
	claims, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "svc-argocd-repo-server" {
		t.Errorf("Subject = %q, want svc-argocd-repo-server", claims.Subject)
	}
	if claims.ClientID != "svc-argocd-repo-server" {
		t.Errorf("ClientID = %q, want svc-argocd-repo-server", claims.ClientID)
	}
	if claims.Audience != "https://github.com" {
		t.Errorf("Audience = %q, want https://github.com", claims.Audience)
	}
	if claims.TenantID != "tenant-uuid" {
		t.Errorf("TenantID = %q, want tenant-uuid", claims.TenantID)
	}
	if !claims.IsMachine() {
		t.Error("IsMachine should be true for svctoken claims")
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://attacker.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
	})
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("want ErrIssuerMismatch, got %v", err)
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://registry.example.com", // bound to harbor
		scope:    "talon:registry.example.com:pull",
	})
	// But presented at github.com — audience confusion attack.
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("want ErrAudienceMismatch, got %v", err)
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	now := time.Now()
	tok := f.mint(t, claimOpts{
		issuer:    "https://id.test",
		audience:  "https://github.com",
		scope:     "talon:github.com:read",
		issuedAt:  now.Add(-2 * time.Hour),
		expiresAt: now.Add(-1 * time.Hour),
	})
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerify_RejectsNotYetValid(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	now := time.Now()
	tok := f.mint(t, claimOpts{
		issuer:    "https://id.test",
		audience:  "https://github.com",
		scope:     "talon:github.com:read",
		notBefore: now.Add(1 * time.Hour),
		issuedAt:  now.Add(1 * time.Hour),
		expiresAt: now.Add(2 * time.Hour),
	})
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrTokenNotYetValid) {
		t.Errorf("want ErrTokenNotYetValid, got %v", err)
	}
}

func TestVerify_RejectsInsufficientScope(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read", // read-only
	})
	// Requesting write
	_, err := v.Verify(context.Background(), tok, "github.com", VerbWrite)
	if !errors.Is(err, ErrScopeInsufficient) {
		t.Errorf("want ErrScopeInsufficient, got %v", err)
	}
}

func TestVerify_AllowsAdminScopeForAllVerbs(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	for _, verb := range []Verb{VerbRead, VerbWrite, VerbPull, VerbPush} {
		t.Run(string(verb), func(t *testing.T) {
			tok := f.mint(t, claimOpts{
				issuer:   "https://id.test",
				audience: "https://registry.example.com",
				scope:    "talon:registry.example.com:admin",
			})
			_, err := v.Verify(context.Background(), tok, "registry.example.com", verb)
			if err != nil {
				t.Errorf("verb %s: unexpected error %v", verb, err)
			}
		})
	}
}

func TestVerify_AllowsBreakGlassProxy(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:proxy",
	})
	_, err := v.Verify(context.Background(), tok, "github.com", VerbWrite)
	if err != nil {
		t.Errorf("break-glass should grant write: %v", err)
	}
}

func TestVerify_RejectsForgedSignature(t *testing.T) {
	f := newTokenFactory(t)
	// Build a token signed by a DIFFERENT key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongSigner, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: other},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), f.kid),
	)
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
		signer:   wrongSigner,
	})
	v := newVerifierAgainst(t, f, "https://id.test")
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("want ErrSignatureInvalid, got %v", err)
	}
}

func TestVerify_RejectsHS256(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")

	// Hand-craft a minimal HS256 JWT: the parser must reject before sig check.
	// jose v4's signer enforces alg at sign time; instead, construct a token
	// claiming alg:HS256 manually via a wrong signer doesn't work either —
	// the verifier's allowedAlgorithms whitelist enforces at ParseSigned.
	hmacSecret := []byte("0123456789abcdef0123456789abcdef")
	hsSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmacSecret},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), f.kid),
	)
	if err != nil {
		t.Fatalf("hs signer: %v", err)
	}
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
		signer:   hsSigner,
	})
	_, err = v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("want ErrAlgNotAllowed, got %v", err)
	}
}

func TestVerify_RejectsReplay(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test", func(c *VerifierConfig) {
		c.ReplayCacheSize = 1024
	})
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
		jti:      "fixed-jti-replay",
	})
	// First use OK.
	if _, err := v.Verify(context.Background(), tok, "github.com", VerbRead); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Replay rejected.
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrReplay) {
		t.Errorf("replay: want ErrReplay, got %v", err)
	}
}

// fakeRevocation implements RevocationStore.
type fakeRevocation struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (f *fakeRevocation) IsRevoked(_ context.Context, jti string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[jti]
}

func TestVerify_RejectsRevoked(t *testing.T) {
	f := newTokenFactory(t)
	revStore := &fakeRevocation{revoked: map[string]bool{"banned-jti": true}}
	v := newVerifierAgainst(t, f, "https://id.test", func(c *VerifierConfig) {
		c.RevocationStore = revStore
	})
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
		jti:      "banned-jti",
	})
	_, err := v.Verify(context.Background(), tok, "github.com", VerbRead)
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("want ErrRevoked, got %v", err)
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	_, err := v.Verify(context.Background(), "this.is.not.a.jwt", "github.com", VerbRead)
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("want ErrTokenMalformed, got %v", err)
	}
	// Empty.
	_, err = v.Verify(context.Background(), "", "github.com", VerbRead)
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("empty: want ErrTokenMalformed, got %v", err)
	}
}

func TestVerify_RejectsEmptyExpectedAudience(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
	})
	_, err := v.Verify(context.Background(), tok, "", VerbRead) // empty host
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("empty host: want ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifyRequest_BearerExtraction(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
	})

	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "github.com"
	if _, err := v.VerifyRequest(r); err != nil {
		t.Errorf("Bearer extraction: %v", err)
	}

	// Case-insensitive scheme.
	r.Header.Set("Authorization", "bearer "+tok)
	if _, err := v.VerifyRequest(r); err != nil {
		t.Errorf("case-insensitive Bearer: %v", err)
	}

	// No header.
	r.Header.Del("Authorization")
	_, err := v.VerifyRequest(r)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("no header: want ErrNoToken, got %v", err)
	}

	// Wrong scheme.
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err = v.VerifyRequest(r)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("Basic scheme: want ErrNoToken, got %v", err)
	}
}

func TestDecide_CookieOnly(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		audience: "https://github.com",
		scope:    "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookie)
	if d.Outcome != OutcomeNotAttempted {
		t.Errorf("cookie-only mode should not attempt bearer; got %v", d.Outcome)
	}
}

func TestDecide_BearerOnly_NoHeader_Rejected(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearer)
	if d.Outcome != OutcomeRejected {
		t.Errorf("bearer-only + no header: want OutcomeRejected, got %v", d.Outcome)
	}
}

func TestDecide_Both_NoHeader_Fallthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBoth)
	if d.Outcome != OutcomeNotAttempted {
		t.Errorf("both + no header: want OutcomeNotAttempted, got %v", d.Outcome)
	}
}

func TestDecide_Both_BadHeader_Fallthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer not-a-jwt")
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBoth)
	if d.Outcome != OutcomeFallthrough {
		t.Errorf("both + bad header: want OutcomeFallthrough, got %v", d.Outcome)
	}
	if d.Err == nil || !strings.Contains(d.Err.Error(), "malformed") {
		t.Errorf("want malformed err, got %v", d.Err)
	}
}

func TestDecide_Both_GoodHeader_Authorised(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-image-updater",
		audience: "https://registry.example.com",
		clientID: "svc-image-updater",
		scope:    "talon:registry.example.com:pull",
	})
	r := httptest.NewRequest(http.MethodGet, "https://registry.example.com/v2/foo/manifests/latest", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "registry.example.com"
	d := v.Decide(r, AuthModeBoth)
	if d.Outcome != OutcomeAuthorised {
		t.Errorf("both + good header: want OutcomeAuthorised, got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.Subject != "svc-image-updater" {
		t.Errorf("missing or wrong claims: %+v", d.Claims)
	}
	if d.Request == nil || ClaimsFromContext(d.Request.Context()) != d.Claims {
		t.Error("Claims not attached to request context")
	}
}

func TestDecide_InvalidMode_Rejected(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://x/", nil)
	r.Host = "x"
	d := v.Decide(r, AuthMode("garbage"))
	if d.Outcome != OutcomeRejected {
		t.Errorf("invalid mode: want OutcomeRejected, got %v", d.Outcome)
	}
}

// TestDecide_BearerOrPassthrough_NoHeader_Passthrough — Atlantis/
// Renovate/legacy-PAT callers send Authorization: Basic, which is NOT
// a Bearer header → extractBearer returns ErrNoToken. Under the
// enterprise mode, the router must proxy directly to upstream so
// GitLab/Harbor handle the Basic PAT natively. Without this contract,
// putting Talon in front of github.com would break every
// existing CI consumer.
func TestDecide_BearerOrPassthrough_NoHeader_Passthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("no header passthrough: want OutcomePassthrough, got %v", d.Outcome)
	}
}

// TestDecide_BearerOrPassthrough_BasicHeader_Passthrough — same as
// above but with an explicit Authorization: Basic header. Confirms
// that Basic doesn't accidentally take the bearer path.
func TestDecide_BearerOrPassthrough_BasicHeader_Passthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Basic b2F1dGgyOmdscGF0LXh4eA==") // oauth2:glpat-xxx
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("Basic header passthrough: want OutcomePassthrough, got %v", d.Outcome)
	}
}

// TestDecide_BearerOrPassthrough_GoodHeader_Authorised — canary
// path: valid Bearer JWT short-circuits to authorised + claims attached.
func TestDecide_BearerOrPassthrough_GoodHeader_Authorised(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrPassthrough)
	if d.Outcome != OutcomeAuthorised {
		t.Errorf("good header: want OutcomeAuthorised, got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.Subject != "svc-argocd-repo-server" {
		t.Errorf("missing claims on authorised passthrough: %+v", d.Claims)
	}
}

// TestDecide_BearerOrPassthrough_BadHeader_Rejected — defense-in-depth:
// a present-but-broken Bearer is an explicit identity assertion. It
// MUST be rejected, not silently passthroughed (which would let an
// attacker who minted a forged Bearer fall back to no-auth on hosts
// where the upstream is permissive).
func TestDecide_BearerOrPassthrough_BadHeader_Rejected(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer not-a-jwt")
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrPassthrough)
	if d.Outcome != OutcomeRejected {
		t.Errorf("bad bearer must NOT passthrough: want OutcomeRejected, got %v", d.Outcome)
	}
}

// TestAuthMode_BearerOrPassthrough_IsValid — guards the validator
// against a regression that would coerce the new value to AuthModeCookie
// (the silent-downgrade-to-cookie path was the entire problem we built
// this mode to avoid).
func TestAuthMode_BearerOrPassthrough_IsValid(t *testing.T) {
	if !AuthModeBearerOrPassthrough.IsValid() {
		t.Error("bearer_or_passthrough must be a recognised AuthMode")
	}
	if AuthMode("bearer_or_passthrough").IsValid() == false {
		t.Error("string form of bearer_or_passthrough must validate")
	}
}

// === Phase 4.5 — credential exchange tests ===

// TestExtractJWTFromBasicPassword_Positives covers the Basic-as-JWT
// shapes the credential-exchange mode must accept. Username slot is
// irrelevant by design — ArgoCD's go-git uses "oauth2", harbor's
// docker client uses the robot-account name, etc.
func TestExtractJWTFromBasicPassword_Positives(t *testing.T) {
	// First segment must be a real JOSE header — a run of filler chars is
	// not one, and is exactly the shape GitLab's job tokens have.
	joseHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	jwt := joseHdr + "." + strings.Repeat("b", 14) + "." + strings.Repeat("c", 18)
	cases := []struct{ user string }{
		{"oauth2"}, {""}, {"any-thing"}, {"x"},
	}
	for _, tc := range cases {
		raw := tc.user + ":" + jwt
		hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
		got, ok := extractJWTFromBasicPassword(hdr)
		if !ok {
			t.Errorf("user=%q: want ok, got false", tc.user)
			continue
		}
		if got != jwt {
			t.Errorf("user=%q: got=%q want=jwt", tc.user, got)
		}
	}
}

// TestExtractJWTFromBasicPassword_Negatives covers the non-JWT
// shapes that MUST fall through (passthrough preserves original
// Authorization — without this, legacy PATs would be misclassified).
func TestExtractJWTFromBasicPassword_Negatives(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
	}{
		{"empty", ""},
		{"only scheme", "Basic"},
		{"scheme with space", "Basic "},
		{"bearer scheme", "Bearer aaa.bbb.ccc"},
		{"malformed base64", "Basic !!!"},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
		{"empty password", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"))},
		{"PAT password", "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-AbC123"))},
		{"2-segment password", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:aaaaaaaaaaa.bbbbbbbbbbb"))},
		{"4-segment password", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:aaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc.dddddddddd"))},
		{"short segments", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:a.b.c"))},

		// Regression: GitLab 18 routable CI job tokens are three
		// dot-separated segments (observed 112/327/342 chars) and so
		// satisfied the old count+length shape test. Being hijacked here
		// made Talon answer a Bearer challenge that no Basic client can
		// meet, failing closed with no usable retry — it broke every
		// `gitlab-ci-token:$CI_JOB_TOKEN` fetch and every kaniko push to
		// the in-cluster registry. The first segment is not a JOSE header,
		// which is what must disqualify it.
		{"gitlab job token (glcbt-)", "Basic " + base64.StdEncoding.EncodeToString([]byte(
			"gitlab-ci-token:glcbt-"+strings.Repeat("A", 106)+"."+strings.Repeat("B", 327)+"."+strings.Repeat("C", 342)))},
		{"gitlab runner token (glrt-)", "Basic " + base64.StdEncoding.EncodeToString([]byte(
			"u:glrt-"+strings.Repeat("A", 106)+"."+strings.Repeat("B", 60)+"."+strings.Repeat("C", 60)))},
		// Three long segments that decode to valid base64url but are not
		// JSON at all — the generic form of the same class.
		{"3 long non-JOSE segments", "Basic " + base64.StdEncoding.EncodeToString([]byte(
			"u:"+strings.Repeat("a", 12)+"."+strings.Repeat("b", 14)+"."+strings.Repeat("c", 18)))},
		// Decodes to valid JSON but carries no "alg" — not a JOSE header.
		{"JSON without alg", "Basic " + base64.StdEncoding.EncodeToString([]byte(
			"u:"+base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","kid":"abc"}`))+
				"."+strings.Repeat("b", 14)+"."+strings.Repeat("c", 18)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := extractJWTFromBasicPassword(tc.hdr); ok {
				t.Errorf("%s: want fall-through, got positive match", tc.name)
			}
		})
	}
}

func TestVerifyRequestBearerOrBasic_BearerFirst(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer: "https://id.test", subject: "svc-x",
		audience: "https://github.com",
		clientID: "svc-x", scope: "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "github.com"
	claims, err := v.VerifyRequestBearerOrBasic(r)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if claims.ClientID != "svc-x" {
		t.Errorf("ClientID = %q", claims.ClientID)
	}
}

// TestVerifyRequestBearerOrBasic_BasicWithJWTPassword — the wire
// shape ArgoCD's go-git produces from a repoCreds Secret.
func TestVerifyRequestBearerOrBasic_BasicWithJWTPassword(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer: "https://id.test", subject: "svc-x",
		audience: "https://github.com",
		clientID: "svc-x", scope: "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("oauth2:"+tok)))
	r.Host = "github.com"
	claims, err := v.VerifyRequestBearerOrBasic(r)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if claims.ClientID != "svc-x" {
		t.Errorf("ClientID = %q", claims.ClientID)
	}
}

func TestVerifyRequestBearerOrBasic_NoToken(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-PAT")))
	r.Host = "github.com"
	_, err := v.VerifyRequestBearerOrBasic(r)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("legacy PAT: want ErrNoToken, got %v", err)
	}
}

func TestDecide_CredentialExchange_BasicWithJWT_Authorised(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer: "https://id.test", subject: "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("oauth2:"+tok)))
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrBasicWithCredentialExchange)
	if d.Outcome != OutcomeAuthorised {
		t.Fatalf("want OutcomeAuthorised, got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.ClientID != "svc-argocd-repo-server" {
		t.Errorf("claims = %+v", d.Claims)
	}
}

// TestDecide_CredentialExchange_LegacyPAT_Passthrough — without
// this contract, every existing Atlantis/Renovate/image-updater
// caller on the same host breaks when the new mode lands.
func TestDecide_CredentialExchange_LegacyPAT_Passthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-LegacyPATValue")))
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrBasicWithCredentialExchange)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("legacy PAT must passthrough: got %v err=%v", d.Outcome, d.Err)
	}
}

func TestDecide_CredentialExchange_NoAuth_Passthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrBasicWithCredentialExchange)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("anon: got %v", d.Outcome)
	}
}

// TestDecide_CredentialExchange_BadBearer_Rejected — same safety
// property as bearer_or_passthrough: present-but-broken Bearer is an
// explicit identity assertion and MUST 401. Silently downgrading to
// passthrough would let an attacker with a forged Bearer get free
// access on permissive upstreams.
func TestDecide_CredentialExchange_BadBearer_Rejected(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer aaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc")
	r.Host = "github.com"
	d := v.Decide(r, AuthModeBearerOrBasicWithCredentialExchange)
	if d.Outcome != OutcomeRejected {
		t.Errorf("bad bearer must reject: got %v err=%v", d.Outcome, d.Err)
	}
}

func TestAuthMode_BearerOrBasicWithCredentialExchange_IsValid(t *testing.T) {
	if !AuthModeBearerOrBasicWithCredentialExchange.IsValid() {
		t.Error("bearer_or_basic_with_credential_exchange must validate")
	}
	if !AuthMode("bearer_or_basic_with_credential_exchange").IsValid() {
		t.Error("string form must validate")
	}
}

// TestReplayLRU_EvictsOldest checks LRU semantics + TTL recycling
// under capacity pressure.
func TestReplayLRU_EvictsOldest(t *testing.T) {
	c := newReplayLRU(3)
	if c.SeenOrAdd("a", time.Hour) {
		t.Error("a fresh")
	}
	if c.SeenOrAdd("b", time.Hour) {
		t.Error("b fresh")
	}
	if c.SeenOrAdd("c", time.Hour) {
		t.Error("c fresh")
	}
	// d fills, a evicts.
	if c.SeenOrAdd("d", time.Hour) {
		t.Error("d fresh")
	}
	if c.Len() != 3 {
		t.Errorf("len=%d, want 3", c.Len())
	}
	// a was evicted — first sighting again.
	if c.SeenOrAdd("a", time.Hour) {
		t.Error("a should be evicted and fresh again")
	}
}

func TestReplayLRU_TTLExpiry(t *testing.T) {
	c := newReplayLRU(8)
	if c.SeenOrAdd("expiring", 1*time.Millisecond) {
		t.Error("first should be fresh")
	}
	time.Sleep(5 * time.Millisecond)
	if c.SeenOrAdd("expiring", time.Hour) {
		t.Error("after TTL expiry, should treat as fresh")
	}
}

func TestReplayLRU_EmptyJTI_NoTrack(t *testing.T) {
	c := newReplayLRU(8)
	if c.SeenOrAdd("", time.Hour) {
		t.Error("empty jti should not be tracked")
	}
	if c.SeenOrAdd("", time.Hour) {
		t.Error("empty jti second time also fresh (untracked)")
	}
	if c.Len() != 0 {
		t.Errorf("empty jti should not occupy slots; len=%d", c.Len())
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer  multi  space ", "multi  space", true},
		{"", "", false},
		{"Basic dXNlcjpwYXNz", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
	}
	for _, tc := range cases {
		got, ok := extractBearer(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("extractBearer(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
