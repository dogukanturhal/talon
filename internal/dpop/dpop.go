// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dpop — RFC 9449 (DPoP / Demonstrating Proof of Possession)
// verifier for service-to-service Bearer tokens.
//
// DPoP binds an access token to the holder of a specific keypair.
// The bearer presents:
//
//	Authorization: DPoP <access-token>
//	DPoP:          <dpop-proof-jwt>
//
// Where the access token carries `cnf.jkt = <jwk-thumbprint>` (RFC
// 7638 thumbprint of the public key the bearer holds), and the DPoP
// proof JWT is signed by the matching private key and includes:
//
//	header.typ = "dpop+jwt"
//	header.alg = <one of the allowed asymmetric algs>
//	header.jwk = <public key in JWK form>
//	payload.htm = <upper-case HTTP method>
//	payload.htu = <RFC 3986 §6.2.2-normalized URI: lowercase
//	                scheme + host, default port elided, fragment
//	                stripped, query preserved — see Normalize()>
//	payload.iat = <unix seconds>
//	payload.jti = <unique-per-proof id>
//	payload.ath = <base64url(SHA-256(access-token))>     // when binding
//	payload.nonce = <server-issued nonce>                // when DPoP nonce in play
//
// Tier-1 verification (this package):
//
//  1. Parse + validate the DPoP proof JWT.
//  2. Confirm header.typ == "dpop+jwt", alg ∈ allowed set, jwk present.
//  3. Verify proof signature against the embedded jwk.
//  4. Confirm payload.htm matches the request method (uppercased).
//  5. Confirm payload.htu matches the normalized request URI.
//  6. Confirm payload.iat is within ±Skew of now.
//  7. Confirm payload.jti has not been seen within ProofTTL → reject
//     on duplicate (replay defense).
//  8. If `expectedATH` is non-empty, confirm payload.ath equals
//     base64url(SHA-256(accessToken)).
//  9. Compute thumbprint of header.jwk (RFC 7638 canonicalized SHA-
//     256) and return it; caller binds against access-token.cnf.jkt.
//
// This package does NOT itself fetch the access token; the caller
// (svctoken.Verifier or oidc.RP) already verifies the access JWT and
// extracts cnf.jkt. This package's contract: "given a request + DPoP
// proof + (optional) access-token-bound thumbprint, decide accept /
// reject and return the canonical thumbprint."
//
// Allowed algorithms (RFC 9449 §4.2): asymmetric algs with public-
// key recovery from the JWK. Talon's allowlist: ES256, ES384, ES512,
// RS256, RS384, RS512, PS256, PS384, PS512, EdDSA. HMAC algs are
// REJECTED — they have no usable public key in JWK form.
//
// Replay cache: this package uses an interface (ReplayCache) so the
// caller can plug in the same Redis-backed cache used for svctoken
// jti replay. The in-memory default is fine for single-replica
// development; production should swap in a shared store.
package dpop

import (
	"crypto"
	stdsha256 "crypto/sha256"
	_ "crypto/sha256" // register SHA-256 for crypto.Hash
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ReplayCache is the SeenOrAdd interface implemented by the
// in-memory LRU here AND by the svctoken replay cache. Allows the
// caller to share one cache across DPoP and service-JWT replay
// tracking if desired.
type ReplayCache interface {
	// SeenOrAdd records jti with the given TTL. Returns true if jti
	// was ALREADY present with a still-valid expiry (= replay).
	SeenOrAdd(jti string, ttl time.Duration) bool
}

// Errors that callers may want to discriminate. All other validation
// failures collapse to a single ErrInvalidProof — leaking the exact
// reason of a malformed proof to the client is a small infoleak.
var (
	ErrMissingProof    = errors.New("dpop: DPoP header missing")
	ErrInvalidProof    = errors.New("dpop: proof failed validation")
	ErrReplay          = errors.New("dpop: jti replay")
	ErrATHMismatch     = errors.New("dpop: ath does not match access token")
	ErrUnsupportedAlg  = errors.New("dpop: unsupported alg")
	ErrIATSkew         = errors.New("dpop: iat outside skew window")
)

// VerifierConfig controls timing tolerances + the replay cache.
//
// Defaults are intended to satisfy RFC 9449 §11 (replay defense) and
// match Auth0/Curity production tunings.
type VerifierConfig struct {
	// AllowedAlgs is the asymmetric-only allowlist. Defaults to the
	// 10-alg set above when nil. Operators should narrow to whatever
	// Falcon-ID actually issues (ES256 in 2026).
	AllowedAlgs []jose.SignatureAlgorithm

	// IATSkew is the tolerance on payload.iat vs server now(). RFC
	// 9449 §4.3 recommends "a few seconds"; we default to 30s to
	// absorb minor NTP drift across the mesh.
	IATSkew time.Duration

	// ProofTTL is the maximum age of an accepted DPoP proof. After
	// this window, a replay would not collide in the cache (entries
	// expire) but the iat check rejects it anyway. Default 60s.
	ProofTTL time.Duration

	// Replay is the jti-replay cache. Required; callers can wire the
	// svctoken replay cache or supply NewMemoryCache() for tests.
	Replay ReplayCache
}

// Verifier validates DPoP proofs per RFC 9449. Construct once at
// startup and reuse — Verify is safe for concurrent use.
type Verifier struct {
	allowedAlgs map[jose.SignatureAlgorithm]struct{}
	iatSkew     time.Duration
	proofTTL    time.Duration
	replay      ReplayCache
}

// NewVerifier returns a configured DPoP verifier. Replay is required;
// returns an error if nil so callers cannot accidentally disable
// replay defense.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Replay == nil {
		return nil, errors.New("dpop: VerifierConfig.Replay is required")
	}
	algs := cfg.AllowedAlgs
	if len(algs) == 0 {
		algs = defaultAllowedAlgs
	}
	set := make(map[jose.SignatureAlgorithm]struct{}, len(algs))
	for _, a := range algs {
		if !isAsymmetric(a) {
			return nil, fmt.Errorf("dpop: alg %s is symmetric and not permitted", a)
		}
		set[a] = struct{}{}
	}
	skew := cfg.IATSkew
	if skew == 0 {
		skew = 30 * time.Second
	}
	ttl := cfg.ProofTTL
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &Verifier{
		allowedAlgs: set,
		iatSkew:     skew,
		proofTTL:    ttl,
		replay:      cfg.Replay,
	}, nil
}

var defaultAllowedAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// VerifyRequest extracts the DPoP proof from req.Header and verifies
// it against the request shape. Returns the JWK thumbprint of the
// proof signing key on success; caller must compare this against
// the access token's `cnf.jkt`.
//
// expectedATH is the base64url(SHA-256(access-token)) string. Pass
// "" to skip ATH binding (e.g. when no access token is presented or
// when the auth scheme is "DPoP <access-token>" and the access token
// is bound to the DPoP key via cnf.jkt only without ATH — both
// patterns appear in RFC 9449).
func (v *Verifier) VerifyRequest(req *http.Request, expectedATH string) (jkt string, err error) {
	proof := req.Header.Get("DPoP")
	if proof == "" {
		return "", ErrMissingProof
	}
	return v.Verify(proof, req.Method, req.URL, expectedATH)
}

// Verify is the lower-level entry point: given a proof string +
// canonical request fields, perform RFC 9449 §4.3 validation. URL
// is normalized internally.
func (v *Verifier) Verify(proof, method string, reqURL *url.URL, expectedATH string) (jkt string, err error) {
	if reqURL == nil {
		return "", fmt.Errorf("%w: nil request URL", ErrInvalidProof)
	}

	parsed, err := jwt.ParseSigned(proof, v.permittedAlgs())
	if err != nil {
		return "", fmt.Errorf("%w: parse: %w", ErrInvalidProof, err)
	}
	if len(parsed.Headers) != 1 {
		return "", fmt.Errorf("%w: expected single JWS header, got %d", ErrInvalidProof, len(parsed.Headers))
	}
	hdr := parsed.Headers[0]

	// RFC 9449 §4.2: header.typ MUST be "dpop+jwt"
	if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return "", fmt.Errorf("%w: typ %q != dpop+jwt", ErrInvalidProof, typ)
	}

	alg := jose.SignatureAlgorithm(hdr.Algorithm)
	if _, ok := v.allowedAlgs[alg]; !ok {
		return "", fmt.Errorf("%w: alg=%s", ErrUnsupportedAlg, alg)
	}

	// header.jwk — embedded public key. go-jose parses the canonical
	// JWS "jwk" header into Header.JSONWebKey (not ExtraHeaders) —
	// see go-jose/v4 shared.go h.JSONWebKey assignment in
	// rawHeader.getJWK().
	if hdr.JSONWebKey == nil {
		return "", fmt.Errorf("%w: missing jwk header", ErrInvalidProof)
	}
	key := *hdr.JSONWebKey
	if !key.IsPublic() {
		// Reject if the embedded key has private material — RFC 9449
		// §4.2 implies the jwk is the PUBLIC half and a private key
		// leak via DPoP is a clear server-side red flag.
		return "", fmt.Errorf("%w: embedded jwk must be public", ErrInvalidProof)
	}

	// Verify signature.
	var claims dpopClaims
	if err := parsed.Claims(key.Public().Key, &claims); err != nil {
		return "", fmt.Errorf("%w: signature: %w", ErrInvalidProof, err)
	}

	// payload.htm (method) — case-insensitive match per RFC 9110 §9.1
	if !strings.EqualFold(claims.HTM, method) {
		return "", fmt.Errorf("%w: htm %q != request %q", ErrInvalidProof, claims.HTM, method)
	}

	// payload.htu (target URI) — RFC 9449 §4.3 says normalize per
	// RFC 3986 §6.2.2 (scheme + host lowercased, default port elided,
	// fragment removed). We do exact-match after normalization on
	// both sides.
	if Normalize(claims.HTU) != Normalize(reqURL.String()) {
		return "", fmt.Errorf("%w: htu mismatch (got %q want %q)", ErrInvalidProof,
			Normalize(claims.HTU), Normalize(reqURL.String()))
	}

	// payload.iat skew check.
	if claims.IAT == 0 {
		return "", fmt.Errorf("%w: missing iat", ErrInvalidProof)
	}
	now := time.Now().Unix()
	if abs64(now-claims.IAT) > int64(v.iatSkew.Seconds()) {
		return "", fmt.Errorf("%w: iat %d skew %ds (now=%d)", ErrIATSkew, claims.IAT, abs64(now-claims.IAT), now)
	}

	// payload.jti replay check. TTL = proofTTL so the cache window
	// matches the freshness window.
	if claims.JTI == "" {
		return "", fmt.Errorf("%w: missing jti", ErrInvalidProof)
	}
	if v.replay.SeenOrAdd(claims.JTI, v.proofTTL) {
		return "", ErrReplay
	}

	// payload.ath binding (optional, but required if caller supplied
	// the expected hash).
	if expectedATH != "" {
		if claims.ATH != expectedATH {
			return "", ErrATHMismatch
		}
	}

	// Compute RFC 7638 thumbprint with SHA-256 (the canonical JWK
	// thumbprint hash; RFC 9449 §6 references RFC 7638 directly and
	// SHA-256 is the JWK-thumbprint default).
	thumbBytes, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %w", ErrInvalidProof, err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbBytes), nil
}

// HashAccessToken returns the base64url(SHA-256(token)) string used
// in DPoP's `ath` claim — exposed for callers (svctoken / proxy)
// that need to derive the expected ATH from a verified access token
// before calling Verify.
func HashAccessToken(token string) string {
	sum := stdsha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}


// Normalize implements the subset of RFC 3986 §6.2.2 needed for
// HTU comparison: lowercase scheme + host, drop default port for
// scheme, strip fragment, KEEP query string (RFC 9449 §4.3 explicitly
// includes query for HTU equality).
//
// Exposed so tests can pin the normalization rule.
func Normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	// Drop default port. Only standard pairs.
	switch u.Scheme {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	u.Host = host
	u.Fragment = ""
	return u.String()
}

// dpopClaims is the canonical RFC 9449 §4.2 claim set.
type dpopClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// permittedAlgs returns the slice form needed by jwt.ParseSigned. Pre-
// computing once at startup saves an allocation per request.
func (v *Verifier) permittedAlgs() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(v.allowedAlgs))
	for a := range v.allowedAlgs {
		out = append(out, a)
	}
	return out
}

func isAsymmetric(a jose.SignatureAlgorithm) bool {
	switch a {
	case jose.HS256, jose.HS384, jose.HS512:
		return false
	}
	return true
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

