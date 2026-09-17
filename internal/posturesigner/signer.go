// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dogukanturhal/talon/internal/caep"
)

// JWSIssuer mints RS256 JWS tokens backed by Vault Transit. The private
// key NEVER leaves Vault — the service sends the unsigned header.payload
// to Vault and receives a base64-encoded RSA signature. This implements
// the Vault Transit sign API:
//
//	POST <vault_addr>/v1/transit/sign/<key_name>
//	{ "input": "<base64(header.payload)>", "hash_algorithm": "sha2-256",
//	  "signature_algorithm": "pkcs1v15" }
//
// Architecture note (ADR 0040 D-003 + posture-signer-key.tf):
//   - Key name: `posture-signer` (rsa-2048, RS256).
//   - Vault policy grants only transit/sign/posture-signer and
//     transit/keys/posture-signer (read for JWKS publication).
//   - The posture-signer SA token is renewed by the Vault Agent Injector
//     sidecar (posture-signer-key.tf token_ttl=1h, token_max_ttl=2h).
type JWSIssuer struct {
	vaultAddr string
	keyName   string
	issuer    string
	audience  string
	httpCl    *http.Client

	// JWKS cache: refreshed from Vault Transit keys endpoint every 5min.
	mu           sync.RWMutex
	jwksCache    []jwkEntry
	jwksCacheAt  time.Time
	jwksCacheTTL time.Duration

	// vaultToken is obtained once at startup via k8s auth and refreshed
	// by the Vault Agent Injector writing it to /vault/secrets/token.
	tokenPath string

	// Clock for tests.
	now func() time.Time
}

// JWSIssuerConfig configures the issuer.
type JWSIssuerConfig struct {
	VaultAddr    string // e.g. "http://vault-ha.vault.svc:8200"
	KeyName      string // Vault Transit key name (default: "posture-signer")
	Issuer       string // iss claim (e.g. "https://posture.hexxlock.com")
	Audience     string // aud claim (e.g. "https://internal.example.com")
	TokenPath    string // path to Vault token file (e.g. "/vault/secrets/token")
	JWKSCacheTTL time.Duration
}

// NewJWSIssuer constructs a JWSIssuer. Call RefreshJWKS once before the
// first sign operation (the server's readiness probe gates on it).
func NewJWSIssuer(cfg JWSIssuerConfig) (*JWSIssuer, error) {
	if cfg.VaultAddr == "" {
		return nil, errors.New("posturesigner: VaultAddr required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("posturesigner: Issuer required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("posturesigner: Audience required")
	}
	if cfg.TokenPath == "" {
		return nil, errors.New("posturesigner: TokenPath required")
	}
	keyName := cfg.KeyName
	if keyName == "" {
		keyName = "posture-signer"
	}
	ttl := cfg.JWKSCacheTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &JWSIssuer{
		vaultAddr:    cfg.VaultAddr,
		keyName:      keyName,
		issuer:       cfg.Issuer,
		audience:     cfg.Audience,
		tokenPath:    cfg.TokenPath,
		jwksCacheTTL: ttl,
		httpCl:       &http.Client{Timeout: 10 * time.Second},
		now:          time.Now,
	}, nil
}

// vaultVersionPrefixRE matches Vault Transit's "vault:vN:" signature
// envelope for any integer version. Anchored at start to avoid eating
// the same substring inside the base64 body (extremely unlikely but
// the anchor is free defense).
var vaultVersionPrefixRE = regexp.MustCompile(`^vault:v\d+:`)

// stripVaultVersionPrefix removes the "vault:vN:" envelope from a Vault
// Transit signature. Returns the input unchanged when no prefix is
// present (e.g. some library versions return the signature bare).
func stripVaultVersionPrefix(s string) string {
	loc := vaultVersionPrefixRE.FindStringIndex(s)
	if loc == nil {
		return s
	}
	return s[loc[1]:]
}

// postureJWTClaims is the canonical payload shape. It MUST match the
// rawClaims struct in internal/posture/posture.go line-for-line.
//
// The `cnf` claim is RFC 8705 §3.1 — confirmation method binding the
// JWS to a specific TLS client certificate. The single supported
// sub-field is `x5t#S256` (RFC 8705 §3.1) carrying the base64url-no-
// pad SHA-256 thumbprint of the device leaf cert that authenticated
// the issuance request. Downstream verifiers MUST compare this
// against the inbound mTLS cert and reject mismatches — that closes
// the JWS-replay-onto-different-mTLS-connection attack class.
type postureJWTClaims struct {
	Iss        string         `json:"iss"`
	Sub        string         `json:"sub"`
	Aud        string         `json:"aud"`
	IAT        int64          `json:"iat"`
	Exp        int64          `json:"exp"`
	UserSub    string         `json:"user_sub,omitempty"`
	Compliance map[string]any `json:"compliance"`
	Cnf        *cnfClaim      `json:"cnf,omitempty"`
}

// cnfClaim implements RFC 8705 §3.1 — x5t#S256 only (no other
// confirmation methods are supported by this issuer).
type cnfClaim struct {
	X5tS256 string `json:"x5t#S256"`
}

// IssueJWS mints a compact RS256 JWS for the given heartbeat.
// The signing happens fully inside Vault Transit; only the public key
// identifier (kid) and the resulting signature bytes are handled in-process.
//
// The returned JWS string can be placed directly into X-Talon-Posture.
func (s *JWSIssuer) IssueJWS(ctx context.Context, req *HeartbeatRequest) (jws string, expiresAt time.Time, err error) {
	now := s.now()
	exp := now.Add(time.Hour)

	// Read current active key version for kid header.
	kid, err := s.activeKID()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("posturesigner: get active KID: %w", err)
	}

	// Build JWS header (compact: base64url(header)).
	hdr := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("posturesigner: marshal header: %w", err)
	}
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	// Build payload. The cnf.x5t#S256 thumbprint is required — the
	// server populates HeartbeatRequest.deviceCertThumbprint via
	// VerifyRequest before reaching this point; an empty value is a
	// programming error indicating the verifier path was bypassed.
	if req.deviceCertThumbprint == "" {
		return "", time.Time{}, fmt.Errorf("posturesigner: device cert thumbprint is empty — verifier path was bypassed")
	}
	claims := postureJWTClaims{
		Iss:        s.issuer,
		Sub:        "device:" + req.DeviceUUID,
		Aud:        s.audience,
		IAT:        now.Unix(),
		Exp:        exp.Unix(),
		UserSub:    req.UserSub,
		Compliance: req.Compliance,
		Cnf:        &cnfClaim{X5tS256: req.deviceCertThumbprint},
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("posturesigner: marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// The signing input is base64(header.payload) — Vault Transit input
	// field must be base64 of the raw bytes to sign.
	signingInput := hdrB64 + "." + payloadB64
	inputB64 := base64.StdEncoding.EncodeToString([]byte(signingInput))

	// Call Vault Transit sign.
	sig, err := s.vaultSign(ctx, inputB64)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("posturesigner: vault sign: %w", err)
	}

	compact := signingInput + "." + sig
	return compact, exp, nil
}

// SignSET signs a CAEP Security Event Token (ADR 0043) with the SAME Vault
// Transit RS256 key used for posture JWS, but with header typ=secevent+jwt
// per RFC 8417. This makes posture-signer a CAEP transmitter (caep.Signer)
// whose SETs the Talon receiver verifies against posture-signer's published
// JWKS — no new key, no Vault dependency leaking into the caep package.
func (s *JWSIssuer) SignSET(ctx context.Context, claims caep.SETClaims) (string, error) {
	kid, err := s.activeKID()
	if err != nil {
		return "", fmt.Errorf("posturesigner: get active KID: %w", err)
	}
	hdr := map[string]string{"alg": "RS256", "typ": "secevent+jwt", "kid": kid}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("posturesigner: marshal SET header: %w", err)
	}
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("posturesigner: marshal SET claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := hdrB64 + "." + payloadB64
	inputB64 := base64.StdEncoding.EncodeToString([]byte(signingInput))
	sig, err := s.vaultSign(ctx, inputB64)
	if err != nil {
		return "", fmt.Errorf("posturesigner: vault sign SET: %w", err)
	}
	return signingInput + "." + sig, nil
}

// vaultSign calls POST <vault>/v1/transit/sign/<keyName> with the given
// base64-encoded input and returns the base64url-encoded signature
// (without the "vault:v1:" prefix that Vault prepends).
func (s *JWSIssuer) vaultSign(ctx context.Context, inputB64 string) (string, error) {
	token, err := s.readToken()
	if err != nil {
		return "", fmt.Errorf("read vault token: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"input":               inputB64,
		"hash_algorithm":      "sha2-256",
		"signature_algorithm": "pkcs1v15",
	})
	url := fmt.Sprintf("%s/v1/transit/sign/%s", s.vaultAddr, s.keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpCl.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned HTTP %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse vault response: %w", err)
	}
	if result.Data.Signature == "" {
		return "", errors.New("vault response missing data.signature")
	}

	// Vault Transit returns "vault:vN:<base64>" for versioned keys. We
	// strip the prefix regardless of the version digit count — the
	// `posture-signer` key auto-rotates every 90 days, so after a few
	// years the version reaches double digits (v10, v11, …). The
	// previous hard-coded v1/v2/v3 list would silently fail at v10+
	// and corrupt the signature, producing an OutcomeVaultError storm
	// every signing call until the version rolled over again.
	//
	// Format spec: golang.org/x/crypto/openpgp/.../vault has no public
	// AST for this; the production format is documented at
	// vaultproject.io/api-docs/secret/transit#sign-data §response.
	raw := stripVaultVersionPrefix(result.Data.Signature)
	// Vault returns standard base64; convert to base64url (no padding).
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Maybe already raw URL encoding.
		decoded, err = base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return "", fmt.Errorf("decode vault signature: %w", err)
		}
	}
	return base64.RawURLEncoding.EncodeToString(decoded), nil
}

// RefreshJWKS fetches the current + past key versions from Vault Transit
// and caches the public keys as JWK entries for /.well-known/jwks.json.
// Called once at startup and periodically by the server's background loop.
func (s *JWSIssuer) RefreshJWKS(ctx context.Context) error {
	token, err := s.readToken()
	if err != nil {
		return fmt.Errorf("posturesigner: read vault token for JWKS: %w", err)
	}

	url := fmt.Sprintf("%s/v1/transit/keys/%s", s.vaultAddr, s.keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("posturesigner: build JWKS request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := s.httpCl.Do(req)
	if err != nil {
		return fmt.Errorf("posturesigner: vault JWKS http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("posturesigner: vault JWKS returned HTTP %d: %s", resp.StatusCode, body)
	}

	// Vault Transit keys response shape:
	// { "data": { "keys": { "1": { "public_key": "-----BEGIN PUBLIC KEY-----\n..." } } } }
	var keysResp struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &keysResp); err != nil {
		return fmt.Errorf("posturesigner: parse JWKS response: %w", err)
	}

	// Sort the version map by NUMERIC version ASCENDING so the slice
	// has a deterministic order — `activeKID()` returns the last
	// element and we need that to be the highest-numbered (newest)
	// version. Go's map iteration is randomized; without sorting,
	// activeKID would return random KIDs after every refresh.
	versions := make([]string, 0, len(keysResp.Data.Keys))
	for v := range keysResp.Data.Keys {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		vi, ei := strconv.Atoi(versions[i])
		vj, ej := strconv.Atoi(versions[j])
		// Non-numeric versions sort lexicographically AFTER numeric
		// (placing them last). Vault Transit always emits "1", "2", …
		// so this is a defensive fallback for forward-compat.
		if ei != nil && ej != nil {
			return versions[i] < versions[j]
		}
		if ei != nil {
			return false
		}
		if ej != nil {
			return true
		}
		return vi < vj
	})

	entries := make([]jwkEntry, 0, len(versions))
	for _, version := range versions {
		kd := keysResp.Data.Keys[version]
		entry, err := pemToJWK(kd.PublicKey, s.keyName+"-v"+version)
		if err != nil {
			// Log and skip malformed entries — partial JWKS is better than none.
			continue
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return errors.New("posturesigner: vault returned zero parseable public keys")
	}

	s.mu.Lock()
	s.jwksCache = entries
	s.jwksCacheAt = s.now()
	s.mu.Unlock()
	return nil
}

// JWKS returns the current cached JWKS as a JSON-serialisable value.
func (s *JWSIssuer) JWKS() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]any, len(s.jwksCache))
	for i, e := range s.jwksCache {
		keys[i] = e
	}
	return map[string]any{"keys": keys}
}

// JWKSCacheAge returns the duration since the JWKS was last refreshed.
// Used by the metrics gauge.
func (s *JWSIssuer) JWKSCacheAge() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.jwksCacheAt.IsZero() {
		return 0
	}
	return s.now().Sub(s.jwksCacheAt)
}

// IsJWKSStale returns true if the cache has never been populated or is
// older than jwksCacheTTL. Used by the readiness probe.
func (s *JWSIssuer) IsJWKSStale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwksCacheAt.IsZero() || s.now().Sub(s.jwksCacheAt) > s.jwksCacheTTL
}

// activeKID returns the kid for the current active key version. Because
// Vault Transit auto-rotates, the kid is derived from the cached entries
// (highest version number). A stale cache is acceptable here — the kid
// just needs to be present in the JWKS for verifiers to find the key.
func (s *JWSIssuer) activeKID() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.jwksCache) == 0 {
		return "", errors.New("posturesigner: JWKS cache is empty — call RefreshJWKS first")
	}
	// Return the last entry (Vault API returns keys in ascending version
	// order, so the last is the newest / active key).
	return s.jwksCache[len(s.jwksCache)-1].KID, nil
}

// readToken reads the Vault token from the file written by the Vault
// Agent Injector (mounted at tokenPath). This is the production pattern
// for Vault Agent template injection — the file is refreshed by the
// sidecar before each renewal deadline.
func (s *JWSIssuer) readToken() (string, error) {
	// We intentionally re-read the file on every call so we always use
	// the most recently renewed token from the Vault Agent Injector.
	// The file is typically ~26 characters (Vault token) — negligible I/O.
	data, err := readFileOnce(s.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read vault token file %q: %w", s.tokenPath, err)
	}
	token := string(bytes.TrimSpace(data))
	if token == "" {
		return "", fmt.Errorf("vault token file %q is empty", s.tokenPath)
	}
	return token, nil
}

// jwkEntry is a minimal RFC 7517 JSON Web Key for an RSA public key.
type jwkEntry struct {
	KID string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded public exponent
}

// pemToJWK parses a PEM RSA public key and returns a JWK entry.
func pemToJWK(pemStr, kid string) (jwkEntry, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return jwkEntry{}, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwkEntry{}, fmt.Errorf("parse PKIX public key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return jwkEntry{}, fmt.Errorf("expected RSA public key, got %T", pub)
	}
	nBytes := rsaKey.N.Bytes()
	eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
	return jwkEntry{
		KID: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}, nil
}

// readFileOnce is an abstraction over os.ReadFile used for token reading.
// Extracted so tests can substitute a mock (see signer_test.go).
var readFileOnce = defaultReadFile

func defaultReadFile(path string) ([]byte, error) {
	// Avoid importing "os" directly so the mock can be substituted in
	// tests without build constraints. We use the io/os package here.
	return osReadFile(path)
}
