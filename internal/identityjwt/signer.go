// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identityjwt mints + verifies RFC 7519 JSON Web Tokens that
// Talon stamps onto every proxied request to upstream services. The
// signed token is the cryptographic counterpart to the unsigned
// X-Talon-* convenience headers (see internal/proxy/proxy.go) — it
// closes the "compromised network position can forge identity" attack
// surface that those headers carry on their own.
//
// Trust model
// -----------
// Talon holds the private signing key; upstream services hold ONLY the
// public key (fetched from the JWKS endpoint this package also serves
// via jwks.go). The split-key arrangement matches every reference IAP:
// Google Cloud IAP (`x-goog-iap-jwt-assertion`), AWS ALB OIDC
// (`x-amzn-oidc-data`), Cloudflare Access (`Cf-Access-Jwt-Assertion`),
// Pomerium (`X-Pomerium-Jwt-Assertion`). NIST SP 800-57 §5.2 ("key
// usage separation") + OWASP ASVS V6.2.1 require this key to be
// dedicated — DO NOT reuse Talon's session-encryption AEAD key here.
//
// Claims
// ------
//
//	iss : https://internal.example.com  (Talon's external URL)
//	sub : iam_users.id (Falcon-ID subject, 36-char UUID)
//	aud : the protected host this token authorises (e.g. internal.example.com)
//	iat / exp : 60-second window — every proxied request gets a fresh token
//	email, groups, roles, tenant_id, sso_chain_id : identity payload
//	  (roles mirrors groups verbatim — see IdentityClaims.Roles)
//	sid : Talon session cookie UUID — lets upstream audit logs join to Talon's audit trail
//
// `aud` is per-host on purpose: a token minted for falcon.ops cannot be
// replayed against argocd.ops even if either's upstream is partially
// compromised (RFC 8725 §3.1 "audience binding").
package identityjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/hexxlock/talon/internal/session"
)

// newJTI returns a fresh UUIDv4 string for the RFC 7519 §4.1.7 jti
// claim. Backed by crypto/rand via google/uuid (the same source the
// audit DecisionID + session UUIDs already use), so uniqueness is
// crypto-strong — the 122-bit random space rules out collisions at
// any feasible mint rate.
func newJTI() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// DefaultTokenLifetime is the `exp - iat` window stamped on every IAP
// identity token. 60 seconds matches Cloudflare Access's default and is
// generous enough to survive the typical clock skew between cluster
// nodes (chrony keeps RKE2 nodes within ~10ms) while keeping the replay
// window short.
const DefaultTokenLifetime = 60 * time.Second

// HeaderName is the HTTP header Talon stamps on every proxied request.
// Matches Pomerium's pattern (`X-Pomerium-Jwt-Assertion`) — namespaced
// to defeat collision with upstream apps that may already consume a
// different X-Auth-* / X-Forwarded-* family.
const HeaderName = "X-Talon-Identity-Token"

// IssuerURLAudienceClaims is the structured payload Sign() embeds in
// the JWT. Mirrors session.Blob's identity fields plus the OAuth /
// OIDC-conventional claim names so upstream verifiers can use stock
// libraries (jose, jwt-go, jose-jwt-bearer-grant) without custom shims.
type IdentityClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	// JTI is the RFC 7519 §4.1.7 JWT ID — a UUIDv4 minted per request
	// so verifiers can implement replay protection within the 60s exp
	// window. Talon never reuses a jti; uniqueness is from
	// crypto/rand. Verifiers MAY refuse a jti seen recently (see
	// internal/identityjwt.Verifier.replayCache) for defense-in-depth
	// against intercepted-token replay.
	JTI    string   `json:"jti,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// Roles is the verified counterpart of the `groups` claim, added so
	// downstream services (eyrie) can authorize on a `roles` claim rather
	// than `groups`. It is populated in SignWithChannel from blob.Groups —
	// the SAME session field that feeds the X-Talon-Groups header — so the
	// switch is behavior-preserving (see the population site for the full
	// rationale). Additive: `groups` is unchanged and still emitted.
	Roles      []string `json:"roles,omitempty"`
	TenantID   string   `json:"tenant_id,omitempty"`
	SSOChainID string   `json:"sso_chain_id,omitempty"`
	SID        string   `json:"sid,omitempty"`

	// Channel is the Talon session channel (ADR 0044): "cookie" (the
	// default agent/browser-cookie session), "bearer" (the desktop SDK
	// Phase-C path), or "clientless" (agentless access-zone session, no
	// device cert). The clientless access-broker (internal/accessbroker)
	// enforces channel=clientless cryptographically off this claim so an
	// agent-channel token cannot be replayed into the agentless terminal
	// broker. omitempty keeps the wire shape backward compatible: tokens
	// minted before this field decode with an empty Channel, which
	// verifiers treat as the default cookie channel.
	Channel string `json:"channel,omitempty"`
}

// Signer mints JWTs from a session.Blob + audience pair. Held by the
// proxy.Handler; one instance per Talon process. The struct exposes a
// pure Sign API; rotation is handled by replacing the signer at startup
// (k8s rolling restart on Secret change).
//
// Multi-key rotation (zero-downtime): the active key is held in
// `privateKey/kid/signer`. A *previous* key can be kept alongside via
// AddPreviousPublicKey() — Sign() always uses the active key, but the
// JWKS endpoint publishes BOTH so verifiers accept JWTs signed by
// either kid during the rotation overlap window. Matches Cloudflare
// Access's N+1 JWKS rotation pattern (and Google IAP's daily-rotation
// model where multiple kids are valid concurrently).
//
// Goroutine-safe by design (RSA keys are immutable after construction;
// previousPublicKeys is append-only after startup).
type Signer struct {
	mu                 sync.RWMutex
	privateKey         *rsa.PrivateKey
	kid                string // matches the active public key on JWKS
	issuer             string // populated into the JWT iss claim — typically Talon's ExternalURL
	lifetime           time.Duration
	signer             jose.Signer
	previousPublicKeys []retiredKey // older keys still valid for verifiers; never used for signing
}

// retiredKey is a public key still published on the JWKS endpoint
// during the rotation overlap window. JWTs signed by its kid are still
// honoured by verifiers; new JWTs are signed only by the active key.
type retiredKey struct {
	publicKey rsa.PublicKey
	kid       string
}

// NewSignerFromPEM constructs a Signer from a PEM-encoded RSA private
// key (PKCS#1 "RSA PRIVATE KEY" or PKCS#8 "PRIVATE KEY"). Returns an
// error if the PEM is malformed, the key is not RSA, or the key size is
// below 2048 bits (RFC 8017 + NIST SP 800-131A recommend ≥2048; we
// fail-closed below that to keep tier-1 supply chain).
//
// issuer is the `iss` claim every signed JWT will carry — typically
// Talon's ExternalURL (e.g. "https://internal.example.com"). Verifiers
// MUST check `iss` matches this exact string.
func NewSignerFromPEM(pemBytes []byte, issuer string) (*Signer, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("identityjwt: empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("identityjwt: no PEM block found in input")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identityjwt: parse PKCS#1 RSA private key: %w", err)
		}
		key = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identityjwt: parse PKCS#8 private key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identityjwt: PKCS#8 key is not RSA (got %T)", parsed)
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("identityjwt: unsupported PEM type %q (want \"RSA PRIVATE KEY\" or \"PRIVATE KEY\")", block.Type)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("identityjwt: RSA key size %d bits is below the 2048-bit minimum (NIST SP 800-131A)", key.N.BitLen())
	}
	if issuer == "" {
		return nil, errors.New("identityjwt: issuer must not be empty")
	}

	kid := computeKid(&key.PublicKey)
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return nil, fmt.Errorf("identityjwt: construct jose signer: %w", err)
	}

	return &Signer{
		privateKey: key,
		kid:        kid,
		issuer:     issuer,
		lifetime:   DefaultTokenLifetime,
		signer:     joseSigner,
	}, nil
}

// Sign mints a signed JWT carrying the blob's identity, scoped to the
// given audience (= the protected host the request is being proxied
// to). Returns a compact-form JWS suitable for transport in an HTTP
// header.
//
// audience MUST be non-empty — the per-host binding is the security
// boundary that prevents cross-route replay (RFC 8725 §3.1). The blob's
// SSOChainID + Sub + Email + Groups + TenantID are surfaced verbatim
// so the upstream can correlate with Talon's audit logs without a
// second round-trip.
func (s *Signer) Sign(blob *session.Blob, audience string) (string, error) {
	return s.SignWithChannel(blob, audience, "")
}

// SignWithChannel is Sign with an explicit ADR 0044 session channel
// stamped into the JWT's `channel` claim. An empty channel is identical
// to Sign (the claim is omitted, decoding to the default cookie channel
// at the verifier). The clientless access-broker mints/consumes
// channel="clientless" tokens so the agentless terminal path is
// cryptographically distinguishable from an agent/cookie session.
func (s *Signer) SignWithChannel(blob *session.Blob, audience, channel string) (string, error) {
	if s == nil {
		return "", errors.New("identityjwt: nil signer (signing not configured)")
	}
	if blob == nil {
		return "", errors.New("identityjwt: nil session blob")
	}
	if audience == "" {
		return "", errors.New("identityjwt: empty audience (per-host binding required)")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.signer == nil {
		// Defensive guard — NewSignerFromPEM always constructs a non-nil
		// jose signer, but a future code path that swaps it (e.g. an
		// at-runtime key reload) could leave the field nil if the new
		// key load fails. Returning a clear error here turns the
		// otherwise-panicking jose.builder.Serialize call into something
		// the readiness probe surfaces cleanly.
		return "", errors.New("identityjwt: jose signer not initialized")
	}
	now := time.Now().UTC()
	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("identityjwt: mint jti: %w", err)
	}
	claims := IdentityClaims{
		Issuer:    s.issuer,
		Subject:   blob.Sub,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.lifetime).Unix(),
		JTI:       jti,
		Email:     blob.Email,
		Groups:    blob.Groups,
		// Roles source: blob.Groups (verbatim — NOT blob.Roles).
		//
		// Talon exposes NO X-Talon-Roles header. The only role/authorization
		// identity Talon surfaces downstream is the X-Talon-Groups header
		// (proxy.injectIdentityHeaders) and this JWT's `groups` claim — both
		// sourced from blob.Groups. blob.Roles is used only for Talon-internal
		// policy evaluation (internal/policy + Rego) and never reaches eyrie.
		//
		// Therefore the value eyrie authorized on came entirely from
		// blob.Groups. Mirroring that exact slice into `roles` lets eyrie
		// switch its authz derivation from `groups` to `roles` with zero
		// behavior change (the two claims are byte-identical). This is a
		// copy, not a new mapping: using blob.Roles here would make eyrie
		// authorize on a different slice than it read before, which the
		// behavior-preserving contract forbids.
		Roles:      blob.Groups,
		TenantID:   blob.TenantID,
		SSOChainID: blob.SSOChainID,
		SID:        blob.SID,
		Channel:    channel,
	}
	raw, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("identityjwt: serialize signed jwt: %w", err)
	}
	return raw, nil
}

// AddPreviousPublicKeyFromPEM registers a retired public key on the
// JWKS endpoint so verifiers continue to honour JWTs that were signed
// by the prior active key during the rotation overlap window.
//
// The retired key is read as a PEM-encoded public key (PKIX "PUBLIC
// KEY" — same format `openssl rsa -in priv.pem -pubout` emits) OR as
// a private key from which the public half is derived. We accept both
// because the canonical Vault secret already carries the private PEM
// and forcing operators to extract the public half during a rotation
// invites mistakes.
//
// Sign() never uses this key — it is publish-only. The active signing
// key is unchanged by this call.
func (s *Signer) AddPreviousPublicKeyFromPEM(pemBytes []byte) error {
	if s == nil {
		return errors.New("identityjwt: nil signer")
	}
	if len(pemBytes) == 0 {
		return errors.New("identityjwt: empty previous-key PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("identityjwt: no PEM block found in previous-key input")
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("identityjwt: parse previous PKCS#1 RSA private key: %w", err)
		}
		pub = &parsed.PublicKey
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("identityjwt: parse previous PKCS#8 private key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("identityjwt: previous PKCS#8 key is not RSA (got %T)", parsed)
		}
		pub = &rsaKey.PublicKey
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("identityjwt: parse previous PKIX public key: %w", err)
		}
		rsaPub, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("identityjwt: previous PKIX key is not RSA (got %T)", parsed)
		}
		pub = rsaPub
	default:
		return fmt.Errorf("identityjwt: unsupported previous-key PEM type %q", block.Type)
	}
	if pub.N.BitLen() < 2048 {
		return fmt.Errorf("identityjwt: previous RSA key size %d bits is below the 2048-bit minimum", pub.N.BitLen())
	}
	kid := computeKid(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if kid == s.kid {
		return nil // the operator handed us the same key as the active one; nothing to publish twice
	}
	for _, rk := range s.previousPublicKeys {
		if rk.kid == kid {
			return nil // idempotent — same retired key registered twice
		}
	}
	s.previousPublicKeys = append(s.previousPublicKeys, retiredKey{publicKey: *pub, kid: kid})
	return nil
}

// PreviousPublicKeys returns a snapshot of the retired public keys
// (kid + key) the signer will publish on the JWKS endpoint alongside
// the active key. The slice is a defensive copy — mutating it does not
// affect the signer.
func (s *Signer) PreviousPublicKeys() []struct {
	Kid       string
	PublicKey rsa.PublicKey
} {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]struct {
		Kid       string
		PublicKey rsa.PublicKey
	}, 0, len(s.previousPublicKeys))
	for _, rk := range s.previousPublicKeys {
		out = append(out, struct {
			Kid       string
			PublicKey rsa.PublicKey
		}{Kid: rk.kid, PublicKey: rk.publicKey})
	}
	return out
}

// HealthCheck performs a synthetic mint + signature-verify roundtrip
// to confirm the signing key is actually usable. Returns nil on
// success, a descriptive error otherwise. Cheap (microseconds — one
// RSA-2048 sign + one RSA-2048 verify on a tiny payload), so it's
// safe to call from a /readyz probe on every request.
//
// Without this primitive, a malformed-PEM Vault projection would
// silently degrade Talon to "unsigned headers only" while keeping the
// pod marked Ready — and every Phase B SDK request would 401 with no
// health signal pointing at the IAP signer as the root cause. The
// health check turns that failure mode into a readiness failure
// surfaced to kube-proxy + the metrics scraper.
func (s *Signer) HealthCheck() error {
	if s == nil {
		return errors.New("identityjwt: nil signer")
	}
	probe := &session.Blob{Sub: "_healthcheck_"}
	raw, err := s.Sign(probe, "_healthcheck_")
	if err != nil {
		return fmt.Errorf("identityjwt: synthetic sign failed: %w", err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return fmt.Errorf("identityjwt: synthetic parse failed: %w", err)
	}
	pub := s.PublicKey()
	var out IdentityClaims
	if err := parsed.Claims(&pub, &out); err != nil {
		return fmt.Errorf("identityjwt: synthetic verify failed: %w", err)
	}
	if out.Subject != probe.Sub || out.Audience != "_healthcheck_" {
		return errors.New("identityjwt: synthetic claims roundtrip mismatch")
	}
	return nil
}

// Kid returns the signer's kid (key id) — exposed for tests + for the
// JWKS handler in jwks.go that publishes the matching public key.
func (s *Signer) Kid() string { return s.kid }

// Issuer returns the iss claim the signer stamps on every JWT.
func (s *Signer) Issuer() string { return s.issuer }

// PublicKey returns the RSA public key for verification — consumed by
// the JWKS handler. Returned by value (rsa.PublicKey is immutable) so
// callers can't mutate the signer's state.
func (s *Signer) PublicKey() rsa.PublicKey { return s.privateKey.PublicKey }

// computeKid derives a stable key-id from the public key's
// SHA-256(DER-encoded-SPKI), base64url-encoded. Matches RFC 7638
// "JSON Web Key Thumbprint" close enough for our purposes (jose's
// JSONWebKey.Thumbprint would also work but adds an indirection).
// Same kid for the same key across restarts; new kid on rotation.
func computeKid(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// MarshalPKIXPublicKey can't fail on a valid *rsa.PublicKey, but
		// the linter wants the error checked — fall back to a stable
		// random-ish marker so the kid is at least unique per process.
		var b [16]byte
		_, _ = rand.Read(b[:])
		return base64.RawURLEncoding.EncodeToString(b[:])
	}
	sum := sha256.Sum256(der)
	// Take 16 bytes ≈ 128 bits of identification — kid is not a secret.
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(sum[:16]), "=")
}
