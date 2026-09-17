// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// FederatedIssuerConfig declares one SECONDARY trusted issuer whose
// JWTs Talon will signature-verify (sig + exp only, NOT audience /
// scope / Falcon-ID-specific claim shape) and then proxy as-is on
// routes whose AuthMode is AuthModeBearerOrFederatedPassthrough.
//
// MOTIVATION — DOCKER REGISTRY V2 / VAULT TOKEN / KEYCLOAK / etc.
//
// Some upstream protocols MANDATE that the client present
// `Authorization: Bearer <upstream-issued-jwt>` on subsequent
// requests, where the JWT was minted by the upstream itself (not by
// Talon's primary IdP, Falcon-ID). The Docker Registry v2 token
// spec is the canonical example: a Docker pull issues `GET /v2/`,
// receives 401 with `Www-Authenticate: Bearer realm="https://
// registry.example.com/service/token",service="harbor-registry"`,
// fetches a Harbor-issued JWT from /service/token (Basic auth with
// a robot account), and retries every subsequent /v2/<repo>/
// manifests/<tag> + blob GET with the Harbor-Bearer. Harbor's JWTs
// are signed by Harbor's OWN private key, not Falcon-ID's JWKS, so
// Talon's standard verify against the Falcon-ID JWKS would 401
// every retry — breaking every Docker pull cluster-wide.
//
// THE TIER-1 PATTERN — ISSUER-AWARE MULTI-TRUST.
//
// Envoy `jwt_authn` (canonical reference), Istio
// RequestAuthentication.jwtRules[], and Ory Oathkeeper
// trusted_issuers[] all converge on the same wire shape: a list of
// trusted issuers, each with its own JWKS source, dispatched by the
// JWT's `iss` claim. Multiple issuers on one route compose via
// `requires_any` (OR-of-verifiers). Crucially — Envoy
// CVE-2021-21378 (GHSA-4996-m8hf-hj27, CVSS 8.2 High) + Istio
// ISTIO-SECURITY-2021-001 codified that UNKNOWN ISSUER MUST be
// classified as VERIFY-FAILURE (reject 401), NEVER as missing-token
// (passthrough-eligible). Conflating the two is a security bypass.
//
// Talon mirrors that invariant: a JWT whose iss is neither the
// primary expected issuer (Falcon-ID) nor any FederatedIssuerConfig
// in this list is REJECTED. Federated trust does NOT relax the
// strict-on-broken-Bearer property; it just admits a known
// secondary issuer.
//
// HARBOR JWT SHAPE (from a live token, 2026-05-30):
//
//	HEADER:  {alg: "RS256", kid: "XCO7:RXR5:...", typ: "JWT"}
//	PAYLOAD: {iss: "harbor-token-issuer", aud: "harbor-registry",
//	          sub: null, access: [{type, name, actions}], exp, iat,
//	          jti, nbf}
//
// Note that aud is "harbor-registry" (Harbor's INTERNAL service
// label, NOT https://registry.example.com) and there is NO `scope`
// claim — the access claim is structured differently. Federated
// trust therefore SKIPS audience binding + scope enforcement at
// Talon and defers per-repo authz to Harbor itself (which
// re-validates the access claim and the Bearer it issued).
//
// This is consistent with how every tier-1 IAP deployment in front
// of a Docker registry works (per 2026-05-30 deep-research workflow
// wf_36f4dd00-d01 — 105-agent adversarial verification): the IAP
// confirms "the token is signed by a key we trust" and lets the
// upstream do the actual access decision. NOT a confused-deputy
// risk for Harbor — Harbor's `access` claim is per-repo, so a token
// for repo A presented to access repo B fails inside Harbor.
//
// CONFUSED-DEPUTY GUARD AT TALON.
//
// To prevent ONE federated trust on host X from being abused to
// reach host Y, FederatedIssuerConfig MAY pin to a host-prefix set
// (AllowedHosts). When non-empty, Talon's middleware only consults
// this issuer for requests whose Host header matches one of the
// listed values. Mirrors Envoy `RequirementRule.match` scoping.
// Empty (default) = federated trust applies to every route running
// AuthModeBearerOrFederatedPassthrough.
type FederatedIssuerConfig struct {
	// Issuer — exact match against the JWT's `iss` claim. Required.
	// Case-sensitive. Talon does NOT normalise (no trailing-slash
	// fixup) — the JWT must carry the literal iss the issuer
	// publishes. For Harbor that's "harbor-token-issuer" (a label,
	// NOT a URL); for a future Vault federation it would be
	// "https://vault.example.com" (URL).
	Issuer string

	// StaticPublicKey — RSA public key for issuers that do NOT
	// publish a JWKS endpoint (Harbor is the canonical example).
	// Mutually exclusive with JWKSURL. Either StaticPublicKey or
	// JWKSURL is required; both is a config error.
	StaticPublicKey *rsa.PublicKey

	// JWKSURL — for issuers that publish a JWKS endpoint. The
	// fetched key set is cached with the same TTL + cooldown
	// semantics as the primary Falcon-ID JWKS.
	//
	// NOTE: not currently implemented (the only live federated
	// issuer at the time of writing — Harbor — uses StaticPublicKey
	// because Harbor does not publish JWKS). Wire shape is reserved
	// for forward compatibility; setting this returns a config
	// error in NewVerifier until the JWKS-URL federated path lands
	// in a follow-up MR.
	JWKSURL string

	// AllowedHosts — optional host-prefix scoping. When non-empty,
	// this federated issuer is only consulted for requests whose
	// (lower-cased) Host header EXACTLY matches one of the listed
	// values. Default (nil/empty) = applies to every route with
	// AuthModeBearerOrFederatedPassthrough. Mirrors Envoy
	// RequirementRule.match.
	AllowedHosts []string
}

// federatedIssuerState — Verifier's internal per-issuer cache.
type federatedIssuerState struct {
	cfg FederatedIssuerConfig
}

// federatedRegistry holds the parsed FederatedIssuerConfig set.
// Indexed by exact issuer string for O(1) iss-claim dispatch.
type federatedRegistry struct {
	mu sync.RWMutex
	// issuers — exact `iss` claim → state. NEVER reset; immutable
	// post-NewVerifier. The RWMutex is here for forward compat
	// (JWKS-URL refresh path would mutate per-state JWKS cache).
	issuers map[string]*federatedIssuerState
}

// newFederatedRegistry validates + indexes a list of
// FederatedIssuerConfig. Returns an error if any entry is
// malformed (missing key, both JWKS-URL and StaticPublicKey,
// duplicate issuer string, etc.).
func newFederatedRegistry(configs []FederatedIssuerConfig) (*federatedRegistry, error) {
	r := &federatedRegistry{
		issuers: make(map[string]*federatedIssuerState, len(configs)),
	}
	for i, c := range configs {
		if c.Issuer == "" {
			return nil, fmt.Errorf("svctoken: FederatedIssuerConfig[%d].Issuer required", i)
		}
		if c.StaticPublicKey == nil && c.JWKSURL == "" {
			return nil, fmt.Errorf("svctoken: FederatedIssuerConfig[%d] (%q): one of StaticPublicKey or JWKSURL required", i, c.Issuer)
		}
		if c.StaticPublicKey != nil && c.JWKSURL != "" {
			return nil, fmt.Errorf("svctoken: FederatedIssuerConfig[%d] (%q): StaticPublicKey and JWKSURL are mutually exclusive", i, c.Issuer)
		}
		if c.JWKSURL != "" {
			return nil, fmt.Errorf("svctoken: FederatedIssuerConfig[%d] (%q): JWKSURL-backed federated issuers not yet supported, use StaticPublicKey", i, c.Issuer)
		}
		if _, dup := r.issuers[c.Issuer]; dup {
			return nil, fmt.Errorf("svctoken: duplicate FederatedIssuerConfig.Issuer %q", c.Issuer)
		}
		// Lower-case AllowedHosts for case-insensitive Host header match.
		if len(c.AllowedHosts) > 0 {
			lowered := make([]string, len(c.AllowedHosts))
			for j, h := range c.AllowedHosts {
				lowered[j] = strings.ToLower(strings.TrimSpace(h))
			}
			c.AllowedHosts = lowered
		}
		r.issuers[c.Issuer] = &federatedIssuerState{cfg: c}
	}
	return r, nil
}

// lookup returns the federated issuer state for an exact iss claim,
// or nil if no federated issuer matches. Cheap O(1) lookup.
func (r *federatedRegistry) lookup(iss string) *federatedIssuerState {
	if r == nil || len(r.issuers) == 0 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.issuers[iss]
}

// hostAllowed checks whether this federated issuer's AllowedHosts
// scoping permits use on a given request Host. Empty AllowedHosts
// = permit all hosts (no per-host pinning).
func (s *federatedIssuerState) hostAllowed(host string) bool {
	if len(s.cfg.AllowedHosts) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, h := range s.cfg.AllowedHosts {
		if h == host {
			return true
		}
	}
	return false
}

// ParseRSAPublicKeyPEM is a helper that decodes a PEM-encoded RSA
// public key (either PKCS#1 RSAPublicKey or PKIX
// SubjectPublicKeyInfo) into a *rsa.PublicKey suitable for use as
// FederatedIssuerConfig.StaticPublicKey. Operators wiring a
// federated issuer from a Helm values block typically pass the
// PEM as a string and call this helper.
func ParseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("svctoken: ParseRSAPublicKeyPEM: no PEM block found")
	}
	// Try PKIX (SubjectPublicKeyInfo, BEGIN PUBLIC KEY) first.
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("svctoken: ParseRSAPublicKeyPEM: PKIX key is not RSA (got %T)", pub)
		}
		return rsaPub, nil
	}
	// Fall back to PKCS#1 (BEGIN RSA PUBLIC KEY).
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	return nil, errors.New("svctoken: ParseRSAPublicKeyPEM: not a valid PKIX or PKCS#1 RSA public key")
}

// VerifyFederated checks whether `raw` is a JWT signed by ANY of the
// federated issuers AND, optionally, whether the configured per-issuer
// AllowedHosts scoping permits this request's Host. On success it
// returns the matching issuer string. On failure it returns the empty
// string + a typed error from this package.
//
// FederatedVerify ENFORCES:
//   - alg in allowedAlgorithms (RS256 only, per RFC 8725 §3.3)
//   - issuer is in the federated registry
//   - host (if AllowedHosts on the issuer is non-empty) is permitted
//   - signature verifies against the issuer's key
//   - exp / nbf / iat with the same clock tolerance as the primary verifier
//
// FederatedVerify DOES NOT ENFORCE:
//   - audience (foreign issuers' aud is structured differently —
//     Harbor's is "harbor-registry"; Talon's audience-mapper is
//     Falcon-ID-specific)
//   - scope (foreign issuers don't carry Falcon-ID-shape scopes —
//     Harbor uses an `access` claim instead, evaluated by Harbor)
//   - replay (jti) or revocation (foreign issuers don't share
//     Falcon-ID's revocation list)
//
// This is the deliberate "signature-and-freshness-only" federated
// trust pattern — the IAP's job is to confirm the token is signed
// by a key we trust and is not expired; the upstream service (Harbor,
// Vault, etc.) re-validates the token with its own enforcement of
// audience, scope, and access claims. This matches the tier-1
// industry-consensus design (deep-research wf_36f4dd00-d01: Envoy
// per-provider config + Istio jwtRules[] + Ory trusted_issuers).
func (v *Verifier) VerifyFederated(ctx context.Context, raw, host string) (string, error) {
	if v.federated == nil || len(v.federated.issuers) == 0 {
		return "", fmt.Errorf("%w: no federated issuers configured", ErrIssuerMismatch)
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: empty token", ErrTokenMalformed)
	}

	parsed, err := jwt.ParseSigned(raw, allowedAlgorithms)
	if err != nil {
		if strings.Contains(err.Error(), "unexpected signature algorithm") {
			return "", fmt.Errorf("%w: %w", ErrAlgNotAllowed, err)
		}
		return "", fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	}
	if len(parsed.Headers) != 1 {
		return "", fmt.Errorf("%w: unexpected JWS header count %d", ErrTokenMalformed, len(parsed.Headers))
	}

	// Extract iss without verifying signature first — we need to
	// pick the right key. UnsafeClaimsWithoutVerification reads
	// only the claim body, no crypto.
	var prelim jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&prelim); err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenMalformed, err)
	}
	iss := prelim.Issuer
	if iss == "" {
		return "", fmt.Errorf("%w: empty iss", ErrIssuerMismatch)
	}

	state := v.federated.lookup(iss)
	if state == nil {
		// CVE-2021-21378 invariant: unknown iss is a verify FAILURE,
		// never a missing-token (passthrough-eligible) case.
		return "", fmt.Errorf("%w: iss %q not in federated registry", ErrIssuerMismatch, iss)
	}

	// Per-issuer host scoping (confused-deputy guard).
	if !state.hostAllowed(host) {
		return "", fmt.Errorf("%w: iss %q not permitted for host %q", ErrIssuerMismatch, iss, host)
	}

	// Verify signature against the federated issuer's key.
	if state.cfg.StaticPublicKey == nil {
		// Defensive: newFederatedRegistry already validated this,
		// but guard against future drift.
		return "", fmt.Errorf("%w: federated issuer %q has no public key", ErrSignatureInvalid, iss)
	}
	var stdClaims jwt.Claims
	if err := parsed.Claims(state.cfg.StaticPublicKey, &stdClaims); err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	// Re-check iss (defense-in-depth — UnsafeClaimsWithoutVerification
	// + post-verify Claims should agree, but if there's an envelope
	// layer or a future jose change, this is the canonical guard).
	if stdClaims.Issuer != iss {
		return "", fmt.Errorf("%w: claim iss %q changed after verify (was %q)", ErrIssuerMismatch, stdClaims.Issuer, iss)
	}

	// Time-bounds with clock tolerance — same semantics as the primary
	// verifier. exp is required; nbf + iat are checked only if present.
	now := time.Now()
	if stdClaims.Expiry == nil {
		return "", fmt.Errorf("%w: federated JWT missing exp", ErrTokenExpired)
	}
	if now.Add(-v.clockTolerance).After(stdClaims.Expiry.Time()) {
		return "", fmt.Errorf("%w: exp=%s now=%s tol=%s",
			ErrTokenExpired,
			stdClaims.Expiry.Time().Format(time.RFC3339),
			now.Format(time.RFC3339),
			v.clockTolerance)
	}
	if stdClaims.NotBefore != nil && now.Add(v.clockTolerance).Before(stdClaims.NotBefore.Time()) {
		return "", fmt.Errorf("%w: nbf=%s now=%s",
			ErrTokenNotYetValid,
			stdClaims.NotBefore.Time().Format(time.RFC3339),
			now.Format(time.RFC3339))
	}
	if stdClaims.IssuedAt != nil && now.Add(v.clockTolerance).Before(stdClaims.IssuedAt.Time()) {
		return "", fmt.Errorf("%w: iat=%s now=%s",
			ErrTokenNotYetValid,
			stdClaims.IssuedAt.Time().Format(time.RFC3339),
			now.Format(time.RFC3339))
	}

	// Deliberate omissions:
	//   - audience: foreign aud claim is upstream-defined (Harbor:
	//     "harbor-registry") and not bindable to the Talon-fronted
	//     host. Upstream re-validates.
	//   - scope: foreign issuers don't carry Falcon-ID-shape scopes.
	//     Harbor's access claim is per-repo and is Harbor's to
	//     enforce.
	//   - replay/revocation: foreign issuers don't participate in
	//     Falcon-ID's jti namespace or revocation list.

	return iss, nil
}

// HasFederatedIssuers reports whether any federated issuer is
// configured. Middleware uses this as a cheap dispatch test before
// calling VerifyFederated on the unknown-iss path.
func (v *Verifier) HasFederatedIssuers() bool {
	return v.federated != nil && len(v.federated.issuers) > 0
}
