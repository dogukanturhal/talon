// SPDX-License-Identifier: AGPL-3.0-or-later

// Package posture verifies a signed device-posture assertion presented
// by the client (typically through a managed-device agent like
// osquery + a Talon-side trust agent, or via an EDR like CrowdStrike
// Falcon Insight forwarding device state into Falcon-ID).
//
// The wire shape is a JWS signed by the posture provider (Falcon-ID
// minted, an EDR pubkey trusted in posture.Verifier, or a managed-
// device CA). The payload encodes a deterministic, time-bounded
// statement of device compliance:
//
//	{
//	  "iss": "https://posture.example.com",
//	  "sub": "device:<machine-uuid>",       // attested device id
//	  "aud": "https://auth.internal.example.com",
//	  "iat": 1717000000,
//	  "exp": 1717003600,                     // <=1h freshness window
//	  "user_sub": "user-123",                // bind to user OR omit
//	  "compliance": {                        // structured fact map
//	    "disk_encrypted": true,
//	    "screen_lock_min": 5,
//	    "edr_running": true,
//	    "os": "macos",
//	    "os_version": "15.2.0",
//	    "patch_level": "2026-05-29",
//	    "managed": true,
//	    "jailbroken": false
//	  }
//	}
//
// The HTTP request carries the signed posture in `X-Talon-Posture`:
//
//	X-Talon-Posture: <compact-JWS>
//
// Talon's verifier checks (in order):
//
//  1. Parse + verify signature against a trusted posture-issuer JWKS
//     (separate trust chain from Falcon-ID — posture issuers are NOT
//     authorized to mint user identity tokens, and vice versa).
//  2. iss is in the trusted issuer set.
//  3. aud includes Talon's audience.
//  4. exp not expired; iat within the freshness window.
//  5. If `user_sub` is present and the request session.Blob.Sub is
//     known, they MUST match. Reject on mismatch.
//  6. The decoded `compliance` map is returned to the caller.
//
// The caller (TalonRoute path rule evaluation) compares the compliance
// facts against the route's `requirePosture` declaration. A missing
// X-Talon-Posture header on a route that requires posture = 401 with
// reason=`posture_missing`. A posture header that fails verification
// = 401 with reason=`posture_invalid`. A posture present but failing
// the route's policy = 403 with reason=`posture_noncompliant`.
//
// # Trust model — keep distinct from Falcon-ID
//
// The posture issuer trust chain is INTENTIONALLY SEPARATE from the
// OIDC IdP trust chain. A compromise of the posture-provider key MUST
// NOT grant the attacker the ability to mint user identity tokens.
// Conversely, a Falcon-ID compromise should not let the attacker
// fabricate "this device is compliant" statements. This mirrors the
// Cloudflare WARP posture-issuer separation: Falcon-ID issues OIDC
// id_tokens; the device-trust subsystem signs posture assertions with
// its own keypair backed by its own HSM.
package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// HeaderName is the request header Talon reads. Tier-1 vendors agree
// on no canonical header name; this is HexxLock's chosen convention.
// Keeps the namespace under X-Talon-* with other Talon-specific
// envelope headers.
const HeaderName = "X-Talon-Posture"

// Device-tier signal. The verifier reads the device trust tier from the
// compliance fact map under this key; jess-issued device certs encode
// `tier=TIER_CORP|TIER_BYOD` in the cert subject and the posture signer
// projects it here (see docs/policy/ztna/ztna_baseline.rego effective_tier).
// The tier selects the governed grace budget (DDIL P3.10) — TIER_CORP →
// GraceCorp, everything else → GraceByod.
const complianceTierKey = "tier"

// Device trust tiers recognized for grace-budget selection. These mirror the
// ztna_baseline.rego tier vocabulary. An absent/unknown tier is treated as
// the BYOD (most-defensive) bucket, exactly as effective_tier defaults there.
const (
	TierCorp = "TIER_CORP"
	TierByod = "TIER_BYOD"
)

// RecommendedGraceCorp / RecommendedGraceByod are the LOCKED PACE staleness
// budgets (the 2026-07-19 DDIL degraded-mode operating spec): a TPM-attested
// device-posture assertion past its hard `exp` is honored in a GOVERNED,
// graceful-degraded mode for at most this long — 10m for a corp device (tight
// ~5min re-attest cadence), 30m for a BYOD device (looser ~15min cadence),
// i.e. ~2× the tier's re-attest cadence, matching the ztna_baseline.rego
// freshness philosophy. They are NOT applied as verifier defaults: grace is
// OFF unless the operator opts in via config (the fail-closed-biased default).
// They are the reviewed values operators should set. See ADR 0010.
const (
	RecommendedGraceCorp = 10 * time.Minute
	RecommendedGraceByod = 30 * time.Minute
)

// Errors callers may want to discriminate.
var (
	ErrMissing          = errors.New("posture: header absent")
	ErrParse            = errors.New("posture: parse failed")
	ErrSignature        = errors.New("posture: signature verification failed")
	ErrIssuerUntrusted  = errors.New("posture: issuer not in trusted set")
	ErrAudienceMismatch = errors.New("posture: aud does not include receiver")
	ErrExpired          = errors.New("posture: expired or iat outside window")
	ErrUserMismatch     = errors.New("posture: user_sub does not match session sub")
	ErrUnsupportedAlg   = errors.New("posture: unsupported alg")
)

// JWKSResolver returns the public key(s) the posture JWS was signed
// with. Implementations should key on (iss, kid) so a posture issuer
// can rotate keys without operator action.
type JWKSResolver interface {
	Keys(ctx context.Context, iss, kid string) ([]any, error)
}

// Claims is the decoded posture assertion. Callers use it to evaluate
// route-level `requirePosture` policy.
type Claims struct {
	Issuer    string
	Subject   string // typically "device:<uuid>"
	UserSub   string // optional binding; "" when posture is device-only
	Audience  string // the matching audience value Talon recognized
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Degraded reports that this posture verified structurally AND by
	// signature (the TPM-attested device key) but is past its hard `exp`
	// (or iat+MaxAge) freshness deadline and is being served WITHIN Talon's
	// governed grace budget (DDIL P3.10 — see VerifierConfig GraceCorp/
	// GraceByod). It is false for a fresh posture and is never true for a
	// posture rejected past grace (that returns ErrExpired, not a Claims).
	// The CONSUMER MUST treat a Degraded posture as admissible only for
	// low/medium-sensitivity routes and deny it on critical/high — grace is
	// a graceful-downgrade, not a full pass.
	Degraded bool

	// GraceUntil is the instant this degraded posture will fail closed — the
	// earliest of the exp+grace and iat+MaxAge+grace deadlines. Zero when
	// Degraded is false. Surfaced to policy so a consumer can display or
	// audit the remaining budget.
	GraceUntil time.Time

	// Compliance is the structured fact map the route policy reads.
	// Tier-1 facts (suggested keys; route policies key on these
	// strings):
	//   - "disk_encrypted":   bool
	//   - "edr_running":      bool
	//   - "screen_lock_min":  int    (minutes; 0 = none)
	//   - "os":               string ("macos","windows","linux","ios","android")
	//   - "os_version":       string
	//   - "patch_level":      string (ISO date)
	//   - "managed":          bool
	//   - "jailbroken":       bool   (true = noncompliant)
	//
	// Posture providers MAY emit additional facts; route policies that
	// don't recognize a key MUST ignore it (default-accept on missing
	// requirement, default-deny on missing fact for a declared check).
	Compliance map[string]any
}

// VerifierConfig wires trust + tunables.
type VerifierConfig struct {
	// TrustedIssuers is the set of valid posture-issuer iss strings.
	// Empty = no issuers trusted; verifier rejects all postures
	// (effectively turns off the feature even if the header is set).
	TrustedIssuers []string

	// ExpectedAudience is the receiver URL (typically Talon's auth
	// host). aud must match.
	ExpectedAudience string

	// AllowedAlgs constrains posture-JWS signing algs. Default:
	// {RS256, ES256, EdDSA}.
	AllowedAlgs []jose.SignatureAlgorithm

	// MaxAge is the max acceptable age (now - iat). Default 1h. RFC
	// 9449-grade postures should be tighter; tier-1 vendors use 5-
	// 30min on WAN-bound clients.
	MaxAge time.Duration

	// Skew is the clock-skew tolerance on iat / exp. Default 30s.
	Skew time.Duration

	// GraceCorp / GraceByod are the DDIL P3.10 governed posture-grace
	// budgets: how long past its hard `exp` (and past iat+MaxAge) a
	// TPM-attested posture is honored in a graceful-DEGRADED mode before it
	// fails closed. The grace is CONSUMER-governed — Talon (the PEP) decides
	// the budget; a device NEVER self-grants it, and grace NEVER bypasses the
	// signature/attestation check (that runs first and still hard-rejects a
	// forged posture). A degraded posture is admissible for low/medium routes
	// and denied on critical/high — the consumer applies that split (see
	// internal/router). GraceCorp applies to TIER_CORP devices, GraceByod to
	// every other tier (TIER_BYOD, breakglass, absent/unknown → the most-
	// defensive bucket).
	//
	// 0 (the default for BOTH) DISABLES grace for that tier — the pre-P3.10
	// hard ErrExpired-at-exp behaviour — so the feature is backward-compatible
	// and OFF unless explicitly configured. The reviewed opt-in values are
	// RecommendedGraceCorp (10m) / RecommendedGraceByod (30m). Keep the budget
	// an explicit reviewed config: do not stretch it to dodge re-attest
	// friction (the grace-window-drift caveat, ADR 0010).
	GraceCorp time.Duration
	GraceByod time.Duration

	// Resolver returns signing keys per (iss, kid).
	Resolver JWKSResolver

	// Clock for tests; defaults to time.Now.
	Clock func() time.Time
}

// Verifier validates posture headers per the package contract above.
type Verifier struct {
	cfg            VerifierConfig
	allowedIssSet  map[string]struct{}
	allowedAlgsSet map[jose.SignatureAlgorithm]struct{}
}

// NewVerifier returns a configured verifier. Returns nil + error if
// any required field is missing.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.TrustedIssuers) == 0 {
		return nil, errors.New("posture: TrustedIssuers required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("posture: ExpectedAudience required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("posture: Resolver required")
	}
	algs := cfg.AllowedAlgs
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}
	}
	algSet := make(map[jose.SignatureAlgorithm]struct{}, len(algs))
	for _, a := range algs {
		algSet[a] = struct{}{}
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = time.Hour
	}
	if cfg.Skew == 0 {
		cfg.Skew = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	issSet := make(map[string]struct{}, len(cfg.TrustedIssuers))
	for _, i := range cfg.TrustedIssuers {
		issSet[i] = struct{}{}
	}
	return &Verifier{cfg: cfg, allowedIssSet: issSet, allowedAlgsSet: algSet}, nil
}

// Verify decodes + validates the posture token. expectedUserSub is the
// session.Blob.Sub at request time; pass "" to disable user-binding
// (device-only posture). When expectedUserSub is non-empty AND the
// token includes user_sub, they MUST match — defends against a
// posture assertion being lifted from one user's device and replayed
// for another user's session.
func (v *Verifier) Verify(ctx context.Context, postureJWT string, expectedUserSub string) (*Claims, error) {
	if postureJWT == "" {
		return nil, ErrMissing
	}
	algs := v.permittedAlgs()
	parsed, err := jwt.ParseSigned(postureJWT, algs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected single header, got %d", ErrParse, len(parsed.Headers))
	}
	hdr := parsed.Headers[0]
	alg := jose.SignatureAlgorithm(hdr.Algorithm)
	if _, ok := v.allowedAlgsSet[alg]; !ok {
		return nil, fmt.Errorf("%w: alg %s not permitted", ErrUnsupportedAlg, alg)
	}

	// Peek at iss before sig-verify so the resolver gets the right
	// issuer key set. UnsafeClaimsWithoutVerification is necessary
	// here — we have no way to look up the JWKS without first
	// reading iss. The full Claims() call below performs the actual
	// signature verification.
	var preview struct {
		Iss string `json:"iss"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&preview); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if preview.Iss == "" {
		return nil, fmt.Errorf("%w: missing iss", ErrParse)
	}
	if _, ok := v.allowedIssSet[preview.Iss]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrIssuerUntrusted, preview.Iss)
	}

	keys, err := v.cfg.Resolver.Keys(ctx, preview.Iss, hdr.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %s/%s: %w", ErrSignature, preview.Iss, hdr.KeyID, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no keys for %s/%s", ErrSignature, preview.Iss, hdr.KeyID)
	}

	var raw rawClaims
	var verifyErr error
	for _, k := range keys {
		if err := parsed.Claims(k, &raw); err == nil {
			verifyErr = nil
			break
		} else {
			verifyErr = err
		}
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, verifyErr)
	}

	// Envelope checks.
	if !audContains(raw.Aud, v.cfg.ExpectedAudience) {
		return nil, fmt.Errorf("%w: receiver %q not in aud %v", ErrAudienceMismatch, v.cfg.ExpectedAudience, raw.Aud)
	}
	now := v.cfg.Clock()
	iat := time.Unix(raw.IAT, 0)
	exp := time.Unix(raw.Exp, 0)

	// DDIL P3.10 governed posture-grace. Freshness is no longer a single hard
	// cliff at exp/MaxAge: a posture past its deadline but WITHIN the tier's
	// governed grace budget is returned in a graceful-DEGRADED mode
	// (Claims.Degraded=true) instead of ErrExpired; only past the grace
	// deadline does it fail closed. The signature check already ran above, so
	// grace NEVER bypasses attestation — a forged/bad-signature posture never
	// reaches this point. The grace budget is Talon's config alone (graceFor);
	// any device-claimed grace field is ignored. `grace == 0` collapses each
	// gate back to the pre-P3.10 hard ErrExpired at exp+Skew / iat+MaxAge+Skew
	// (backward compatible — the feature is off by default).
	grace := v.graceFor(tierFromCompliance(raw.Compliance))
	var degraded bool
	// graceUntil tracks the earliest instant the degraded posture will fail
	// closed across the two independent freshness constraints. Zero unless
	// degraded.
	var graceUntil time.Time
	tightenGraceUntil := func(d time.Time) {
		if graceUntil.IsZero() || d.Before(graceUntil) {
			graceUntil = d
		}
	}

	// exp gate. Fresh while now ≤ exp+Skew; degraded while exp+Skew < now ≤
	// exp+grace; fail closed past exp+grace.
	if raw.Exp > 0 && now.After(exp.Add(v.cfg.Skew)) {
		graceDeadline := exp.Add(grace)
		if now.After(graceDeadline) {
			return nil, fmt.Errorf("%w: exp %s grace %s now %s", ErrExpired, exp, grace, now)
		}
		degraded = true
		tightenGraceUntil(graceDeadline)
	}

	// iat / MaxAge gate. A missing iat is malformed and always hard-rejected —
	// grace never resurrects a posture that never stated when it was minted.
	if raw.IAT == 0 {
		return nil, fmt.Errorf("%w: missing iat", ErrExpired)
	}
	if now.Sub(iat) > v.cfg.MaxAge+v.cfg.Skew {
		graceDeadline := iat.Add(v.cfg.MaxAge + grace)
		if now.After(graceDeadline) {
			return nil, fmt.Errorf("%w: iat %s age %s > MaxAge %s + grace %s", ErrExpired, iat, now.Sub(iat), v.cfg.MaxAge, grace)
		}
		degraded = true
		tightenGraceUntil(graceDeadline)
	}

	// user_sub binding (defends against posture-replay across users).
	if expectedUserSub != "" && raw.UserSub != "" && raw.UserSub != expectedUserSub {
		return nil, fmt.Errorf("%w: claim %q session %q", ErrUserMismatch, raw.UserSub, expectedUserSub)
	}

	return &Claims{
		Issuer:     raw.Iss,
		Subject:    raw.Sub,
		UserSub:    raw.UserSub,
		Audience:   v.cfg.ExpectedAudience,
		IssuedAt:   iat,
		ExpiresAt:  exp,
		Degraded:   degraded,
		GraceUntil: graceUntil,
		Compliance: raw.Compliance,
	}, nil
}

// Evaluate compares the posture claims against a set of fact
// requirements. Returns (ok, missingOrFailedFact). Used by the
// router after Verify when the route declares `requirePosture`.
//
// Requirement semantics:
//   - bool value true  ⇒ claim must be present AND truthy
//   - bool value false ⇒ claim must be present AND falsy
//   - int  value N     ⇒ claim must be present, numeric, >= N
//     (used for screen_lock_min: 5 ⇒ ≥5min lock)
//   - string value     ⇒ claim must equal exactly
//
// A required fact missing from the posture = noncompliant. Posture
// extras are ignored.
//
// This function is intentionally bare — a Rego policy layered on top
// of TalonRoute (see internal/policy/rego.go) can express more
// complex device-trust rules; this function covers the common 90%
// case without forcing operators to write Rego for a 3-fact check.
func Evaluate(claims *Claims, required map[string]any) (ok bool, failedKey string) {
	if claims == nil || claims.Compliance == nil {
		return false, "_no_claims"
	}
	for k, want := range required {
		got, present := claims.Compliance[k]
		if !present {
			return false, k
		}
		switch w := want.(type) {
		case bool:
			gb, ok := got.(bool)
			if !ok || gb != w {
				return false, k
			}
		case int:
			gn, ok := toInt(got)
			if !ok || gn < w {
				return false, k
			}
		case float64:
			gn, ok := toInt(got)
			if !ok || float64(gn) < w {
				return false, k
			}
		case string:
			gs, ok := got.(string)
			if !ok || gs != w {
				return false, k
			}
		default:
			// Unknown requirement type; reject to fail-closed.
			return false, k
		}
	}
	return true, ""
}

// --- internal helpers ------------------------------------------------

type rawClaims struct {
	Iss        string         `json:"iss"`
	Sub        string         `json:"sub"`
	Aud        rawAud         `json:"aud"`
	IAT        int64          `json:"iat"`
	Exp        int64          `json:"exp"`
	UserSub    string         `json:"user_sub,omitempty"`
	Compliance map[string]any `json:"compliance"`
}

// rawAud handles RFC 7519 §4.1.3 audience polymorphism (string OR
// array). Mirrors the caep.audienceField pattern; lifted out
// separately so each package can evolve independently.
type rawAud []string

func (a *rawAud) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("aud: %w", err)
		}
		*a = rawAud{s}
		return nil
	}
	if data[0] == '[' {
		var ss []string
		if err := json.Unmarshal(data, &ss); err != nil {
			return fmt.Errorf("aud: %w", err)
		}
		*a = rawAud(ss)
		return nil
	}
	return fmt.Errorf("aud: expected string or array, got %s", data[:1])
}

func audContains(a rawAud, want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float32:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// tierFromCompliance reads the device trust tier from the verified compliance
// fact map for grace-budget selection. Returns "" when the posture carried no
// tier claim (the caller's graceFor then falls back to the BYOD budget, the
// most-defensive bucket — mirroring ztna_baseline.rego effective_tier).
func tierFromCompliance(c map[string]any) string {
	if c == nil {
		return ""
	}
	if t, ok := c[complianceTierKey].(string); ok {
		return t
	}
	return ""
}

// graceFor returns the governed posture-grace budget for a device tier
// (DDIL P3.10). TIER_CORP uses GraceCorp; every other tier (TIER_BYOD,
// breakglass, absent/unknown) uses GraceByod. A zero budget disables grace
// for that tier — the pre-P3.10 hard fail-closed-at-exp behaviour — so grace
// is OFF unless the operator configures it. The budget is Talon's config
// alone: a device cannot self-grant grace (this reads no device-supplied
// grace field).
func (v *Verifier) graceFor(tier string) time.Duration {
	if tier == TierCorp {
		return v.cfg.GraceCorp
	}
	return v.cfg.GraceByod
}

func (v *Verifier) permittedAlgs() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(v.allowedAlgsSet))
	for a := range v.allowedAlgsSet {
		out = append(out, a)
	}
	return out
}
