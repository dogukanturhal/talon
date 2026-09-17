// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"strconv"
	"strings"

	"github.com/dogukanturhal/talon/internal/session"
)

// rfc8176MFAFactors is the set of RFC 8176 §2 `amr` values that each
// individually qualify as multi-factor authentication. Membership of
// any of these in the session's AMR list satisfies the
// `mfaRequired` route gate when no RequireACR list is configured.
//
// The "mfa" umbrella value is included so a token that contains ONLY
// the umbrella (without the originating factor names — some IdPs
// emit it that way) still passes. `pwd` is excluded since password
// alone is the single-factor baseline; `user` is excluded because it
// is a sub-step of WebAuthn ceremonies (it always accompanies `hwk`
// or `swk`, never appears alone as a factor).
var rfc8176MFAFactors = map[string]struct{}{
	"mfa":    {}, // RFC 8176 §2 umbrella value
	"otp":    {}, // one-time password (TOTP, SMS-OTP, email-OTP)
	"hwk":    {}, // hardware key (WebAuthn / FIDO2)
	"swk":    {}, // software key
	"sms":    {}, // SMS-delivered code
	"tel":    {}, // telephone callback
	"face":   {}, // facial recognition
	"fpt":    {}, // fingerprint
	"iris":   {}, // iris scan
	"retina": {}, // retinal scan
	"vbm":    {}, // voice biometric
	"geo":    {}, // geolocation
	"kba":    {}, // knowledge-based answer
	"pin":    {}, // PIN
	"sc":     {}, // smart card
	"wia":    {}, // Windows Integrated Authentication
}

// containsAnyMFA reports whether amr contains any RFC 8176 §2
// multi-factor method (umbrella or any concrete factor). Used as the
// fallback branch of the step-up gate when a route has not configured
// a RequireACR list. Permissive by design — RFC 8176 §1 calls strict
// amr matching "more brittle than acr" precisely because IdPs vary in
// which umbrella/specific values they emit. Accepting any RFC 8176
// multi-factor signal absorbs that variance without weakening the
// gate's actual security property (that ≥1 second factor was used).
func containsAnyMFA(amr []string) bool {
	for _, v := range amr {
		if _, ok := rfc8176MFAFactors[v]; ok {
			return true
		}
	}
	return false
}

// stepUpSatisfied is the canonical "does the session satisfy this
// route's step-up requirement?" check. Returns (satisfied, reason)
// where reason is "acr", "amr", "not_required", or "" (failed). The
// reason is used by the audit/metric labels so operators can tell
// which path the gate followed.
//
// Decision order:
//
//  1. If the route configures requireACR (non-empty), check it
//     against blob.ACR. This is the RFC 8176 §1-recommended path —
//     stable LoA reference, not a factor enumeration.
//  2. Otherwise, if mfaRequired is set, accept any RFC 8176 §2
//     multi-factor signal in blob.AMR (umbrella or specific factor).
//  3. Otherwise no step-up required.
//
// Empty requireACR with mfaRequired=false short-circuits to allow.
func stepUpSatisfied(mfaRequired bool, requireACR []string, blob *session.Blob) (bool, string) {
	if len(requireACR) > 0 {
		for _, want := range requireACR {
			if blob.ACR == want {
				return true, "acr"
			}
		}
		return false, ""
	}
	if !mfaRequired {
		return true, "not_required"
	}
	if containsAnyMFA(blob.AMR) {
		return true, "amr"
	}
	return false, ""
}

// clientlessWebAuthnFactors is the subset of RFC 8176 §2 `amr` values
// that prove a WebAuthn / FIDO2 / platform-authenticator ceremony — the
// AAL2-or-better bar the clientless tier demands (ADR 0044 §"Trust
// model"). A clientless session has NO device cert, so the AAL cap is the
// load-bearing control: it MUST step up to a phishing-resistant
// authenticator before reaching ANY access-zone route.
//
// `hwk` (hardware key) is the canonical WebAuthn/FIDO2 roaming-authenticator
// signal; `swk` (software key) covers platform authenticators / passkeys
// bound to the device. Both are NIST SP 800-63B AAL2+ when combined with
// the prior `pwd` factor Falcon-ID always emits. We deliberately do NOT
// accept the generic `mfa`/`otp`/`sms` umbrella here — SMS/OTP is AAL2 by
// SP 800-63B but NOT phishing-resistant, and the whole point of the
// clientless cap is to require a phishing-resistant factor for unmanaged
// devices. This is STRICTER than the route-level mfaRequired gate by
// design.
var clientlessWebAuthnFactors = map[string]struct{}{
	"hwk": {}, // hardware key (WebAuthn / FIDO2 roaming authenticator)
	"swk": {}, // software key (platform authenticator / device-bound passkey)
}

// clientlessAALSatisfied reports whether the session meets the clientless
// tier's AAL cap (ADR 0044): a WebAuthn/FIDO2 factor (`hwk`/`swk`) in the
// session's `amr`, OR an ACR claim asserting AAL2+. The ACR branch lets a
// deployment whose IdP emits a stable LoA reference (e.g.
// "urn:hexxlock:aal2"/"urn:hexxlock:aal3") satisfy the cap without Talon
// re-deriving AAL from the factor enumeration — RFC 8176 §1 prefers acr.
//
// Fail-closed: an empty/absent amr+acr (e.g. a password-only session)
// returns false, so the caller forces a WebAuthn step-up before any
// clientless route is reachable.
func clientlessAALSatisfied(blob *session.Blob) bool {
	for _, v := range blob.AMR {
		if _, ok := clientlessWebAuthnFactors[v]; ok {
			return true
		}
	}
	switch blob.ACR {
	case "urn:hexxlock:aal2", "urn:hexxlock:aal3":
		return true
	}
	return false
}

// clientlessStepUpACR is the RFC 9470 acr_values the clientless AAL
// challenge advertises so the client knows to re-authenticate with a
// phishing-resistant (AAL2) factor. Mirrors the HexxLock LoA vocabulary
// the IdP and SDK already share (see stepUpSatisfied / ADR 0001).
var clientlessStepUpACR = []string{"urn:hexxlock:aal2"}

// mfaMaxAgeSecForSensitivity returns the WebAuthn/MFA freshness window
// (seconds) a route of the given ZTNA sensitivity class advertises in its
// RFC 9470 challenge. The tiers MIRROR the ztna_baseline.rego recency gates
// (docs/policy/ztna/ztna_baseline.rego: webauthn_fresh_1h / _12h) so the
// header the client sees matches what the Rego policy actually enforces:
//
//	critical → 3600   (1h step-up window)
//	high     → 43200  (12h)
//	other    → 0      (no freshness advertised; presence-only MFA)
//
// Header-only: this advertises the expectation per RFC 9470 §4.1 so a
// client can pre-emptively re-authenticate. The authoritative allow/deny
// freshness gate is the Rego baseline (AAL3 recency) — this function never
// changes a decision, so it carries zero lockout risk.
func mfaMaxAgeSecForSensitivity(sensitivity string) int {
	switch sensitivity {
	case "critical":
		return 3600
	case "high":
		return 43200
	default:
		return 0
	}
}

// BuildRFC9470Challenge returns the WWW-Authenticate header value
// for an unsatisfied step-up requirement, per RFC 9470 OAuth 2.0
// Step Up Authentication Challenge §4:
//
//	WWW-Authenticate: Bearer error="insufficient_user_authentication",
//	                  acr_values="<space-separated values>",
//	                  max_age=<seconds>
//
// We emit `error` always (the load-bearing parameter per the RFC's MUST
// clause), `acr_values` when the route pins an ACR list, and `max_age`
// when the route's sensitivity advertises a freshness window
// (maxAgeSec > 0). max_age tells a client how recent the authentication
// must be — it mirrors the Rego baseline's WebAuthn-recency gate so the
// advertised expectation matches what is actually enforced.
//
// When acrValues is empty (route uses the v1alpha1 mfaRequired
// fallback path with no ACR list), emit only the `error`
// parameter (+ max_age when set) — clients interpret that as "any MFA
// satisfies, but it must be recent". Same shape Okta + Auth0 emit when
// the resource doesn't pin a specific ACR.
//
// HexxLock's specific ACR vocabulary (e.g., "urn:hexxlock:aal2")
// flows through verbatim — the IdP and the SDK already share
// the same identifiers.
//
// Returns empty string when neither acrValues nor mfaRequired is
// set (i.e., no step-up demanded). Caller checks for empty and
// skips emitting the header in that case.
func BuildRFC9470Challenge(acrValues []string, mfaRequired bool, maxAgeSec int) string {
	if len(acrValues) == 0 && !mfaRequired {
		return ""
	}
	var b strings.Builder
	b.WriteString(`Bearer error="insufficient_user_authentication"`)
	if len(acrValues) > 0 {
		b.WriteString(`, acr_values="`)
		// RFC 9470 §4.1: acr_values is a space-separated list. The IdP
		// and SDK interpret this verbatim. Don't escape inner quotes
		// — none of our ACR identifiers contain double-quotes (URN
		// syntax forbids them, and IdP-emitted business-rule refs
		// follow the same convention). If a future ACR value DID
		// require an embedded quote, we'd need to escape it per
		// RFC 7235 §2.2; for now no-escape keeps the header
		// human-readable in tcpdumps and access logs.
		b.WriteString(strings.Join(acrValues, " "))
		b.WriteByte('"')
	}
	if maxAgeSec > 0 {
		// RFC 9470 §4.1: max_age is a number of seconds (no quotes).
		b.WriteString(`, max_age=`)
		b.WriteString(strconv.Itoa(maxAgeSec))
	}
	return b.String()
}
