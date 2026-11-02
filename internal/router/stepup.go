// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"net/http"
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

// passkeyStepUpACR is the Falcon-ID acr_values token for the AAL3
// (phishing-resistant WebAuthn/passkey) level (falcon-id
// internal/services/oauth_provider_service_claims.go:46, advertised in
// discovery acr_values_supported). Talon asks for it on a passkey step-up and
// does NOT trust it blindly: the IdP's ACR gate accepts any MFA factor, so the
// callback only refreshes Blob.LastWebAuthnAt when the new id_token's amr
// actually carries a hardware/software-key factor (hardwareFactorAuthTime).
const passkeyStepUpACR = "urn:hexxlock:aal3" //nolint:gosec // ACR URN, not a credential

// passkeyStepUpLoopGuardSec bounds how long after a passkey step-up round
// trip a still-stale passkey time is treated as "the step-up just ran and did
// not help" (user picked TOTP, IdP ignored acr, ...). Within the window Talon
// falls through to the normal Rego deny instead of redirecting again. The
// marker is Blob.PasskeyStepUpAt, set only when the callback completed a
// handshake that was started as a passkey step-up, so ordinary sign-ins and
// silent-SSO re-auth never trip the guard.
const passkeyStepUpLoopGuardSec = 180

// passkeyStepUpMaxAgeSec is the passkey freshness window that triggers a
// step-up: the STRICTEST window the ZTNA baseline Rego applies for the
// sensitivity (ztna_baseline.rego: TIER_BYOD aal3 needs webauthn_fresh_1h on
// high; TIER_CORP critical needs webauthn_fresh_1h). It is deliberately
// stricter than mfaMaxAgeSecForSensitivity (12h for high), so a high route
// does not dead-end in a 403 for BYOD. Routes below high are not stepped up.
func passkeyStepUpMaxAgeSec(sensitivity string) int {
	switch sensitivity {
	case "critical", "high":
		return 3600
	default:
		return 0
	}
}

// passkeyStepUpAction is the outcome of passkeyStepUpDecision.
type passkeyStepUpAction int

const (
	// passkeyStepUpNone: no step-up needed (or the loop guard tripped); fall
	// through to the Rego decision.
	passkeyStepUpNone passkeyStepUpAction = iota
	// passkeyStepUpRedirect: interactive browser request; redirect to a
	// passkey re-authentication with the original URL as return target.
	passkeyStepUpRedirect
	// passkeyStepUpChallenge: API/XHR/asset request; answer 401 with an
	// RFC 9470 challenge instead of a redirect.
	passkeyStepUpChallenge
	// passkeyStepUpAuditOnly: step-up would be required but the route is
	// auditOnly; log the would-deny and let the request continue.
	passkeyStepUpAuditOnly
)

// passkeyStepUpDecision decides, BEFORE Rego runs, whether the request must
// first go through a passkey step-up. It is a pure function of its inputs so
// the loop guard is unit-testable.
//
//   - tier: posture compliance tier ("" when unknown). TIER_BREAKGLASS on a
//     critical route is allowed by the Rego without any webauthn recency, so
//     it is never stepped up.
//   - lastWebAuthnAt: Blob.LastWebAuthnAt (0 = no hardware factor ever).
//   - passkeyStepUpAt: Blob.PasskeyStepUpAt (0 = this session did not come
//     from a passkey step-up).
//   - interactive: GET/HEAD navigation expecting HTML (see isInteractiveBrowserRequest).
func passkeyStepUpDecision(sensitivity, tier string, lastWebAuthnAt, passkeyStepUpAt, now int64, auditOnly, interactive bool) passkeyStepUpAction {
	maxAge := passkeyStepUpMaxAgeSec(sensitivity)
	if maxAge <= 0 {
		return passkeyStepUpNone
	}
	if sensitivity == "critical" && tier == "TIER_BREAKGLASS" {
		return passkeyStepUpNone
	}
	if lastWebAuthnAt > 0 && now-lastWebAuthnAt <= int64(maxAge) {
		return passkeyStepUpNone
	}
	// Loop guard: a passkey step-up just completed and the passkey time is
	// still stale, so another redirect cannot help. Fall through to the deny.
	if passkeyStepUpAt > 0 && now-passkeyStepUpAt >= 0 && now-passkeyStepUpAt <= passkeyStepUpLoopGuardSec {
		return passkeyStepUpNone
	}
	if auditOnly {
		return passkeyStepUpAuditOnly
	}
	if interactive {
		return passkeyStepUpRedirect
	}
	return passkeyStepUpChallenge
}

// isInteractiveBrowserRequest reports whether req is a top-level browser
// navigation that can follow a redirect chain: GET/HEAD, not an XHR/asset
// fetch, and an Accept header that lists text/html.
func isInteractiveBrowserRequest(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	if isXHROrAssetRequest(req) {
		return false
	}
	return strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/html")
}
