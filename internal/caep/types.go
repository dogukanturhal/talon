// SPDX-License-Identifier: AGPL-3.0-or-later

// Package caep — receiver for OpenID Continuous Access Evaluation
// Profile (CAEP) 1.0 Security Event Tokens (SETs) per RFC 8417
// (Subject Information Format) and the OpenID Foundation CAEP 1.0
// Final spec (published 2025-08-29).
//
// Wire shape — a SET is a JWS-signed JWT with this payload:
//
//	{
//	  "iss": "https://id.example.com",
//	  "aud": "https://auth.internal.example.com",
//	  "iat": 1717000000,
//	  "jti": "uniq-event-id",
//	  "events": {
//	    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
//	      "subject": {
//	        "format": "iss_sub",
//	        "iss": "https://id.example.com",
//	        "sub": "user-123"
//	      },
//	      "event_timestamp": 1717000000,
//	      "initiating_entity": "admin",
//	      "reason_admin": {"en": "Compromised credentials"}
//	    }
//	  }
//	}
//
// Talon's response semantics (per ADR 0010 fail-mode policy):
//
//	session-revoked / credential-change / account-disabled →
//	    immediate RevokeBySubject(sub) of every active session
//	risk-level-change → audit + emit `caep.risk_change` event;
//	    operator policy decides whether to auto-revoke
//	device-compliance-change → audit + future hook to posture
//	    policy (not yet wired)
//
// Wire protocol — RFC 8935 Push Delivery via HTTP POST. The transmitter
// (Falcon-ID) POSTs to Talon's `/caep/events` endpoint with:
//
//	Content-Type: application/secevent+jwt
//	Authorization: Bearer <transmitter-mint-token>     (optional)
//	body = <compact-JWS>
//
// Response: 202 Accepted on success; 400 on parse failure; 401 on
// signature/transmitter-auth failure; 5xx on internal error.
package caep

// Event types — exact strings from the OpenID CAEP 1.0 Final spec
// and SECEVENT RISC profile. Operators MUST match on the FULL URN;
// don't shorten. Wazuh rules key on these for triage.
const (
	// EventSessionRevoked — the transmitter's session is gone. Talon
	// MUST revoke every Talon session that maps to (iss, sub).
	EventSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	// EventCredentialChange — credential rotated (password change,
	// passkey re-enrolled, security-key replaced). Talon revokes all
	// sessions to force re-auth.
	EventCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // event-type URN, not a credential

	// EventRiskLevelChange — risk score moved. Talon emits audit;
	// auto-revoke only when paired with a Talon-side risk policy
	// (out of MVP scope).
	EventRiskLevelChange = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"

	// EventDeviceComplianceChange — registered device fell out of
	// compliance (jailbreak, no disk encryption, etc.). Future hook
	// for posture policy. Emits audit for now.
	EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"

	// EventAssuranceLevelChange — AAL/IAL changed (e.g. user lost a
	// hardware key and dropped from AAL3 to AAL2). Talon emits audit;
	// route-level RequireACR check naturally enforces on next request.
	EventAssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

	// EventAccountDisabled — RISC profile event. Talon revokes all.
	EventAccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

	// EventAccountPurged — RISC profile event; account terminated.
	// Talon revokes all + tombstones the sub in the per-sub cache.
	EventAccountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged"

	// EventAccountCredentialChangeRequired — RISC profile; force-
	// password-change pending. Talon revokes all so the user re-auths
	// and goes through the credential-update flow on the IdP.
	EventAccountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required" //nolint:gosec // event-type URN, not a credential
)

// Subject is the CAEP "subject" identifier inside an event payload.
// RFC 8417 §1.2 + §3 + Subject Identifiers for SETs (RFC 9493) define
// a polymorphic shape — Talon only consumes `iss_sub` format because
// that's what Falcon-ID emits. Other formats (`email`, `phone_number`)
// are decoded into the same struct but with extra fields possibly set;
// callers must check Format before keying on Sub.
type Subject struct {
	Format string `json:"format"`         // typically "iss_sub"
	Iss    string `json:"iss,omitempty"`  // present when format=iss_sub
	Sub    string `json:"sub,omitempty"`  // present when format=iss_sub
	Email  string `json:"email,omitempty"`
}

// EventPayload is the per-event-type body inside the SET's `events`
// claim. Most CAEP events share these fields; format-specific extras
// are deliberately not modeled (forward-compat).
type EventPayload struct {
	Subject          Subject     `json:"subject"`
	EventTimestamp   int64       `json:"event_timestamp,omitempty"`
	InitiatingEntity string      `json:"initiating_entity,omitempty"`
	ReasonAdmin      LangMap     `json:"reason_admin,omitempty"`
	ReasonUser       LangMap     `json:"reason_user,omitempty"`
	// CurrentLevel + PreviousLevel for risk-level / assurance-level events
	CurrentLevel  string `json:"current_level,omitempty"`
	PreviousLevel string `json:"previous_level,omitempty"`
}

// LangMap is the {"en": "...", "es": "..."} shape CAEP uses for
// human-readable reason strings.
type LangMap map[string]string

// SETClaims is the canonical envelope per RFC 8417 §2.
type SETClaims struct {
	Iss    string                  `json:"iss"`
	Aud    audienceField           `json:"aud"`
	IAT    int64                   `json:"iat"`
	JTI    string                  `json:"jti"`
	Events map[string]EventPayload `json:"events"`
	// TXN — optional transaction identifier; useful for SIEM
	// correlation across the transmitter/receiver pair.
	TXN string `json:"txn,omitempty"`
	// SubID — optional top-level subject (RFC 8417 §1.2). Falcon-ID
	// MAY include this; receivers normalize via subjectFromEvent().
	SubID *Subject `json:"sub_id,omitempty"`
}
