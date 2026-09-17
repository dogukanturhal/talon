// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import "errors"

// Sentinel errors. Callers branch with errors.Is. Every other error
// from the package wraps one of these so failure-categorisation works
// regardless of wrap depth.
var (
	// ErrNoToken — request did not carry an Authorization: Bearer header.
	// Caller decides fall-through (cookie path) or 401 (bearer-only Server CR).
	ErrNoToken = errors.New("svctoken: no bearer token")

	// ErrTokenMalformed — header value didn't parse as a compact JWS,
	// or the claims block didn't carry required fields.
	ErrTokenMalformed = errors.New("svctoken: token malformed")

	// ErrSignatureInvalid — RS256 signature did not verify against any
	// kid in the cached JWKS, even after a forced refresh.
	ErrSignatureInvalid = errors.New("svctoken: signature verification failed")

	// ErrIssuerMismatch — iss didn't match the configured Falcon-ID
	// issuer URL. Always a security-relevant reject.
	ErrIssuerMismatch = errors.New("svctoken: issuer mismatch")

	// ErrAudienceMismatch — aud didn't match the request's Host (or
	// the operator-supplied derivative). RFC 8725 §3.1 audience
	// confusion defense.
	ErrAudienceMismatch = errors.New("svctoken: audience mismatch")

	// ErrTokenExpired — exp is in the past beyond clock tolerance.
	ErrTokenExpired = errors.New("svctoken: token expired")

	// ErrTokenNotYetValid — nbf/iat in the future beyond tolerance.
	ErrTokenNotYetValid = errors.New("svctoken: token not yet valid")

	// ErrAlgNotAllowed — JWS header carried an alg outside the RS256
	// whitelist. RFC 8725 §3.3 defense.
	ErrAlgNotAllowed = errors.New("svctoken: alg not allowed")

	// ErrScopeInsufficient — token's scope claim did not grant the
	// permission requested for this host/verb tuple. Tier-1 ABAC.
	ErrScopeInsufficient = errors.New("svctoken: scope insufficient")

	// ErrReplay — the JWT's jti has been seen before within the
	// replay-cache TTL. Opt-in defense-in-depth.
	ErrReplay = errors.New("svctoken: jti replay")

	// ErrRevoked — the JWT's jti is on Falcon-ID's per-jti revocation
	// list. Emergency revocation path.
	ErrRevoked = errors.New("svctoken: jti revoked")

	// ErrJWKSUnavailable — Talon couldn't fetch Falcon-ID's JWKS.
	// Fail-closed in production; the cookie path may still succeed.
	ErrJWKSUnavailable = errors.New("svctoken: jwks unavailable")
)

// Reason normalises a verify failure to a stable, low-cardinality
// label suitable for Prom metrics + audit log discriminators.
// Mirror of identityjwt.Reason in spirit; distinct values so dashboards
// can split inbound (svctoken) from outbound (identityjwt) signals.
type Reason string

const (
	ReasonOK                Reason = "ok"
	ReasonNoToken           Reason = "no_token"
	ReasonMalformed         Reason = "malformed"
	ReasonSignatureInvalid  Reason = "signature_invalid"
	ReasonIssuerMismatch    Reason = "issuer_mismatch"
	ReasonAudienceMismatch  Reason = "audience_mismatch"
	ReasonTokenExpired      Reason = "expired"
	ReasonTokenNotYetValid  Reason = "not_yet_valid"
	ReasonAlgNotAllowed     Reason = "alg_not_allowed"
	ReasonScopeInsufficient Reason = "scope_insufficient"
	ReasonReplay            Reason = "replay"
	ReasonRevoked           Reason = "revoked"
	ReasonJWKSUnavailable   Reason = "jwks_unavailable"
	ReasonCacheHit          Reason = "cache_hit"
)

// reasonForError maps a wrapped error to its Reason. Returns
// ReasonMalformed for any non-recognised error — the safe default that
// avoids leaking internal error messages into metric label values.
func reasonForError(err error) Reason {
	switch {
	case err == nil:
		return ReasonOK
	case errors.Is(err, ErrNoToken):
		return ReasonNoToken
	case errors.Is(err, ErrSignatureInvalid):
		return ReasonSignatureInvalid
	case errors.Is(err, ErrIssuerMismatch):
		return ReasonIssuerMismatch
	case errors.Is(err, ErrAudienceMismatch):
		return ReasonAudienceMismatch
	case errors.Is(err, ErrTokenExpired):
		return ReasonTokenExpired
	case errors.Is(err, ErrTokenNotYetValid):
		return ReasonTokenNotYetValid
	case errors.Is(err, ErrAlgNotAllowed):
		return ReasonAlgNotAllowed
	case errors.Is(err, ErrScopeInsufficient):
		return ReasonScopeInsufficient
	case errors.Is(err, ErrReplay):
		return ReasonReplay
	case errors.Is(err, ErrRevoked):
		return ReasonRevoked
	case errors.Is(err, ErrJWKSUnavailable):
		return ReasonJWKSUnavailable
	default:
		return ReasonMalformed
	}
}
