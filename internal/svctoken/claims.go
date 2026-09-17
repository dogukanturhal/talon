// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"strings"
	"time"
)

// Claims is the verified, normalised view of a Falcon-ID-issued
// client_credentials JWT. Populated by Verifier.Verify after all
// security gates pass. Mirrors the claim shape emitted by
// falcon-id/internal/services/oauth_provider_service_tokens.go:195-212
// for the no-user (client_credentials) grant path.
//
// The fields are deliberately a SUBSET of the full JWT payload: only
// the values Talon needs for policy + audit + downstream propagation
// are surfaced. This keeps the policy evaluator's contract small and
// stable against future Falcon-ID JWT schema additions.
type Claims struct {
	// Issuer (iss) — Falcon-ID's external URL, pinned to
	// VerifierConfig.ExpectedIssuer.
	Issuer string

	// Subject (sub) — for client_credentials grants, equals the
	// client_id (per RFC 6749 §4.4 / Falcon-ID's
	// oauth_provider_service_tokens.go:202). For example:
	// "svc-argocd-repo-server", "svc-image-updater".
	Subject string

	// Audience (aud) — the Talon-fronted host this token is bound to
	// (RFC 8707 resource→aud). Verified == request Host header.
	Audience string

	// ClientID (client_id) — explicit client identifier; for c_c grants
	// equals Subject by construction, kept distinct for forward-compat
	// with on_behalf_of / token-exchange flows.
	ClientID string

	// TenantID — Falcon-ID multi-tenancy discriminator. Propagates to
	// audit logs so cross-tenant access attempts are visible.
	TenantID string

	// Scopes — the requested scope list intersected with the client's
	// registered scopes. Format: each entry is a single token like
	// "talon:github.com:read" (see scope.go).
	Scopes []string

	// JTI (jti) — JWT ID for replay-cache + revocation-list lookup.
	JTI string

	// IssuedAt (iat) and ExpiresAt (exp) — wall-clock for cache TTL.
	IssuedAt  time.Time
	ExpiresAt time.Time

	// --- End-user identity (authorization_code / refresh_token) ---
	//
	// All empty for client_credentials grants: Falcon-ID's
	// emitSubjectClaims early-returns on a nil user
	// (falcon-id/internal/services/oauth_provider_service_claims.go:221),
	// so a machine token carries no groups/roles/amr by construction.
	// Populated for human tokens when the mint requested the `groups` /
	// `roles` scopes, and consumed by the router to run the SAME policy
	// evaluation a browser session gets.

	// Groups — Falcon-ID `groups` claim (/path/style iam_groups paths).
	Groups []string

	// Roles — Falcon-ID `roles` claim ("platform_admin", "iam_admin").
	// The platform's iam_groups table is empty by default, so role names
	// arrive here rather than in Groups; the policy RoleFilter checks both.
	Roles []string

	// Email / PreferredUsername — human-readable identity for the audit
	// trail. Never a policy input.
	Email             string
	PreferredUsername string

	// AMR / ACR — authentication method + context class (RFC 8176,
	// OIDC Core §2). Carried so a future step-up gate on the Bearer path
	// has the evidence available; not yet consulted (see the router's
	// user-token block).
	AMR []string
	ACR string
}

// IsMachine reports whether this token represents a machine identity
// (RFC 6749 §4.4 client_credentials) rather than a human.
//
// Falcon-ID sets sub = client_id for the client_credentials grant
// (oauth_provider_service_tokens.go:286, citing the Auth0/Okta/Keycloak
// convention and RFC 8693 §4.3) and emits no subject claims at all for
// it. A human's authorization_code token therefore carries sub = the
// user's UUID, which never equals client_id.
//
// The test is deliberately ASYMMETRIC and FAIL-CLOSED: a token counts as
// machine only when it positively matches the client_credentials shape.
// Anything unrecognised is treated as a user identity, which routes it
// through the full policy evaluation instead of the machine fast path
// that skips it. A future Falcon-ID grant whose claim shape this code
// has never seen therefore receives MORE checks, not fewer — the safe
// direction for an IAP to be wrong in.
func (c *Claims) IsMachine() bool {
	if c.ClientID == "" || c.Subject != c.ClientID {
		return false
	}
	// Defence in depth: a client_credentials token must also be free of
	// end-user claims. If Falcon-ID ever mints an on-behalf-of token that
	// keeps sub == client_id while carrying user identity, it must NOT
	// take the machine path.
	return len(c.Groups) == 0 && len(c.Roles) == 0 && len(c.AMR) == 0
}

// HasScope reports whether the claim's scope list contains a specific
// scope token (exact match, case-sensitive per RFC 6749 §3.3).
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AnyScopeMatchingHostVerb returns true if the claim grants ANY scope
// that authorises the given host+verb. This is the policy hot path —
// the inverse lookup of scope.Check.
func (c *Claims) AnyScopeMatchingHostVerb(host string, verb Verb) bool {
	host = strings.ToLower(host)
	for _, s := range c.Scopes {
		if scopeAuthorisesHostVerb(s, host, verb) {
			return true
		}
	}
	return false
}
