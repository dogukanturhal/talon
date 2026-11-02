// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import "testing"

// TestIsMachine is the guard on the discriminator that decides whether a
// verified Bearer token takes the machine fast path (scope + audience
// only) or the end-user path (full policy evaluation: RoleFilter over
// groups/roles, then SpiceDB CheckPermission). Getting it wrong in the
// permissive direction means a human's token skips authorisation
// entirely, so the property under test is the ASYMMETRY, not just the
// two happy cases.
//
// Ground truth for the claim shapes, in Falcon-ID:
//
//   - client_credentials sets sub = client_id explicitly
//     (oauth_provider_service_tokens.go:286, following the
//     Auth0/Okta/Keycloak convention and RFC 8693 §4.3).
//   - emitSubjectClaims early-returns on a nil user
//     (oauth_provider_service_claims.go:221), so a machine token carries
//     no groups/roles/amr at all — not "usually none", none by
//     construction.
//
// Both live shapes below were verified against the running IdP on
// 2026-08-16 before this discriminator shipped.
func TestIsMachine(t *testing.T) {
	cases := []struct {
		name string
		c    Claims
		want bool
	}{
		// --- The machine path. Both of these are live production
		// shapes; svc-argocd-repo-server-gitlab-ops in particular
		// fronts every ArgoCD repo-server clone, so a false here
		// would break platform-wide GitOps sync.
		{
			"client_credentials — argocd repo-server (live shape)",
			Claims{
				Subject:  "svc-svc-argocd-repo-server-gitlab-ops",
				ClientID: "svc-svc-argocd-repo-server-gitlab-ops",
				Scopes:   []string{"talon:github.com:read"},
			},
			true,
		},
		{
			"client_credentials — npm developer client (live shape)",
			Claims{
				Subject:  "svc-svc-npm-dev-dogukanturhal",
				ClientID: "svc-svc-npm-dev-dogukanturhal",
				Scopes:   []string{"talon:npm.internal.example.com:read"},
			},
			true,
		},

		// --- The user path.
		{
			"authorization_code — human with groups",
			Claims{
				Subject:  "3f9a1c22-0b7e-4d51-9c33-7a1e8b0d4f60",
				ClientID: "talon-cli",
				Groups:   []string{"/platform/admins"},
				Roles:    []string{"platform_admin"},
			},
			false,
		},

		// Adversarial: a human token minted WITHOUT the `groups` /
		// `roles` scopes carries no subject claims, so it looks
		// claim-for-claim like a machine token except for sub. If the
		// discriminator keyed on "has no groups" instead of on sub,
		// this token would take the fast path and skip authorisation —
		// i.e. dropping a scope from the mint request would become a
		// way to opt out of policy. It must be a user, and then fail
		// the RoleFilter for having no groups.
		{
			"authorization_code — human, no groups/roles scopes requested",
			Claims{
				Subject:  "3f9a1c22-0b7e-4d51-9c33-7a1e8b0d4f60",
				ClientID: "talon-cli",
			},
			false,
		},

		// Adversarial: unrecognised shape. An absent client_id means
		// the sub == client_id test cannot be evaluated at all, so
		// there is no evidence this is a machine. Fail closed — route
		// it through policy evaluation rather than past it. No live
		// Falcon-ID grant produces this today (24h of Talon logs showed
		// zero empty client_ids across all six machine consumers); the
		// case exists so a future grant type cannot silently inherit
		// the fast path.
		{
			"unknown shape — client_id absent, fail closed",
			Claims{Subject: "whatever"},
			false,
		},

		// Adversarial: defence in depth. If Falcon-ID ever mints an
		// on-behalf-of / impersonation token that keeps sub == client_id
		// while carrying end-user claims, the sub test alone would call
		// it a machine and skip the group gate for a token that
		// represents a person.
		{
			"impersonation-shaped — sub == client_id but carries user claims",
			Claims{
				Subject:  "svc-impersonator",
				ClientID: "svc-impersonator",
				Roles:    []string{"platform_admin"},
			},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.IsMachine(); got != tc.want {
				t.Errorf("IsMachine() = %v, want %v (sub=%q client_id=%q groups=%v roles=%v amr=%v)",
					got, tc.want, tc.c.Subject, tc.c.ClientID, tc.c.Groups, tc.c.Roles, tc.c.AMR)
			}
		})
	}
}

// TestIsMachine_AnyUserClaimDefeatsMachinePath pins the defence-in-depth
// half of the discriminator one claim at a time. IsMachine consults
// groups, roles AND amr; a regression that dropped any single one from
// the check would still pass TestIsMachine's impersonation case (which
// sets roles), so each is asserted independently here.
func TestIsMachine_AnyUserClaimDefeatsMachinePath(t *testing.T) {
	for _, tc := range []struct {
		claim string
		c     Claims
	}{
		{"groups", Claims{Subject: "svc-x", ClientID: "svc-x", Groups: []string{"/platform/admins"}}},
		{"roles", Claims{Subject: "svc-x", ClientID: "svc-x", Roles: []string{"platform_admin"}}},
		{"amr", Claims{Subject: "svc-x", ClientID: "svc-x", AMR: []string{"pwd", "mfa"}}},
	} {
		t.Run(tc.claim, func(t *testing.T) {
			if tc.c.IsMachine() {
				t.Errorf("a token carrying %q must not take the machine path", tc.claim)
			}
		})
	}
}
