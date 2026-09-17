// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy is the PE in NIST SP 800-207 terms: it answers
// allow/deny for an authenticated session against a route. Phase 1 ships
// only the group filter; Phase 2 adds SpiceDB CheckPermission per route.
package policy

import (
	"context"
	"errors"

	"github.com/dogukanturhal/talon/internal/session"
)

// Decision is the PE's verdict.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
	Error Decision = "error"
)

// Reason annotates a Deny/Error decision for audit logs.
type Reason string

const (
	ReasonOK              Reason = "ok"
	ReasonMissingRole    Reason = "missing_required_role"
	ReasonNoSession       Reason = "no_session"
	ReasonExpiredSession  Reason = "expired_session"
	ReasonRevokedSession  Reason = "revoked_session"
	ReasonAuthTagFailed   Reason = "auth_tag_failed"
	ReasonInternal        Reason = "internal"
	ReasonNoPermission    Reason = "no_permission" // SpiceDB check fails (Phase 2)
	// Per-host session-control reasons (Phase 4 per-host TTL/IP-rebind/
	// device-claim batch). Distinct from ReasonExpiredSession so the
	// audit pipeline can tell "session aged past per-host cap" apart
	// from "Redis TTL expired the record".
	ReasonPerHostExpired      Reason = "per_host_expired"
	ReasonPerHostIdleTimeout  Reason = "per_host_idle_timeout"
	ReasonNetworkChange       Reason = "network_change"
	ReasonDeviceClaimMissing  Reason = "device_claim_missing"
	ReasonDeviceClaimMismatch Reason = "device_claim_mismatch"
	// Clientless-channel session-control reasons (ADR 0044 Phase 1).
	// ReasonClientlessExpired is distinct from ReasonPerHostExpired so the
	// audit pipeline can tell "session aged past the tighter clientless cap"
	// apart from the per-host absolute-TTL deny — a clientless session is
	// time-boxed harder than the same route's agent sessions.
	ReasonClientlessExpired Reason = "clientless_expired"
)

// Verdict bundles a Decision with its Reason for both metrics and audit.
type Verdict struct {
	Decision Decision
	Reason   Reason
}

// RoleFilter is the Phase 1 PE.
type RoleFilter struct {
	required string
}

// NewRoleFilter returns a PE that requires every session to carry the
// given group claim.
func NewRoleFilter(required string) *RoleFilter {
	return &RoleFilter{required: required}
}

// Evaluate is invoked per request after the session is resolved.
//
// Checks BOTH the `groups` and `roles` Falcon-ID claims because the
// platform's iam_groups table is empty by default — role names like
// "platform_admin" arrive in the `roles` claim, not `groups`. The
// reverse case (a future iam_group named after a role) is also handled.
// SpiceDB Phase 2.1 supersedes this with relation-based CheckPermission.
func (g *RoleFilter) Evaluate(ctx context.Context, b *session.Blob) Verdict {
	for _, grp := range b.Groups {
		if grp == g.required {
			return Verdict{Decision: Allow, Reason: ReasonOK}
		}
	}
	for _, role := range b.Roles {
		if role == g.required {
			return Verdict{Decision: Allow, Reason: ReasonOK}
		}
	}
	return Verdict{Decision: Deny, Reason: ReasonMissingRole}
}

// Errors that callers may branch on.
var (
	ErrInvalidPolicy = errors.New("policy: invalid configuration")
)
