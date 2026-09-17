// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"testing"

	"github.com/dogukanturhal/talon/internal/session"
)

// The role-gate migration turns a cluster-wide "you must hold
// platform_admin" filter into something a route can decide for itself.
// The failure that matters is not a denied developer — it is an
// ACCIDENTAL ALLOW, so these pin the fail-closed edges rather than the
// happy path.
//
// SpiceDB is nil throughout: that is precisely the "no authority to
// consult" condition, and under the legacy code it inherited the
// RoleFilter's Allow. With the gate in shadow/off that inheritance would
// be an open door on every host at once.

func blobWith(roles ...string) *session.Blob {
	return &session.Blob{Sub: "user-uuid", Roles: roles}
}

func TestRoleGate_EnforceKeepsLegacyBehaviour(t *testing.T) {
	pe := NewCompositePolicy(NewRoleFilter("platform_admin"), nil, RoleGateEnforce)

	if v := pe.Evaluate(context.Background(), blobWith("platform_admin"), "npm.ops", "editor", ""); v.Decision != Allow {
		t.Errorf("holder of the required role must pass under enforce: %+v", v)
	}
	if v := pe.Evaluate(context.Background(), blobWith("developers"), "npm.ops", "editor", ""); v.Decision != Deny {
		t.Errorf("non-holder must be denied under enforce: %+v", v)
	}
}

// The core safety property. Without SpiceDB there is no per-route
// authority, so shadow/off must DENY — never fall back to the role
// filter's verdict, which is no longer gating anything.
func TestRoleGate_ShadowAndOffFailClosedWithoutSpiceDB(t *testing.T) {
	for _, mode := range []RoleGateMode{RoleGateShadow, RoleGateOff} {
		t.Run(string(mode), func(t *testing.T) {
			pe := NewCompositePolicy(NewRoleFilter("platform_admin"), nil, mode)
			// Even a platform_admin — who WOULD have passed the role filter —
			// must not be allowed through on an unconsultable authority.
			if v := pe.Evaluate(context.Background(), blobWith("platform_admin"), "npm.ops", "editor", ""); v.Decision == Allow {
				t.Errorf("mode %s allowed a request with no authority to consult: %+v", mode, v)
			}
		})
	}
}

// A route with no permission set must not become a bypass once the role
// filter stops backstopping it.
func TestRoleGate_EmptyPermissionDeniesUnderShadowAndOff(t *testing.T) {
	for _, mode := range []RoleGateMode{RoleGateShadow, RoleGateOff} {
		pe := NewCompositePolicy(NewRoleFilter("platform_admin"), nil, mode)
		if v := pe.Evaluate(context.Background(), blobWith("platform_admin"), "npm.ops", "", ""); v.Decision == Allow {
			t.Errorf("mode %s: empty route permission must not allow: %+v", mode, v)
		}
	}
}

// An unrecognised or empty mode string must resolve to enforce. A typo in
// TALON_ROLE_GATE_MODE removing an authorisation gate is the kind of
// failure that would go unnoticed until it mattered.
func TestParseRoleGateMode_UnknownDefaultsToEnforce(t *testing.T) {
	for _, in := range []string{"", "Off", "OFF", "disabled", "yes", "true", "shadowy"} {
		if got := ParseRoleGateMode(in); got != RoleGateEnforce {
			t.Errorf("ParseRoleGateMode(%q) = %q, want enforce", in, got)
		}
	}
	if got := ParseRoleGateMode("shadow"); got != RoleGateShadow {
		t.Errorf("shadow not parsed: %q", got)
	}
	if got := ParseRoleGateMode("off"); got != RoleGateOff {
		t.Errorf("off not parsed: %q", got)
	}
}

// The zero value must be safe: a caller constructed without an explicit
// mode keeps the enforcing behaviour.
func TestNewCompositePolicy_ZeroModeIsEnforce(t *testing.T) {
	pe := NewCompositePolicy(NewRoleFilter("platform_admin"), nil, "")
	if v := pe.Evaluate(context.Background(), blobWith("developers"), "npm.ops", "editor", ""); v.Decision != Deny {
		t.Errorf("zero mode must enforce: %+v", v)
	}
}
