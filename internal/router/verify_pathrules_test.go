// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"testing"

	v1beta1 "github.com/dogukanturhal/talon/api/v1beta1"
)

// TestOverlayUpstreamPolicy_PermissionOverride checks the per-path
// permission override — the most common Phase 7.3 use case (different
// access tier per path on the same host).
func TestOverlayUpstreamPolicy_PermissionOverride(t *testing.T) {
	base := upstreamEntry{permission: "viewer"}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{Permission: "editor"})
	if out.permission != "editor" {
		t.Errorf("permission: want editor (overlay), got %q", out.permission)
	}
}

func TestOverlayUpstreamPolicy_PermissionInheritedWhenUnset(t *testing.T) {
	base := upstreamEntry{permission: "admin"}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{}) // empty rule policy
	if out.permission != "admin" {
		t.Errorf("permission: want admin (inherited), got %q", out.permission)
	}
}

func TestOverlayUpstreamPolicy_AuthModeOverride(t *testing.T) {
	base := upstreamEntry{authMode: "cookie"}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{AuthMode: "bearer"})
	if string(out.authMode) != "bearer" {
		t.Errorf("authMode: want bearer (overlay), got %q", out.authMode)
	}
}

func TestOverlayUpstreamPolicy_AuthModeInvalidIgnored(t *testing.T) {
	// Unrecognised authMode value MUST NOT silently downgrade to
	// cookie — the host default must persist (overlay refuses to
	// apply invalid values).
	base := upstreamEntry{authMode: "bearer"}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{AuthMode: "nonsense"})
	if string(out.authMode) != "bearer" {
		t.Errorf("invalid authMode should inherit host default; got %q", out.authMode)
	}
}

func TestOverlayUpstreamPolicy_MfaRequiredAdditive(t *testing.T) {
	// MfaRequired is additive — a rule that sets it true MUST tighten,
	// never relax. A host with mfaRequired=true cannot be loosened by
	// a rule with mfaRequired=false (false is the zero value, which we
	// treat as "inherit").
	base := upstreamEntry{mfaRequired: true}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{MfaRequired: false})
	if !out.mfaRequired {
		t.Errorf("mfaRequired: host-required must NOT be loosened by zero-value overlay")
	}

	base2 := upstreamEntry{mfaRequired: false}
	out2 := overlayUpstreamPolicy(base2, v1beta1.Policy{MfaRequired: true})
	if !out2.mfaRequired {
		t.Errorf("mfaRequired: overlay should tighten; got %v", out2.mfaRequired)
	}
}

func TestOverlayUpstreamPolicy_AcrValuesReplace(t *testing.T) {
	// AcrValues OVERRIDES rather than appends. Matches the documented
	// "fields set on the rule override the default" semantics from
	// the v1beta1 schema header comment.
	base := upstreamEntry{requireACR: []string{"urn:hexxlock:aal1"}}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{
		AcrValues: []string{"urn:hexxlock:aal2", "urn:hexxlock:aal3"},
	})
	if len(out.requireACR) != 2 ||
		out.requireACR[0] != "urn:hexxlock:aal2" ||
		out.requireACR[1] != "urn:hexxlock:aal3" {
		t.Errorf("AcrValues: want [aal2 aal3] (overlay-replace), got %v", out.requireACR)
	}
}

func TestOverlayUpstreamPolicy_AcrValuesInheritedWhenEmpty(t *testing.T) {
	base := upstreamEntry{requireACR: []string{"urn:hexxlock:aal2"}}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{}) // empty
	if len(out.requireACR) != 1 || out.requireACR[0] != "urn:hexxlock:aal2" {
		t.Errorf("AcrValues: empty overlay should inherit; got %v", out.requireACR)
	}
}

func TestOverlayUpstreamPolicy_DoesNotMutateOriginalEntry(t *testing.T) {
	// The overlay must return a per-request COPY; mutating the result
	// must NOT affect the host-default entry stored in the upstreams
	// map. (Otherwise a per-path overlay would permanently rebind the
	// host policy.)
	base := upstreamEntry{
		permission: "viewer",
		requireACR: []string{"urn:hexxlock:aal1"},
	}
	out := overlayUpstreamPolicy(base, v1beta1.Policy{
		Permission: "admin",
		AcrValues:  []string{"urn:hexxlock:aal3"},
	})
	// Mutate the result.
	out.permission = "MUTATED"
	out.requireACR[0] = "MUTATED"
	// Original must be untouched.
	if base.permission != "viewer" {
		t.Errorf("overlay mutated base.permission: %q", base.permission)
	}
	if base.requireACR[0] != "urn:hexxlock:aal1" {
		t.Errorf("overlay shared backing array on base.requireACR: %q", base.requireACR[0])
	}
}

func TestIsValidAuthMode(t *testing.T) {
	for _, m := range []string{
		"cookie", "bearer", "both",
		"bearer_or_passthrough",
		"bearer_or_basic_with_credential_exchange",
		"bearer_or_federated_passthrough",
		"cookie_or_bearer_or_passthrough",
		"anonymous",
	} {
		if !isValidAuthMode(m) {
			t.Errorf("isValidAuthMode(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"", "COOKIE", "bear", "x", "cookie ", " bearer"} {
		if isValidAuthMode(m) {
			t.Errorf("isValidAuthMode(%q) = true, want false", m)
		}
	}
}
