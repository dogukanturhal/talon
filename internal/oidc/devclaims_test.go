// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"encoding/json"
	"sort"
	"testing"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
)

// TestAllowedDeviceClaimNames_NoDriftWithCRD asserts the local mirror in
// rp.go is byte-identical to the v1alpha1 source-of-truth slice. The
// duplication was an intentional package-dep avoidance call, but a
// silent drift here would mean the CRD validation accepts a claim name
// the OIDC capture pipeline ignores — a route requiring that claim
// would always fail-closed even when the IdP emits the claim. This
// test turns the rp.go "MUST stay in sync" comment into a hard CI gate.
func TestAllowedDeviceClaimNames_NoDriftWithCRD(t *testing.T) {
	t.Parallel()
	got := append([]string(nil), allowedDeviceClaimNames...)
	want := append([]string(nil), gatewayv1alpha1.AllowedDeviceClaimNames...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("length drift: oidc=%d v1alpha1=%d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("drift at sorted index %d: oidc=%q v1alpha1=%q", i, got[i], want[i])
		}
	}
}

// TestStringifyClaim covers the every-shape table for the id_token
// device-claim normaliser. Each row asserts the equality-key form an
// operator would write under TalonRoute.spec.requireDeviceClaims[].equals.
func TestStringifyClaim(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string-passthrough", "abc-123", "abc-123"},
		{"bool-true", true, "true"},
		{"bool-false", false, "false"},
		// JSON numbers always decode into float64 unless UseNumber is set.
		// The "decimal int when fractional part is zero" branch is what
		// keeps `equals: "1"` working with a token that emitted `1`.
		{"number-int", float64(1), "1"},
		{"number-int-zero", float64(0), "0"},
		{"number-int-large", float64(1700000000), "1700000000"},
		{"number-float", float64(1.5), "1.5"},
		{"number-jsonnumber", json.Number("42"), "42"},
		{"nil-empty", nil, ""},
		// Objects and arrays serialise back to canonical JSON. Operators
		// pin specific shapes via `equals: '{"x":1}'` rather than learning
		// a claim-type DSL.
		{"object", map[string]any{"x": float64(1)}, `{"x":1}`},
		{"array-of-strings", []any{"a", "b"}, `["a","b"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := stringifyClaim(tc.in)
			if got != tc.want {
				t.Errorf("stringifyClaim(%T %v) = %q, want %q", tc.in, tc.in, got, tc.want)
			}
		})
	}
}

// TestStringifyClaim_DropsEmpty — the caller skips writing keys when
// stringifyClaim returns "". This test pins the contract that nil and
// only nil produces the empty-string drop signal; falsy values like
// `false` or `0` produce real keys ("false" / "0") so policies can
// distinguish "claim present and falsy" from "claim absent" without
// inspecting the IdP-side mapping rules.
func TestStringifyClaim_DropsEmpty(t *testing.T) {
	t.Parallel()
	if got := stringifyClaim(nil); got != "" {
		t.Errorf("nil must produce empty drop signal, got %q", got)
	}
	if got := stringifyClaim(false); got == "" {
		t.Errorf("bool false must NOT collapse to empty (would lose 'present-and-false' signal)")
	}
	if got := stringifyClaim(float64(0)); got == "" {
		t.Errorf("number 0 must NOT collapse to empty (would lose 'present-and-zero' signal)")
	}
}
