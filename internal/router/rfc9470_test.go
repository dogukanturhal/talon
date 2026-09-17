// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"strings"
	"testing"
)

// TestBuildRFC9470Challenge_WithACR locks the canonical wire shape:
//   Bearer error="insufficient_user_authentication", acr_values="<space-list>"
// per RFC 9470 §4.1. APISIX / Envoy / Istio downstreams branch on
// these exact parameter names so this format is load-bearing.
func TestBuildRFC9470Challenge_WithACR(t *testing.T) {
	got := BuildRFC9470Challenge([]string{"urn:hexxlock:aal2"}, true, 0)
	want := `Bearer error="insufficient_user_authentication", acr_values="urn:hexxlock:aal2"`
	if got != want {
		t.Errorf("BuildRFC9470Challenge:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestBuildRFC9470Challenge_MultipleACR(t *testing.T) {
	got := BuildRFC9470Challenge(
		[]string{"urn:hexxlock:aal2", "urn:hexxlock:aal3"}, true, 0)
	if !strings.Contains(got, `acr_values="urn:hexxlock:aal2 urn:hexxlock:aal3"`) {
		t.Errorf("space-separated acr_values per RFC 9470 §4.1; got %q", got)
	}
}

func TestBuildRFC9470Challenge_MfaOnly_NoACR(t *testing.T) {
	// When mfaRequired=true but no AcrValues, emit just the error
	// parameter — clients interpret as "any MFA satisfies". Same
	// shape Okta and Auth0 emit when the resource doesn't pin a
	// specific ACR.
	got := BuildRFC9470Challenge(nil, true, 0)
	want := `Bearer error="insufficient_user_authentication"`
	if got != want {
		t.Errorf("BuildRFC9470Challenge mfa-only:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestBuildRFC9470Challenge_NoStepUp_Empty(t *testing.T) {
	if got := BuildRFC9470Challenge(nil, false, 0); got != "" {
		t.Errorf("no step-up should yield empty string; got %q", got)
	}
	if got := BuildRFC9470Challenge([]string{}, false, 0); got != "" {
		t.Errorf("empty AcrValues + no mfaRequired should yield empty; got %q", got)
	}
}

func TestBuildRFC9470Challenge_ParameterOrder(t *testing.T) {
	// RFC 9470 §4 examples emit `error` BEFORE `acr_values`.
	// Some clients (older Okta SDK) parse positionally; preserve
	// the canonical order.
	got := BuildRFC9470Challenge([]string{"urn:hexxlock:aal2"}, true, 0)
	errIdx := strings.Index(got, "error=")
	acrIdx := strings.Index(got, "acr_values=")
	if errIdx == -1 || acrIdx == -1 {
		t.Fatalf("expected both error= and acr_values= in %q", got)
	}
	if errIdx >= acrIdx {
		t.Errorf("error= must precede acr_values= per RFC 9470 §4; got %q", got)
	}
}

// TestBuildRFC9470Challenge_MaxAge verifies the freshness advertisement:
// a route with a sensitivity-derived max-age emits `max_age=<seconds>`
// AFTER acr_values (RFC 9470 §4.1 — max_age is an unquoted number).
func TestBuildRFC9470Challenge_MaxAge(t *testing.T) {
	got := BuildRFC9470Challenge([]string{"urn:hexxlock:aal3"}, true, 3600)
	want := `Bearer error="insufficient_user_authentication", acr_values="urn:hexxlock:aal3", max_age=3600`
	if got != want {
		t.Errorf("with max_age:\n  got:  %q\n  want: %q", got, want)
	}
	// max_age without an ACR list (mfaRequired fallback path).
	got = BuildRFC9470Challenge(nil, true, 43200)
	want = `Bearer error="insufficient_user_authentication", max_age=43200`
	if got != want {
		t.Errorf("max_age mfa-only:\n  got:  %q\n  want: %q", got, want)
	}
	// max_age=0 omits the parameter (no freshness window advertised).
	if got := BuildRFC9470Challenge([]string{"urn:hexxlock:aal2"}, true, 0); strings.Contains(got, "max_age") {
		t.Errorf("max_age=0 must omit the parameter; got %q", got)
	}
}

// TestMFAMaxAgeForSensitivity locks the tiers to the ztna_baseline.rego
// recency gates (webauthn_fresh_1h / _12h).
func TestMFAMaxAgeForSensitivity(t *testing.T) {
	cases := map[string]int{
		"critical": 3600,
		"high":     43200,
		"medium":   0,
		"low":      0,
		"":         0,
	}
	for sens, want := range cases {
		if got := mfaMaxAgeSecForSensitivity(sens); got != want {
			t.Errorf("mfaMaxAgeSecForSensitivity(%q): want %d, got %d", sens, want, got)
		}
	}
}
