// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"testing"

	"github.com/dogukanturhal/talon/internal/session"
)

// TestClientlessAALSatisfied exercises the ADR 0044 AAL cap helper. The
// clientless tier (agentless, no device cert) demands a phishing-resistant
// WebAuthn/FIDO2 factor (hwk/swk) OR an AAL2+ acr — STRICTER than the
// route-level mfaRequired gate (which accepts any RFC 8176 second factor,
// including the non-phishing-resistant otp/sms). Fail-closed on a
// password-only or empty session.
func TestClientlessAALSatisfied(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		blob *session.Blob
		want bool
	}{
		{"hardware key (FIDO2 roaming)", &session.Blob{AMR: []string{"pwd", "hwk"}}, true},
		{"software key (platform passkey)", &session.Blob{AMR: []string{"pwd", "swk"}}, true},
		{"acr aal2", &session.Blob{ACR: "urn:hexxlock:aal2"}, true},
		{"acr aal3", &session.Blob{ACR: "urn:hexxlock:aal3"}, true},
		{"hwk wins even with acr empty", &session.Blob{AMR: []string{"hwk"}}, true},

		// Fail-closed cases — NOT phishing-resistant or no second factor.
		{"password only", &session.Blob{AMR: []string{"pwd"}}, false},
		{"otp is MFA but not phishing-resistant", &session.Blob{AMR: []string{"pwd", "otp", "mfa"}}, false},
		{"sms is MFA but not phishing-resistant", &session.Blob{AMR: []string{"pwd", "sms"}}, false},
		{"generic mfa umbrella alone insufficient", &session.Blob{AMR: []string{"mfa"}}, false},
		{"empty amr+acr", &session.Blob{}, false},
		{"acr aal1 insufficient", &session.Blob{ACR: "urn:hexxlock:aal1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clientlessAALSatisfied(c.blob); got != c.want {
				t.Errorf("clientlessAALSatisfied(%+v) = %v, want %v", c.blob, got, c.want)
			}
		})
	}
}

// TestClientlessStepUpACRChallenge asserts the clientless AAL deny emits an
// RFC 9470 challenge advertising the AAL2 acr_values — the wire signal a
// browser/SDK client needs to re-authenticate with a phishing-resistant
// factor. Built from the same BuildRFC9470Challenge the route-level
// step-up gate uses, so the header shape is consistent across surfaces.
func TestClientlessStepUpACRChallenge(t *testing.T) {
	t.Parallel()
	got := BuildRFC9470Challenge(clientlessStepUpACR, true, 0)
	want := `Bearer error="insufficient_user_authentication", acr_values="urn:hexxlock:aal2"`
	if got != want {
		t.Errorf("clientless RFC 9470 challenge =\n  %q\nwant\n  %q", got, want)
	}
}
