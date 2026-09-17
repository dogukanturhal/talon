// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"testing"

	"github.com/dogukanturhal/talon/internal/session"
)

func TestContainsAnyMFA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		amr  []string
		want bool
	}{
		{"empty", nil, false},
		{"pwd_only_no_mfa", []string{"pwd"}, false},
		{"pwd_and_user_no_mfa", []string{"pwd", "user"}, false},
		{"umbrella_only", []string{"mfa"}, true},
		{"umbrella_with_factors", []string{"pwd", "otp", "mfa"}, true},
		{"otp_alone", []string{"otp"}, true},
		{"hwk_alone", []string{"hwk"}, true},
		{"hwk_with_user", []string{"hwk", "user"}, true},
		{"sms", []string{"sms"}, true},
		{"fingerprint", []string{"fpt"}, true},
		{"face", []string{"face"}, true},
		{"unknown_factor", []string{"pwd", "totally_made_up"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := containsAnyMFA(tc.amr); got != tc.want {
				t.Errorf("containsAnyMFA(%v) = %v, want %v", tc.amr, got, tc.want)
			}
		})
	}
}

func TestStepUpSatisfied(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		mfaRequired bool
		requireACR  []string
		blob        *session.Blob
		wantOK      bool
		wantReason  string
	}{
		// Decision 1 — RequireACR set, ACR matches.
		{
			name:       "acr_match",
			requireACR: []string{"urn:hexxlock:aal2"},
			blob:       &session.Blob{ACR: "urn:hexxlock:aal2"},
			wantOK:     true,
			wantReason: "acr",
		},
		{
			name:       "acr_match_one_of",
			requireACR: []string{"urn:hexxlock:aal2", "urn:hexxlock:aal3"},
			blob:       &session.Blob{ACR: "urn:hexxlock:aal3"},
			wantOK:     true,
			wantReason: "acr",
		},
		{
			name:       "acr_mismatch_fails",
			requireACR: []string{"urn:hexxlock:aal3"},
			blob:       &session.Blob{ACR: "urn:hexxlock:aal2", AMR: []string{"pwd", "otp", "mfa"}},
			wantOK:     false,
			wantReason: "",
		},
		{
			name:       "acr_missing_fails_even_with_strong_amr",
			requireACR: []string{"urn:hexxlock:aal2"},
			blob:       &session.Blob{ACR: "", AMR: []string{"pwd", "otp", "mfa"}},
			wantOK:     false,
			wantReason: "",
		},

		// Decision 2 — mfaRequired without RequireACR; permissive amr.
		{
			name:        "amr_umbrella_satisfies",
			mfaRequired: true,
			blob:        &session.Blob{AMR: []string{"pwd", "mfa"}},
			wantOK:      true,
			wantReason:  "amr",
		},
		{
			name:        "amr_specific_factor_satisfies",
			mfaRequired: true,
			blob:        &session.Blob{AMR: []string{"pwd", "otp"}},
			wantOK:      true,
			wantReason:  "amr",
		},
		{
			name:        "amr_hwk_satisfies",
			mfaRequired: true,
			blob:        &session.Blob{AMR: []string{"hwk", "user"}},
			wantOK:      true,
			wantReason:  "amr",
		},
		{
			name:        "amr_pwd_only_fails",
			mfaRequired: true,
			blob:        &session.Blob{AMR: []string{"pwd"}},
			wantOK:      false,
			wantReason:  "",
		},
		{
			name:        "amr_empty_fails",
			mfaRequired: true,
			blob:        &session.Blob{},
			wantOK:      false,
			wantReason:  "",
		},

		// Decision 3 — neither configured, always satisfied.
		{
			name:       "no_requirements",
			blob:       &session.Blob{AMR: []string{"pwd"}},
			wantOK:     true,
			wantReason: "not_required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, reason := stepUpSatisfied(tc.mfaRequired, tc.requireACR, tc.blob)
			if ok != tc.wantOK || reason != tc.wantReason {
				t.Errorf("stepUpSatisfied(mfa=%v, acr=%v, blob.AMR=%v, blob.ACR=%q) = (%v, %q), want (%v, %q)",
					tc.mfaRequired, tc.requireACR, tc.blob.AMR, tc.blob.ACR,
					ok, reason, tc.wantOK, tc.wantReason)
			}
		})
	}
}

// TestStepUpSatisfied_RegressionAdminOpsLoop reproduces the 2026-05-15
// admin-tier redirect-loop scenario: Falcon-ID emits amr=["pwd","otp"]
// without the umbrella, and the strict `contains(amr, "mfa")` check
// rejects the session every request. With the new permissive
// containsAnyMFA fallback, the same input satisfies the gate.
func TestStepUpSatisfied_RegressionAdminOpsLoop(t *testing.T) {
	t.Parallel()
	blob := &session.Blob{AMR: []string{"pwd", "otp"}}
	ok, reason := stepUpSatisfied(true, nil, blob)
	if !ok {
		t.Fatalf("admin-ops loop regression: pwd+otp session must satisfy mfaRequired gate, got (%v, %q)", ok, reason)
	}
	if reason != "amr" {
		t.Errorf("expected reason=amr (fallback path), got %q", reason)
	}
}
