// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"testing"
	"time"
)

// TestValidateLogoutClaims covers the spec-§2.4 + §2.6 invariants the
// handler enforces on top of the IDTokenVerifier's signature/iss/aud/exp
// checks. End-to-end coverage with a real go-oidc test issuer + miniredis
// rides a follow-up MR (Talon doesn't yet have a test-OP harness; gap
// SLO-01-FOLLOWUP-INTEGRATION).
func TestValidateLogoutClaims(t *testing.T) {
	t.Parallel()

	const expectedIss = "https://id.hexxlock.com"
	const skew = 5 * time.Minute
	now := time.Now().Unix()

	validBody := func() *logoutClaims {
		return &logoutClaims{
			Issuer:   expectedIss,
			IssuedAt: now,
			JTI:      "11111111-2222-3333-4444-555555555555",
			Subject:  "01234567-89ab-cdef-0123-456789abcdef",
			Events: map[string]interface{}{
				backchannelLogoutEventClaim: map[string]interface{}{},
			},
		}
	}

	tests := []struct {
		name    string
		mutate  func(c *logoutClaims)
		wantErr error
	}{
		{
			name:    "happy path with sub",
			mutate:  func(c *logoutClaims) {},
			wantErr: nil,
		},
		{
			name: "happy path with sid only (sub empty)",
			mutate: func(c *logoutClaims) {
				c.Subject = ""
				c.SID = "session-9876"
			},
			wantErr: nil,
		},
		{
			name: "happy path: events map[string]interface{} encoded as nil (struct{}{} marshal variant)",
			mutate: func(c *logoutClaims) {
				c.Events = map[string]interface{}{
					backchannelLogoutEventClaim: nil,
				}
			},
			wantErr: nil,
		},
		{
			name: "iss mismatch",
			mutate: func(c *logoutClaims) {
				c.Issuer = "https://evil.example.com"
			},
			wantErr: errIssuerMismatch,
		},
		{
			name: "iss empty",
			mutate: func(c *logoutClaims) {
				c.Issuer = ""
			},
			wantErr: errIssuerMismatch,
		},
		{
			name: "missing jti",
			mutate: func(c *logoutClaims) {
				c.JTI = ""
			},
			wantErr: errMissingJTI,
		},
		{
			name: "missing iat",
			mutate: func(c *logoutClaims) {
				c.IssuedAt = 0
			},
			wantErr: errMissingIAT,
		},
		{
			name: "iat in the future beyond skew",
			mutate: func(c *logoutClaims) {
				c.IssuedAt = now + int64((skew + time.Minute).Seconds())
			},
			wantErr: errIATFuture,
		},
		{
			name: "iat older than max skew",
			mutate: func(c *logoutClaims) {
				c.IssuedAt = now - int64((skew + time.Minute).Seconds())
			},
			wantErr: errIATTooOld,
		},
		{
			name: "iat at the edge inside skew is accepted",
			mutate: func(c *logoutClaims) {
				c.IssuedAt = now - int64(skew.Seconds()) + 1
			},
			wantErr: nil,
		},
		{
			name: "nonce present is rejected",
			mutate: func(c *logoutClaims) {
				c.Nonce = "abc"
			},
			wantErr: errForbiddenNonce,
		},
		{
			name: "neither sub nor sid present",
			mutate: func(c *logoutClaims) {
				c.Subject = ""
				c.SID = ""
			},
			wantErr: errMissingSubAndSID,
		},
		{
			name: "events claim missing entirely",
			mutate: func(c *logoutClaims) {
				c.Events = nil
			},
			wantErr: errMissingEvents,
		},
		{
			name: "events claim present but missing logout event key",
			mutate: func(c *logoutClaims) {
				c.Events = map[string]interface{}{
					"http://schemas.openid.net/event/something-else": map[string]interface{}{},
				}
			},
			wantErr: errMissingLogoutEvent,
		},
		{
			name: "logout event value is non-empty object",
			mutate: func(c *logoutClaims) {
				c.Events = map[string]interface{}{
					backchannelLogoutEventClaim: map[string]interface{}{
						"unexpected": "data",
					},
				}
			},
			wantErr: errMalformedLogoutEvent,
		},
		{
			name: "logout event value is the wrong type",
			mutate: func(c *logoutClaims) {
				c.Events = map[string]interface{}{
					backchannelLogoutEventClaim: "not-an-object",
				}
			},
			wantErr: errMalformedLogoutEvent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := validBody()
			tt.mutate(c)
			err := validateLogoutClaims(c, expectedIss, skew)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validateLogoutClaims: unexpected error: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateLogoutClaims: got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestReasonFromValidationErr asserts every sentinel maps to a stable
// X-Talon-Reason value. Operators grep on these strings, so renames are
// breaking changes.
func TestReasonFromValidationErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{errIssuerMismatch, "issuer_mismatch"},
		{errMissingJTI, "missing_jti"},
		{errMissingIAT, "missing_iat"},
		{errIATFuture, "iat_future"},
		{errIATTooOld, "iat_too_old"},
		{errForbiddenNonce, "forbidden_nonce"},
		{errMissingSubAndSID, "missing_sub_and_sid"},
		{errMissingEvents, "missing_events"},
		{errMissingLogoutEvent, "missing_logout_event"},
		{errMalformedLogoutEvent, "malformed_logout_event"},
		{errors.New("unknown"), "claims_invalid"},
	}
	for _, c := range cases {
		if got := reasonFromValidationErr(c.err); got != c.want {
			t.Errorf("reasonFromValidationErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
