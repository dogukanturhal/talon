// SPDX-License-Identifier: AGPL-3.0-or-later
package oidc

import "testing"

func TestStepUpAuthParams(t *testing.T) {
	t.Parallel()

	if got := stepUpAuthParams(""); got != nil {
		t.Errorf("empty mfa: want nil, got %v", got)
	}
	if got := stepUpAuthParams("bogus"); got != nil {
		t.Errorf("unknown mfa: want nil, got %v", got)
	}
	generic := stepUpAuthParams("1")
	if generic["acr_values"] != "mfa" || generic["max_age"] != "0" {
		t.Errorf("mfa=1: got %v", generic)
	}
	pk := stepUpAuthParams("passkey")
	if pk["acr_values"] != "urn:hexxlock:aal3" || pk["max_age"] != "0" {
		t.Errorf("mfa=passkey: got %v", pk)
	}
	if _, bad := pk["prompt"]; bad {
		t.Error("prompt must never be set (Falcon-ID prompt=login ends the SSO session)")
	}
}

func TestStepUpMode(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{"": "", "1": "1", "passkey": "passkey", "bogus": ""} {
		if got := stepUpMode(in); got != want {
			t.Errorf("stepUpMode(%q) = %q, want %q", in, got, want)
		}
	}
}
