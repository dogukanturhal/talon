// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import "testing"

func TestStepUpParams_NoPromptLogin(t *testing.T) {
	if _, ok := stepUpParams["prompt"]; ok {
		t.Fatal("step-up must not send prompt (prompt=login logs the user out of Falcon-ID SSO)")
	}
	if stepUpParams["max_age"] != "0" {
		t.Errorf("max_age = %q, want 0", stepUpParams["max_age"])
	}
	if stepUpParams["acr_values"] != "mfa" {
		t.Errorf("acr_values = %q, want mfa", stepUpParams["acr_values"])
	}
}
