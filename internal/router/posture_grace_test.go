// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import "testing"

// TestPostureDegradedDeny pins the DDIL P3.10 consumer-side graceful-downgrade
// scope: a governed-degraded device posture (past its hard exp but within
// Talon's grace budget) is ADMISSIBLE for low/medium-sensitivity routes and
// DENIED on critical/high (privileged) ones. This mirrors the offline
// session/PDP privileged tiering (privilegedSensitivity) — a decayed
// device-trust claim can never reach the most sensitive resources, and Talon
// (the consumer/PEP), not the device, is the sole authority on this scope.
func TestPostureDegradedDeny(t *testing.T) {
	cases := []struct {
		sensitivity string
		wantDeny    bool
	}{
		{"critical", true}, // privileged → degraded posture denied
		{"high", true},     // privileged → degraded posture denied
		{"medium", false},  // non-privileged → degraded posture served within grace
		{"low", false},     // non-privileged → degraded posture served within grace
		{"", false},        // unset defaults to non-privileged (route-sensitivity "medium")
		{"unknown", false}, // any non-critical/high class is non-privileged
	}
	for _, c := range cases {
		if got := postureDegradedDeny(c.sensitivity); got != c.wantDeny {
			t.Errorf("postureDegradedDeny(%q) = %v, want %v", c.sensitivity, got, c.wantDeny)
		}
	}
}

// TestPostureDegradedDeny_MatchesPrivilegedSensitivity asserts the graceful-
// downgrade split stays coupled to the SAME privileged classifier the offline
// session/PDP budgets use, so the posture, session, and authz degraded windows
// agree on what "privileged" means for a given route.
func TestPostureDegradedDeny_MatchesPrivilegedSensitivity(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low", "", "weird"} {
		if postureDegradedDeny(s) != privilegedSensitivity(s) {
			t.Errorf("postureDegradedDeny(%q)=%v diverged from privilegedSensitivity=%v",
				s, postureDegradedDeny(s), privilegedSensitivity(s))
		}
	}
}
