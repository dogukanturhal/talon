// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"testing"
	"time"
)

// TestZTNABaseline_DenyReasonSingleOutput guards against
// eval_conflict_error: several deny conditions hold at once (stale
// posture, TIER_CORP without device cert, AAL1 on a critical route) and
// deny_reason must still resolve to exactly one — the first in the else
// chain.
func TestZTNABaseline_DenyReasonSingleOutput(t *testing.T) {
	ev, err := CompileRego(context.Background(), readZTNABaseline(t))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	in := &RegoInput{
		User:    RegoInputUser{Sub: "u1", AMR: []string{"pwd"}, AMRRecencySeconds: 1800},
		Route:   RegoInputRoute{Host: "argocd.internal.example.com", Permission: "viewer"},
		Request: RegoInputRequest{Method: "GET", Path: "/x"},
		Posture: &RegoInputPosture{
			IssuedAt: time.Now().Unix() - 7200,
			Compliance: map[string]any{
				"tier":              "TIER_CORP",
				"device_cert_valid": false,
				"network_class":     "trusted",
				"route_sensitivity": "critical",
			},
		},
	}
	ok, reason, err := ev.EvaluateWithReason(context.Background(), in)
	if err != nil {
		t.Fatalf("evaluate (conflict?): %v", err)
	}
	if ok {
		t.Fatal("expected deny")
	}
	if want := "ztna: posture stale (iat too old for tier)"; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
}
