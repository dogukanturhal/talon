// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestZTNABaseline_Compile verifies the operator-distributed ZTNA
// baseline Rego module (docs/policy/ztna/ztna_baseline.rego) compiles
// against Talon's CompileRego entry point. Operators copy-paste this
// module into TalonRoute.spec.regoPolicy; if it ever stops compiling
// we want CI to fail BEFORE the bundle ships to operators.
func TestZTNABaseline_Compile(t *testing.T) {
	module := readZTNABaseline(t)

	ctx := context.Background()
	ev, err := CompileRego(ctx, module)
	if err != nil {
		t.Fatalf("ZTNA baseline failed to compile: %v", err)
	}
	if ev == nil {
		t.Fatal("ZTNA baseline compile returned nil evaluator")
	}
}

// TestZTNABaseline_Matrix exercises the tier × sensitivity × AAL
// decision matrix from ADR 0040 §Decision row + ztna_baseline.rego
// §"Allow rules". Pins the contract — accidental matrix drift surfaces
// as a Go test failure.
func TestZTNABaseline_Matrix(t *testing.T) {
	module := readZTNABaseline(t)
	ctx := context.Background()
	ev, err := CompileRego(ctx, module)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	now := time.Now().Unix()

	tests := []struct {
		name     string
		in       *RegoInput
		wantPass bool
	}{
		{
			name: "TIER_CORP+AAL3+medium → allow",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  1800,
				},
				Route: RegoInputRoute{Host: "internal.example.com", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_CORP",
						"device_cert_valid": true,
						"network_class":     "trusted",
						"route_sensitivity": "medium",
					},
				},
			},
			wantPass: true,
		},
		{
			name: "TIER_CORP+AAL1+medium → deny",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd"},
					AMRRecencySeconds:  1800,
				},
				Route: RegoInputRoute{Host: "internal.example.com", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_CORP",
						"device_cert_valid": true,
						"network_class":     "trusted",
						"route_sensitivity": "medium",
					},
				},
			},
			wantPass: false,
		},
		{
			name:     "no posture → deny",
			in:       &RegoInput{User: RegoInputUser{Sub: "u1", AMR: []string{"pwd", "hwk"}, AMRRecencySeconds: 1800}, Route: RegoInputRoute{Host: "g", Permission: "viewer"}, Request: RegoInputRequest{Method: "GET", Path: "/x"}},
			wantPass: false,
		},
		{
			name: "TIER_CORP stale posture (1h) → deny",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  1800,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 3600,
					Compliance: map[string]any{
						"tier":              "TIER_CORP",
						"device_cert_valid": true,
						"network_class":     "trusted",
						"route_sensitivity": "medium",
					},
				},
			},
			wantPass: false,
		},
		{
			name: "TIER_BYOD AAL3 low → allow",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_BYOD",
						"device_cert_valid": false,
						"network_class":     "internet",
						"route_sensitivity": "low",
					},
				},
			},
			wantPass: true,
		},
		{
			name: "TIER_BYOD critical → deny",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_BYOD",
						"device_cert_valid": false,
						"network_class":     "internet",
						"route_sensitivity": "critical",
					},
				},
			},
			wantPass: false,
		},
		{
			name: "critical without AAL3 → deny",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "otp"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_CORP",
						"device_cert_valid": true,
						"network_class":     "trusted",
						"route_sensitivity": "critical",
					},
				},
			},
			wantPass: false,
		},
		{
			name: "critical AAL3 with 1h step-up → allow",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_CORP",
						"device_cert_valid": true,
						"network_class":     "trusted",
						"route_sensitivity": "critical",
					},
				},
			},
			wantPass: true,
		},
		{
			name: "BREAKGLASS without approval → deny",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_BREAKGLASS",
						"route_sensitivity": "critical",
					},
				},
			},
			wantPass: false,
		},
		{
			name: "BREAKGLASS with approval → allow",
			in: &RegoInput{
				User: RegoInputUser{
					Sub:                "u1",
					AMR:                []string{"pwd", "hwk", "approval"},
					AMRRecencySeconds:  60,
				},
				Route: RegoInputRoute{Host: "g", Permission: "viewer"},
				Request: RegoInputRequest{Method: "GET", Path: "/x"},
				Posture: &RegoInputPosture{
					IssuedAt: now - 60,
					Compliance: map[string]any{
						"tier":              "TIER_BREAKGLASS",
						"route_sensitivity": "critical",
					},
				},
			},
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ev.Evaluate(ctx, tc.in)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got != tc.wantPass {
				t.Errorf("got allow=%v, want %v", got, tc.wantPass)
			}
		})
	}
}

func readZTNABaseline(t *testing.T) string {
	t.Helper()
	// docs/policy/ztna/ztna_baseline.rego is two levels up from
	// internal/policy/.
	p := filepath.Join("..", "..", "docs", "policy", "ztna", "ztna_baseline.rego")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	s := string(b)
	if !strings.Contains(s, "package talon.route") {
		t.Fatalf("ZTNA baseline missing 'package talon.route' header")
	}
	return s
}
