// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"strings"
	"testing"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
)

// TestValidateRoute_Sensitivity exercises the ZTNA Phase 5.b
// enum-validation gate on TalonRouteSpec.Sensitivity. Belt-and-braces
// alongside the CRD `+kubebuilder:validation:Enum=` tag — catches
// values that bypassed the OpenAPIv3 schema (cross-version drift,
// etcd-direct writes, conversion-webhook edge cases).
func TestValidateRoute_Sensitivity(t *testing.T) {
	base := &gatewayv1alpha1.TalonRoute{
		Spec: gatewayv1alpha1.TalonRouteSpec{
			Host: "internal.example.com",
			Upstream: gatewayv1alpha1.Upstream{
				Service: "grafana",
				Port:    80,
			},
		},
	}

	cases := []struct {
		name       string
		value      string
		wantErr    bool
		errContains string
	}{
		{"empty defers to medium", "", false, ""},
		{"low", "low", false, ""},
		{"medium", "medium", false, ""},
		{"high", "high", false, ""},
		{"critical", "critical", false, ""},
		{"typo", "criticla", true, "spec.sensitivity"},
		{"casefold not allowed", "MEDIUM", true, "spec.sensitivity"},
		{"unknown tier", "extreme", true, "low|medium|high|critical"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base.DeepCopy()
			r.Spec.Sensitivity = c.value
			err := validateRoute(r)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", c.value)
				}
				if !strings.Contains(err.Error(), c.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), c.errContains)
				}
			} else if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.value, err)
			}
		})
	}
}
