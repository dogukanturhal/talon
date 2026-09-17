// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"strings"
	"testing"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
)

// TestValidateRoute_ClientlessHostZone exercises ADR 0044 Phase 1 — a
// TalonRoute whose spec.host lives in a configured access zone
// (TALON_CLIENTLESS_HOST_SUFFIXES) must be admitted on equal footing with
// the admin-tier protected zones, so the access zone is a first-class route
// class. When no clientless suffixes are configured the access host is
// rejected (tier disabled), preserving existing single-zone behaviour.
func TestValidateRoute_ClientlessHostZone(t *testing.T) {
	base := func(host string) *gatewayv1alpha1.TalonRoute {
		return &gatewayv1alpha1.TalonRoute{
			Spec: gatewayv1alpha1.TalonRouteSpec{
				Host: host,
				Upstream: gatewayv1alpha1.Upstream{
					Service: "grafana",
					Port:    80,
				},
			},
		}
	}

	// Snapshot + restore the package-level suffix vars (set from env at
	// init) so this test is hermetic regardless of the runner's env.
	savedProtected := protectedHostSuffixes
	savedClientless := clientlessHostSuffixes
	t.Cleanup(func() {
		protectedHostSuffixes = savedProtected
		clientlessHostSuffixes = savedClientless
	})

	t.Run("access host admitted when clientless zone configured", func(t *testing.T) {
		protectedHostSuffixes = []string{"internal.example.com"}
		clientlessHostSuffixes = []string{".access.hexxlock.com"}
		if err := validateRoute(base("argocd.access.hexxlock.com")); err != nil {
			t.Fatalf("access-zone host must be admitted, got %v", err)
		}
		// Admin zone still works alongside the access zone.
		if err := validateRoute(base("internal.example.com")); err != nil {
			t.Fatalf("admin-zone host must still be admitted, got %v", err)
		}
	})

	t.Run("access host rejected when clientless zone disabled", func(t *testing.T) {
		protectedHostSuffixes = []string{"internal.example.com"}
		clientlessHostSuffixes = nil
		err := validateRoute(base("argocd.access.hexxlock.com"))
		if err == nil {
			t.Fatal("access-zone host must be rejected when clientless tier disabled")
		}
		if !strings.Contains(err.Error(), "must end with one of") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("suffix-collision attack rejected", func(t *testing.T) {
		// A leading-dot suffix (".access.hexxlock.com") must NOT match a host
		// that merely ends with the same letters at a non-dotted boundary.
		protectedHostSuffixes = nil
		clientlessHostSuffixes = []string{".access.hexxlock.com"}
		if err := validateRoute(base("evilaccess.hexxlock.com")); err == nil {
			t.Fatal("non-dotted-boundary host must be rejected (suffix-collision guard)")
		}
	})
}
