// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"testing"

	"github.com/dogukanturhal/talon/internal/config"
)

// TestIsSafeReturnURL_ClientlessZone exercises ADR 0044 Phase 1 — the
// open-redirect validator must accept return URLs into a configured
// clientless access zone, otherwise the OIDC redirect back to
// `<app>.access.hexxlock.com` after sign-in would be rejected and the
// clientless auth flow could never complete. Admin zones keep working and
// suffix-collision / non-https targets stay rejected.
func TestIsSafeReturnURL_ClientlessZone(t *testing.T) {
	t.Parallel()
	r := &RP{cfg: &config.Config{
		ProtectedHostSuffixes:  []string{"internal.example.com"},
		ClientlessHostSuffixes: []string{".access.hexxlock.com"},
	}}
	cases := []struct {
		rd   string
		want bool
	}{
		{"https://argocd.access.hexxlock.com/applications", true}, // access zone
		{"https://internal.example.com/graph", true},       // admin zone
		{"https://evilaccess.hexxlock.com/", false},               // suffix-collision (no dotted boundary)
		{"https://evil.com/access.hexxlock.com", false},           // foreign host
		{"http://argocd.access.hexxlock.com/", false},             // non-https rejected
		{"::not a url", false},                                    // unparseable
	}
	for _, c := range cases {
		if got := r.isSafeReturnURL(c.rd); got != c.want {
			t.Errorf("isSafeReturnURL(%q) = %v, want %v", c.rd, got, c.want)
		}
	}
}

// TestIsSafeReturnURL_ClientlessDisabledFallback — with no protected zones
// configured the validator falls back to the cookie-domain check; the
// access zone is only accepted when ClientlessHostSuffixes is set. Guards
// against accidentally widening the redirect allow-list on upgrade.
func TestIsSafeReturnURL_ClientlessDisabledFallback(t *testing.T) {
	t.Parallel()
	r := &RP{cfg: &config.Config{CookieDomain: "internal.example.com"}}
	if r.isSafeReturnURL("https://argocd.access.hexxlock.com/") {
		t.Error("access-zone rd must be rejected when clientless tier disabled and no matching cookie domain")
	}
	if !r.isSafeReturnURL("https://internal.example.com/") {
		t.Error("cookie-domain-matching rd must be accepted in the legacy fallback")
	}
}
