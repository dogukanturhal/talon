// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"testing"

	"github.com/dogukanturhal/talon/internal/config"
	"github.com/dogukanturhal/talon/internal/policy"
)

func TestSessionChannel(t *testing.T) {
	r := &Router{cfg: &config.Config{
		ClientlessHostSuffixes: []string{".access.example.com", ".access.apps.example.com"},
	}}
	cases := []struct {
		host string
		want string
	}{
		{"argocd.access.example.com", policy.ChannelClientless},
		{"app.access.apps.example.com", policy.ChannelClientless},
		{"ARGOCD.ACCESS.EXAMPLE.COM", policy.ChannelClientless},      // case-insensitive
		{"argocd.access.example.com:8443", policy.ChannelClientless}, // :port stripped
		{"argocd.internal.example.com", policy.ChannelCookie},             // agent zone
		{"grafana.apps.example.com", policy.ChannelCookie},
		{"notaccess.example.com", policy.ChannelCookie}, // suffix must match the dotted boundary
	}
	for _, c := range cases {
		if got := r.sessionChannel(c.host); got != c.want {
			t.Errorf("sessionChannel(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestSessionChannel_DisabledWhenNoSuffixes(t *testing.T) {
	// Empty ClientlessHostSuffixes = clientless tier disabled → every host is
	// the default agent channel, so existing deployments are unchanged.
	r := &Router{cfg: &config.Config{}}
	if got := r.sessionChannel("anything.access.example.com"); got != policy.ChannelCookie {
		t.Errorf("with no suffixes configured, sessionChannel = %q, want %q", got, policy.ChannelCookie)
	}
}
