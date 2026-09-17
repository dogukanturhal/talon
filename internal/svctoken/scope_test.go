// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerbForRequest(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   Verb
	}{
		{"get on REST", http.MethodGet, "/api/v4/projects/1", VerbRead},
		{"head", http.MethodHead, "/api/v4/projects/1", VerbRead},
		{"options preflight", http.MethodOptions, "/api/v4/projects/1", VerbRead},
		{"post REST", http.MethodPost, "/api/v4/projects", VerbWrite},
		{"put REST", http.MethodPut, "/api/v4/projects/1", VerbWrite},
		{"patch REST", http.MethodPatch, "/api/v4/projects/1", VerbWrite},
		{"delete REST", http.MethodDelete, "/api/v4/projects/1", VerbWrite},
		{"docker v2 pull manifest", http.MethodGet, "/v2/falcon-id/falcon-id/manifests/latest", VerbPull},
		{"docker v2 pull blob HEAD", http.MethodHead, "/v2/falcon-id/falcon-id/blobs/sha256:abc", VerbPull},
		{"docker v2 push blob PATCH", http.MethodPatch, "/v2/falcon-id/falcon-id/blobs/uploads/xyz", VerbPush},
		{"docker v2 push manifest PUT", http.MethodPut, "/v2/falcon-id/falcon-id/manifests/latest", VerbPush},
		{"docker v2 push POST", http.MethodPost, "/v2/falcon-id/falcon-id/blobs/uploads/", VerbPush},
		{"docker v2 push DELETE", http.MethodDelete, "/v2/falcon-id/falcon-id/manifests/latest", VerbPush},

		// Git smart-HTTP — discovery leg (GET, query-driven service).
		{"git clone discovery", http.MethodGet, "/hexxlock/talon.git/info/refs?service=git-upload-pack", VerbRead},
		{"git push discovery", http.MethodGet, "/hexxlock/talon.git/info/refs?service=git-receive-pack", VerbWrite},
		{"git refs no service", http.MethodGet, "/hexxlock/talon.git/info/refs", VerbRead},

		// Git smart-HTTP — data-transfer leg (POST). This is the
		// regression Phase 5 caught: naive HTTP method classification
		// rejected scope=read JWTs on every clone's second leg.
		{"git clone data POST", http.MethodPost, "/hexxlock/talon.git/git-upload-pack", VerbRead},
		{"git push data POST", http.MethodPost, "/hexxlock/talon.git/git-receive-pack", VerbWrite},

		// Bare repo without .git suffix — same suffix-match still
		// classifies correctly.
		{"git bare repo clone POST", http.MethodPost, "/hexxlock/talon/git-upload-pack", VerbRead},
		{"git bare repo push POST", http.MethodPost, "/hexxlock/talon/git-receive-pack", VerbWrite},

		// Adversarial: a NON-git endpoint that happens to be POST
		// `/git-upload-pack` should still classify as read — Talon
		// can't tell the difference at the verb layer (caller must
		// run a host-specific scope rule if they care).
		{"non-git host with git-upload-pack URL POST", http.MethodPost, "/api/git-upload-pack", VerbRead},

		// Adversarial: REST endpoint `/info/refs` not under a .git
		// path. Falls through smart-HTTP detection by way of being
		// a plain GET → read. (Suffix match catches it as smart-HTTP,
		// but smart-HTTP read is the same as REST read anyway.)
		{"non-git /info/refs", http.MethodGet, "/info/refs", VerbRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.com"+tc.path, nil)
			if got := VerbForRequest(r); got != tc.want {
				t.Errorf("VerbForRequest(%s %s) = %q, want %q", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

func TestVerbForRequest_NilSafe(t *testing.T) {
	if got := VerbForRequest(nil); got != VerbRead {
		t.Errorf("VerbForRequest(nil) = %q, want %q (safe default)", got, VerbRead)
	}
}

func TestScopeAuthorisesHostVerb(t *testing.T) {
	cases := []struct {
		name  string
		scope string
		host  string
		verb  Verb
		want  bool
	}{
		// Exact match
		{"exact match read", "talon:git.example.com:read", "git.example.com", VerbRead, true},
		{"exact match write", "talon:git.example.com:write", "git.example.com", VerbWrite, true},
		{"exact match pull", "talon:registry.example.com:pull", "registry.example.com", VerbPull, true},
		{"exact match push", "talon:registry.example.com:push", "registry.example.com", VerbPush, true},

		// Case-insensitive host
		{"host case-insensitive", "talon:git.example.com:read", "git.example.com", VerbRead, true},
		{"host case-insensitive request", "talon:Git.EXAMPLE.com:read", "other.example.com", VerbRead, false /* request host not covered by scope */},

		// admin verb
		{"admin grants read", "talon:git.example.com:admin", "git.example.com", VerbRead, true},
		{"admin grants write", "talon:git.example.com:admin", "git.example.com", VerbWrite, true},
		{"admin grants pull", "talon:registry.example.com:admin", "registry.example.com", VerbPull, true},
		{"admin grants push", "talon:registry.example.com:admin", "registry.example.com", VerbPush, true},

		// Wildcard host
		{"wildcard host read", "talon:*:read", "git.example.com", VerbRead, true},
		{"wildcard host other host", "talon:*:read", "registry.example.com", VerbRead, true},

		// Break-glass
		{"break-glass any host any verb", "talon:proxy", "git.example.com", VerbWrite, true},
		{"break-glass other host", "talon:proxy", "registry.example.com", VerbPush, true},

		// Negative — wrong verb
		{"wrong verb", "talon:git.example.com:read", "git.example.com", VerbWrite, false},
		{"wrong host", "talon:registry.example.com:read", "git.example.com", VerbRead, false},

		// Negative — malformed
		{"empty scope", "", "git.example.com", VerbRead, false},
		{"wrong prefix", "iap:git.example.com:read", "git.example.com", VerbRead, false},
		{"too few parts", "talon:git.example.com", "git.example.com", VerbRead, false},
		{"too many parts", "talon:git.example.com:read:extra", "git.example.com", VerbRead, false},
		{"plain word", "admin", "git.example.com", VerbRead, false},

		// Pull vs read distinction (defense-in-depth)
		{"pull doesn't grant read", "talon:registry.example.com:pull", "registry.example.com", VerbRead, false},
		{"read doesn't grant pull", "talon:registry.example.com:read", "registry.example.com", VerbPull, false},
		{"push doesn't grant write", "talon:registry.example.com:push", "registry.example.com", VerbWrite, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeAuthorisesHostVerb(tc.scope, tc.host, tc.verb)
			if got != tc.want {
				t.Errorf("scopeAuthorisesHostVerb(%q, %q, %q) = %v, want %v",
					tc.scope, tc.host, tc.verb, got, tc.want)
			}
		})
	}
}

func TestExpectedAudienceForHost(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"git.example.com", "https://git.example.com"},
		{"git.example.com", "https://git.example.com"},
		{" registry.example.com ", "https://registry.example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := expectedAudienceForHost(tc.host); got != tc.want {
				t.Errorf("expectedAudienceForHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestClaimsAnyScopeMatchingHostVerb(t *testing.T) {
	c := &Claims{Scopes: []string{
		"talon:git.example.com:read",
		"talon:registry.example.com:pull",
	}}
	if !c.AnyScopeMatchingHostVerb("git.example.com", VerbRead) {
		t.Error("expected match for gitlab:read")
	}
	if c.AnyScopeMatchingHostVerb("git.example.com", VerbWrite) {
		t.Error("unexpected match for gitlab:write")
	}
	if !c.AnyScopeMatchingHostVerb("registry.example.com", VerbPull) {
		t.Error("expected match for harbor:pull")
	}
	if c.AnyScopeMatchingHostVerb("registry.example.com", VerbPush) {
		t.Error("unexpected match for harbor:push")
	}
}
