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
		{"exact match read", "talon:github.com:read", "github.com", VerbRead, true},
		{"exact match write", "talon:github.com:write", "github.com", VerbWrite, true},
		{"exact match pull", "talon:ghcr.io/dogukanturhal:pull", "ghcr.io/dogukanturhal", VerbPull, true},
		{"exact match push", "talon:ghcr.io/dogukanturhal:push", "ghcr.io/dogukanturhal", VerbPush, true},

		// Case-insensitive host
		{"host case-insensitive", "talon:github.com:read", "github.com", VerbRead, true},
		{"host case-insensitive request", "talon:github.com:read", "github.com", VerbRead, false /* request host not pre-normalised; caller responsibility */},

		// admin verb
		{"admin grants read", "talon:github.com:admin", "github.com", VerbRead, true},
		{"admin grants write", "talon:github.com:admin", "github.com", VerbWrite, true},
		{"admin grants pull", "talon:ghcr.io/dogukanturhal:admin", "ghcr.io/dogukanturhal", VerbPull, true},
		{"admin grants push", "talon:ghcr.io/dogukanturhal:admin", "ghcr.io/dogukanturhal", VerbPush, true},

		// Wildcard host
		{"wildcard host read", "talon:*:read", "github.com", VerbRead, true},
		{"wildcard host other host", "talon:*:read", "ghcr.io/dogukanturhal", VerbRead, true},

		// Break-glass
		{"break-glass any host any verb", "talon:proxy", "github.com", VerbWrite, true},
		{"break-glass other host", "talon:proxy", "ghcr.io/dogukanturhal", VerbPush, true},

		// Negative — wrong verb
		{"wrong verb", "talon:github.com:read", "github.com", VerbWrite, false},
		{"wrong host", "talon:ghcr.io/dogukanturhal:read", "github.com", VerbRead, false},

		// Negative — malformed
		{"empty scope", "", "github.com", VerbRead, false},
		{"wrong prefix", "iap:github.com:read", "github.com", VerbRead, false},
		{"too few parts", "talon:github.com", "github.com", VerbRead, false},
		{"too many parts", "talon:github.com:read:extra", "github.com", VerbRead, false},
		{"plain word", "admin", "github.com", VerbRead, false},

		// Pull vs read distinction (defense-in-depth)
		{"pull doesn't grant read", "talon:ghcr.io/dogukanturhal:pull", "ghcr.io/dogukanturhal", VerbRead, false},
		{"read doesn't grant pull", "talon:ghcr.io/dogukanturhal:read", "ghcr.io/dogukanturhal", VerbPull, false},
		{"push doesn't grant write", "talon:ghcr.io/dogukanturhal:push", "ghcr.io/dogukanturhal", VerbWrite, false},
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
		{"github.com", "https://github.com"},
		{"github.com", "https://github.com"},
		{" ghcr.io/dogukanturhal ", "https://ghcr.io/dogukanturhal"},
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
		"talon:github.com:read",
		"talon:ghcr.io/dogukanturhal:pull",
	}}
	if !c.AnyScopeMatchingHostVerb("github.com", VerbRead) {
		t.Error("expected match for gitlab:read")
	}
	if c.AnyScopeMatchingHostVerb("github.com", VerbWrite) {
		t.Error("unexpected match for gitlab:write")
	}
	if !c.AnyScopeMatchingHostVerb("ghcr.io/dogukanturhal", VerbPull) {
		t.Error("expected match for harbor:pull")
	}
	if c.AnyScopeMatchingHostVerb("ghcr.io/dogukanturhal", VerbPush) {
		t.Error("unexpected match for harbor:push")
	}
}
