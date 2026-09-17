// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"net/http"
	"strings"
)

// Verb is the normalised action the policy engine reasons about. It's
// derived from a request's HTTP method + path. The verb namespace is
// deliberately small for Phase 1; Phase 5 adds path-policies as
// additive enrichments.
type Verb string

const (
	// VerbRead — safe HTTP methods: GET, HEAD, OPTIONS.
	VerbRead Verb = "read"

	// VerbWrite — state-changing HTTP methods: POST, PUT, PATCH, DELETE.
	// Catch-all for non-pull-push API writes (REST, GraphQL).
	VerbWrite Verb = "write"

	// VerbPull — Docker Registry v2 read operations
	// (GET /v2/...). Distinct from generic :read so policy can
	// authorise registry-pull WITHOUT authorising other GET endpoints
	// on the same host (defence in depth for kubelet-style narrow
	// consumers).
	VerbPull Verb = "pull"

	// VerbPush — Docker Registry v2 write operations
	// (PUT|POST|PATCH /v2/...). Distinct from :write for symmetry
	// with :pull.
	VerbPush Verb = "push"
)

// VerbForRequest maps an HTTP request to its policy verb. Three
// protocol families get path-aware special cases:
//
//   - Docker Registry v2 (`/v2/...`): GET/HEAD → pull; POST/PUT/PATCH/
//     DELETE → push. Hostname-agnostic — any request whose path
//     begins with `/v2/` is treated as registry traffic.
//   - Git smart-HTTP (`*.git/info/refs?service=...` and
//     `*.git/git-upload-pack` or `*.git/git-receive-pack`): the
//     operation is determined by the SERVICE name, NOT the HTTP
//     method. Smart-HTTP clones use POST on the data-transfer leg
//     (per Documentation/technical/http-protocol.txt §5.2) but the
//     operation is read-only.
//   - Plain REST (everything else): GET/HEAD/OPTIONS → read; all
//     other methods → write.
//
// Adding new protocol-aware branches is preferred over teaching JWT
// issuers to grant write scopes to read-only consumers — the latter
// would conflate "this client only needs to clone" with "this client
// can push", which weakens the audit trail and breaks the principle
// of least privilege.
//
// Callers needing per-host overrides (e.g., a host that exposes a
// `/v2/` URL but is NOT a registry, or a non-git tool that names its
// endpoints `git-upload-pack`) can wire a custom VerbMapper into the
// verifier.
func VerbForRequest(r *http.Request) Verb {
	if r == nil {
		return VerbRead
	}
	path := r.URL.Path

	// Docker Registry v2 path family.
	if strings.HasPrefix(path, "/v2/") {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return VerbPull
		case http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
			return VerbPush
		}
	}

	// Git smart-HTTP path family. Two endpoints per repo:
	//
	//   GET  <repo>.git/info/refs?service=git-upload-pack    — clone discovery
	//   GET  <repo>.git/info/refs?service=git-receive-pack   — push discovery
	//   POST <repo>.git/git-upload-pack                       — clone data transfer
	//   POST <repo>.git/git-receive-pack                      — push data transfer
	//
	// `git-upload-pack` is the clone/fetch service; `git-receive-pack`
	// is the push service. Naming the service `upload-pack` for the
	// READ operation is a Git-protocol nomenclature inversion that
	// trips up every IAP that uses HTTP method semantics naively —
	// `upload-pack` means "the server uploads packs to the client",
	// i.e., clone. See Documentation/technical/http-protocol.txt for
	// the protocol spec.
	if isGitSmartHTTPRequest(path) {
		if isGitPushPath(path, r.URL.RawQuery) {
			return VerbWrite
		}
		return VerbRead
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return VerbRead
	default:
		return VerbWrite
	}
}

// isGitSmartHTTPRequest reports whether the path matches one of git's
// smart-HTTP endpoints: `*/info/refs` or paths ending in
// `/git-upload-pack` / `/git-receive-pack`.
//
// The match is intentionally cheap — a real git URL also includes a
// `.git` path segment somewhere upstream but we don't enforce that
// (some servers expose bare repos without the `.git` suffix, and the
// `git-(upload|receive)-pack` suffix is distinctive enough on its
// own).
func isGitSmartHTTPRequest(path string) bool {
	if strings.HasSuffix(path, "/info/refs") {
		return true
	}
	if strings.HasSuffix(path, "/git-upload-pack") {
		return true
	}
	if strings.HasSuffix(path, "/git-receive-pack") {
		return true
	}
	return false
}

// isGitPushPath returns true if the request is the WRITE half of the
// smart-HTTP protocol. Two routes get write semantics:
//
//   - `*/git-receive-pack` — push data transfer (POST).
//   - `*/info/refs?service=git-receive-pack` — push capability
//     discovery (GET). The query string is the authoritative
//     signal; the HTTP method here is GET.
//
// Everything else hitting one of the three smart-HTTP paths is read.
func isGitPushPath(path, rawQuery string) bool {
	if strings.HasSuffix(path, "/git-receive-pack") {
		return true
	}
	if strings.HasSuffix(path, "/info/refs") {
		// Cheap scan of the raw query — avoids allocating a values
		// map for the single `service` key.
		return strings.Contains(rawQuery, "service=git-receive-pack")
	}
	return false
}

// scopeAuthorisesHostVerb is the core scope-match predicate. Returns
// true if `scope` (one entry from a JWT's scope claim) grants the
// request's host+verb combination.
//
// Recognised scope shapes:
//   - "talon:proxy"                       — broad, ANY host, ANY verb.
//                                           Reserved for break-glass clients;
//                                           Falcon-ID gates issuance.
//   - "talon:<host>:<verb>"               — narrow, exact host + exact verb.
//   - "talon:<host>:admin"                — narrow host, ALL verbs.
//   - "talon:*:<verb>"                    — ANY host, exact verb (rare, mostly
//                                           for ops-tools that legitimately
//                                           touch every Talon-fronted host).
//
// Match is case-insensitive on host (hostnames are case-insensitive
// per RFC 4343) and case-sensitive on verb (lowercase only — verbs are
// our internal namespace, not protocol-level).
func scopeAuthorisesHostVerb(scope, host string, verb Verb) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return false
	}
	// Break-glass: talon:proxy matches anything.
	if scope == "talon:proxy" {
		return true
	}
	parts := strings.Split(scope, ":")
	if len(parts) != 3 || parts[0] != "talon" {
		// Unrecognised scope shape — defense-in-depth, deny.
		return false
	}
	scopeHost := strings.ToLower(parts[1])
	scopeVerb := parts[2]
	if scopeHost != "*" && scopeHost != host {
		return false
	}
	if scopeVerb == "admin" {
		return true
	}
	return Verb(scopeVerb) == verb
}

// expectedAudienceForHost computes the expected `aud` claim for an
// incoming request. Convention: the audience is the canonical
// HTTPS origin of the Talon-fronted host (e.g., a request to
// `github.com` expects `aud=https://github.com`).
// Matches Falcon-ID's RFC 8707 `resource` parameter convention
// (oauth_provider_service_tokens.go:42-46).
//
// Operators can override per-host via AudienceMapper in VerifierConfig
// if a deployment needs a different canonical form (e.g., port-
// qualified, path-qualified).
func expectedAudienceForHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	return "https://" + host
}
