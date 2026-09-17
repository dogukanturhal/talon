// SPDX-License-Identifier: AGPL-3.0-or-later

// Package router — pathRules matcher engine (Phase 6b).
//
// The matcher walks a route's v1beta1 PathRules in declared order
// (first-match-wins) and returns the matching rule (if any). Result
// is consumed by router.Verify (Phase 7.3) to overlay per-path policy
// on top of the host-default policy.
//
// 12-pitfall coverage (from docs/sessions/2026-06-01-talon-pathrules-
// handoff-prompt.md):
//
//  1. Path normalization: percent-decode + collapse // + resolve .|..
//     before matching. Mirrors Envoy's `normalize_path: true` +
//     `merge_slashes: true` defaults.
//  2. Reject %2F / %5C (percent-encoded slash/backslash) by default.
//  3. Strip path parameters (`;jsessionid=...`) before matching.
//  4. Match on PATH ONLY, not path+query.
//  5. First-match-wins ordering must be stable across reconciles —
//     preserve YAML list order; do not let map iteration reorder.
//  6. Default-deny on no-match is the host-level concern; this matcher
//     ONLY answers "which rule matched". The caller decides what
//     no-match means.
//  7. RE2 only, no PCRE. The Go stdlib `regexp` package is RE2-only by
//     construction; admission-time rejection of backreferences /
//     lookaround is by `regexp.Compile` returning an error on those
//     constructs (RE2 doesn't recognize them).
//  8. Compile regex at admission, NOT per-request. `CompileRule`
//     does this once; `Match` consumes the precompiled program.
//  9. Method matching case-sensitive per RFC 7230 §3.1.1; path matching
//     case-sensitive per RFC 3986 §6.2.2.1.
// 10. MFA step-up uses RFC 9470 wire format — handled in stepup.go,
//     consumed by Verify when MfaRequired and the cookie session
//     lacks `acr` per the rule's AcrValues. Not the matcher's
//     concern.
// 11. Property: requests to `path`, `path/`, `path?q=1`, `path;x=1`,
//     `path/../path`, `path%2Fextra` MUST all reach the same
//     decision when their normalized form matches the rule.
// 12. Per-rule metric `talon_authz_decision_total{rule="<name>",
//     action=...}` — wired by the Verify caller, NOT the matcher.
package router

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	v1beta1 "github.com/hexxlock/talon/api/v1beta1"
)

// CompiledRule is the precompiled form of a v1beta1.PathRule, ready
// for per-request matching. CompileRule prepares this once per rule
// at reconcile time (or v1beta1 admission); the data plane consumes
// it on every request via Match.
//
// The wrapped *v1beta1.PathRule is what the caller dereferences to
// get the Policy/Action/Name fields once the match has fired — so the
// matcher returns a CompiledRule pointer rather than just a yes/no
// bool.
type CompiledRule struct {
	// Rule is the original spec entry. Name + Policy + Action are
	// read directly by the Verify caller.
	Rule *v1beta1.PathRule

	// pathRegex is the precompiled RE2 program when the rule's Match
	// uses PathRegex. nil for exact / prefix matchers.
	pathRegex *regexp.Regexp

	// methodSet is the lowercased-NEVER-NO method set for O(1) check.
	// Empty = all methods (matches anything).
	//
	// Wait — pitfall 9 says case-sensitive per RFC 7230 §3.1.1. So we
	// store methods VERBATIM (uppercase by HTTP convention) and the
	// caller compares directly. No lowercasing.
	methodSet map[string]struct{}

	// matchKind is the cached "which of Path/PathPrefix/PathRegex"
	// the rule uses, so the per-request hot path doesn't re-introspect
	// the spec each time.
	matchKind matchKind
}

type matchKind int

const (
	matchKindPath matchKind = iota + 1
	matchKindPathPrefix
	matchKindPathRegex
)

// CompileRules precompiles every PathRule in a slice. Returns the
// compiled slice in the SAME ORDER (load-bearing for first-match-wins
// — pitfall 5). Any single-rule failure returns the FIRST error +
// nil — admission-time rejection should reject the whole TalonRoute,
// not silently skip the bad rule.
//
// Caller (reconciler) maps the error to `Registered=False reason=
// ValidationFailed` so the operator sees the failure on `kubectl
// get talonroute`.
func CompileRules(rules []v1beta1.PathRule) ([]CompiledRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	out := make([]CompiledRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for i := range rules {
		// Aliased loop var, not the closure-capture footgun — we're
		// just taking the pointer for storage in CompiledRule.
		rule := &rules[i]
		if rule.Name == "" {
			return nil, errInvalidRule("rule[" + itoa(i) + "]: empty name")
		}
		if _, dup := seen[rule.Name]; dup {
			return nil, errInvalidRule("rule[" + itoa(i) + "]: duplicate name " + rule.Name)
		}
		seen[rule.Name] = struct{}{}
		c, err := CompileRule(rule)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// CompileRule precompiles a single PathRule. Exported for test reach;
// production code calls CompileRules.
func CompileRule(rule *v1beta1.PathRule) (CompiledRule, error) {
	cr := CompiledRule{Rule: rule}
	m := rule.Match

	// Exactly-one-of Path / PathPrefix / PathRegex.
	nset := 0
	if m.Path != "" {
		nset++
		cr.matchKind = matchKindPath
	}
	if len(m.PathPrefix) > 0 {
		nset++
		cr.matchKind = matchKindPathPrefix
	}
	if m.PathRegex != "" {
		nset++
		cr.matchKind = matchKindPathRegex
	}
	if nset == 0 {
		return cr, errInvalidRule("rule " + rule.Name + ": exactly one of path/pathPrefix/pathRegex must be set, got zero")
	}
	if nset > 1 {
		return cr, errInvalidRule("rule " + rule.Name + ": exactly one of path/pathPrefix/pathRegex must be set, got " + itoa(nset))
	}

	// Path / PathPrefix: validate normalization friendliness (no
	// percent-encoding in the rule itself; rules are operator-authored
	// strings, not URL-encoded — letting them carry %XX would mean
	// rules and normalized request paths could mismatch).
	switch cr.matchKind {
	case matchKindPath:
		if strings.ContainsRune(m.Path, '%') {
			return cr, errInvalidRule("rule " + rule.Name + ": path contains '%' — rules must use literal characters, not percent-encoding")
		}
		if !strings.HasPrefix(m.Path, "/") {
			return cr, errInvalidRule("rule " + rule.Name + ": path must start with '/' (got " + m.Path + ")")
		}
	case matchKindPathPrefix:
		for _, p := range m.PathPrefix {
			if p == "" {
				return cr, errInvalidRule("rule " + rule.Name + ": pathPrefix contains empty string")
			}
			if strings.ContainsRune(p, '%') {
				return cr, errInvalidRule("rule " + rule.Name + ": pathPrefix contains '%' — use literal characters")
			}
			if !strings.HasPrefix(p, "/") {
				return cr, errInvalidRule("rule " + rule.Name + ": pathPrefix entry must start with '/' (got " + p + ")")
			}
		}
	case matchKindPathRegex:
		// RE2-only — Go's `regexp` package IS RE2; backreferences /
		// lookaround compile-error here (pitfall 7). Anchor to start
		// for prefix-like semantics; trailing-anchor is operator's
		// choice via the regex itself.
		re, err := regexp.Compile(m.PathRegex)
		if err != nil {
			return cr, errInvalidRule("rule " + rule.Name + ": pathRegex compile: " + err.Error())
		}
		cr.pathRegex = re
	}

	// Methods — uppercase verbatim per RFC 7230 §3.1.1 (case-sensitive
	// — pitfall 9). Empty list = match all.
	if len(m.Methods) > 0 {
		cr.methodSet = make(map[string]struct{}, len(m.Methods))
		for _, mth := range m.Methods {
			if mth == "" {
				return cr, errInvalidRule("rule " + rule.Name + ": methods contains empty string")
			}
			cr.methodSet[mth] = struct{}{}
		}
	}

	return cr, nil
}

// FirstMatch walks the precompiled rules in declared order and
// returns the first that matches the request. Returns nil when no
// rule matches — caller falls back to the route's DefaultPolicy.
//
// Pitfall 11 — property: this function MUST produce the same answer
// for `path`, `path/`, `path?q=1`, `path;x=1`, `path/../path`,
// `path%2Fextra` after normalization. The normalization function is
// called ONCE per request before iterating rules; rules see the
// canonical path.
//
// Pitfall 4 — match on path only, NOT path+query. The normalized
// path argument MUST already have the query stripped by the caller
// (router.go does this when extracting from req.URL.Path which
// excludes the query per net/url semantics).
func FirstMatch(rules []CompiledRule, method, rawPath string) *CompiledRule {
	path, err := NormalizePath(rawPath)
	if err != nil {
		// Pitfall 2 — %2F / %5C reject. Nil match means "no rule
		// matched" — caller falls back to DefaultPolicy.deny (when
		// configured) or to permissive. The reject decision itself
		// happens at the router layer where the original request can
		// be 400'd with a meaningful reason.
		return nil
	}
	for i := range rules {
		r := &rules[i]
		// Method gate first (cheap).
		if r.methodSet != nil {
			if _, ok := r.methodSet[method]; !ok {
				continue
			}
		}
		// Path gate.
		matched := false
		switch r.matchKind {
		case matchKindPath:
			matched = (path == r.Rule.Match.Path)
		case matchKindPathPrefix:
			for _, p := range r.Rule.Match.PathPrefix {
				if strings.HasPrefix(path, p) {
					matched = true
					break
				}
			}
		case matchKindPathRegex:
			matched = r.pathRegex.MatchString(path)
		}
		if matched {
			return r
		}
	}
	return nil
}

// NormalizePath applies the canonicalization that pitfalls 1-3
// require:
//
//  - strip path parameters (`;jsessionid=...`) per RFC 3986 §3.3
//    and Istio CVE-shape #27409 (pitfall 3)
//  - percent-decode SAFE characters; REJECT %2F / %5C (pitfall 2 +
//    Envoy default `path_with_escaped_slashes_action: REJECT_REQUEST`)
//  - collapse runs of `/` to a single `/` (Envoy `merge_slashes: true`)
//  - resolve `.` and `..` segments per RFC 3986 §5.2.4 "Remove Dot
//    Segments"
//
// Returns the canonical path. Returns a non-nil error ONLY for the
// %2F / %5C reject case — the caller should map this to a 400 Bad
// Request at the data-plane layer.
func NormalizePath(p string) (string, error) {
	if p == "" {
		return "/", nil
	}

	// Strip path parameters from EACH segment. RFC 3986 §3.3 puts
	// `;params` after the segment; Istio CVE-27409 surfaced the
	// bypass where /admin;.css matched an "ends with .css" allow.
	// We strip them BEFORE the prefix/regex match so rules see only
	// the path.
	p = stripPathParams(p)

	// Reject percent-encoded slashes BEFORE decoding so we don't
	// silently let a %2F-bearing path through. Same posture as
	// Envoy's REJECT_REQUEST default. Future per-route opt-in to
	// allow %2F is out of scope for Phase 6b — when a route needs
	// it (Docker Registry v2 blob path?), add a per-rule
	// AllowEncodedSlashes bool then.
	if containsPctSlash(p) {
		return "", errEncodedSlashRejected
	}

	// Percent-decode. url.PathUnescape handles the standard set;
	// since we've already rejected %2F/%5C, the remaining encodings
	// are safe to decode.
	decoded, err := url.PathUnescape(p)
	if err != nil {
		// Malformed percent-encoding (e.g. "%ZZ"). Treat as reject —
		// same as Envoy's REJECT_REQUEST on malformed paths.
		return "", errEncodedSlashRejected
	}

	// Collapse `//` runs and resolve `.`/`..` segments.
	decoded = collapseAndResolve(decoded)

	if decoded == "" {
		return "/", nil
	}
	return decoded, nil
}

var errEncodedSlashRejected = errors.New("path contains percent-encoded slash (%2F or %5C) — rejected")

// containsPctSlash returns true if the input has %2F or %5C
// (case-insensitive — RFC 3986 §2.1: "The uppercase hexadecimal
// digits 'A' through 'F' are equivalent to the lowercase digits
// 'a' through 'f', respectively").
func containsPctSlash(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		a := s[i+1]
		b := s[i+2]
		// %2F (slash) or %5C (backslash) — uppercase OR lowercase hex.
		if (a == '2' && (b == 'F' || b == 'f')) ||
			(a == '5' && (b == 'C' || b == 'c')) {
			return true
		}
	}
	return false
}

// stripPathParams removes `;params` from each segment of the path.
// RFC 3986 §3.3 path syntax: path-abempty = *( "/" segment )
// where segment = *pchar; semicolons within a segment are reserved
// per §3.4 but historically used (J2EE jsessionid, .NET ASP.NET).
// Istio CVE-27409 showed the bypass; this strip closes it.
//
// Returns the input with each segment's `;...` tail removed.
func stripPathParams(p string) string {
	if !strings.ContainsRune(p, ';') {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	segStart := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			// Write segment [segStart:i], stripping any ;params tail.
			seg := p[segStart:i]
			if semi := strings.IndexByte(seg, ';'); semi >= 0 {
				seg = seg[:semi]
			}
			b.WriteString(seg)
			if i < len(p) {
				b.WriteByte('/')
			}
			segStart = i + 1
		}
	}
	return b.String()
}

// collapseAndResolve applies the two Envoy `merge_slashes` + `.`/`..`
// resolution steps in one pass. Implements RFC 3986 §5.2.4 "Remove
// Dot Segments" with the additional collapse rule. Preserves
// trailing-slash semantics — `/api/` and `/api` are semantically
// distinct per HTTP routing convention (Envoy, nginx, K8s ingress
// all treat them as different).
func collapseAndResolve(p string) string {
	if p == "" {
		return ""
	}
	leadingSlash := strings.HasPrefix(p, "/")

	// Trailing-slash semantic — preserve when the input had one
	// AFTER stripping `.` and `..`. A pure `..` at the end that pops
	// the last segment shouldn't synthesise a trailing slash; that's
	// the "/api/../ → /" case which collapseAndResolve maps to "/".
	// A literal trailing `/` on a real segment IS preserved.
	trailingSlash := strings.HasSuffix(p, "/") && len(p) > 1

	out := make([]string, 0, 8)
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			// skip: empty (// collapse) or current-dir
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	joined := strings.Join(out, "/")
	if leadingSlash {
		joined = "/" + joined
	}
	if trailingSlash && len(out) > 0 && !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	if joined == "" {
		return "/"
	}
	return joined
}

// --- helpers ---------------------------------------------------------

type invalidRuleErr struct{ msg string }

func (e *invalidRuleErr) Error() string { return e.msg }

func errInvalidRule(msg string) error { return &invalidRuleErr{msg: msg} }

// IsInvalidRule reports whether err is a CompileRule validation
// failure. Reconciler uses this to set Registered=False with reason
// ValidationFailed (mirrors the existing TalonRouteRegistered logic
// in internal/controller).
func IsInvalidRule(err error) bool {
	var t *invalidRuleErr
	return errors.As(err, &t)
}

// itoa is a tiny strconv.Itoa alternative — keeps the error-message
// hot path strconv-free. Not perf-critical; clarity over micro-opt.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
