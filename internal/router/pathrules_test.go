// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"strings"
	"testing"

	v1beta1 "github.com/dogukanturhal/talon/api/v1beta1"
)

// ---------------------------------------------------------------------
// Pitfall 1: Path normalization (decode + collapse // + resolve . / ..)
// ---------------------------------------------------------------------

func TestNormalizePath_DecodeCollapseResolve(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// passthrough
		{"/api/v1/projects", "/api/v1/projects"},
		// trailing slash preserved
		{"/api/", "/api/"},
		// double slashes collapse
		{"//api//v1//projects", "/api/v1/projects"},
		// current-dir resolves
		{"/api/./v1/./projects", "/api/v1/projects"},
		// parent-dir resolves
		{"/api/v1/../v2/projects", "/api/v2/projects"},
		// nested .. cannot escape root
		{"/../../etc/passwd", "/etc/passwd"},
		// safe percent-encoding (space → %20) decodes
		{"/api/hello%20world", "/api/hello world"},
		// case-insensitive hex
		{"/api/hello%2Bworld", "/api/hello+world"}, // %2B = '+'
		// empty → root
		{"", "/"},
		// root-only
		{"/", "/"},
	}
	for _, tc := range cases {
		got, err := NormalizePath(tc.in)
		if err != nil {
			t.Errorf("NormalizePath(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------
// Pitfall 2: Reject %2F / %5C by default
// ---------------------------------------------------------------------

func TestNormalizePath_RejectEncodedSlash(t *testing.T) {
	rejected := []string{
		"/api/v1/projects%2Fpasswd",   // %2F lowercase 'f' too
		"/api/v1/projects%2fpasswd",   // lowercase
		"/api/v1/projects%5Cback",     // %5C
		"/api/v1/projects%5cback",     // lowercase
		"/api%2Fadmin",                // even in the middle
		"%2F",                          // alone
	}
	for _, in := range rejected {
		got, err := NormalizePath(in)
		if err == nil {
			t.Errorf("NormalizePath(%q) = %q, want REJECT", in, got)
		}
	}
}

func TestNormalizePath_RejectMalformedPercent(t *testing.T) {
	// Malformed %-encoding should also reject (Envoy REJECT_REQUEST).
	rejected := []string{
		"/api/%ZZ",
		"/api/%2",   // truncated
		"/api/%",    // bare percent
	}
	for _, in := range rejected {
		_, err := NormalizePath(in)
		if err == nil {
			t.Errorf("NormalizePath(%q) accepted malformed %%-encoding", in)
		}
	}
}

// ---------------------------------------------------------------------
// Pitfall 3: Strip path parameters (;jsessionid=...)
// Istio CVE-27409 shape.
// ---------------------------------------------------------------------

func TestNormalizePath_StripsPathParameters(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/admin;jsessionid=abc", "/admin"},
		{"/path;p1=v1/sub;p2=v2", "/path/sub"},
		// segment with no params unchanged
		{"/no/params", "/no/params"},
		// param-only path becomes root
		{"/;junk", "/"},
		// CVE-27409 shape: /admin;.css must match /admin, not /admin;.css
		{"/admin;.css", "/admin"},
	}
	for _, tc := range cases {
		got, err := NormalizePath(tc.in)
		if err != nil {
			t.Errorf("NormalizePath(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------
// Pitfall 7: RE2-only — regex constructs PCRE-supports-but-RE2-doesn't
// must reject at CompileRule.
// ---------------------------------------------------------------------

func TestCompileRule_RejectsPCREConstructs(t *testing.T) {
	// RE2 (and Go's `regexp`) reject these constructs explicitly —
	// they require backtracking, which RE2 avoids by design for the
	// linear-time guarantee. CompileRule surfaces the regexp.Compile
	// error as InvalidRule so admission catches it before the route
	// reaches production.
	//
	// NOTE: Go's regexp accepts `(?<name>foo)` AS WELL AS `(?P<name>
	// foo)` for named captures (since Go 1.22) — that's NOT PCRE-
	// specific, both forms work. The truly-rejected constructs are
	// the ones requiring backtracking.
	bad := []string{
		`foo(?=bar)`,       // lookahead
		`foo(?!bar)`,       // negative lookahead
		`(foo)\1`,          // backreference
		`foo(?<=bar)`,      // lookbehind (parses as malformed named capture)
	}
	for _, re := range bad {
		_, err := CompileRule(&v1beta1.PathRule{
			Name:  "test",
			Match: v1beta1.PathRuleMatch{PathRegex: re},
		})
		if err == nil {
			t.Errorf("CompileRule with PCRE regex %q should reject, accepted", re)
			continue
		}
		if !IsInvalidRule(err) {
			t.Errorf("CompileRule with PCRE regex %q: want IsInvalidRule, got %v", re, err)
		}
	}
}

func TestCompileRule_AcceptsValidRE2(t *testing.T) {
	ok := []string{
		`^/api/v\d+/`,
		`/admin/.*`,
		`^/[a-z0-9]+/?$`,
		`(?P<v>v\d+)`, // RE2 named-capture (Perl-style)
		`(?<v>v\d+)`,  // Go 1.22+ also accepts the bare `(?<name>...)` form
	}
	for _, re := range ok {
		_, err := CompileRule(&v1beta1.PathRule{
			Name:  "test",
			Match: v1beta1.PathRuleMatch{PathRegex: re},
		})
		if err != nil {
			t.Errorf("CompileRule with valid RE2 regex %q: unexpected error: %v", re, err)
		}
	}
}

// ---------------------------------------------------------------------
// Pitfall 5: First-match-wins ordering stable across reconciles.
// CompileRules MUST preserve list order regardless of YAML or
// in-memory representation.
// ---------------------------------------------------------------------

func TestCompileRules_PreservesOrder(t *testing.T) {
	rules := []v1beta1.PathRule{
		{Name: "first", Match: v1beta1.PathRuleMatch{Path: "/a"}},
		{Name: "second", Match: v1beta1.PathRuleMatch{Path: "/b"}},
		{Name: "third", Match: v1beta1.PathRuleMatch{Path: "/c"}},
	}
	compiled, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	got := []string{compiled[0].Rule.Name, compiled[1].Rule.Name, compiled[2].Rule.Name}
	want := []string{"first", "second", "third"}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("CompileRules order: position %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFirstMatch_FirstWins(t *testing.T) {
	rules, err := CompileRules([]v1beta1.PathRule{
		{Name: "api-broad", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/"}}},
		{Name: "api-admin", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/admin/"}}},
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	// /api/admin/foo matches BOTH; first-match-wins → "api-broad".
	// This is the dead-code-second-rule case the operator should flag,
	// but the matcher honours declaration order strictly.
	m := FirstMatch(rules, "GET", "/api/admin/foo")
	if m == nil {
		t.Fatalf("expected match, got nil")
	}
	if m.Rule.Name != "api-broad" {
		t.Errorf("first-match-wins violated: got %q, want api-broad", m.Rule.Name)
	}
}

// ---------------------------------------------------------------------
// Pitfall 9: Method matching case-sensitive per RFC 7230 §3.1.1
// ---------------------------------------------------------------------

func TestFirstMatch_MethodCaseSensitive(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{
			Name: "rw",
			Match: v1beta1.PathRuleMatch{
				PathPrefix: []string{"/api/"},
				Methods:    []string{"GET", "POST"},
			},
		},
	})
	// Match GET (exact case).
	if m := FirstMatch(rules, "GET", "/api/x"); m == nil {
		t.Errorf("GET should match")
	}
	// Reject get (lowercase).
	if m := FirstMatch(rules, "get", "/api/x"); m != nil {
		t.Errorf("get (lowercase) should NOT match; RFC 7230 §3.1.1")
	}
	// Reject Get (mixed case).
	if m := FirstMatch(rules, "Get", "/api/x"); m != nil {
		t.Errorf("Get (mixed case) should NOT match; RFC 7230 §3.1.1")
	}
}

func TestFirstMatch_EmptyMethodsMatchesAll(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "any", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/x/"}}},
	})
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "WHATEVER"} {
		if got := FirstMatch(rules, m, "/x/y"); got == nil {
			t.Errorf("empty Methods should match %q", m)
		}
	}
}

// ---------------------------------------------------------------------
// Pitfall 11: Property — equivalent paths reach same decision.
// ---------------------------------------------------------------------

func TestFirstMatch_PropertyEquivalentPaths(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "api", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/"}}},
	})
	// All of these should normalize to a path under /api/ → match
	// the "api" rule.
	equivalents := []string{
		"/api/foo",
		"/api/foo/",                  // trailing slash variant
		"/api//foo",                  // collapsed //
		"/api/./foo",                 // current-dir
		"/api/bar/../foo",            // parent-dir
		"/api/foo;jsessionid=abc",    // path parameter
		"/api/hello%20world/foo",     // safe percent-decode (decodes inside)
	}
	for _, p := range equivalents {
		m := FirstMatch(rules, "GET", p)
		if m == nil || m.Rule.Name != "api" {
			t.Errorf("path %q should match 'api' rule; got %v", p, m)
		}
	}
}

// ---------------------------------------------------------------------
// Match-kind dispatch tests (Path / PathPrefix / PathRegex)
// ---------------------------------------------------------------------

func TestFirstMatch_ExactPath(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "health", Match: v1beta1.PathRuleMatch{Path: "/-/health"}},
	})
	if m := FirstMatch(rules, "GET", "/-/health"); m == nil || m.Rule.Name != "health" {
		t.Errorf("exact /-/health should match")
	}
	if m := FirstMatch(rules, "GET", "/-/health/sub"); m != nil {
		t.Errorf("exact Path should NOT match prefix")
	}
}

func TestFirstMatch_PathPrefix_AnyOf(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "api-or-info", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/", "/info/refs"}}},
	})
	// Match either prefix.
	for _, p := range []string{"/api/v1/projects", "/info/refs"} {
		if m := FirstMatch(rules, "GET", p); m == nil {
			t.Errorf("path %q should match", p)
		}
	}
	// Not a prefix of either.
	if m := FirstMatch(rules, "GET", "/admin/foo"); m != nil {
		t.Errorf("path /admin/foo should not match")
	}
}

func TestFirstMatch_PathRegex(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "versioned", Match: v1beta1.PathRuleMatch{PathRegex: `^/v\d+/`}},
	})
	if m := FirstMatch(rules, "GET", "/v1/projects"); m == nil {
		t.Errorf("/v1/projects should match /v\\d+/")
	}
	if m := FirstMatch(rules, "GET", "/v42/x"); m == nil {
		t.Errorf("/v42/x should match")
	}
	if m := FirstMatch(rules, "GET", "/vNaN/x"); m != nil {
		t.Errorf("/vNaN/x should NOT match (\\d only)")
	}
}

func TestFirstMatch_NoMatch_ReturnsNil(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "only-api", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/"}}},
	})
	if m := FirstMatch(rules, "GET", "/admin/"); m != nil {
		t.Errorf("no-match should return nil, got %v", m)
	}
}

func TestFirstMatch_EmptyRules_ReturnsNil(t *testing.T) {
	if m := FirstMatch(nil, "GET", "/anything"); m != nil {
		t.Errorf("empty rules should return nil")
	}
	if m := FirstMatch([]CompiledRule{}, "GET", "/anything"); m != nil {
		t.Errorf("empty rules should return nil")
	}
}

func TestFirstMatch_RejectedPath_ReturnsNil(t *testing.T) {
	rules, _ := CompileRules([]v1beta1.PathRule{
		{Name: "api", Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/api/"}}},
	})
	// %2F in path → normalization rejects → matcher returns nil so
	// caller can fail-closed.
	if m := FirstMatch(rules, "GET", "/api%2Fadmin"); m != nil {
		t.Errorf("%%2F path should fail normalization → nil match; got %v", m)
	}
}

// ---------------------------------------------------------------------
// Admission validation tests
// ---------------------------------------------------------------------

func TestCompileRule_RejectsEmptyName(t *testing.T) {
	_, err := CompileRules([]v1beta1.PathRule{
		{Name: "", Match: v1beta1.PathRuleMatch{Path: "/x"}},
	})
	if err == nil || !IsInvalidRule(err) {
		t.Errorf("empty name should reject as InvalidRule")
	}
}

func TestCompileRule_RejectsDuplicateName(t *testing.T) {
	_, err := CompileRules([]v1beta1.PathRule{
		{Name: "dup", Match: v1beta1.PathRuleMatch{Path: "/a"}},
		{Name: "dup", Match: v1beta1.PathRuleMatch{Path: "/b"}},
	})
	if err == nil || !IsInvalidRule(err) {
		t.Errorf("duplicate name should reject as InvalidRule")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate, got: %v", err)
	}
}

func TestCompileRule_RejectsZeroMatchKinds(t *testing.T) {
	_, err := CompileRule(&v1beta1.PathRule{
		Name:  "empty-match",
		Match: v1beta1.PathRuleMatch{}, // nothing set
	})
	if err == nil || !IsInvalidRule(err) {
		t.Errorf("zero match-kinds should reject")
	}
}

func TestCompileRule_RejectsMultipleMatchKinds(t *testing.T) {
	_, err := CompileRule(&v1beta1.PathRule{
		Name: "multi-match",
		Match: v1beta1.PathRuleMatch{
			Path:       "/a",
			PathPrefix: []string{"/b/"},
		},
	})
	if err == nil || !IsInvalidRule(err) {
		t.Errorf("multiple match-kinds should reject")
	}
}

func TestCompileRule_RejectsPercentInRule(t *testing.T) {
	// Rules are operator-authored literal strings — they MUST NOT
	// carry percent-encoding (otherwise rule and normalized request
	// path could mismatch).
	_, err := CompileRule(&v1beta1.PathRule{
		Name:  "encoded",
		Match: v1beta1.PathRuleMatch{Path: "/api%2Fadmin"},
	})
	if err == nil {
		t.Errorf("rule with %% should reject")
	}
}

func TestCompileRule_RejectsNoLeadingSlash(t *testing.T) {
	_, err := CompileRule(&v1beta1.PathRule{
		Name:  "no-slash",
		Match: v1beta1.PathRuleMatch{Path: "api/v1"},
	})
	if err == nil {
		t.Errorf("path without leading slash should reject")
	}
}

func TestCompileRule_RejectsEmptyPrefixEntry(t *testing.T) {
	_, err := CompileRule(&v1beta1.PathRule{
		Name:  "empty-prefix",
		Match: v1beta1.PathRuleMatch{PathPrefix: []string{"/ok/", ""}},
	})
	if err == nil {
		t.Errorf("empty pathPrefix entry should reject")
	}
}

func TestCompileRules_EmptyInput_NoError(t *testing.T) {
	c, err := CompileRules(nil)
	if err != nil {
		t.Errorf("empty rules: unexpected error: %v", err)
	}
	if c != nil {
		t.Errorf("empty rules: expected nil result, got %v", c)
	}
}
