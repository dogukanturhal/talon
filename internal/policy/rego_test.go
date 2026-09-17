// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"strings"
	"testing"
)

func sampleInput() *RegoInput {
	return &RegoInput{
		User: RegoInputUser{
			Sub:      "user-uuid",
			Email:    "alice@example.com",
			Groups:   []string{"platform-admin"},
			Roles:    []string{"platform_admin"},
			TenantID: "00000000-0000-0000-0000-000000000002",
			AMR:      []string{"pwd", "mfa"},
		},
		Route: RegoInputRoute{
			Host:       "internal.example.com",
			Permission: "admin",
		},
		Request: RegoInputRequest{
			Method: "GET",
			Path:   "/v1/sys/health",
			SrcIP:  "10.0.50.5",
		},
	}
}

// TestRego_NilEvaluatorAllows — the no-policy path must collapse to
// allow. Callers composing Rego as a narrowing step treat nil as a
// no-op so the existing role + SpiceDB allow stands.
func TestRego_NilEvaluatorAllows(t *testing.T) {
	t.Parallel()
	var e *RegoEvaluator
	ok, err := e.Evaluate(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("nil eval: %v", err)
	}
	if !ok {
		t.Fatal("nil evaluator must allow")
	}
}

// TestRego_EmptyModuleString — empty string → nil evaluator (caller
// treats as no-op). The route reconciler relies on this so a TalonRoute
// without spec.policyRego doesn't pay the OPA setup cost.
func TestRego_EmptyModuleString(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), "")
	if err != nil {
		t.Fatalf("compile empty: %v", err)
	}
	if e != nil {
		t.Fatal("empty module must return nil evaluator")
	}
}

// TestRego_DefaultAllow — module that only declares the default returns
// allow=true. The "no narrowing" baseline.
func TestRego_DefaultAllow(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), `package talon.route

default allow := true
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := e.Evaluate(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !ok {
		t.Fatal("default allow must be true")
	}
}

// TestRego_NarrowingDenyByTenant — operator denies on tenant_id mismatch.
// Asserts the mid-stream evaluation correctly reads input.user.tenant_id
// and flips allow to false.
func TestRego_NarrowingDenyByTenant(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), `package talon.route

default allow := true

allow := false if {
    input.user.tenant_id != "00000000-0000-0000-0000-000000000002"
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Matching tenant — allow.
	in := sampleInput()
	ok, err := e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval matching: %v", err)
	}
	if !ok {
		t.Fatal("matching tenant must allow")
	}

	// Mismatching tenant — deny.
	in.User.TenantID = "wrong-tenant"
	ok, err = e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval mismatching: %v", err)
	}
	if ok {
		t.Fatal("mismatching tenant must deny")
	}
}

// TestRego_NarrowingByRequestPath — operator denies write methods on
// vault. Validates input.request.method is reachable from rules.
func TestRego_NarrowingByRequestPath(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), `package talon.route

default allow := true

# Vault destructive operations require a stronger AMR than vanilla mfa.
write_methods := {"POST", "PUT", "PATCH", "DELETE"}

allow := false if {
    input.route.host == "internal.example.com"
    input.request.method == m
    write_methods[m]
    not "webauthn" in input.user.amr
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	in := sampleInput()
	in.Request.Method = "POST"
	// AMR has [pwd, mfa] only; no webauthn → deny.
	ok, err := e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval POST/no-webauthn: %v", err)
	}
	if ok {
		t.Fatal("vault POST without webauthn must deny")
	}

	// With webauthn AMR — allow.
	in.User.AMR = []string{"pwd", "webauthn"}
	ok, err = e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval POST/webauthn: %v", err)
	}
	if !ok {
		t.Fatal("vault POST with webauthn must allow")
	}

	// GET is fine regardless.
	in.Request.Method = "GET"
	in.User.AMR = []string{"pwd"}
	ok, err = e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval GET: %v", err)
	}
	if !ok {
		t.Fatal("vault GET must allow regardless of AMR")
	}
}

// TestRego_CompileError — operator's syntactically broken module surfaces
// at compile time so the reconciler can mark the TalonRoute as
// invalid. Runtime requests don't pay this cost on every eval.
func TestRego_CompileError(t *testing.T) {
	t.Parallel()
	_, err := CompileRego(context.Background(), `package talon.route

# missing := operator
default allow true
`)
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "compile") && !strings.Contains(err.Error(), "rego") {
		t.Fatalf("error should mention rego/compile: %v", err)
	}
}

// TestRego_NonBoolAllow — if the operator's module sets allow to a
// non-bool, surface a clear error. Better than silently coercing.
func TestRego_NonBoolAllow(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), `package talon.route

default allow := "yes"
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	_, err = e.Evaluate(context.Background(), sampleInput())
	if err == nil {
		t.Fatal("expected error for non-bool allow")
	}
	if !strings.Contains(err.Error(), "bool") {
		t.Fatalf("error should mention bool requirement: %v", err)
	}
}

// TestRego_PostureInputAvailable — confirms operators can write
// policies that key on the X-Talon-Posture decoded claims via the
// new RegoInput.Posture field. The router populates this field after
// internal/posture.Verify succeeds; nil-Posture remains a valid input
// shape so policies that don't use posture continue to work.
func TestRego_PostureInputAvailable(t *testing.T) {
	t.Parallel()
	module := `package talon.route

default allow := true
allow if {
    input.posture.compliance.disk_encrypted == true
    input.posture.compliance.os == "macos"
}
`
	e, err := CompileRego(context.Background(), module)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Compliant device — allow.
	in := sampleInput()
	in.Posture = &RegoInputPosture{
		Issuer:  "https://posture.test",
		Subject: "device:abc",
		Compliance: map[string]any{
			"disk_encrypted": true,
			"os":             "macos",
		},
	}
	ok, err := e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval compliant: %v", err)
	}
	if !ok {
		t.Errorf("compliant macos device should be allowed")
	}

	// Non-compliant device (windows) — falls back to default allow=true
	// because we wrote `default allow := true` AND no additional `allow`
	// rule fired. To assert deny, the operator writes
	// `default allow := false`; this test verifies the input shape
	// reaches the evaluator, not the policy semantics.
	in.Posture.Compliance["os"] = "windows"
	ok, err = e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval non-compliant: %v", err)
	}
	if !ok {
		t.Errorf("windows device with default=true should still be allowed by default")
	}

	// Posture-deny semantics — `default allow := false`.
	denyModule := `package talon.route

default allow := false
allow if {
    input.posture.compliance.disk_encrypted == true
    input.posture.compliance.os == "macos"
}
`
	e2, err := CompileRego(context.Background(), denyModule)
	if err != nil {
		t.Fatalf("compile deny: %v", err)
	}
	in.Posture.Compliance["os"] = "windows"
	ok, err = e2.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("eval deny: %v", err)
	}
	if ok {
		t.Errorf("windows device with default=false should be denied")
	}
}

// TestRego_NoAllowDeclared — module that doesn't bind data.talon.route.allow
// (e.g. operator forgot the declaration). Eval treats unbound result as
// "no narrowing" → true. Operators wanting hard-deny-by-default declare
// `default allow := false` explicitly.
func TestRego_NoAllowDeclared(t *testing.T) {
	t.Parallel()
	e, err := CompileRego(context.Background(), `package talon.route

# operator wrote a deny rule but forgot the default
deny_for_carol if {
    input.user.email == "carol@example.com"
}
`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := e.Evaluate(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !ok {
		t.Fatal("module without allow declared must default to allow=true")
	}
}
