// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmbeddedSchema_Loads(t *testing.T) {
	v, err := newSchemaValidator("", false)
	if err != nil {
		t.Fatalf("embedded schema should load: %v", err)
	}
	if v.schema == nil {
		t.Fatal("schema is nil")
	}
}

func TestSchemaValidator_ValidRecord(t *testing.T) {
	v, err := newSchemaValidator("", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cases := []string{
		// minimal: just ts
		`{"ts":"2026-06-07T10:00:00Z"}`,
		// full
		`{"ts":"2026-06-07T10:00:00.123456789Z","seq":42,"prev_hash":"abc","hash":"def","event":"access_granted","sub":"01H","email":"a@b","tenant_id":"t1","route":"argocd.internal.example.com","method":"GET","path":"/","decision":"allow","reason":"ok","src_ip":"10.0.0.1","session_id":"s1","permission":"argocd.app.get","iss":"https://id.example.com","decision_id":"d1","sso_chain_id":"sso1","talon_version":"v1.0.0"}`,
		// additionalProperties: true — tolerates unknown fields
		`{"ts":"2026-06-07T10:00:00Z","custom_field":"value"}`,
	}
	for i, line := range cases {
		violation, decodeErr := v.validate([]byte(line))
		if decodeErr != nil {
			t.Errorf("case[%d] decode err: %v", i, decodeErr)
		}
		if violation != nil {
			t.Errorf("case[%d] should be valid but got: %v", i, violation)
		}
	}
}

func TestSchemaValidator_InvalidRecord(t *testing.T) {
	v, err := newSchemaValidator("", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cases := []struct {
		name string
		line string
		// substring expected to appear in the violation message
		expect string
	}{
		{
			name:   "missing required ts",
			line:   `{"event":"access_granted"}`,
			expect: "ts",
		},
		{
			name:   "wrong type seq (string not int)",
			line:   `{"ts":"2026-06-07T10:00:00Z","seq":"not_a_number"}`,
			expect: "seq",
		},
		{
			name:   "unknown HTTP method",
			line:   `{"ts":"2026-06-07T10:00:00Z","method":"BREW"}`,
			expect: "method",
		},
		{
			name:   "unknown decision",
			line:   `{"ts":"2026-06-07T10:00:00Z","decision":"shrug"}`,
			expect: "decision",
		},
		{
			name:   "hash field invalid pattern (non-hex)",
			line:   `{"ts":"2026-06-07T10:00:00Z","hash":"NOT-HEX!!!"}`,
			expect: "hash",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			violation, decodeErr := v.validate([]byte(c.line))
			if decodeErr != nil {
				t.Fatalf("decode err: %v", decodeErr)
			}
			if violation == nil {
				t.Fatalf("should be invalid but accepted")
			}
			if !strings.Contains(violation.Error(), c.expect) {
				t.Logf("violation: %v", violation)
				t.Errorf("expected substring %q in violation message", c.expect)
			}
		})
	}
}

func TestSchemaValidator_ReportFormat(t *testing.T) {
	v, err := newSchemaValidator("", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Inject violations
	_, _ = v.validate([]byte(`{"event":"missing_ts"}`))
	_, _ = v.validate([]byte(`{"event":"missing_ts_again"}`))

	var buf bytes.Buffer
	v.report(&buf)
	out := buf.String()
	if !strings.Contains(out, "2 violations") {
		t.Errorf("expected '2 violations' in report; got %q", out)
	}
}

func TestSchemaValidator_ZeroViolationsReport(t *testing.T) {
	v, err := newSchemaValidator("", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var buf bytes.Buffer
	v.report(&buf)
	out := buf.String()
	if !strings.Contains(out, "0 violations") {
		t.Errorf("expected '0 violations'; got %q", out)
	}
}

func TestNilSchemaValidator_IsNoOp(t *testing.T) {
	var v *schemaValidator
	violation, decodeErr := v.validate([]byte("anything"))
	if violation != nil || decodeErr != nil {
		t.Errorf("nil validator should no-op; got violation=%v decodeErr=%v", violation, decodeErr)
	}
	var buf bytes.Buffer
	v.report(&buf)
	if buf.String() != "" {
		t.Errorf("nil validator report() should no-op; got %q", buf.String())
	}
}
