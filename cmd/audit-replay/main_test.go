// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMatch_TimeBounds(t *testing.T) {
	rec := auditRecord{Timestamp: time.Date(2026, 6, 6, 17, 0, 0, 0, time.UTC)}
	cases := []struct {
		name string
		f    filters
		want bool
	}{
		{"no bounds", filters{}, true},
		{"after since", filters{since: time.Date(2026, 6, 6, 16, 0, 0, 0, time.UTC)}, true},
		{"before since", filters{since: time.Date(2026, 6, 6, 18, 0, 0, 0, time.UTC)}, false},
		{"before until", filters{until: time.Date(2026, 6, 6, 18, 0, 0, 0, time.UTC)}, true},
		{"after until", filters{until: time.Date(2026, 6, 6, 16, 0, 0, 0, time.UTC)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := match(rec, tc.f); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatch_Subject(t *testing.T) {
	rec := auditRecord{
		Timestamp: time.Now(),
		Sub:       "01HZZ1",
		Email:     "ops@example.com",
	}
	cases := []struct {
		name    string
		subject string
		want    bool
	}{
		{"bare sub", "01HZZ1", true},
		{"user_sub prefix", "user_sub=01HZZ1", true},
		{"sub prefix", "sub=01HZZ1", true},
		{"email match", "ops@example.com", true},
		{"email prefix", "email=ops@example.com", true},
		{"mismatch", "01XYZ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filters{subject: tc.subject}
			if got := match(rec, f); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatch_RouteSubstring(t *testing.T) {
	rec := auditRecord{Timestamp: time.Now(), Route: "vault.internal.example.com"}
	if !match(rec, filters{route: "vault.internal"}) {
		t.Error("vault.internal should match")
	}
	if match(rec, filters{route: "grafana"}) {
		t.Error("grafana should not match")
	}
}

func TestDenyStats_TopReasons(t *testing.T) {
	ds := newDenyStats()
	for i := 0; i < 5; i++ {
		ds.observe(auditRecord{Decision: "deny", Reason: "ztna: posture stale"})
	}
	for i := 0; i < 2; i++ {
		ds.observe(auditRecord{Decision: "deny", Reason: "ztna: AAL3 required"})
	}
	ds.observe(auditRecord{Decision: "allow"})
	ds.observe(auditRecord{Decision: "allow"})

	var buf bytes.Buffer
	ds.report(&buf, 5)
	s := buf.String()
	// allow count
	if !strings.Contains(s, "allow        2") {
		t.Errorf("missing allow count: %s", s)
	}
	if !strings.Contains(s, "deny         7") {
		t.Errorf("missing deny count: %s", s)
	}
	// top reason
	if !strings.Contains(s, "5  ztna: posture stale") {
		t.Errorf("missing top reason: %s", s)
	}
}

func TestGapTracker_NoGap(t *testing.T) {
	g := newGapTracker()
	for i := int64(1); i <= 5; i++ {
		g.observe(i)
	}
	var buf bytes.Buffer
	g.report(&buf)
	if !strings.Contains(buf.String(), "no gaps detected") {
		t.Errorf("expected no gaps: %s", buf.String())
	}
}

func TestGapTracker_GapDetected(t *testing.T) {
	g := newGapTracker()
	g.observe(1)
	g.observe(2)
	g.observe(5) // gap of 2 (3, 4 missing)
	g.observe(6)

	var buf bytes.Buffer
	g.report(&buf)
	s := buf.String()
	if !strings.Contains(s, "gap: 2 → 5 (2 missing)") {
		t.Errorf("expected gap report: %s", s)
	}
}

func TestStreamFile_SkipMalformedNonStrict(t *testing.T) {
	input := `{"ts":"2026-06-06T17:00:00Z","sub":"01H","decision":"allow"}
not-json
{"ts":"2026-06-06T17:01:00Z","sub":"01H","decision":"deny","reason":"foo"}
`
	collected := []auditRecord{}
	cb := func(line []byte, rec auditRecord) {
		collected = append(collected, rec)
	}
	tf := func(t *testing.T) {
		// pipe via strings.NewReader by writing temp file
		f, err := writeTemp(t, input)
		if err != nil {
			t.Fatal(err)
		}
		err = streamFile(f, false, cb)
		if err != nil {
			t.Fatalf("non-strict should not error on malformed: %v", err)
		}
	}
	tf(t)
	if len(collected) != 2 {
		t.Errorf("got %d valid records, want 2", len(collected))
	}
}

// writeTemp lays input down in a tempfile + returns the path.
func writeTemp(t *testing.T, s string) (string, error) {
	t.Helper()
	d := t.TempDir()
	p := d + "/in.ndjson"
	return p, os.WriteFile(p, []byte(s), 0o600)
}
