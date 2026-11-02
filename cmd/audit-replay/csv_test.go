// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func csvRec(ts string, opts ...func(*auditRecord)) auditRecord {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	r := auditRecord{
		Seq:          42,
		PrevHash:     "phABC",
		Hash:         "hDEF",
		Event:        "access_denied",
		Timestamp:    t,
		Sub:          "01H_USER",
		Email:        "alice@example.com",
		TenantID:     "tenant-foo",
		Route:        "argocd.internal.example.com",
		Method:       "GET",
		Path:         "/api/v1/projects",
		Decision:     "deny",
		Reason:       "ztna: tier=TIER_BYOD",
		SrcIP:        "10.0.50.5",
		SessionID:    "sess-1",
		Permission:   "argocd.application.get",
		Issuer:       "https://id.example.com",
		DecisionID:   "dec-7",
		SSOChainID:   "ssoc-9",
		TalonVersion: "v1.42.0",
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func TestCSVWriter_HeaderAndRowAlignment(t *testing.T) {
	var buf bytes.Buffer
	w := newCSVWriter(&buf)
	if err := w.write(csvRec("2026-06-07T10:00:01Z")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Parse the CSV back; the round-trip MUST succeed under
	// encoding/csv's RFC 4180 reader.
	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv read-back: %v", err)
	}
	if got, want := len(rows), 2; got != want {
		t.Fatalf("expected 2 rows (1 header + 1 data); got %d", got)
	}
	if got, want := len(rows[0]), 20; got != want {
		t.Fatalf("header width drift: got %d cols, want %d", got, want)
	}
	if got, want := len(rows[1]), 20; got != want {
		t.Fatalf("row width drift: got %d cols, want %d", got, want)
	}
	if rows[0][0] != "timestamp_utc" {
		t.Fatalf("first header column must be timestamp_utc (the auditor's sort key); got %q", rows[0][0])
	}
	if rows[1][1] != "sess-1" {
		t.Fatalf("session_id must be in column 2; got %q", rows[1][1])
	}
}

func TestCSVWriter_QuotesCommasAndNewlines(t *testing.T) {
	// Reason field with adversarial content — commas, embedded quotes,
	// and a newline. The CSV writer MUST quote + escape these per
	// RFC 4180 so the round-trip through Excel / encoding/csv is lossless.
	r := csvRec("2026-06-07T10:00:01Z", func(r *auditRecord) {
		r.Reason = `ztna: tier="TIER_BYOD", route requires "TIER_CORP"
(from baseline.rego)`
		r.Path = `/api/v1/projects?filter="default"`
	})
	var buf bytes.Buffer
	w := newCSVWriter(&buf)
	if err := w.write(r); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	rdr := csv.NewReader(&buf)
	rows, err := rdr.ReadAll()
	if err != nil {
		t.Fatalf("csv read-back failed (likely quoting bug): %v", err)
	}
	if got, want := len(rows), 2; got != want {
		t.Fatalf("expected 2 rows; got %d", got)
	}
	// Round-trip equality: reason and path must round-trip exactly.
	if rows[1][7] != r.Reason {
		t.Fatalf("Reason round-trip drift:\n got %q\nwant %q", rows[1][7], r.Reason)
	}
	if rows[1][11] != r.Path {
		t.Fatalf("Path round-trip drift:\n got %q\nwant %q", rows[1][11], r.Path)
	}
}

func TestCSVWriter_EmptyFilterEmitsHeadersOnly(t *testing.T) {
	// Auditors prefer "empty table with headers" over "empty file".
	// newCSVWriter writes the header eagerly so a run that matches
	// zero records still produces a parseable artifact.
	var buf bytes.Buffer
	w := newCSVWriter(&buf)
	if err := w.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "timestamp_utc,session_id,subject,") {
		t.Fatalf("eager header missing; got %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("expected exactly one (header) line; got %d newlines: %q", strings.Count(out, "\n"), out)
	}
}

func TestCSVWriter_TimestampNanoFormat(t *testing.T) {
	// The CSV timestamp column uses RFC 3339 nano precision so
	// sort-by-time in Excel / pandas / numbers preserves sub-second
	// ordering when multiple records share a millisecond window.
	r := csvRec("2026-06-07T10:00:01.123456789Z")
	var buf bytes.Buffer
	w := newCSVWriter(&buf)
	_ = w.write(r)
	_ = w.flush()

	rdr := csv.NewReader(&buf)
	rows, _ := rdr.ReadAll()
	got := rows[1][0]
	want := "2026-06-07T10:00:01.123456789Z"
	if got != want {
		t.Fatalf("timestamp format drift: got %q, want %q", got, want)
	}
}
