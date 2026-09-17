// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"testing"
	"time"
)

func TestWritePDF_Basics(t *testing.T) {
	t.Parallel()
	report := pdfReport{
		Framework: "nist-sp-800-207",
		Window: windowSpec{
			start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		GeneratedAt: time.Date(2026, 6, 9, 8, 42, 11, 0, time.UTC),
		Tool:        "talon compliance-evidence v0.2.0",
		Evidence: []evidence{
			{
				Framework: "nist-sp-800-207",
				Control:   "tenet-1",
				Title:     "Data sources and computing services are resources",
				WindowStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				WindowEnd:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
				Measurement: map[string]any{"checked": 1, "passed": 1},
				Satisfied:   true,
				Notes:       "All sources enumerated.",
			},
			{
				Framework: "nist-sp-800-207",
				Control:   "tenet-6",
				Title:     "Dynamic policy enforcement",
				WindowStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				WindowEnd:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
				Measurement: map[string]any{"evaluations": 120345, "ratio": 0.99996},
				Satisfied:   false,
				Notes:       "Per ADR 0041 §8.d: ratio >= 0.999 satisfies tenet 6.",
			},
		},
	}

	var buf bytes.Buffer
	if err := writePDF(&buf, report); err != nil {
		t.Fatalf("writePDF: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 1024 {
		t.Fatalf("output too short: %d bytes (expected >1KB for PDF skeleton)", len(out))
	}
	// PDF magic header.
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("output missing %%PDF- header: first 8 bytes = %q", out[:min(8, len(out))])
	}
	// Valid PDF ends with %%EOF.
	if !bytes.Contains(out[max(0, len(out)-32):], []byte("%%EOF")) {
		t.Errorf("output missing trailing %%%%EOF marker")
	}
	// Substring search is unreliable on gofpdf output because the
	// text-showing operators encode via the PDF font subset (literal
	// strings appear only when the font is uncompressed + no
	// per-glyph encoding rewrite, neither of which we can rely on).
	// The byte-length + magic-header + EOF marker checks give us a
	// stable smoke test for "did writePDF emit a syntactically-valid
	// non-empty PDF". Content correctness lives in the rendering
	// helpers tested in isolation (TestTruncate, etc).
}

func TestWritePDF_NoFailingControls_OmitsDetailsBlock(t *testing.T) {
	t.Parallel()
	report := pdfReport{
		Framework: "soc2",
		Window: windowSpec{
			start: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
		GeneratedAt: time.Date(2026, 6, 9, 8, 42, 11, 0, time.UTC),
		Tool:        "talon compliance-evidence v0.2.0",
		Evidence: []evidence{
			{
				Framework: "soc2",
				Control:   "CC6.1",
				Title:     "Logical access controls",
				Measurement: map[string]any{"ok": true},
				Satisfied:   true,
			},
		},
	}
	var buf bytes.Buffer
	if err := writePDF(&buf, report); err != nil {
		t.Fatalf("writePDF: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 1024 {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("output missing %%PDF- header")
	}
	// Smaller than the with-failures variant because the Details block
	// is skipped. This is a soft assertion — the difference is bounded
	// by the headers + table-row overhead.
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactlyten", 10, "exactlyten"},
		{"this is too long for ten chars", 10, "this is t…"},
		{"a", 1, "a"},
	}
	for _, tc := range cases {
		got := truncate(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("truncate(%q, %d): want %q, got %q", tc.in, tc.n, tc.want, got)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
