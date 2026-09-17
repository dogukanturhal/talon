// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

// csvWriter wraps stdlib encoding/csv to emit audit records in a
// flat tabular form suitable for spreadsheet review + downstream
// compliance-evidence reporting. Used by the `--output csv` mode
// (Phase 8.c.4 close-out per ADR 0041 §8.c).
//
// Why CSV rather than something richer (Parquet, JSONL): the
// auditor audience already has Excel / Numbers / Google Sheets
// open. CSV imports without extra tooling and round-trips through
// the existing 7-year WORM retention contract as a plain-text
// artifact. The richer-format tradeoff isn't worth it for the
// human-driven workflow this CLI serves.
//
// Column choice rationale: the columns mirror the auditor's
// canonical "who / when / what / where / why" frame. Order is
// stable across releases — downstream spreadsheet templates rely
// on positional column indices, so reordering is a breaking
// change. New columns get APPENDED, never inserted.
//
// Encoding: stdlib encoding/csv handles all quoting + escaping
// per RFC 4180. Cells containing commas, quotes, or newlines are
// double-quoted; embedded quotes are doubled. Auditor tools all
// follow RFC 4180; cross-tool compatibility is the goal.
type csvWriter struct {
	w       *csv.Writer
	headers []string
}

// newCSVWriter constructs a CSV emitter writing to w and writes the
// header row eagerly. The eager-write ensures the file is parseable
// even when no records match the filter (auditors prefer "empty
// table with headers" over "empty file").
func newCSVWriter(w io.Writer) *csvWriter {
	c := &csvWriter{
		w: csv.NewWriter(w),
		// Stable column order — see file header rationale. New
		// columns ONLY at the end of this slice.
		headers: []string{
			// Identity
			"timestamp_utc", "session_id", "subject", "email", "tenant_id",
			// Decision
			"event", "decision", "reason", "permission",
			// Surface
			"route", "method", "path", "src_ip",
			// Chain (forensics)
			"seq", "hash", "prev_hash",
			// Provenance
			"iss", "decision_id", "sso_chain_id", "talon_version",
		},
	}
	_ = c.w.Write(c.headers)
	return c
}

// write emits one audit record as a CSV row. The row column order
// MUST match the header order exactly; this is enforced by the
// inline expansion below — if you add a column to headers, add the
// matching field here.
func (c *csvWriter) write(r auditRecord) error {
	row := []string{
		r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		r.SessionID,
		r.Sub,
		r.Email,
		r.TenantID,
		r.Event,
		r.Decision,
		r.Reason,
		r.Permission,
		r.Route,
		r.Method,
		r.Path,
		r.SrcIP,
		strconv.FormatInt(r.Seq, 10),
		r.Hash,
		r.PrevHash,
		r.Issuer,
		r.DecisionID,
		r.SSOChainID,
		r.TalonVersion,
	}
	if len(row) != len(c.headers) {
		// Defensive: catches the "added a header but forgot the
		// matching row field" class of bug at runtime rather than
		// silently emitting a mis-aligned CSV.
		return fmt.Errorf("csv writer: row width %d != header width %d (header drift)", len(row), len(c.headers))
	}
	return c.w.Write(row)
}

// flush writes any buffered CSV rows + returns the underlying
// writer error. MUST be called before main exits; the bufio
// chain in main.go already defers an Out.Flush so as long as
// csvWriter is on top of that bufio.Writer the chain works.
func (c *csvWriter) flush() error {
	c.w.Flush()
	return c.w.Error()
}
