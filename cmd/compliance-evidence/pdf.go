// SPDX-License-Identifier: AGPL-3.0-or-later

// pdf.go — Phase 8.d.3 overall PDF summary report.
//
// Renders a single PDF that aggregates every control evidence emitted
// for a (framework, window) tuple. Auditors get a single artifact
// reviewable without unpacking the JSON bundle; the JSON files remain
// the source of truth for tooling.
//
// Layout (single A4 page expandable to multiple if needed):
//
//	┌─────────────────────────────────────────────────────────┐
//	│ HexxLock Compliance Evidence                            │
//	│ Framework: nist-sp-800-207                              │
//	│ Window:    2026-04-01 → 2026-07-01                      │
//	│ Generated: 2026-06-09T08:42:11Z by talon compliance-    │
//	│            evidence vX.Y.Z                              │
//	├─────────────────────────────────────────────────────────┤
//	│ Summary                                                  │
//	│  Total controls evaluated:  7                            │
//	│  Satisfied:                 6                            │
//	│  Failing:                   1                            │
//	├─────────────────────────────────────────────────────────┤
//	│ Per-control results                                      │
//	│  ┌──────────┬─────────────────────────┬─────────────┐    │
//	│  │ control  │ title                    │ satisfied?  │    │
//	│  ├──────────┼─────────────────────────┼─────────────┤    │
//	│  │ tenet-1  │ ...                      │ YES         │    │
//	│  │ ...      │ ...                      │ ...         │    │
//	│  └──────────┴─────────────────────────┴─────────────┘    │
//	├─────────────────────────────────────────────────────────┤
//	│ Details (per failing control)                            │
//	│  control: tenet-6                                        │
//	│   notes: Per ADR 0041 §8.d: ratio >= 0.999 satisfies...   │
//	│   measurement: { evaluations_with_decision: 120345, ... } │
//	└─────────────────────────────────────────────────────────┘
//
// The PDF is deterministic — same inputs produce the same byte stream
// (modulo the "Generated" timestamp which is an audit-supplied field
// via the --pdf-generated-at flag, defaulting to now).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// pdfReport aggregates the per-control evidence for a single
// (framework, window) bundle and renders an overall PDF.
type pdfReport struct {
	Framework   string
	Window      windowSpec
	GeneratedAt time.Time
	Tool        string // e.g. "talon compliance-evidence v0.2.0"
	Evidence    []evidence
}

// writePDF writes a PDF summary report to w.
func writePDF(w io.Writer, r pdfReport) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// Title block
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(0, 10, "HexxLock Compliance Evidence", "", 1, "L", false, 0, "")
	pdf.Ln(1)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 5, fmt.Sprintf("Framework: %s", r.Framework), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("Window:    %s -> %s",
		r.Window.start.Format("2006-01-02"),
		r.Window.end.Format("2006-01-02"),
	), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("Generated: %s by %s",
		r.GeneratedAt.UTC().Format(time.RFC3339),
		r.Tool,
	), "", 1, "L", false, 0, "")

	pdf.Ln(4)
	hline(pdf)
	pdf.Ln(4)

	// Summary block
	total := len(r.Evidence)
	satisfied := 0
	for _, e := range r.Evidence {
		if e.Satisfied {
			satisfied++
		}
	}
	failing := total - satisfied

	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 7, "Summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 5, fmt.Sprintf("  Total controls evaluated:  %d", total), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("  Satisfied:                 %d", satisfied), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("  Failing:                   %d", failing), "", 1, "L", false, 0, "")

	pdf.Ln(4)
	hline(pdf)
	pdf.Ln(4)

	// Per-control table — control | title | satisfied
	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 7, "Per-control results", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(230, 230, 230)
	pdf.CellFormat(35, 7, "Control", "1", 0, "L", true, 0, "")
	pdf.CellFormat(120, 7, "Title", "1", 0, "L", true, 0, "")
	pdf.CellFormat(25, 7, "Satisfied", "1", 1, "C", true, 0, "")
	pdf.SetFont("Helvetica", "", 9)

	// Stable ordering (the bundle is already in framework-defined order,
	// but render deterministically by sorting by control id as a guard
	// against future shuffling).
	sorted := make([]evidence, len(r.Evidence))
	copy(sorted, r.Evidence)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Control < sorted[j].Control
	})
	for _, e := range sorted {
		yn := "NO"
		if e.Satisfied {
			yn = "YES"
		}
		pdf.CellFormat(35, 6, truncate(e.Control, 22), "1", 0, "L", false, 0, "")
		pdf.CellFormat(120, 6, truncate(e.Title, 75), "1", 0, "L", false, 0, "")
		pdf.CellFormat(25, 6, yn, "1", 1, "C", false, 0, "")
	}

	pdf.Ln(4)

	// Detail block — only failing controls get the long form, to keep
	// the summary PDF compact for clean runs.
	if failing > 0 {
		hline(pdf)
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 7, "Details (failing controls)", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		for _, e := range sorted {
			if e.Satisfied {
				continue
			}
			pdf.SetFont("Helvetica", "B", 10)
			pdf.CellFormat(0, 6, fmt.Sprintf("control: %s — %s", e.Control, e.Title), "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 9)
			if e.Notes != "" {
				pdf.MultiCell(0, 5, "notes: "+e.Notes, "", "L", false)
			}
			// Pretty-print measurement map.
			if len(e.Measurement) > 0 {
				blob, err := json.MarshalIndent(e.Measurement, "  ", "  ")
				if err == nil {
					pdf.MultiCell(0, 5, "measurement:\n  "+string(blob), "", "L", false)
				}
			}
			pdf.Ln(2)
		}
	}

	return pdf.Output(w)
}

// hline draws a thin horizontal rule across the current writable width.
func hline(pdf *gofpdf.Fpdf) {
	x := pdf.GetX()
	y := pdf.GetY()
	w, _ := pdf.GetPageSize()
	left, _, right, _ := pdf.GetMargins()
	pdf.SetDrawColor(180, 180, 180)
	pdf.Line(left, y, w-right, y)
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetXY(x, y)
}

// truncate returns s clipped to n runes with a trailing ellipsis if
// truncation occurred. n includes the ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return strings.Repeat(".", n)
	}
	return s[:n-1] + "…"
}
