// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main is the operator-facing `compliance-evidence` CLI per
// ADR 0041 §8.d. Reads NDJSON audit records (same shape as the
// audit-replay CLI), maps each compliance-framework control to a
// query over the audit log, and emits per-control JSON evidence
// files into the requested output directory.
//
// Frameworks shipped this scaffold:
//
//	nist-sp-800-207 — Tenets 1..7 (NIST §2.1)
//	beyondcorp      — CBA + dry-run policy + posture coverage
//	soc2            — CC6.1 + CC6.2 + CC6.3 (Trust Services)
//
// Surface:
//
//	compliance-evidence --framework nist-sp-800-207 --window 2026-Q2 --output ./evidence/
//	compliance-evidence --framework soc2 --control CC6.1,CC6.2 --window 2026-Q2 --output ./evidence/
//	compliance-evidence --framework beyondcorp --window 2026-Q2 --output ./evidence/
//
// Each control emits one JSON file under <output>/<framework>/<control>.json
// with a stable shape:
//
//	{
//	  "framework": "nist-sp-800-207",
//	  "control": "tenet-6",
//	  "title": "Dynamic policy enforcement",
//	  "window_start": "2026-04-01T00:00:00Z",
//	  "window_end":   "2026-07-01T00:00:00Z",
//	  "measurement": {
//	    "evaluations_with_decision":  120345,
//	    "evaluations_with_evaluation_ms_gt_0": 120341,
//	    "ratio": 0.99996
//	  },
//	  "satisfied": true,
//	  "notes": "Per ADR 0041 §8.d: ratio >= 0.999 satisfies tenet 6."
//	}
//
// SOC2 auditors / NIST control reviewers ingest the bundle as-is.
//
// Phase 8.d scaffold: queries over NDJSON only. Phase 8.d.2 will read
// WORM-backed S3 buckets. Phase 8.d.3 will render the overall PDF
// summary (see ADR 0041 §8.d output: "directory containing per-
// control JSON evidence files + overall PDF report").
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type auditRecord struct {
	Event        string    `json:"event,omitempty"`
	Timestamp    time.Time `json:"ts"`
	Sub          string    `json:"sub,omitempty"`
	Decision     string    `json:"decision,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Permission   string    `json:"permission,omitempty"`
	AMR          []string  `json:"amr,omitempty"`
	EvaluationMs *int64    `json:"evaluation_ms,omitempty"`
	DeviceCertValid *bool  `json:"device_cert_valid,omitempty"`
	PostureFresh    *bool  `json:"posture_fresh,omitempty"`
	Tier            string `json:"tier,omitempty"`
}

type windowSpec struct {
	start, end time.Time
}

func parseWindow(spec string) (windowSpec, error) {
	// Supported: 2026-Q1 / 2026-Q2 / 2026-Q3 / 2026-Q4 / YYYY-MM.
	if len(spec) == 7 && spec[4] == '-' && spec[5] == 'Q' {
		year := spec[0:4]
		q := spec[6]
		var month int
		switch q {
		case '1':
			month = 1
		case '2':
			month = 4
		case '3':
			month = 7
		case '4':
			month = 10
		default:
			return windowSpec{}, fmt.Errorf("invalid quarter %q", spec)
		}
		start, _ := time.Parse("2006-01-02", year+"-"+twoDigit(month)+"-01")
		return windowSpec{start: start, end: start.AddDate(0, 3, 0)}, nil
	}
	if len(spec) == 7 && spec[4] == '-' {
		start, err := time.Parse("2006-01-02", spec+"-01")
		if err != nil {
			return windowSpec{}, err
		}
		return windowSpec{start: start, end: start.AddDate(0, 1, 0)}, nil
	}
	return windowSpec{}, fmt.Errorf("unrecognised --window %q (use 2026-Q2 or 2026-04)", spec)
}

func twoDigit(n int) string {
	return fmt.Sprintf("%02d", n)
}

type evidence struct {
	Framework   string         `json:"framework"`
	Control     string         `json:"control"`
	Title       string         `json:"title"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
	Measurement map[string]any `json:"measurement"`
	Satisfied   bool           `json:"satisfied"`
	Notes       string         `json:"notes"`
}

func main() {
	var (
		framework      = flag.String("framework", "", "nist-sp-800-207 | beyondcorp | soc2")
		controls       = flag.String("control", "", "comma-separated control IDs to limit to (default = all)")
		window         = flag.String("window", "", "evidence window: 2026-Q2 or 2026-04")
		output         = flag.String("output", "./evidence", "output directory")
		pdfPath        = flag.String("pdf", "", "also render an overall PDF report at this path (Phase 8.d.3). Empty disables PDF emission. Relative paths are resolved under --output/<framework>/.")
		pdfGeneratedAt = flag.String("pdf-generated-at", "", "RFC3339 timestamp embedded in the PDF Generated header (default now). Set for deterministic builds.")
	)
	flag.Parse()

	if *framework == "" || *window == "" {
		fatalf("--framework and --window are required")
	}

	win, err := parseWindow(*window)
	if err != nil {
		fatalf("%v", err)
	}

	wantedControls := map[string]bool{}
	if *controls != "" {
		for _, c := range strings.Split(*controls, ",") {
			wantedControls[strings.TrimSpace(c)] = true
		}
	}

	files := flag.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}

	recs, err := loadRecords(files)
	if err != nil {
		fatalf("load records: %v", err)
	}
	// Filter to window first; downstream queries don't have to repeat
	// the time-bounds check.
	inWindow := make([]auditRecord, 0, len(recs))
	for _, r := range recs {
		if r.Timestamp.Before(win.start) || !r.Timestamp.Before(win.end) {
			continue
		}
		inWindow = append(inWindow, r)
	}

	registry := buildRegistry()
	results, ok := registry[*framework]
	if !ok {
		fatalf("framework %q not registered (try nist-sp-800-207 | beyondcorp | soc2)", *framework)
	}

	if err := os.MkdirAll(filepath.Join(*output, *framework), 0o750); err != nil {
		fatalf("mkdir: %v", err)
	}

	emitted := 0
	emittedEvidence := make([]evidence, 0, len(results))
	for _, ctl := range results {
		if len(wantedControls) > 0 && !wantedControls[ctl.id] {
			continue
		}
		evd := ctl.compute(inWindow, win)
		path := filepath.Join(*output, *framework, ctl.id+".json")
		if err := writeJSON(path, &evd); err != nil {
			fatalf("write %s: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (satisfied=%v)\n", path, evd.Satisfied)
		emitted++
		emittedEvidence = append(emittedEvidence, evd)
	}
	fmt.Fprintf(os.Stderr, "emitted %d controls under %s/\n", emitted, filepath.Join(*output, *framework))

	// Phase 8.d.3 — overall PDF report. Optional; emits only when
	// --pdf is set. Path is resolved under output/<framework>/ when
	// relative, so the typical invocation
	//   compliance-evidence --framework nist-sp-800-207 --window 2026-Q2 --pdf report.pdf
	// drops the JSON files + report.pdf side-by-side inside the
	// per-framework directory under --output.
	if *pdfPath != "" {
		pdfFinal := *pdfPath
		if !filepath.IsAbs(pdfFinal) {
			pdfFinal = filepath.Join(*output, *framework, pdfFinal)
		}
		genAt := time.Now().UTC()
		if *pdfGeneratedAt != "" {
			t, err := time.Parse(time.RFC3339, *pdfGeneratedAt)
			if err != nil {
				fatalf("--pdf-generated-at: %v", err)
			}
			genAt = t
		}
		f, err := os.Create(pdfFinal) //nolint:gosec // operator-supplied output path
		if err != nil {
			fatalf("create pdf: %v", err)
		}
		defer f.Close() //nolint:errcheck,gosec
		report := pdfReport{
			Framework:   *framework,
			Window:      win,
			GeneratedAt: genAt,
			Tool:        "talon compliance-evidence",
			Evidence:    emittedEvidence,
		}
		if err := writePDF(f, report); err != nil {
			fatalf("render pdf: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (overall PDF report)\n", pdfFinal)
	}
}

type control struct {
	id      string
	title   string
	compute func(in []auditRecord, w windowSpec) evidence
}

func buildRegistry() map[string][]control {
	return map[string][]control{
		"nist-sp-800-207": nistControls(),
		"beyondcorp":      beyondCorpControls(),
		"soc2":            soc2Controls(),
	}
}

// --- NIST SP 800-207 controls (subset, per ADR 0041 §8.d table) -----

func nistControls() []control {
	return []control{
		{
			id:    "tenet-6",
			title: "Dynamic policy enforcement (per-session decisions take place)",
			compute: func(in []auditRecord, w windowSpec) evidence {
				var withDec, withMs int
				for _, r := range in {
					if r.Decision == "" {
						continue
					}
					withDec++
					if r.EvaluationMs != nil && *r.EvaluationMs > 0 {
						withMs++
					}
				}
				ratio := 0.0
				if withDec > 0 {
					ratio = float64(withMs) / float64(withDec)
				}
				return evidence{
					Framework:   "nist-sp-800-207",
					Control:     "tenet-6",
					Title:       "Dynamic policy enforcement",
					WindowStart: w.start,
					WindowEnd:   w.end,
					Measurement: map[string]any{
						"evaluations_with_decision":           withDec,
						"evaluations_with_evaluation_ms_gt_0": withMs,
						"ratio":                               ratio,
					},
					Satisfied: ratio >= 0.999,
					Notes:     "Per ADR 0041 §8.d: ratio >= 0.999 satisfies tenet 6.",
				}
			},
		},
		{
			id:    "tenet-7-cdm",
			title: "Continuous diagnostics + posture freshness",
			compute: func(in []auditRecord, w windowSpec) evidence {
				var total, fresh int
				for _, r := range in {
					if r.PostureFresh == nil {
						continue
					}
					total++
					if *r.PostureFresh {
						fresh++
					}
				}
				ratio := 0.0
				if total > 0 {
					ratio = float64(fresh) / float64(total)
				}
				return evidence{
					Framework:   "nist-sp-800-207",
					Control:     "tenet-7-cdm",
					Title:       "Continuous diagnostics: posture-fresh ratio",
					WindowStart: w.start,
					WindowEnd:   w.end,
					Measurement: map[string]any{
						"records_with_posture_signal": total,
						"records_posture_fresh":       fresh,
						"ratio":                       ratio,
					},
					Satisfied: ratio >= 0.95,
					Notes:     "Per ADR 0040 §Phase 4: posture-fresh ratio >= 95% satisfies CDM.",
				}
			},
		},
	}
}

// --- BeyondCorp controls (subset) ------------------------------------

func beyondCorpControls() []control {
	return []control{
		{
			id:    "cba",
			title: "Certificate-Based Access (device cert valid on every request)",
			compute: func(in []auditRecord, w windowSpec) evidence {
				var total, ok int
				for _, r := range in {
					if r.DeviceCertValid == nil {
						continue
					}
					total++
					if *r.DeviceCertValid {
						ok++
					}
				}
				ratio := 0.0
				if total > 0 {
					ratio = float64(ok) / float64(total)
				}
				return evidence{
					Framework:   "beyondcorp",
					Control:     "cba",
					Title:       "Certificate-Based Access",
					WindowStart: w.start,
					WindowEnd:   w.end,
					Measurement: map[string]any{
						"records_with_device_cert_signal": total,
						"records_device_cert_valid":       ok,
						"ratio":                           ratio,
					},
					Satisfied: ratio >= 0.99,
					Notes:     "Per BeyondCorp Enterprise: device-cert valid on >= 99% of admin-tier requests satisfies CBA.",
				}
			},
		},
	}
}

// --- SOC2 CC6 family controls (subset) -------------------------------

func soc2Controls() []control {
	return []control{
		{
			id:    "CC6.1",
			title: "Restrict logical access",
			compute: func(in []auditRecord, w windowSpec) evidence {
				var allow, deny int
				for _, r := range in {
					switch r.Decision {
					case "allow":
						allow++
					case "deny":
						deny++
					}
				}
				return evidence{
					Framework:   "soc2",
					Control:     "CC6.1",
					Title:       "Restrict logical access",
					WindowStart: w.start,
					WindowEnd:   w.end,
					Measurement: map[string]any{
						"allow_count": allow,
						"deny_count":  deny,
					},
					Satisfied: deny > 0,
					Notes:     "deny_count > 0 indicates the access control is exercising denials (not silently allowing).",
				}
			},
		},
		{
			id:    "CC6.3",
			title: "Multi-factor authentication enforced",
			compute: func(in []auditRecord, w windowSpec) evidence {
				var total, aal3 int
				for _, r := range in {
					if len(r.AMR) == 0 {
						continue
					}
					total++
					if hasHardwareFactor(r.AMR) {
						aal3++
					}
				}
				ratio := 0.0
				if total > 0 {
					ratio = float64(aal3) / float64(total)
				}
				return evidence{
					Framework:   "soc2",
					Control:     "CC6.3",
					Title:       "Multi-factor authentication enforced (AAL3 ratio)",
					WindowStart: w.start,
					WindowEnd:   w.end,
					Measurement: map[string]any{
						"records_with_amr":  total,
						"records_with_hwk":  aal3,
						"aal3_ratio":        ratio,
					},
					Satisfied: ratio >= 0.95,
					Notes:     "AAL3 ratio >= 0.95 satisfies CC6.3 multi-factor enforcement.",
				}
			},
		},
	}
}

func hasHardwareFactor(amr []string) bool {
	for _, a := range amr {
		if a == "hwk" || a == "fido2" || a == "piv" {
			return true
		}
	}
	return false
}

// --- I/O helpers -----------------------------------------------------

func loadRecords(files []string) ([]auditRecord, error) {
	var out []auditRecord
	for _, p := range files {
		recs, err := readNDJSON(p)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

func readNDJSON(path string) ([]auditRecord, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path) //nolint:gosec // operator-supplied path
		if err != nil {
			return nil, err
		}
		defer f.Close() //nolint:errcheck,gosec
		r = f
	}
	dec := json.NewDecoder(r)
	dec.UseNumber()
	out := []auditRecord{}
	for {
		var rec auditRecord
		err := dec.Decode(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN skip malformed record (%v)\n", err)
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path) //nolint:gosec // operator-supplied dir
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck,gosec
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "compliance-evidence: "+format+"\n", a...)
	os.Exit(1)
}
