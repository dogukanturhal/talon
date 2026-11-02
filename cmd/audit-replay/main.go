// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main is the operator-facing `audit-replay` CLI per ADR 0041
// §8.c. Reads NDJSON audit records (internal/audit Record shape) from
// stdin or files, applies filters, and emits NDJSON to stdout or
// summary statistics on stderr.
//
// Scaffold shipped this MR:
//
//	audit-replay --since 2026-06-06T17:00:00Z [--until ...]
//	             [--subject user_sub=01HZZ...]
//	             [--check-gaps]
//	             [--ztna-decision-stats]
//	             [file...]
//
// Deferred follow-ups (separate MRs):
//
//   - --reconstruct-session  HTML timeline render (Phase 8.c.2)
//   - --validate-schema      JSON-schema enforcement against talon.audit.v1
//     (Phase 8.c.3 — schema file lives at
//     docs/architecture/0041-schema.json once authored)
//   - --output html|csv      structured-output mode (Phase 8.c.4)
//
// Reads NDJSON — one record per line. Lines that don't parse as JSON
// objects are dropped with a stderr WARN unless --strict, in which
// case the tool exits nonzero. WORM bucket reads (s3://...) land in
// Phase 8.c.5 — see s3.go for the env-var contract.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// auditRecord is the minimal subset of internal/audit.Record fields
// this CLI's filters + statistics operate on. We deliberately do NOT
// import internal/audit here — the CLI must be able to read audit logs
// emitted by older Talon binaries whose Record shape may have drifted
// from current master. Forward compatibility is essential for the
// 7-year WORM retention horizon.
type auditRecord struct {
	// chain.Stamp embedded fields.
	Seq      int64  `json:"seq,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`

	Event        string    `json:"event,omitempty"`
	Timestamp    time.Time `json:"ts"`
	Sub          string    `json:"sub,omitempty"`
	Email        string    `json:"email,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Route        string    `json:"route,omitempty"`
	Method       string    `json:"method,omitempty"`
	Path         string    `json:"path,omitempty"`
	Decision     string    `json:"decision,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	SrcIP        string    `json:"src_ip,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	Permission   string    `json:"permission,omitempty"`
	Issuer       string    `json:"iss,omitempty"`
	DecisionID   string    `json:"decision_id,omitempty"`
	SSOChainID   string    `json:"sso_chain_id,omitempty"`
	TalonVersion string    `json:"talon_version,omitempty"`
}

type filters struct {
	since   time.Time
	until   time.Time
	subject string // matches sub OR email
	route   string
}

func main() {
	var (
		sinceStr           = flag.String("since", "", "RFC 3339 lower-bound timestamp (inclusive)")
		untilStr           = flag.String("until", "", "RFC 3339 upper-bound timestamp (inclusive)")
		subject            = flag.String("subject", "", "filter to subject (matches `sub` or `email`)")
		route              = flag.String("route", "", "filter to route (matches `route` substring)")
		checkGaps          = flag.Bool("check-gaps", false, "report sequence gaps per chain.Stamp.Seq")
		denyStats          = flag.Bool("ztna-decision-stats", false, "report top-N deny reasons + AAL distribution")
		strict             = flag.Bool("strict", false, "exit nonzero on any malformed line (default: warn-and-skip)")
		topN               = flag.Int("top", 10, "top-N for deny-stats")
		printRecord        = flag.Bool("print", true, "print matching records as NDJSON (default true; --print=false silences for stats-only runs)")
		reconstructSession = flag.String("reconstruct-session", "", "session_id to render as a chronological HTML timeline (ADR 0041 §8.c.2). Disables --print + --ztna-decision-stats; emits HTML to stdout")
		outputFormat       = flag.String("output", "ndjson", "stdout format for matching records: ndjson (default) | csv. --output=csv disables --print + emits one header row + N data rows (ADR 0041 §8.c.4)")
		validateSchema     = flag.String("validate-schema", "", "validate every record against the talon.audit.v1 JSON Schema. Empty = use embedded docs/architecture/0041-schema.json; path = use operator-supplied override. WARN on stderr per violation; --strict makes the first violation FATAL (ADR 0041 §8.c.3)")
	)
	flag.Parse()

	f := filters{subject: *subject, route: *route}
	if *sinceStr != "" {
		t, err := time.Parse(time.RFC3339, *sinceStr)
		if err != nil {
			fatalf("--since: %v", err)
		}
		f.since = t
	}
	if *untilStr != "" {
		t, err := time.Parse(time.RFC3339, *untilStr)
		if err != nil {
			fatalf("--until: %v", err)
		}
		f.until = t
	}

	inputs := flag.Args()
	if len(inputs) == 0 {
		// Stdin mode — common for `cat audit.log | audit-replay ...`.
		inputs = []string{"-"}
	}

	stats := newDenyStats()
	gaps := newGapTracker()
	var session *sessionBuilder
	// --reconstruct-session is a TERMINAL mode: it disables NDJSON
	// pass-through + stats emission and emits exactly one HTML page
	// to stdout. The mode is mutually-exclusive by design — auditors
	// reading the HTML expect the timeline to be the only output
	// (any extra NDJSON or stats would corrupt the artifact for the
	// 7-year WORM retention horizon).
	if *reconstructSession != "" {
		session = newSessionBuilder(*reconstructSession)
		*printRecord = false
		*denyStats = false
		// Keep --check-gaps available alongside reconstruction — gap
		// info on stderr is non-interfering with the stdout HTML.
	}
	var schema *schemaValidator
	// --validate-schema activates the JSON Schema validator. Empty
	// path = use the embedded canonical talon.audit.v1 schema; a
	// supplied path uses the operator's schema file (e.g. tenant-
	// specific extension). Surfaced AS soon as the flag is set;
	// errors compile-time are FATAL because there's no way to
	// recover if the schema doesn't load.
	//
	// flag is checked separately from the empty default by walking
	// flag.Visit (Go stdlib's only way to distinguish "flag set to
	// empty string" from "flag not set"). Operators pass
	// `--validate-schema=` to mean "embedded schema"; bare
	// `--validate-schema` means the same; omitting the flag
	// entirely means "no validation".
	schemaFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "validate-schema" {
			schemaFlagSet = true
		}
	})
	if schemaFlagSet {
		var err error
		schema, err = newSchemaValidator(*validateSchema, *strict)
		if err != nil {
			fatalf("--validate-schema: %v", err)
		}
	}

	matched := 0
	out := bufio.NewWriter(os.Stdout)
	defer func() { _ = out.Flush() }()
	// --output csv switches the per-record emission from NDJSON
	// pass-through to a CSV row. Mutually exclusive with the NDJSON
	// pass-through (the writer is bound to one schema per run);
	// --print is silenced when --output=csv is set so the file is
	// a valid single-schema CSV.
	var csvOut *csvWriter
	switch *outputFormat {
	case "ndjson":
		// default — no extra writer needed; existing pass-through fires.
	case "csv":
		if *reconstructSession != "" {
			fatalf("--output=csv is mutually exclusive with --reconstruct-session")
		}
		csvOut = newCSVWriter(out)
		*printRecord = false
	default:
		fatalf("--output: unknown format %q (valid: ndjson, csv)", *outputFormat)
	}

	for _, path := range inputs {
		err := streamFile(path, *strict, func(line []byte, rec auditRecord) {
			if !match(rec, f) {
				return
			}
			matched++
			if schema != nil {
				violation, decodeErr := schema.validate(line)
				if decodeErr != nil {
					// Already-decoded by streamFile; this branch is
					// effectively unreachable in practice, but guard
					// against a future code-path change.
					if *strict {
						fatalf("schema: %v", decodeErr)
					}
					fmt.Fprintf(os.Stderr, "WARN schema decode: %v\n", decodeErr)
				}
				if violation != nil {
					if *strict {
						fatalf("schema violation (strict): %v", violation)
					}
					fmt.Fprintf(os.Stderr, "WARN %v\n", violation)
				}
			}
			if *checkGaps {
				gaps.observe(rec.Seq)
			}
			if *denyStats {
				stats.observe(rec)
			}
			if session != nil {
				session.observe(rec)
			}
			if csvOut != nil {
				if err := csvOut.write(rec); err != nil {
					fatalf("csv write: %v", err)
				}
			}
			if *printRecord {
				_, _ = out.Write(line)
				if !strings.HasSuffix(string(line), "\n") {
					_, _ = out.WriteString("\n")
				}
			}
		})
		if err != nil {
			fatalf("read %s: %v", path, err)
		}
	}

	if *checkGaps {
		gaps.report(os.Stderr)
	}
	if *denyStats {
		stats.report(os.Stderr, *topN)
	}
	if session != nil {
		timeline := session.finalize()
		if err := renderHTML(out, timeline); err != nil {
			fatalf("render html: %v", err)
		}
	}
	if csvOut != nil {
		if err := csvOut.flush(); err != nil {
			fatalf("csv flush: %v", err)
		}
	}
	if schema != nil {
		schema.report(os.Stderr)
	}
	fmt.Fprintf(os.Stderr, "matched=%d\n", matched)
}

func streamFile(path string, strict bool, emit func([]byte, auditRecord)) error {
	var r io.Reader
	switch {
	case path == "-":
		r = os.Stdin
	case isS3URL(path):
		// Phase 8.c.5 WORM bucket reads — see s3.go for env-var contract.
		obj, err := openS3(path)
		if err != nil {
			return err
		}
		defer obj.Close() //nolint:errcheck,gosec
		r = obj
	default:
		f, err := os.Open(path) //nolint:gosec // path is operator-provided CLI arg
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck,gosec
		r = f
	}
	sc := bufio.NewScanner(r)
	// 1 MiB max line — audit records with very long Path / Reason can
	// approach this; safe upper bound.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			if strict {
				return fmt.Errorf("parse line: %w", err)
			}
			fmt.Fprintf(os.Stderr, "WARN skip malformed line (%v)\n", err)
			continue
		}
		emit(append([]byte(nil), line...), rec)
	}
	return sc.Err()
}

func match(r auditRecord, f filters) bool {
	if !f.since.IsZero() && r.Timestamp.Before(f.since) {
		return false
	}
	if !f.until.IsZero() && r.Timestamp.After(f.until) {
		return false
	}
	if f.subject != "" {
		key := f.subject
		// Tolerate "user_sub=01H..." or bare value.
		key = strings.TrimPrefix(key, "user_sub=")
		key = strings.TrimPrefix(key, "sub=")
		key = strings.TrimPrefix(key, "email=")
		if r.Sub != key && r.Email != key {
			return false
		}
	}
	if f.route != "" && !strings.Contains(r.Route, f.route) {
		return false
	}
	return true
}

// denyStats — top-N reasons + decision counts.
type denyStats struct {
	reasons   map[string]int
	decisions map[string]int
}

func newDenyStats() *denyStats {
	return &denyStats{
		reasons:   map[string]int{},
		decisions: map[string]int{},
	}
}

func (d *denyStats) observe(r auditRecord) {
	d.decisions[r.Decision]++
	if r.Decision == "deny" && r.Reason != "" {
		d.reasons[r.Reason]++
	}
}

type kv struct {
	k string
	v int
}

func (d *denyStats) report(w io.Writer, topN int) {
	_, _ = fmt.Fprintf(w, "\n-- ZTNA decision stats --\n")
	keys := make([]string, 0, len(d.decisions))
	for k := range d.decisions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "  %-12s %d\n", k, d.decisions[k])
	}

	_, _ = fmt.Fprintf(w, "\n-- Top %d deny reasons --\n", topN)
	pairs := make([]kv, 0, len(d.reasons))
	for k, v := range d.reasons {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > topN {
		pairs = pairs[:topN]
	}
	for _, p := range pairs {
		_, _ = fmt.Fprintf(w, "  %5d  %s\n", p.v, p.k)
	}
}

// gapTracker — checks chain.Stamp.Seq for missing values.
//
// Per ADR 0041 §8.b the sequence is per-pod-monotonic; sequence gaps
// scoped to (pod, seq) require tracking source.pod too. The scaffold
// reports any non-contiguous seq pair regardless of pod — operators
// reading the report MUST cross-reference with the source.pod field
// (which the scaffold prints alongside in the next iteration).
type gapTracker struct {
	last  int64
	count int64
	gaps  []string
}

func newGapTracker() *gapTracker {
	return &gapTracker{last: -1}
}

func (g *gapTracker) observe(seq int64) {
	g.count++
	if g.last == -1 {
		g.last = seq
		return
	}
	if seq != g.last+1 && seq > g.last {
		g.gaps = append(g.gaps, fmt.Sprintf("gap: %d → %d (%d missing)", g.last, seq, seq-g.last-1))
	}
	g.last = seq
}

func (g *gapTracker) report(w io.Writer) {
	_, _ = fmt.Fprintf(w, "\n-- Sequence-gap check (%d records scanned) --\n", g.count)
	if len(g.gaps) == 0 {
		_, _ = fmt.Fprintf(w, "  no gaps detected\n")
		return
	}
	for _, gap := range g.gaps {
		_, _ = fmt.Fprintf(w, "  %s\n", gap)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "audit-replay: "+format+"\n", a...)
	os.Exit(1)
}

