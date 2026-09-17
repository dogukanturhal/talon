// SPDX-License-Identifier: AGPL-3.0-or-later

// evidence.go — `talon evidence` subcommand surface for the Tier-1 Gap 4
// audit / compliance evidence chain. Boot prompt §4 Gap 4 calls out a
// CLI shape:
//
//	talon evidence export --since=YYYY-MM-DD --until=YYYY-MM-DD \
//	                      --controls=CC6.6,CC6.1 \
//	                      --format=csv|json
//
// First-cut deliberately operator-pipe friendly: read NDJSON audit
// events from stdin (the operator pipes a Loki query through), filter
// by --since / --until / --controls / --decision-id / --sso-chain-id,
// emit CSV or NDJSON to stdout.
//
// HMAC + cosign-signed manifest land in a follow-up MR — they need a
// signing key supply chain that's bigger than the export filter.
//
// `talon evidence redact --user=<uuid>` is the GDPR Art. 17 tombstone
// CLI: stream-transform NDJSON audit events so any matching user's PII
// fields are pseudonymised (sha256-hashed) while the surrounding event
// row stays intact for compliance integrity. Operator chains the
// redact + export passes:
//
//	loki query '...' \
//	  | talon evidence redact --user=<sub> \
//	  | talon evidence export --controls=CC6.6 \
//	                          --hmac-key=audit.key \
//	                          --manifest=q1.json > q1.csv

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// controlMap maps a SOC 2 / ISO control identifier to the audit event
// types that are evidence for it. Keep in sync with
// docs/compliance/control-mapping.md (single source of truth — the doc
// is canonical, this code is the runtime filter that grew from it).
//
// Each entry can match by event type prefix OR by event type +
// reason combination (the colon-separated form). The export filter
// returns events whose event type appears in the control's list.
var controlMap = map[string][]string{
	// SOC 2 Trust Services Criteria 2017 (with 2022 revision).
	"CC6.1": {
		"oidc.callback",
		"request.allow",
		"request.deny",
		"forward_auth.verify",
	},
	"CC6.2": {
		"session.create",
		"serviceclient.created", // future event
	},
	"CC6.3": {
		"request.allow:permission=admin", // permission-qualified
		"admin.revoke",
		"auth.mfa_challenge",
	},
	"CC6.6": {
		"cv.invalidate", // any reason — Falcon-ID-driven invalidation
		"admin.revoke",
		"session.revoke",
	},
	"CC6.7": {
		"oidc.callback",
		"forward_auth.verify",
	},
	// ISO/IEC 27001:2022 Annex A — pulls from the same event set with
	// different control identifiers.
	"A.5.15": {"request.allow", "request.deny"},
	"A.5.16": {"oidc.callback", "session.create"},
	"A.5.17": {"session.create"},
	"A.5.18": {"request.allow", "request.deny"},
	"A.8.2":  {"request.allow:permission=admin", "admin.revoke"},
	"A.8.3":  {"request.allow", "request.deny"},
	"A.8.5":  {"oidc.callback", "auth.mfa_challenge"},
	"A.8.15": {"*"}, // every audit event is logging
	"A.8.16": {"cv.invalidate"},
}

// evidenceFlags holds parsed CLI flags.
type evidenceFlags struct {
	since       string
	until       string
	controlsCSV string
	format      string
	decisionID  string
	ssoChainID  string
	user        string
	help        bool
	// Tier-1 chain-of-custody (boot prompt §4 Gap 4):
	hmacKeyPath  string // file containing raw HMAC key bytes
	manifestPath string // path to write the JSON manifest
}

// runEvidence is the entrypoint for `talon evidence ...`. Returns the
// process exit code.
func runEvidence(args []string) int {
	if len(args) == 0 {
		evidenceUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "export":
		return runEvidenceExport(args[1:])
	case "redact":
		return runEvidenceRedact(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "-h", "--help", "help":
		evidenceUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "talon evidence: unknown subcommand %q\n", args[0])
		evidenceUsage(os.Stderr)
		return 2
	}
}

func evidenceUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `usage: talon evidence <command> [flags]

commands:
  export   Filter NDJSON audit events from stdin against a control mapping.
           Pipe a Loki / Wazuh query into stdin; the filter emits CSV or
           NDJSON to stdout.

  redact   Stream-transform NDJSON audit events to pseudonymise (sha256)
           the PII fields belonging to one user, satisfying GDPR Art. 17
           right-to-erasure while preserving the row count + chain
           integrity for ongoing compliance. Pipe in front of export.

flags (redact):
  --user=<sub>           Required. OIDC sub of the user whose PII to
                         tombstone. Events with matching sub get sub /
                         email / src_ip / session_id replaced by
                         sha256:<hex> values; non-matching events pass
                         through verbatim.

flags (export):
  --since=YYYY-MM-DD     Inclusive lower bound on event ts.
  --until=YYYY-MM-DD     Exclusive upper bound on event ts.
  --controls=CC6.6,...   Comma-separated control identifiers; events that
                         don't match any control's event-type list are
                         dropped. Empty = no control filter.
  --decision-id=<ulid>   Drop events whose decision_id != this value.
  --sso-chain-id=<id>    Drop events whose sso_chain_id != this value.
  --user=<sub>           Drop events whose sub != this value.
  --format=csv|ndjson    Default: csv.

chain-of-custody flags:
  --hmac-key=<path>      Path to file holding the raw HMAC-SHA256 key.
                         When set, CSV gains a row_hmac column carrying
                         HMAC(prev_hmac || canonical_row, key) so any
                         row tamper breaks the chain.
  --manifest=<path>      Write a JSON manifest of the export to this
                         path: scanned/matched counts, filter values,
                         sha256 of the full output, final_hmac, and
                         hmac_key_id fingerprint. cosign-sign the
                         manifest separately:
                           cosign sign-blob --key cosign.key \
                             --output-signature manifest.sig \
                             manifest.json

example:
  loki-cli query '{namespace="talon"} |= "subsystem=audit"' \
    | talon evidence export --since=2026-01-01 --until=2026-04-01 \
                            --controls=CC6.6 --format=csv \
                            --hmac-key=/etc/talon/audit-hmac.key \
                            --manifest=q1-cc6.6.manifest.json \
                            > q1-cc6.6.csv
  cosign sign-blob --key cosign.key --output-signature q1-cc6.6.manifest.sig \
                   q1-cc6.6.manifest.json
`)
	_, _ = fmt.Fprintf(w, "\nrecognised controls: %s\n", strings.Join(availableControls(), ", "))
}

// runEvidenceExport implements `talon evidence export`. Returns exit code.
func runEvidenceExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we write our own usage
	var f evidenceFlags
	fs.StringVar(&f.since, "since", "", "")
	fs.StringVar(&f.until, "until", "", "")
	fs.StringVar(&f.controlsCSV, "controls", "", "")
	fs.StringVar(&f.format, "format", "csv", "")
	fs.StringVar(&f.decisionID, "decision-id", "", "")
	fs.StringVar(&f.ssoChainID, "sso-chain-id", "", "")
	fs.StringVar(&f.user, "user", "", "")
	fs.StringVar(&f.hmacKeyPath, "hmac-key", "", "")
	fs.StringVar(&f.manifestPath, "manifest", "", "")
	fs.BoolVar(&f.help, "h", false, "")
	fs.BoolVar(&f.help, "help", false, "")
	if err := fs.Parse(args); err != nil {
		evidenceUsage(os.Stderr)
		return 2
	}
	if f.help {
		evidenceUsage(os.Stdout)
		return 0
	}
	if f.format != "csv" && f.format != "ndjson" {
		fmt.Fprintf(os.Stderr, "--format must be csv or ndjson, got %q\n", f.format)
		return 2
	}
	since, until, err := parseTimeWindow(f.since, f.until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	allowedEvents, err := resolveControls(f.controlsCSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	return filterAndEmit(os.Stdin, os.Stdout, f, allowedEvents, since, until)
}

// runEvidenceRedact implements `talon evidence redact --user=<sub>`.
// Streams NDJSON audit events from in to out; events whose `sub` field
// matches the flag get a tombstone marker plus PII fields rewritten to
// sha256:<hex> form. Non-matching events pass through unchanged so an
// operator can chain redact in front of export without losing the
// surrounding context.
//
// PII fields tombstoned: sub, email, src_ip, session_id.
//
// Why pseudonymise rather than delete the row: GDPR Art. 17(3)(e)
// permits retention "for the establishment, exercise or defence of
// legal claims." Auditors keep the count + sequence; the data subject's
// identifiers are no longer linkable. ua_hash is already a sha256 in
// the upstream audit pipeline so it's left alone.
func runEvidenceRedact(args []string, in io.Reader, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		user string
		help bool
	)
	fs.StringVar(&user, "user", "", "")
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	if err := fs.Parse(args); err != nil {
		evidenceUsage(errOut)
		return 2
	}
	if help {
		evidenceUsage(out)
		return 0
	}
	if user == "" {
		_, _ = fmt.Fprintln(errOut, "talon evidence redact: --user=<sub> is required")
		return 2
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	bw := bufio.NewWriter(out)
	defer func() { _ = bw.Flush() }()

	scanned := 0
	redacted := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			// Pass-through for non-JSON lines so chained pipes stay aligned.
			_, _ = bw.Write(line)
			_, _ = bw.WriteString("\n")
			continue
		}
		scanned++
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			_, _ = bw.Write(line)
			_, _ = bw.WriteString("\n")
			continue
		}
		var sub string
		if r, ok := raw["sub"]; ok {
			_ = json.Unmarshal(r, &sub)
		}
		if sub == user {
			tombstoneFields(raw)
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			raw["redacted"] = json.RawMessage("true")
			raw["redaction_reason"] = json.RawMessage(`"gdpr_art_17"`)
			raw["redaction_at"] = json.RawMessage(`"` + ts + `"`)
			redacted++
		}
		body, err := json.Marshal(raw)
		if err != nil {
			// Should not happen — raw came from json.Unmarshal. Pass through
			// the original line rather than fail the stream.
			_, _ = bw.Write(line)
			_, _ = bw.WriteString("\n")
			continue
		}
		_, _ = bw.Write(body)
		_, _ = bw.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(errOut, "evidence redact: stdin read error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(errOut, "evidence redact: scanned=%d redacted=%d user=%s\n", scanned, redacted, user)
	return 0
}

// tombstoneFields replaces the canonical PII fields on raw with
// sha256:<hex> placeholders. Empty / missing fields stay missing — no
// new keys are added, so the JSON shape stays minimal.
func tombstoneFields(raw map[string]json.RawMessage) {
	const piiPrefix = "sha256:"
	for _, k := range []string{"sub", "email", "src_ip", "session_id"} {
		r, ok := raw[k]
		if !ok {
			continue
		}
		var v string
		if err := json.Unmarshal(r, &v); err != nil || v == "" {
			continue
		}
		h := sha256.Sum256([]byte(v))
		raw[k] = json.RawMessage(`"` + piiPrefix + hex.EncodeToString(h[:]) + `"`)
	}
}

// parseTimeWindow returns (since, until). Both can be zero-time meaning
// no bound. Accepts YYYY-MM-DD or full RFC3339.
func parseTimeWindow(sinceS, untilS string) (time.Time, time.Time, error) {
	parse := func(s, label string) (time.Time, error) {
		if s == "" {
			return time.Time{}, nil
		}
		// Try date first, then RFC3339.
		if t, err := time.Parse("2006-01-02", s); err == nil {
			return t, nil
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, nil
		}
		return time.Time{}, fmt.Errorf("--%s must be YYYY-MM-DD or RFC3339, got %q", label, s)
	}
	since, err := parse(sinceS, "since")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	until, err := parse(untilS, "until")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return since, until, nil
}

// resolveControls turns a comma-separated control list into a set of
// event-type strings to match against. Empty input = nil set = match
// every event (the user filters via other flags).
func resolveControls(csv string) (map[string]struct{}, error) {
	if csv == "" {
		return nil, nil
	}
	out := map[string]struct{}{}
	for _, c := range strings.Split(csv, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		events, ok := controlMap[c]
		if !ok {
			return nil, fmt.Errorf("unknown control %q (see docs/compliance/control-mapping.md)", c)
		}
		for _, e := range events {
			out[e] = struct{}{}
		}
	}
	return out, nil
}

// auditEvent matches the JSON shape internal/audit/audit.go emits.
// Permissive — extra fields are tolerated; the filter only inspects
// the fields it cares about.
type auditEvent struct {
	Event       string    `json:"event"`
	TS          time.Time `json:"ts"`
	Sub         string    `json:"sub,omitempty"`
	Email       string    `json:"email,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Route       string    `json:"route,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Permission  string    `json:"permission,omitempty"`
	Issuer      string    `json:"iss,omitempty"`
	DecisionID  string    `json:"decision_id,omitempty"`
	SSOChainID  string    `json:"sso_chain_id,omitempty"`
}

// loadHMACKey reads the raw key bytes from path. The file must contain
// at least 32 bytes (HMAC-SHA256 block size). Trailing whitespace is
// trimmed so a key written with a trailing newline still works.
//
// gosec G304 suppressed: `path` is a CLI flag value supplied by the
// operator running the evidence-export tool; the user is the trust
// boundary. The same flag value can already invoke any subcommand of
// the binary, so a path-traversal here is not a new privilege.
func loadHMACKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied CLI flag
	if err != nil {
		return nil, fmt.Errorf("read hmac key: %w", err)
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("hmac key too short: %d bytes (need >= 32)", len(b))
	}
	return b, nil
}

// hmacKeyID returns the first 8 bytes (16 hex chars) of SHA-256(key) so
// the manifest can identify which key signed the export without
// publishing the key itself.
func hmacKeyID(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:8])
}

// canonicalRow joins the CSV field values with a NUL separator so the
// HMAC chain doesn't depend on CSV escaping rules. Caller passes only
// the data fields (no row_hmac).
func canonicalRow(fields []string) []byte {
	total := 0
	for _, f := range fields {
		total += len(f) + 1
	}
	out := make([]byte, 0, total)
	for i, f := range fields {
		if i > 0 {
			out = append(out, 0)
		}
		out = append(out, f...)
	}
	return out
}

// manifest is the JSON sidecar that an auditor cosign-signs.
type manifest struct {
	Version      int               `json:"version"`
	TalonVersion string            `json:"talon_version"`
	GeneratedAt  string            `json:"generated_at"`
	Format       string            `json:"format"`
	Filters      map[string]string `json:"filters"`
	Scanned      int               `json:"scanned"`
	Matched      int               `json:"matched"`
	OutputSHA256 string            `json:"output_sha256"`
	FinalHMAC    string            `json:"final_hmac,omitempty"`
	HMACKeyID    string            `json:"hmac_key_id,omitempty"`
}

// filterAndEmit reads NDJSON from in, filters per flags, writes CSV or
// NDJSON to out. Returns process exit code.
//
// Chain-of-custody (when --hmac-key is set):
//   - CSV gains a row_hmac column. row_hmac[i] = HMAC-SHA256(
//     row_hmac[i-1] || canonical_fields(row[i]), key).
//   - The canonical_fields form NUL-joins the data field values so
//     CSV-escaping doesn't alter the HMAC input.
//   - Auditors verify by replaying the chain against the same key.
//
// Manifest (when --manifest is set):
//   - JSON sidecar with sha256 of the entire output, final HMAC, key
//     fingerprint, filter values, scan/match counts, talon version.
//   - cosign-signing the manifest is the operator's separate step
//     (documented in --help).
func filterAndEmit(in io.Reader, out io.Writer, f evidenceFlags, allowedEvents map[string]struct{}, since, until time.Time) int {
	// Pre-compute the permission-qualified entries so we can match
	// "request.allow:permission=admin" against an allow event with
	// permission="admin".
	type qualifiedEvent struct {
		event      string
		permission string
	}
	var qualified []qualifiedEvent
	plain := map[string]struct{}{}
	wildcard := false
	for k := range allowedEvents {
		if k == "*" {
			wildcard = true
			continue
		}
		if i := strings.IndexByte(k, ':'); i >= 0 {
			ev := k[:i]
			rest := k[i+1:]
			if v, ok := strings.CutPrefix(rest, "permission="); ok {
				qualified = append(qualified, qualifiedEvent{event: ev, permission: v})
				continue
			}
		}
		plain[k] = struct{}{}
	}

	// Chain-of-custody key + initial HMAC chain state. nil key disables.
	var hmacKey []byte
	if f.hmacKeyPath != "" {
		k, err := loadHMACKey(f.hmacKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "evidence export: %v\n", err)
			return 2
		}
		hmacKey = k
	}
	prevHMAC := make([]byte, 0)

	// Hash the entire output as we write it so the manifest can carry
	// a stable sha256 over the bytes the auditor will actually receive.
	outHasher := sha256.New()
	teedOut := io.MultiWriter(out, outHasher)

	headerFields := []string{
		"ts", "event", "decision", "reason",
		"sub", "email", "tenant_id",
		"route", "method", "path",
		"session_id", "permission", "iss",
		"decision_id", "sso_chain_id",
	}
	if hmacKey != nil {
		headerFields = append(headerFields, "row_hmac")
	}

	var (
		csvW  *csv.Writer
		jsonW *bufio.Writer
	)
	if f.format == "csv" {
		csvW = csv.NewWriter(teedOut)
		_ = csvW.Write(headerFields)
	} else {
		jsonW = bufio.NewWriter(teedOut)
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	matched := 0
	scanned := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // tolerate blank lines / log-format prefixes
		}
		scanned++
		var e auditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed lines
		}
		if !since.IsZero() && e.TS.Before(since) {
			continue
		}
		if !until.IsZero() && !e.TS.Before(until) {
			continue
		}
		if f.user != "" && e.Sub != f.user {
			continue
		}
		if f.decisionID != "" && e.DecisionID != f.decisionID {
			continue
		}
		if f.ssoChainID != "" && e.SSOChainID != f.ssoChainID {
			continue
		}
		if !wildcard && allowedEvents != nil {
			if _, plainOK := plain[e.Event]; !plainOK {
				ok := false
				for _, q := range qualified {
					if q.event == e.Event && q.permission == e.Permission {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
		}
		matched++
		if f.format == "csv" {
			row := []string{
				e.TS.Format(time.RFC3339Nano),
				e.Event, e.Decision, e.Reason,
				e.Sub, e.Email, e.TenantID,
				e.Route, e.Method, e.Path,
				e.SessionID, e.Permission, e.Issuer,
				e.DecisionID, e.SSOChainID,
			}
			if hmacKey != nil {
				h := hmac.New(sha256.New, hmacKey)
				h.Write(prevHMAC)
				h.Write(canonicalRow(row))
				prevHMAC = h.Sum(nil)
				row = append(row, hex.EncodeToString(prevHMAC))
			}
			_ = csvW.Write(row)
		} else {
			b, _ := json.Marshal(e)
			if hmacKey != nil {
				h := hmac.New(sha256.New, hmacKey)
				h.Write(prevHMAC)
				h.Write(b)
				prevHMAC = h.Sum(nil)
			}
			_, _ = jsonW.Write(b)
			_, _ = jsonW.WriteString("\n")
		}
	}
	if csvW != nil {
		csvW.Flush()
	}
	if jsonW != nil {
		_ = jsonW.Flush()
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "evidence export: stdin read error: %v\n", err)
		return 1
	}

	if f.manifestPath != "" {
		m := manifest{
			Version:      1,
			TalonVersion: version,
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			Format:       f.format,
			Filters: map[string]string{
				"since":         f.since,
				"until":         f.until,
				"controls":      f.controlsCSV,
				"decision_id":   f.decisionID,
				"sso_chain_id":  f.ssoChainID,
				"user":          f.user,
			},
			Scanned:      scanned,
			Matched:      matched,
			OutputSHA256: hex.EncodeToString(outHasher.Sum(nil)),
		}
		if hmacKey != nil {
			m.FinalHMAC = hex.EncodeToString(prevHMAC)
			m.HMACKeyID = hmacKeyID(hmacKey)
		}
		body, mErr := json.MarshalIndent(&m, "", "  ")
		if mErr != nil {
			fmt.Fprintf(os.Stderr, "evidence export: marshal manifest: %v\n", mErr)
			return 1
		}
		body = append(body, '\n')
		if err := os.WriteFile(f.manifestPath, body, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "evidence export: write manifest: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(os.Stderr, "evidence export: manifest=%s\n", f.manifestPath)
	}

	_, _ = fmt.Fprintf(os.Stderr, "evidence export: scanned=%d matched=%d\n", scanned, matched)
	return 0
}

// availableControls is exported for testing/help — alphabetised list
// of recognised control identifiers.
func availableControls() []string {
	out := make([]string, 0, len(controlMap))
	for k := range controlMap {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
