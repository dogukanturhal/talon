// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureNDJSON = `{"event":"request.allow","ts":"2026-03-01T10:00:00Z","sub":"alice","email":"a@b","permission":"admin","decision_id":"d1","sso_chain_id":"s1"}
{"event":"request.allow","ts":"2026-03-15T10:00:00Z","sub":"bob","email":"b@b","permission":"viewer","decision_id":"d2","sso_chain_id":"s2"}
{"event":"cv.invalidate","ts":"2026-03-20T10:00:00Z","sub":"alice","reason":"user_disabled","decision_id":"d3","sso_chain_id":"s1"}
{"event":"admin.revoke","ts":"2026-04-01T10:00:00Z","sub":"bob","reason":"streaming_webhook","decision_id":"d4","sso_chain_id":"s2"}
{"event":"request.deny","ts":"2026-04-15T10:00:00Z","sub":"carol","reason":"missing_required_role","decision_id":"d5","sso_chain_id":"s3"}
this is not json — should be skipped without erroring
{"event":"request.allow","ts":"2025-12-01T10:00:00Z","sub":"alice","permission":"viewer","decision_id":"d0","sso_chain_id":"s0"}
`

func TestFilterAndEmit_TimeWindow(t *testing.T) {
	t.Parallel()
	since, until, err := parseTimeWindow("2026-03-01", "2026-04-01")
	if err != nil {
		t.Fatalf("parseTimeWindow: %v", err)
	}
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out, evidenceFlags{format: "csv"}, nil, since, until)
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	rows := readCSV(t, out)
	// 5 events in the window (the 2025 event is before; the 2026-04-15
	// event is at-or-after `until`); plus the malformed line is skipped.
	if got, want := len(rows)-1, 3; got != want {
		t.Fatalf("rows=%d want %d (header excluded). rows=%v", got, want, rows)
	}
}

func TestFilterAndEmit_ControlsCC66(t *testing.T) {
	t.Parallel()
	allowed, err := resolveControls("CC6.6")
	if err != nil {
		t.Fatalf("resolveControls: %v", err)
	}
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out, evidenceFlags{format: "csv"}, allowed, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	rows := readCSV(t, out)
	// CC6.6 = cv.invalidate + admin.revoke + session.revoke. Fixture has
	// one of each first two, none of the third.
	gotEvents := map[string]int{}
	for _, r := range rows[1:] {
		gotEvents[r[1]]++
	}
	if gotEvents["cv.invalidate"] != 1 || gotEvents["admin.revoke"] != 1 {
		t.Fatalf("CC6.6 mismatch: %v", gotEvents)
	}
	if gotEvents["request.allow"] != 0 {
		t.Fatalf("CC6.6 leaked allow events: %v", gotEvents)
	}
}

func TestFilterAndEmit_ControlsCC63_PermissionQualified(t *testing.T) {
	t.Parallel()
	// CC6.3 = privileged access — request.allow:permission=admin only;
	// the fixture's two allow events are permission=admin (alice) and
	// permission=viewer (bob). Only alice's should pass.
	allowed, err := resolveControls("CC6.3")
	if err != nil {
		t.Fatalf("resolveControls: %v", err)
	}
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out, evidenceFlags{format: "csv"}, allowed, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	rows := readCSV(t, out)
	allowEvents := 0
	for _, r := range rows[1:] {
		if r[1] == "request.allow" {
			allowEvents++
			if r[11] != "admin" { // permission column
				t.Fatalf("CC6.3 leaked non-admin permission: %v", r)
			}
		}
	}
	if allowEvents != 1 {
		t.Fatalf("expected exactly 1 allow event for CC6.3, got %d (rows=%v)", allowEvents, rows)
	}
}

func TestFilterAndEmit_DecisionIDExact(t *testing.T) {
	t.Parallel()
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out,
		evidenceFlags{format: "ndjson", decisionID: "d3"}, nil, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	body := out.String()
	if !strings.Contains(body, `"decision_id":"d3"`) {
		t.Fatalf("missing d3: %s", body)
	}
	if strings.Contains(body, `"decision_id":"d1"`) || strings.Contains(body, `"decision_id":"d2"`) {
		t.Fatalf("leaked other decision_ids: %s", body)
	}
}

func TestFilterAndEmit_SSOChainCorrelation(t *testing.T) {
	t.Parallel()
	// Reconstruct the chain for sso_chain_id=s1 — should pull alice's
	// request.allow + cv.invalidate (both on s1).
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out,
		evidenceFlags{format: "csv", ssoChainID: "s1"}, nil, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	rows := readCSV(t, out)
	if len(rows)-1 != 2 {
		t.Fatalf("expected 2 events for s1, got %d: %v", len(rows)-1, rows)
	}
}

func TestResolveControls_UnknownControl(t *testing.T) {
	t.Parallel()
	if _, err := resolveControls("CC99.9"); err == nil {
		t.Fatal("expected error for unknown control")
	}
}

func TestParseTimeWindow_RFC3339(t *testing.T) {
	t.Parallel()
	since, until, err := parseTimeWindow("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if since.IsZero() || until.IsZero() {
		t.Fatal("zero time")
	}
}

func TestParseTimeWindow_Invalid(t *testing.T) {
	t.Parallel()
	if _, _, err := parseTimeWindow("yesterday", ""); err == nil {
		t.Fatal("expected error")
	}
}

// TestRedact_TombstonesMatchedSubOnly — only events with sub=<user>
// get PII rewritten; other rows pass through untouched.
func TestRedact_TombstonesMatchedSubOnly(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`{"event":"request.allow","ts":"2026-03-01T10:00:00Z","sub":"alice","email":"alice@example.com","session_id":"sess-1"}
{"event":"request.allow","ts":"2026-03-15T10:00:00Z","sub":"bob","email":"bob@example.com","session_id":"sess-2"}
{"event":"cv.invalidate","ts":"2026-03-20T10:00:00Z","sub":"alice","reason":"user_disabled","session_id":"sess-3"}
`)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	rc := runEvidenceRedact([]string{"--user=alice"}, in, out, errOut)
	if rc != 0 {
		t.Fatalf("rc=%d errOut=%s", rc, errOut.String())
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}

	// Row 1 — alice, must be redacted.
	var r1 map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &r1)
	expectedSub := "sha256:" + hex.EncodeToString(sha256Hash("alice"))
	if r1["sub"] != expectedSub {
		t.Fatalf("row1 sub not pseudonymised: %v", r1["sub"])
	}
	if !strings.HasPrefix(r1["email"].(string), "sha256:") {
		t.Fatalf("row1 email not pseudonymised: %v", r1["email"])
	}
	if !strings.HasPrefix(r1["session_id"].(string), "sha256:") {
		t.Fatalf("row1 session_id not pseudonymised: %v", r1["session_id"])
	}
	if r1["redacted"] != true {
		t.Fatal("row1 missing redacted=true marker")
	}
	if r1["redaction_reason"] != "gdpr_art_17" {
		t.Fatalf("row1 wrong redaction_reason: %v", r1["redaction_reason"])
	}
	if _, ok := r1["redaction_at"].(string); !ok {
		t.Fatal("row1 missing redaction_at")
	}

	// Row 2 — bob, must NOT be redacted.
	var r2 map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &r2)
	if r2["sub"] != "bob" {
		t.Fatalf("row2 should not be redacted, got sub=%v", r2["sub"])
	}
	if r2["email"] != "bob@example.com" {
		t.Fatalf("row2 email mutated: %v", r2["email"])
	}
	if _, redacted := r2["redacted"]; redacted {
		t.Fatal("row2 has redacted marker — should be untouched")
	}

	// Row 3 — alice again, must be redacted.
	var r3 map[string]any
	_ = json.Unmarshal([]byte(lines[2]), &r3)
	if !strings.HasPrefix(r3["sub"].(string), "sha256:") {
		t.Fatalf("row3 sub not pseudonymised: %v", r3["sub"])
	}
}

// TestRedact_DeterministicHash — the same sub + email always produces
// the same sha256 across runs, so cross-event correlation on hashed
// values still works for the auditor without leaking the original PII.
func TestRedact_DeterministicHash(t *testing.T) {
	t.Parallel()
	a := redactOne(t, `{"event":"x","ts":"2026-03-01T10:00:00Z","sub":"alice","email":"a@b"}`, "alice")
	b := redactOne(t, `{"event":"y","ts":"2026-03-02T10:00:00Z","sub":"alice","email":"a@b"}`, "alice")
	if a["sub"] != b["sub"] {
		t.Fatalf("hash not deterministic across events: %v vs %v", a["sub"], b["sub"])
	}
	if a["email"] != b["email"] {
		t.Fatalf("email hash not deterministic: %v vs %v", a["email"], b["email"])
	}
}

// TestRedact_RequiresUserFlag — `redact` without --user is a usage error.
func TestRedact_RequiresUserFlag(t *testing.T) {
	t.Parallel()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	rc := runEvidenceRedact(nil, strings.NewReader(""), out, errOut)
	if rc != 2 {
		t.Fatalf("expected rc=2, got %d", rc)
	}
	if !strings.Contains(errOut.String(), "--user=<sub>") {
		t.Fatalf("missing usage hint: %s", errOut.String())
	}
}

// TestRedact_NDJSON_PassthroughOnGarbage — non-JSON lines pipe through
// verbatim so chaining with `loki query | redact | export` doesn't lose
// alignment with surrounding log-format prefixes.
func TestRedact_NDJSON_PassthroughOnGarbage(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("not json line 1\n{\"event\":\"x\",\"sub\":\"alice\"}\nnot json line 2\n")
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	rc := runEvidenceRedact([]string{"--user=alice"}, in, out, errOut)
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	body := out.String()
	if !strings.Contains(body, "not json line 1") || !strings.Contains(body, "not json line 2") {
		t.Fatalf("garbage lines lost: %s", body)
	}
}

func redactOne(t *testing.T, line, user string) map[string]any {
	t.Helper()
	out := &bytes.Buffer{}
	rc := runEvidenceRedact([]string{"--user=" + user}, strings.NewReader(line+"\n"), out, &bytes.Buffer{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m); err != nil {
		t.Fatalf("decode redacted line: %v", err)
	}
	return m
}

func sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func readCSV(t *testing.T, b *bytes.Buffer) [][]string {
	t.Helper()
	r := csv.NewReader(b)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("readCSV: %v", err)
	}
	return rows
}

// TestFilterAndEmit_HMACChain — with a key, every CSV row carries an
// HMAC computed over (prev_hmac || canonical_fields). Verifies the chain
// reconstructs deterministically: same key + same input = same final hmac.
func TestFilterAndEmit_HMACChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	manifestPath := filepath.Join(dir, "m.json")
	// 32-byte key (HMAC-SHA256 expects ≥32 bytes per loadHMACKey).
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out,
		evidenceFlags{format: "csv", hmacKeyPath: keyPath, manifestPath: manifestPath},
		nil, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}

	rows := readCSV(t, out)
	if rows[0][len(rows[0])-1] != "row_hmac" {
		t.Fatalf("expected row_hmac column, got header=%v", rows[0])
	}

	// Recompute the chain independently.
	keyBytes, _ := os.ReadFile(keyPath)
	for len(keyBytes) > 0 && keyBytes[len(keyBytes)-1] == '\n' {
		keyBytes = keyBytes[:len(keyBytes)-1]
	}
	prev := []byte{}
	for i, r := range rows[1:] {
		fields := r[:len(r)-1]
		gotHex := r[len(r)-1]
		h := hmac.New(sha256.New, keyBytes)
		h.Write(prev)
		h.Write(canonicalRow(fields))
		expected := h.Sum(nil)
		if hex.EncodeToString(expected) != gotHex {
			t.Fatalf("row %d hmac mismatch: got %s want %s",
				i, gotHex, hex.EncodeToString(expected))
		}
		prev = expected
	}

	// Manifest should carry final HMAC + key fingerprint.
	mb, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.FinalHMAC != hex.EncodeToString(prev) {
		t.Fatalf("manifest final_hmac mismatch: got %s want %s",
			m.FinalHMAC, hex.EncodeToString(prev))
	}
	if m.HMACKeyID == "" {
		t.Fatal("manifest hmac_key_id missing")
	}
	if m.OutputSHA256 == "" || len(m.OutputSHA256) != 64 {
		t.Fatalf("manifest output_sha256 invalid: %q", m.OutputSHA256)
	}
}

// TestFilterAndEmit_HMACDetectsTamper — if any CSV byte is modified after
// signing, the auditor's chain replay fails. Asserts the property holds
// for a representative tamper (flip one character in row 1's email).
func TestFilterAndEmit_HMACDetectsTamper(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out,
		evidenceFlags{format: "csv", hmacKeyPath: keyPath},
		nil, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	body := out.String()
	tampered := strings.Replace(body, "alice", "ALICE", 1)
	if tampered == body {
		t.Fatal("test fixture didn't contain expected substring to tamper")
	}

	// Replay the chain on the tampered CSV.
	keyBytes, _ := os.ReadFile(keyPath)
	rows, err := csv.NewReader(strings.NewReader(tampered)).ReadAll()
	if err != nil {
		t.Fatalf("readCSV: %v", err)
	}
	prev := []byte{}
	mismatch := false
	for _, r := range rows[1:] {
		fields := r[:len(r)-1]
		gotHex := r[len(r)-1]
		h := hmac.New(sha256.New, keyBytes)
		h.Write(prev)
		h.Write(canonicalRow(fields))
		exp := h.Sum(nil)
		if hex.EncodeToString(exp) != gotHex {
			mismatch = true
			break
		}
		prev = exp
	}
	if !mismatch {
		t.Fatal("tampered CSV passed HMAC verification — chain is broken")
	}
}

// TestLoadHMACKey_TooShort — keys shorter than 32 bytes must error.
func TestLoadHMACKey_TooShort(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "short")
	_ = os.WriteFile(p, []byte("too-short"), 0o600)
	if _, err := loadHMACKey(p); err == nil {
		t.Fatal("expected error on short key")
	}
}

// TestFilterAndEmit_ManifestWithoutHMAC — --manifest without --hmac-key
// still emits a usable manifest (sha256 + counts), just no HMAC fields.
func TestFilterAndEmit_ManifestWithoutHMAC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "m.json")
	out := &bytes.Buffer{}
	rc := filterAndEmit(strings.NewReader(fixtureNDJSON), out,
		evidenceFlags{format: "csv", manifestPath: manifestPath},
		nil, time.Time{}, time.Time{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	mb, _ := os.ReadFile(manifestPath)
	var m manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.OutputSHA256 == "" {
		t.Fatal("missing output_sha256 (must be present even without HMAC)")
	}
	if m.FinalHMAC != "" || m.HMACKeyID != "" {
		t.Fatalf("HMAC fields populated despite no --hmac-key: %+v", m)
	}
}
