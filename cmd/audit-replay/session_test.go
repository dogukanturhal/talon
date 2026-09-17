// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// helper builds an auditRecord with the fields exercised by the
// session reconstruction path.
func sessRec(seq int64, ts string, event, decision string, prevHash, hash string) auditRecord {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return auditRecord{
		Seq:       seq,
		Timestamp: t,
		Event:     event,
		Decision:  decision,
		PrevHash:  prevHash,
		Hash:      hash,
		SessionID: "sess-1",
		Sub:       "01H_USER",
		Email:     "alice@example.com",
		TenantID:  "tenant-foo",
		Route:     "internal.example.com",
		Method:    "GET",
		Path:      "/api/v1/projects",
		SrcIP:     "10.0.50.5",
		Reason:    "",
	}
}

func TestSessionBuilder_ObserveFiltersBySessionID(t *testing.T) {
	b := newSessionBuilder("sess-1")
	b.observe(sessRec(1, "2026-06-07T10:00:00Z", "login_success", "allow", "", "h1"))
	other := sessRec(2, "2026-06-07T10:00:01Z", "access_granted", "allow", "h1", "h2")
	other.SessionID = "sess-OTHER"
	b.observe(other)
	if got, want := len(b.records), 1; got != want {
		t.Fatalf("only matching session records should be retained; got %d, want %d", got, want)
	}
}

func TestSessionBuilder_FinalizeSortsAndBuildsTimeline(t *testing.T) {
	b := newSessionBuilder("sess-1")
	// Intentionally insert OUT OF ORDER to exercise the sort path.
	b.observe(sessRec(3, "2026-06-07T10:00:03Z", "access_granted", "allow", "h2", "h3"))
	b.observe(sessRec(1, "2026-06-07T10:00:01Z", "login_success", "allow", "", "h1"))
	b.observe(sessRec(2, "2026-06-07T10:00:02Z", "mfa_challenge_passed", "allow", "h1", "h2"))

	tl := b.finalize()

	if !tl.ChainValid {
		t.Fatalf("chain should be valid; break at %d (%s)", tl.ChainBreakAt, tl.ChainBreakReason)
	}
	if got, want := len(tl.Records), 3; got != want {
		t.Fatalf("record count: got %d, want %d", got, want)
	}
	for i := 1; i < len(tl.Records); i++ {
		if tl.Records[i].Timestamp.Before(tl.Records[i-1].Timestamp) {
			t.Fatalf("records not sorted at index %d", i)
		}
	}
	if got, want := tl.SessionID, "sess-1"; got != want {
		t.Fatalf("SessionID: got %q, want %q", got, want)
	}
	if got, want := tl.Subject, "01H_USER"; got != want {
		t.Fatalf("Subject: got %q, want %q", got, want)
	}
	if got, want := len(tl.Transitions), 3; got != want {
		t.Fatalf("transitions: got %d, want %d (one per recognized event)", got, want)
	}
	if tl.Transitions[0].Label != "login success" {
		t.Fatalf("first transition: got %q, want %q", tl.Transitions[0].Label, "login success")
	}
}

func TestSessionBuilder_DetectsHashChainBreak(t *testing.T) {
	b := newSessionBuilder("sess-1")
	b.observe(sessRec(1, "2026-06-07T10:00:01Z", "login_success", "allow", "", "abcDEF1234567890"))
	b.observe(sessRec(2, "2026-06-07T10:00:02Z", "access_granted", "allow",
		"WRONG_PREV_HASH", "fedCBA987654321"))

	tl := b.finalize()

	if tl.ChainValid {
		t.Fatalf("chain should be flagged BROKEN; ChainValid=%v", tl.ChainValid)
	}
	if got, want := tl.ChainBreakAt, 1; got != want {
		t.Fatalf("ChainBreakAt: got %d, want %d", got, want)
	}
	if !strings.Contains(tl.ChainBreakReason, "WRONG_PREV_H") {
		t.Fatalf("ChainBreakReason should embed truncated wrong-prev hash: %q", tl.ChainBreakReason)
	}
}

func TestSessionBuilder_TolerantOfMissingChainFields(t *testing.T) {
	b := newSessionBuilder("sess-1")
	// Mixed mode: first record carries chain fields, second one
	// (older pod) does not. Must not flag the chain as broken.
	b.observe(sessRec(1, "2026-06-07T10:00:01Z", "login_success", "allow", "", "h1"))
	unchained := sessRec(2, "2026-06-07T10:00:02Z", "access_granted", "allow", "", "")
	b.observe(unchained)

	tl := b.finalize()

	if !tl.ChainValid {
		t.Fatalf("mixed-mode chain (one half missing fields) must remain ChainValid=true; got false")
	}
	if len(tl.Diagnostics) == 0 {
		t.Fatalf("mixed-mode should surface a diagnostic note")
	}
	if !strings.Contains(tl.Diagnostics[0], "chain-aware unknown") {
		t.Fatalf("diagnostic should explain mixed-mode: %q", tl.Diagnostics[0])
	}
}

func TestRenderHTML_EmitsSelfContainedPage(t *testing.T) {
	b := newSessionBuilder("sess-1")
	b.observe(sessRec(1, "2026-06-07T10:00:01Z", "login_success", "allow", "", "h1"))
	b.observe(sessRec(2, "2026-06-07T10:00:02Z", "access_denied", "deny", "h1", "h2"))

	tl := b.finalize()
	tl.Records[1].Reason = "ztna: tier=TIER_BYOD route requires TIER_CORP"

	var buf bytes.Buffer
	if err := renderHTML(&buf, tl); err != nil {
		t.Fatalf("renderHTML returned error: %v", err)
	}

	html := buf.String()
	// No external assets — must be self-contained.
	if strings.Contains(html, "<script") || strings.Contains(html, "src=") {
		t.Fatalf("rendered HTML must NOT embed JS or external assets; got JS/script reference")
	}
	if !strings.Contains(html, "<!doctype html>") {
		t.Fatalf("rendered HTML should declare doctype")
	}
	if !strings.Contains(html, "sess-1") {
		t.Fatalf("rendered HTML should embed the session id")
	}
	if !strings.Contains(html, "internal.example.com") {
		t.Fatalf("rendered HTML should embed the route field")
	}
	if !strings.Contains(html, "01H_USER") {
		t.Fatalf("rendered HTML should embed the subject")
	}
	// Deny reason must appear and be escaped if it contained <script>
	// (which it doesn't here but the renderer uses html/template so
	// any user-supplied field is auto-escaped).
	if !strings.Contains(html, "TIER_BYOD") {
		t.Fatalf("rendered HTML should embed the deny reason")
	}
}

func TestRenderHTML_XSSSafe(t *testing.T) {
	// Audit records with attacker-controlled fields MUST be escaped by
	// html/template — html/template auto-escapes string fields without
	// any opt-in needed in the template. This test enforces that
	// invariant doesn't regress (e.g. by someone migrating to text/template
	// in a refactor).
	b := newSessionBuilder("sess-XSS")
	r := sessRec(1, "2026-06-07T10:00:01Z", "access_denied", "deny", "", "h1")
	r.SessionID = "sess-XSS"
	r.Sub = "<script>alert(1)</script>"
	r.Email = `"><img src=x onerror=alert(2)>`
	r.Reason = `ztna: <iframe src=javascript:alert(3)>`
	b.observe(r)
	tl := b.finalize()

	var buf bytes.Buffer
	if err := renderHTML(&buf, tl); err != nil {
		t.Fatalf("renderHTML returned error: %v", err)
	}
	html := buf.String()
	// XSS check: the dangerous LITERAL constructs must NOT appear as
	// active HTML; the safe escaped forms (`&lt;`, `&gt;`, `&#34;`)
	// are fine. html/template's auto-escaping turns angle brackets
	// into entity refs so the injected tags cannot become live DOM.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("Sub field was not HTML-escaped; XSS surface present")
	}
	if strings.Contains(html, "<img src=x onerror=alert(2)>") {
		t.Fatalf("Email field was not HTML-escaped; raw <img> tag present")
	}
	if strings.Contains(html, "<iframe src=javascript:alert(3)>") {
		t.Fatalf("Reason field was not HTML-escaped; raw <iframe> tag present")
	}
}

func TestTransitionFor_AllKnownEventsMap(t *testing.T) {
	cases := []struct {
		event string
		want  string
	}{
		{"access_granted", "access granted"},
		{"access_denied", "access denied"},
		{"login_success", "login success"},
		{"mfa_challenge_passed", "mfa passed"},
		{"mfa_challenge_failed", "mfa failed"},
		{"session_revoked", "session revoked"},
		{"grant_issued", "grant issued"},
		{"posture_attached", "posture attached"},
		{"posture_expired", "posture expired"},
		{"unrecognized_event", ""},
	}
	for _, c := range cases {
		r := sessRec(1, "2026-06-07T10:00:00Z", c.event, "", "", "")
		got := transitionFor(r).Label
		if got != c.want {
			t.Errorf("transitionFor(%q): got %q, want %q", c.event, got, c.want)
		}
	}
}

func TestTruncateHash_Bounded(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"0123456789ab", "0123456789ab"},     // exactly 12
		{"0123456789abcdef", "0123456789ab"}, // 16 → 12
		{strings.Repeat("0", 64), strings.Repeat("0", 12)}, // 64-char SHA-256
	}
	for _, c := range cases {
		got := truncateHash(c.in)
		if got != c.want {
			t.Errorf("truncateHash(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}
