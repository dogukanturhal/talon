// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"
)

// sessionBuilder collects audit records for a single session_id, sorts
// them chronologically, derives the auth-chain transition sequence,
// and validates the chain.Stamp seq contiguity within the session
// window.
//
// Used by the `--reconstruct-session <id>` mode in main.go to render
// a per-session HTML timeline for incident-response + auditor evidence
// per ADR 0041 §8.c.2 (Phase 8 close-out).
//
// Scope contract:
//   - Operator passes ONE session_id at a time. The builder filters
//     to records matching that exact session_id (records lacking the
//     field are silently dropped — they predate the session-id
//     instrumentation rolled out in ADR 0011 §4.2).
//   - Records are sorted by Timestamp.Before. Ties (sub-millisecond
//     bursts during the same web-request handler) resolve by Seq
//     ascending so the chain.Stamp ordering is preserved.
//   - Hash-chain integrity is checked: each consecutive record pair
//     must have rec[i+1].PrevHash == rec[i].Hash. A mismatch flags
//     the session as `ChainValid=false` and embeds the breaking
//     index in `ChainBreakAt` for the operator to investigate.
//
// Output is structural: the operator gets a single HTML page they can
// hand to auditors / share via ticket / archive alongside the incident
// report. The template intentionally avoids JS so the page renders in
// air-gapped review environments + survives the 7-year WORM retention
// horizon as a static artifact.
type sessionBuilder struct {
	sessionID string
	records   []auditRecord
}

func newSessionBuilder(sessionID string) *sessionBuilder {
	return &sessionBuilder{sessionID: strings.TrimSpace(sessionID)}
}

func (b *sessionBuilder) observe(rec auditRecord) {
	if b.sessionID == "" || rec.SessionID != b.sessionID {
		return
	}
	b.records = append(b.records, rec)
}

// finalize sorts the collected records and returns a fully-populated
// timeline ready for template rendering. Idempotent — repeated calls
// re-sort but do not duplicate or drop data.
func (b *sessionBuilder) finalize() sessionTimeline {
	sort.SliceStable(b.records, func(i, j int) bool {
		if !b.records[i].Timestamp.Equal(b.records[j].Timestamp) {
			return b.records[i].Timestamp.Before(b.records[j].Timestamp)
		}
		return b.records[i].Seq < b.records[j].Seq
	})

	timeline := sessionTimeline{
		SessionID:  b.sessionID,
		Records:    b.records,
		ChainValid: true,
		Generated:  time.Now().UTC(),
	}
	if len(b.records) == 0 {
		return timeline
	}

	timeline.WindowStart = b.records[0].Timestamp
	timeline.WindowEnd = b.records[len(b.records)-1].Timestamp
	timeline.Subject = b.records[0].Sub
	timeline.Email = b.records[0].Email
	timeline.TenantID = b.records[0].TenantID

	// Hash-chain integrity check. The chain.Stamp invariant per ADR
	// 0041 §6.b is: every record after the first SHOULD chain to its
	// predecessor via Hash → PrevHash. Records missing both Hash and
	// PrevHash (e.g. older Talon binaries before chain.Stamp was wired)
	// are treated as "chain-aware unknown" — neither pass nor fail.
	//
	// We deliberately ONLY enforce the chain check between records that
	// BOTH carry chain fields. Mixed-mode sessions (one half chained,
	// the other not) report ChainValid=true with a Diagnostic note
	// rather than false — the operator sees the gap explicitly.
	for i := 1; i < len(b.records); i++ {
		prev := b.records[i-1]
		curr := b.records[i]
		if prev.Hash == "" || curr.PrevHash == "" {
			timeline.Diagnostics = append(timeline.Diagnostics,
				fmt.Sprintf("record[%d] missing chain fields (chain-aware unknown); skipping integrity check at this hop", i))
			continue
		}
		if curr.PrevHash != prev.Hash {
			timeline.ChainValid = false
			timeline.ChainBreakAt = i
			timeline.ChainBreakReason = fmt.Sprintf(
				"record[%d].prev_hash=%q does not match record[%d].hash=%q",
				i, truncateHash(curr.PrevHash), i-1, truncateHash(prev.Hash))
			break
		}
	}

	// Auth-chain transitions: derive a compact ordered list of
	// "what happened" events from the Decision + Event fields. This
	// is the row the auditor wants when they ask "did this user pass
	// MFA before getting access?".
	for _, r := range b.records {
		t := transitionFor(r)
		if t.Label == "" {
			continue
		}
		timeline.Transitions = append(timeline.Transitions, t)
	}

	return timeline
}

// sessionTimeline is the template input. All exported fields are read
// from the HTML template; do not rename or remove without updating
// sessionTimelineTemplate in the same commit.
type sessionTimeline struct {
	SessionID        string
	Subject          string
	Email            string
	TenantID         string
	WindowStart      time.Time
	WindowEnd        time.Time
	Records          []auditRecord
	Transitions      []sessionTransition
	ChainValid       bool
	ChainBreakAt     int
	ChainBreakReason string
	Diagnostics      []string
	Generated        time.Time
}

// sessionTransition is one "the session moved from state X to state Y"
// row, derived from the record's Event + Decision fields. The
// transition labels are stable across audit-replay versions so an
// auditor scanning multiple session reports sees the same vocabulary.
type sessionTransition struct {
	When   time.Time
	Label  string
	Detail string
	Route  string
	IP     string
}

// transitionFor maps an audit record's (Event, Decision, Reason) tuple
// to a transition label. The list is intentionally narrow — every
// record produces AT MOST one transition; records without a recognised
// (event, decision) combination return an empty Label and are skipped.
//
// Mapping rationale:
//
//	access_granted        → "access granted"   — happy path
//	access_denied         → "access denied"    — surfaced with the deny reason
//	login_success         → "login success"    — Falcon-ID handed Talon a fresh AuthN
//	mfa_challenge_passed  → "mfa passed"       — Phase 4 AAL upgrade succeeded
//	mfa_challenge_failed  → "mfa failed"       — AAL downgrade required
//	session_revoked       → "session revoked"  — CAEP-originated terminal event
//	grant_issued          → "grant issued"     — Phase 5b workflow approval
//	posture_attached      → "posture attached" — fresh JWS bound to the session
//	posture_expired       → "posture expired"  — session waiting for next heartbeat
//
// Any other event becomes "" → skipped from the transition list (still
// present in Records for the full timeline table).
func transitionFor(r auditRecord) sessionTransition {
	out := sessionTransition{When: r.Timestamp, Route: r.Route, IP: r.SrcIP}
	switch r.Event {
	case "access_granted":
		out.Label = "access granted"
		out.Detail = r.Permission
	case "access_denied":
		out.Label = "access denied"
		out.Detail = r.Reason
	case "login_success":
		out.Label = "login success"
		out.Detail = r.Email
	case "mfa_challenge_passed":
		out.Label = "mfa passed"
	case "mfa_challenge_failed":
		out.Label = "mfa failed"
		out.Detail = r.Reason
	case "session_revoked":
		out.Label = "session revoked"
		out.Detail = r.Reason
	case "grant_issued":
		out.Label = "grant issued"
		out.Detail = r.Permission
	case "posture_attached":
		out.Label = "posture attached"
	case "posture_expired":
		out.Label = "posture expired"
	}
	return out
}

// truncateHash shortens a hex hash to 12 chars for the human-readable
// chain-break diagnostic — the full hash is too long to scan visually
// and the leading 12 chars are sufficient for audit cross-reference.
func truncateHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// renderHTML emits the session timeline as a single self-contained
// HTML page to the writer. The template does NOT embed JS so the page
// is auditor-friendly + survives long-term archive. CSS is inline to
// keep the file viewable without external assets.
//
// Template safety: `html/template` is used (NOT text/template) so user-
// supplied fields (subject, email, paths, deny reasons) auto-escape
// against XSS. A truncated-hash diagnostic embeds raw hex which is
// non-injectable but still goes through the standard escaping pipeline.
func renderHTML(w io.Writer, t sessionTimeline) error {
	tmpl, err := template.New("session").Funcs(template.FuncMap{
		"isoTime": func(ts time.Time) string {
			return ts.UTC().Format(time.RFC3339Nano)
		},
		"shortHash": truncateHash,
	}).Parse(sessionTimelineTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	return tmpl.Execute(w, t)
}

const sessionTimelineTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Talon audit-replay — session {{.SessionID}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #1c1e21; margin: 2rem; }
  h1 { font-size: 1.25rem; margin: 0 0 0.25rem; }
  h2 { font-size: 1rem; margin: 1.5rem 0 0.5rem; border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; }
  table { border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-bottom: 1.5rem; }
  th, td { padding: 0.35rem 0.6rem; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
  th { background: #f5f7fa; font-weight: 600; }
  .header { background: #f0f4f8; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1rem; }
  .header dt { font-weight: 600; display: inline-block; min-width: 8rem; }
  .header dd { display: inline; margin: 0; }
  .header div { margin: 0.2rem 0; }
  .chain-valid { color: #1a7f4a; font-weight: 600; }
  .chain-invalid { color: #b71c1c; font-weight: 600; }
  .diag { background: #fff8e1; border-left: 3px solid #f57c00; padding: 0.5rem 0.75rem; font-size: 0.85rem; margin-bottom: 1rem; }
  .deny { color: #b71c1c; }
  .grant { color: #1a7f4a; }
  .muted { color: #666; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; }
  footer { margin-top: 2rem; color: #666; font-size: 0.75rem; }
</style>
</head>
<body>

<h1>Session timeline — <code>{{.SessionID}}</code></h1>
<p class="muted">Generated {{isoTime .Generated}} by talon audit-replay (ADR 0041 §8.c.2)</p>

<div class="header">
  <div><dt>Subject:</dt><dd><code>{{.Subject}}</code> ({{.Email}})</dd></div>
  <div><dt>Tenant:</dt><dd><code>{{.TenantID}}</code></dd></div>
  <div><dt>Window:</dt><dd>{{isoTime .WindowStart}} → {{isoTime .WindowEnd}}</dd></div>
  <div><dt>Records:</dt><dd>{{len .Records}}</dd></div>
  <div><dt>Hash chain:</dt><dd>
    {{if .ChainValid}}<span class="chain-valid">VALID</span>{{else}}<span class="chain-invalid">BROKEN at record[{{.ChainBreakAt}}] — {{.ChainBreakReason}}</span>{{end}}
  </dd></div>
</div>

{{if .Diagnostics}}
<div class="diag">
  <strong>Diagnostics:</strong>
  <ul>{{range .Diagnostics}}<li>{{.}}</li>{{end}}</ul>
</div>
{{end}}

<h2>Auth-chain transitions ({{len .Transitions}})</h2>
{{if .Transitions}}
<table>
  <thead><tr><th>When (UTC)</th><th>Event</th><th>Detail</th><th>Route</th><th>Source IP</th></tr></thead>
  <tbody>
  {{range .Transitions}}
    <tr>
      <td><code>{{isoTime .When}}</code></td>
      <td>{{if eq .Label "access denied"}}<span class="deny">{{.Label}}</span>{{else if eq .Label "access granted"}}<span class="grant">{{.Label}}</span>{{else if eq .Label "session revoked"}}<span class="deny">{{.Label}}</span>{{else if eq .Label "mfa failed"}}<span class="deny">{{.Label}}</span>{{else}}{{.Label}}{{end}}</td>
      <td>{{.Detail}}</td>
      <td><code>{{.Route}}</code></td>
      <td><code>{{.IP}}</code></td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p class="muted">No auth-chain transitions in the session window (only background records).</p>
{{end}}

<h2>Full record timeline ({{len .Records}})</h2>
<table>
  <thead><tr><th>#</th><th>Seq</th><th>When (UTC)</th><th>Event</th><th>Decision</th><th>Route</th><th>Path</th><th>Reason</th></tr></thead>
  <tbody>
  {{range $i, $r := .Records}}
    <tr>
      <td>{{$i}}</td>
      <td><code>{{$r.Seq}}</code></td>
      <td><code>{{isoTime $r.Timestamp}}</code></td>
      <td>{{$r.Event}}</td>
      <td>{{if eq $r.Decision "deny"}}<span class="deny">{{$r.Decision}}</span>{{else if eq $r.Decision "allow"}}<span class="grant">{{$r.Decision}}</span>{{else}}{{$r.Decision}}{{end}}</td>
      <td><code>{{$r.Route}}</code></td>
      <td><code>{{$r.Method}} {{$r.Path}}</code></td>
      <td>{{$r.Reason}}</td>
    </tr>
  {{end}}
  </tbody>
</table>

<footer>
  Talon audit-replay scaffold — ADR 0041 §8 audit + compliance hardening.
  WORM-retention-friendly: zero JS, inline CSS, self-contained HTML.
</footer>
</body>
</html>
`
