// SPDX-License-Identifier: AGPL-3.0-or-later
package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPasskeyStepUpDecision(t *testing.T) {
	t.Parallel()

	const now = int64(1_000_000)
	cases := []struct {
		name        string
		sensitivity string
		tier        string
		lastWebAuth int64
		marker      int64 // Blob.PasskeyStepUpAt
		auditOnly   bool
		interactive bool
		want        passkeyStepUpAction
	}{
		{"low_sensitivity_never", "low", "", 0, 0, false, true, passkeyStepUpNone},
		{"medium_sensitivity_never", "medium", "TIER_BYOD", 0, 0, false, true, passkeyStepUpNone},
		{"empty_sensitivity_never", "", "", 0, 0, false, true, passkeyStepUpNone},
		{"critical_fresh_passkey", "critical", "TIER_CORP", now - 600, 0, false, true, passkeyStepUpNone},
		{"critical_stale_redirects", "critical", "TIER_CORP", now - 7200, 0, false, true, passkeyStepUpRedirect},
		{"critical_no_passkey_redirects", "critical", "TIER_CORP", 0, 0, false, true, passkeyStepUpRedirect},
		{"critical_boundary_exactly_1h_ok", "critical", "TIER_CORP", now - 3600, 0, false, true, passkeyStepUpNone},
		{"critical_just_over_1h_redirects", "critical", "TIER_CORP", now - 3601, 0, false, true, passkeyStepUpRedirect},
		// High: Rego needs 1h for BYOD, so the strictest window (1h) applies.
		{"high_2h_stale_redirects", "high", "TIER_BYOD", now - 7200, 0, false, true, passkeyStepUpRedirect},
		{"high_2h_stale_corp_redirects", "high", "TIER_CORP", now - 7200, 0, false, true, passkeyStepUpRedirect},
		{"high_30m_ok", "high", "TIER_BYOD", now - 1800, 0, false, true, passkeyStepUpNone},
		// Breakglass on critical: Rego has no recency requirement.
		{"critical_breakglass_never", "critical", "TIER_BREAKGLASS", 0, 0, false, true, passkeyStepUpNone},
		{"high_breakglass_still_steps_up", "high", "TIER_BREAKGLASS", 0, 0, false, true, passkeyStepUpRedirect},
		{"xhr_gets_challenge", "critical", "TIER_CORP", now - 7200, 0, false, false, passkeyStepUpChallenge},
		{"auditonly_logs_only", "critical", "TIER_CORP", now - 7200, 0, true, true, passkeyStepUpAuditOnly},
		{"auditonly_xhr_logs_only", "critical", "TIER_CORP", 0, 0, true, false, passkeyStepUpAuditOnly},
		// Silent-SSO / plain sign-in session: young IAT but no step-up marker
		// (the guard must NOT trip) and a stale passkey -> redirect.
		{"fresh_silent_sso_no_marker_redirects", "critical", "TIER_CORP", now - 7200, 0, false, true, passkeyStepUpRedirect},
		// Loop guard: a passkey step-up just completed, passkey still stale.
		{"loop_guard_marker_recent_stale", "critical", "TIER_CORP", now - 7200, now - 30, false, true, passkeyStepUpNone},
		{"loop_guard_marker_recent_no_passkey", "critical", "TIER_CORP", 0, now - 30, false, true, passkeyStepUpNone},
		{"loop_guard_edge_inside", "critical", "TIER_CORP", 0, now - passkeyStepUpLoopGuardSec, false, true, passkeyStepUpNone},
		{"loop_guard_edge_outside", "critical", "TIER_CORP", 0, now - passkeyStepUpLoopGuardSec - 1, false, true, passkeyStepUpRedirect},
		{"loop_guard_beats_auditonly_log", "critical", "TIER_CORP", 0, now - 30, true, true, passkeyStepUpNone},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := passkeyStepUpDecision(tc.sensitivity, tc.tier, tc.lastWebAuth, tc.marker, now, tc.auditOnly, tc.interactive)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsInteractiveBrowserRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		want   bool
	}{
		{"get_html_navigate", http.MethodGet, map[string]string{"Accept": "text/html,application/xhtml+xml", "Sec-Fetch-Mode": "navigate"}, true},
		{"head_html", http.MethodHead, map[string]string{"Accept": "text/html"}, true},
		{"post_html", http.MethodPost, map[string]string{"Accept": "text/html"}, false},
		{"get_json", http.MethodGet, map[string]string{"Accept": "application/json"}, false},
		{"get_no_accept", http.MethodGet, nil, false},
		{"get_html_but_fetch_cors", http.MethodGet, map[string]string{"Accept": "text/html", "Sec-Fetch-Mode": "cors"}, false},
		{"get_html_xhr_header", http.MethodGet, map[string]string{"Accept": "text/html", "X-Requested-With": "XMLHttpRequest"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, "https://vault.ops.example/ui", nil)
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			if got := isInteractiveBrowserRequest(req); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
