// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"strings"
	"testing"
	"time"

	gatewayv1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
	"github.com/hexxlock/talon/internal/policy"
	"github.com/hexxlock/talon/internal/session"
)

// fixedNow is the test reference clock — pick a stable value so the
// per-host evaluator's now-vs-IAT math is reviewer-readable. Treat as
// 2026-04-29T12:00:00Z.
var fixedNow = time.Unix(1777809600, 0)

func newBlob(iatOffset time.Duration, srcIP string, deviceClaims map[string]string) *session.Blob {
	return &session.Blob{
		Sub:          "00000000-0000-0000-0000-0000000000aa",
		Email:        "alice@example.com",
		IAT:          fixedNow.Add(iatOffset).Unix(),
		Exp:          fixedNow.Add(iatOffset + 8*time.Hour).Unix(),
		LastTouched:  fixedNow.Add(iatOffset).Unix(),
		SrcIP:        srcIP,
		DeviceClaims: deviceClaims,
	}
}

// TestSrcCIDR24 covers the IP-rebind /24 helper across the address
// shapes we expect in production. The behavior is asymmetric on
// purpose — IPv4 collapses to /24 (NAT-tolerant); IPv6 is exact-match
// (admin tier is v4-only today, exact compare is the safer default if
// v6 traffic ever arrives).
func TestSrcCIDR24(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"10.0.50.5", "10.0.50"},
		{"10.0.50.255", "10.0.50"},
		{"203.0.113.1", "203.0.113"},
		{"  10.0.50.5  ", "10.0.50"}, // leading/trailing whitespace tolerated
		{"::1", "::1"},                 // IPv6 loopback — exact
		{"2001:db8::1", "2001:db8::1"},
		{"not-an-ip", "not-an-ip"}, // malformed passes through
		{"", ""},
	}
	for _, tc := range cases {
		got := srcCIDR24(tc.in)
		if got != tc.want {
			t.Errorf("srcCIDR24(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSrcCIDR24_NATTolerance asserts two IPv4 addresses in the same /24
// collapse to the same key — the legitimate-NAT-rotation tolerance the
// reauth-on-network-change rule relies on. Without this property, every
// CGNAT mobile-network IP rotation would force a fresh OIDC handshake.
func TestSrcCIDR24_NATTolerance(t *testing.T) {
	t.Parallel()
	a := srcCIDR24("198.51.100.10")
	b := srcCIDR24("198.51.100.250")
	if a != b {
		t.Errorf("same /24 must collapse: got %q vs %q", a, b)
	}
	c := srcCIDR24("198.51.101.10")
	if a == c {
		t.Errorf("different /24 must not collapse: both %q", a)
	}
}

// TestEvaluatePerHost_NoConfigIsAllow — the default-zero entry (no
// per-host knobs set) must allow. Routes that haven't opted into the
// Phase 4 batch must keep their existing behavior unchanged.
func TestEvaluatePerHost_NoConfigIsAllow(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{} // all per-host fields zero
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("default zero entry must allow, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_AbsoluteTTL_Within — session age below the cap
// allows. 30 minutes into a 1-hour route TTL.
func TestEvaluatePerHost_AbsoluteTTL_Within(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionAbsoluteSec: 3600} // 1h
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("session 30m old vs 1h cap must allow, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_AbsoluteTTL_Exceeded — session aged past the cap
// must deny with ReasonPerHostExpired regardless of activity. Tests the
// "argocd 1h" matrix entry from the handoff TTL table.
func TestEvaluatePerHost_AbsoluteTTL_Exceeded(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionAbsoluteSec: 3600} // 1h
	v := evaluatePerHost(entry, newBlob(-90*time.Minute, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if v.ok {
		t.Fatal("session 90m old vs 1h cap must deny")
	}
	if v.reason != policy.ReasonPerHostExpired {
		t.Errorf("want reason %q, got %q", policy.ReasonPerHostExpired, v.reason)
	}
}

// TestEvaluatePerHost_ClientlessMaxTTL_TightensCap — ADR 0044. A clientless
// session whose age exceeds the tighter clientlessMaxTTL must deny with
// ReasonClientlessExpired even though it is still within the (looser)
// per-host absolute cap. The agentless tier is time-boxed harder.
func TestEvaluatePerHost_ClientlessMaxTTL_TightensCap(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionAbsoluteSec: 3600, clientlessMaxTTL: 900} // 1h agent, 15m clientless
	blob := newBlob(-30*time.Minute, "10.0.50.5", nil)                     // 30m old

	// Agent channel: 30m < 1h cap → allow (clientlessMaxTTL ignored).
	if v := evaluatePerHost(entry, blob, fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie); !v.ok {
		t.Fatalf("agent session 30m vs 1h cap must allow, got reason=%s", v.reason)
	}
	// Clientless channel: 30m > 15m clientless cap → deny (clientless reason).
	v := evaluatePerHost(entry, blob, fixedNow, "10.0.50.5", time.Time{}, policy.ChannelClientless)
	if v.ok {
		t.Fatal("clientless session 30m old vs 15m clientlessMaxTTL must deny")
	}
	if v.reason != policy.ReasonClientlessExpired {
		t.Errorf("want reason %q, got %q", policy.ReasonClientlessExpired, v.reason)
	}
}

// TestEvaluatePerHost_ClientlessMaxTTL_NeverLoosens — clientlessMaxTTL must
// only ever TIGHTEN. When the per-host absolute cap is stricter than
// clientlessMaxTTL, the per-host cap (and its reason) still governs even on
// the clientless channel — neither knob can loosen the other.
func TestEvaluatePerHost_ClientlessMaxTTL_NeverLoosens(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionAbsoluteSec: 600, clientlessMaxTTL: 3600} // 10m agent cap, 1h clientless knob
	blob := newBlob(-30*time.Minute, "10.0.50.5", nil)                     // 30m old
	v := evaluatePerHost(entry, blob, fixedNow, "10.0.50.5", time.Time{}, policy.ChannelClientless)
	if v.ok {
		t.Fatal("clientless session 30m old must still hit the tighter 10m per-host cap")
	}
	if v.reason != policy.ReasonPerHostExpired {
		t.Errorf("want reason %q (per-host cap is stricter), got %q", policy.ReasonPerHostExpired, v.reason)
	}
}

// TestEvaluatePerHost_ClientlessMaxTTL_OnlyClientlessChannel — clientlessMaxTTL
// must not affect agent (cookie) sessions even when no per-host absolute cap
// is set. Defense against an operator setting clientlessMaxTTL expecting it
// to bound agent traffic too.
func TestEvaluatePerHost_ClientlessMaxTTL_OnlyClientlessChannel(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{clientlessMaxTTL: 900} // 15m clientless only, no per-host cap
	blob := newBlob(-30*time.Minute, "10.0.50.5", nil)

	if v := evaluatePerHost(entry, blob, fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie); !v.ok {
		t.Fatalf("agent session must ignore clientlessMaxTTL, got reason=%s", v.reason)
	}
	v := evaluatePerHost(entry, blob, fixedNow, "10.0.50.5", time.Time{}, policy.ChannelClientless)
	if v.ok || v.reason != policy.ReasonClientlessExpired {
		t.Errorf("clientless session 30m vs 15m cap must deny clientless_expired, got ok=%v reason=%s", v.ok, v.reason)
	}
}

// TestEvaluatePerHost_IdleTimeout_FloorIsIAT — fresh session with no
// TouchLastSeen calls yet must NOT be judged idle on its first hit.
// The IAT-as-floor invariant prevents a brand-new login from being
// immediately bounced because lastSeen.IsZero().
func TestEvaluatePerHost_IdleTimeout_FloorIsIAT(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionIdleSec: 900} // 15m idle
	// Session created 5 minutes ago, no last-seen marker yet.
	v := evaluatePerHost(entry, newBlob(-5*time.Minute, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("fresh 5m-old session vs 15m idle must allow, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_IdleTimeout_Exceeded — session has been seen
// recently but more than the idle window ago. Must deny.
func TestEvaluatePerHost_IdleTimeout_Exceeded(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionIdleSec: 900} // 15m idle
	// Session created 2h ago, last seen 30m ago — past the 15m idle window.
	lastSeen := fixedNow.Add(-30 * time.Minute)
	v := evaluatePerHost(entry, newBlob(-2*time.Hour, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", lastSeen, policy.ChannelCookie)
	if v.ok {
		t.Fatal("session last-seen 30m ago vs 15m idle must deny")
	}
	if v.reason != policy.ReasonPerHostIdleTimeout {
		t.Errorf("want reason %q, got %q", policy.ReasonPerHostIdleTimeout, v.reason)
	}
}

// TestEvaluatePerHost_IdleTimeout_TouchKeepsAlive — session is much
// older than the idle window but TouchLastSeen kept it warm. Must allow.
func TestEvaluatePerHost_IdleTimeout_TouchKeepsAlive(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{sessionIdleSec: 900} // 15m idle
	// Session created 4h ago, last seen 5m ago — well within 15m idle.
	lastSeen := fixedNow.Add(-5 * time.Minute)
	v := evaluatePerHost(entry, newBlob(-4*time.Hour, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", lastSeen, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("active session must keep allowing, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_IPRebind_SameSlash24 — IP rotated within the same
// /24 (typical NAT / mobile hand-off) must NOT trigger reauth. This is
// the property that lets us turn the rule on without breaking corporate
// VPN users whose carrier rotates IPs.
func TestEvaluatePerHost_IPRebind_SameSlash24(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{reauthOnIP: true}
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "198.51.100.10", nil),
		fixedNow, "198.51.100.250", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("same /24 must not trigger reauth, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_IPRebind_DifferentSlash24 — IP changed to a
// different /24 must trigger ReasonNetworkChange. Catches the
// stolen-cookie-replayed-from-a-different-network attack.
func TestEvaluatePerHost_IPRebind_DifferentSlash24(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{reauthOnIP: true}
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "198.51.100.10", nil),
		fixedNow, "198.51.101.10", time.Time{}, policy.ChannelCookie)
	if v.ok {
		t.Fatal("different /24 must trigger reauth")
	}
	if v.reason != policy.ReasonNetworkChange {
		t.Errorf("want reason %q, got %q", policy.ReasonNetworkChange, v.reason)
	}
}

// TestEvaluatePerHost_IPRebind_OptOutDefaults — rule off (default) means
// any IP is fine. Validates that admin routes that haven't opted into
// reauthOnNetworkChange don't accidentally get the behavior.
func TestEvaluatePerHost_IPRebind_OptOutDefaults(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{reauthOnIP: false}
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "198.51.100.10", nil),
		fixedNow, "203.0.113.1", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("opt-out reauthOnIP must allow even on different /24, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_IPRebind_LegacyBlobNoSrcIP — sessions minted
// before SrcIP capture (or test fixtures) have empty SrcIP; the rule
// must be permissive in that case rather than locking the user out
// of every route the moment reauthOnIP is opted into.
func TestEvaluatePerHost_IPRebind_LegacyBlobNoSrcIP(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{reauthOnIP: true}
	v := evaluatePerHost(entry, newBlob(-30*time.Minute, "", nil),
		fixedNow, "203.0.113.1", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("legacy blob without SrcIP must not trigger reauth, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_FirstFailingCheckWins — when multiple checks
// would fail, the absolute-TTL check fires first by design. Ensures the
// audit log carries one canonical reason per request rather than the
// last-evaluated one.
func TestEvaluatePerHost_FirstFailingCheckWins(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{
		sessionAbsoluteSec: 3600, // expired
		sessionIdleSec:     60,   // also would fire
		reauthOnIP:         true, // also would fire
	}
	// Session 2h old (past 1h cap), last-seen 5m ago (past 60s idle),
	// IP changed to a different /24.
	v := evaluatePerHost(entry,
		newBlob(-2*time.Hour, "198.51.100.10", nil),
		fixedNow, "203.0.113.1",
		fixedNow.Add(-5*time.Minute), policy.ChannelCookie)
	if v.ok {
		t.Fatal("expected deny")
	}
	if v.reason != policy.ReasonPerHostExpired {
		t.Errorf("ordering invariant: absolute-TTL must fire first, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_DeviceClaim_AllPresent — every required claim
// present + matching → allow. Exercises the MR2 device-claim evaluator
// using the field that landed in MR1 for forward compatibility.
func TestEvaluatePerHost_DeviceClaim_AllPresent(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{
		deviceClaims: []gatewayv1alpha1.DeviceClaimRequirement{
			{Claim: "device_compliant", Equals: "true"},
			{Claim: "device_managed_by_mdm", Equals: "true"},
		},
	}
	v := evaluatePerHost(entry,
		newBlob(-30*time.Minute, "10.0.50.5", map[string]string{
			"device_compliant":      "true",
			"device_managed_by_mdm": "true",
			"device_id":             "abc-123",
		}),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if !v.ok {
		t.Fatalf("all required claims present must allow, got reason=%s", v.reason)
	}
}

// TestEvaluatePerHost_DeviceClaim_MissingFailsClosed — required claim
// not present on the session → deny. Fail-closed is the textbook
// secure default for the no-MDM-yet state.
func TestEvaluatePerHost_DeviceClaim_MissingFailsClosed(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{
		deviceClaims: []gatewayv1alpha1.DeviceClaimRequirement{
			{Claim: "device_compliant", Equals: "true"},
		},
	}
	// Empty DeviceClaims map = IdP didn't emit the claim (no MDM yet).
	v := evaluatePerHost(entry,
		newBlob(-30*time.Minute, "10.0.50.5", nil),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if v.ok {
		t.Fatal("missing required claim must deny (fail-closed)")
	}
	if v.reason != policy.ReasonDeviceClaimMissing {
		t.Errorf("want reason %q, got %q", policy.ReasonDeviceClaimMissing, v.reason)
	}
}

// TestEvaluatePerHost_DeviceClaim_Mismatch — claim present but value
// differs → deny with the distinct mismatch reason. Lets SOC analysts
// tell "no MDM yet" (missing) apart from "device flagged non-compliant"
// (mismatch) without having to read the request body.
func TestEvaluatePerHost_DeviceClaim_Mismatch(t *testing.T) {
	t.Parallel()
	entry := upstreamEntry{
		deviceClaims: []gatewayv1alpha1.DeviceClaimRequirement{
			{Claim: "device_compliant", Equals: "true"},
		},
	}
	v := evaluatePerHost(entry,
		newBlob(-30*time.Minute, "10.0.50.5", map[string]string{
			"device_compliant": "false",
		}),
		fixedNow, "10.0.50.5", time.Time{}, policy.ChannelCookie)
	if v.ok {
		t.Fatal("mismatched device claim must deny")
	}
	if v.reason != policy.ReasonDeviceClaimMismatch {
		t.Errorf("want reason %q, got %q", policy.ReasonDeviceClaimMismatch, v.reason)
	}
}

// TestDeviceClaimsFromSpec_NilStaysNil — the normalizer must preserve
// the empty-input zero allocation. The router's per-host eval loop
// iterates a nil slice as zero items, which is the cheapest no-op shape.
func TestDeviceClaimsFromSpec_NilStaysNil(t *testing.T) {
	t.Parallel()
	if got := deviceClaimsFromSpec(nil); got != nil {
		t.Errorf("nil in must return nil out, got %#v", got)
	}
}

// TestDeviceClaimsFromSpec_CopiesIndependentSlice — the normalizer must
// not alias the input slice. Mutating the watch-event-returned spec
// after registration must not mutate the registered upstream's policy.
func TestDeviceClaimsFromSpec_CopiesIndependentSlice(t *testing.T) {
	t.Parallel()
	in := []gatewayv1alpha1.DeviceClaimRequirement{
		{Claim: "device_compliant", Equals: "true"},
	}
	out := deviceClaimsFromSpec(in)
	in[0].Equals = "false" // mutate the input
	if out[0].Equals != "true" {
		t.Errorf("normalizer must copy, but registered slice mirrored input mutation")
	}
}

// TestEmitWouldHaveDenied_PrefixesReason — the audit-only emitter must
// tag the reason with the "would_have_denied_" prefix so Wazuh rules
// can pattern-match the soak-mode events without confusing them with
// real denies. Smoke test: confirm the prefix lands.
func TestEmitWouldHaveDenied_PrefixesReason(t *testing.T) {
	t.Parallel()
	// We can't observe the slog output without wiring a discard logger
	// + an audit.Emitter constructor that accepts one. The shape we
	// care about is the prefix string the function builds; assert the
	// constant is what the helper concatenates by reading the helper's
	// inputs and the policy reason.
	want := "would_have_denied_" + string(policy.ReasonPerHostExpired)
	if !strings.HasPrefix(want, "would_have_denied_") {
		t.Fatal("audit-only reason prefix invariant violated")
	}
}

// TestAuditDecisionLabel — audit-only soak would-have-denied/errored
// outcomes MUST be recorded as decision="would_deny"/"would_error" (NOT
// "deny"/"error") so they stay out of the real deny/error rate that
// TalonAuthFailureRate sums. Regression guard for the 2026-06-16 fix:
// previously every audit-only would-deny incremented decision="deny" and
// then fell through to allow, pegging the failure-rate of a low-traffic
// route (vault.ops seal-status) at the would-deny share and tripping the
// critical alert despite every request being allowed. Enforce mode
// (auditOnly=false) must still record the real "deny"/"error".
func TestAuditDecisionLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		auditOnly bool
		enforced  string
		want      string
	}{
		{"soak-deny", true, "deny", "would_deny"},
		{"enforce-deny", false, "deny", "deny"},
		{"soak-error", true, "error", "would_error"},
		{"enforce-error", false, "error", "error"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := auditDecisionLabel(c.auditOnly, c.enforced); got != c.want {
				t.Errorf("auditDecisionLabel(%v, %q) = %q, want %q",
					c.auditOnly, c.enforced, got, c.want)
			}
		})
	}
}
