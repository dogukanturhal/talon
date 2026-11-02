// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"strings"
	"testing"
	"time"
)

// TestStripVaultVersionPrefix_V10AndAbove locks the regex fix for
// signature parsing. The previous hard-coded v1/v2/v3 list silently
// failed at v10+; with auto-rotate every 90d the production key hits
// v10 in ~2 years and would corrupt EVERY signature thereafter.
func TestStripVaultVersionPrefix_V10AndAbove(t *testing.T) {
	cases := []struct {
		raw    string
		expect string
	}{
		{"vault:v1:abcdef", "abcdef"},
		{"vault:v9:xyz123", "xyz123"},
		{"vault:v10:future_sig", "future_sig"}, // would break old code
		{"vault:v42:much_later", "much_later"},
		{"vault:v100:far_future", "far_future"},
		// No prefix — return unchanged.
		{"raw_signature_no_prefix", "raw_signature_no_prefix"},
		// Empty — return unchanged.
		{"", ""},
	}
	for _, c := range cases {
		if got := stripVaultVersionPrefix(c.raw); got != c.expect {
			t.Errorf("stripVaultVersionPrefix(%q) = %q, want %q", c.raw, got, c.expect)
		}
	}
}

// TestHeartbeat_FutureSkew_Rejected locks the asymmetric clock-skew
// guard (B2 from review): a future-dated iat beyond ±2s ceiling is
// rejected even though the symmetric ±30s window would have admitted
// up to 30s. Prevents replay where an attacker forward-stamps a
// harvested nonce to stretch its dedup-cache lifetime.
func TestHeartbeat_FutureSkew_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	// 15s in the future — would have passed the OLD symmetric ±30s
	// window but MUST fail the new asymmetric ±2s ceiling.
	r := HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Tier:       TierCorp,
		Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 bytes b64url
		IAT:        now.Add(15 * time.Second).Unix(),
		Compliance: map[string]any{},
	}

	err := r.Validate(now)
	if err == nil {
		t.Fatal("expected rejection of 15s-future iat (asymmetric guard)")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("err should mention future-timestamp; got: %v", err)
	}
}

// TestHeartbeat_PastSkewWithinWindow_Accepted preserves the existing
// past-skew tolerance — 25s in the past is honest NTP slop.
func TestHeartbeat_PastSkewWithinWindow_Accepted(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	r := HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Tier:       TierCorp,
		Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 bytes b64url
		IAT:        now.Add(-25 * time.Second).Unix(),
		Compliance: map[string]any{},
	}

	if err := r.Validate(now); err != nil {
		t.Errorf("25s-past iat should be accepted; got: %v", err)
	}
}

// TestNonceCache_StopIsIdempotent locks the sync.Once fix for B3.
// A second Stop must NOT panic (the original close-of-closed channel
// would). The chart's deployment runs main.go which explicitly calls
// Stop() during graceful shutdown; any future refactor that
// reintroduces a `defer` would otherwise crash the pod.
func TestNonceCache_StopIsIdempotent(t *testing.T) {
	c := NewNonceCache()
	c.Stop()
	// Recover from any panic the second Stop might trigger if the
	// guard was removed.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Stop panicked: %v", r)
		}
	}()
	c.Stop() // must be a no-op
}
