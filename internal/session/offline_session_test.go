// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

type fakeSessionMetrics struct {
	served int
	denied int
}

func (m *fakeSessionMetrics) OnSessionOfflineServed() { m.served++ }
func (m *fakeSessionMetrics) OnSessionOfflineDenied() { m.denied++ }

func newTestOfflineSessionCache(t *testing.T, fc *resilient.FakeClock, m OfflineSessionMetrics) *OfflineSessionCache {
	t.Helper()
	c, err := NewOfflineSessionCache(OfflineSessionConfig{
		StandardBudget:   15 * time.Minute,
		PrivilegedBudget: 5 * time.Minute,
		RecordInterval:   time.Nanosecond, // effectively no re-sign throttle in tests
		Clock:            fc,
		Metrics:          m,
	})
	if err != nil {
		t.Fatalf("NewOfflineSessionCache: %v", err)
	}
	return c
}

const (
	tCookie = "cookie-abc-123"
	tSubj   = "user-123"
)

// testBlob is a minimal valid session blob. exp==0 disables the hard-expiry
// check (Serve only enforces Blob.Exp when non-zero).
func testBlob(sub string, exp int64) *Blob {
	return &Blob{V: SchemaVersion, Sub: sub, Roles: []string{"platform_admin"}, Exp: exp}
}

// TestOfflineSession_ServedWithinBudget is the P3.1 happy path: a session
// recorded on a live read is served offline while inside the tier budget.
func TestOfflineSession_ServedWithinBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeSessionMetrics{}
	c := newTestOfflineSessionCache(t, fc, m)

	c.Record(tCookie, testBlob(tSubj, 0))

	fc.Advance(14 * time.Minute) // within the 15m standard budget
	b, ok := c.Serve(tCookie, false)
	if !ok || b == nil {
		t.Fatalf("within budget: want served blob, got (b=%v, ok=%v)", b, ok)
	}
	if b.Sub != tSubj {
		t.Fatalf("served blob Sub=%q, want %q", b.Sub, tSubj)
	}
	if m.served != 1 {
		t.Fatalf("expected 1 served metric, got %+v", m)
	}
}

// TestOfflineSession_DeniedAfterBudget: past the budget the cached session is
// no longer honoured and the read falls through to fail-closed.
func TestOfflineSession_DeniedAfterBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeSessionMetrics{}
	c := newTestOfflineSessionCache(t, fc, m)

	c.Record(tCookie, testBlob(tSubj, 0))

	fc.Advance(16 * time.Minute) // past the 15m standard budget
	if b, ok := c.Serve(tCookie, false); ok || b != nil {
		t.Fatalf("past budget: want (nil, false), got (%v, %v)", b, ok)
	}
	if m.denied != 1 {
		t.Fatalf("expected 1 denied metric, got %+v", m)
	}
}

// TestOfflineSession_PrivilegedShorterBudget: from the SAME single recorded
// decision, at +6m a privileged (critical/high) route is already past its 5m
// budget while a standard route still serves — proving the serve-time tiering.
func TestOfflineSession_PrivilegedShorterBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	c := newTestOfflineSessionCache(t, fc, nil)

	c.Record(tCookie, testBlob(tSubj, 0))
	fc.Advance(6 * time.Minute) // > 5m privileged, < 15m standard

	if _, ok := c.Serve(tCookie, true); ok {
		t.Fatal("privileged route past its 5m budget must not serve at +6m")
	}
	if _, ok := c.Serve(tCookie, false); !ok {
		t.Fatal("standard route within its 15m budget must still serve at +6m")
	}
}

// TestOfflineSession_RevokedEpochDeniedOffline is the "revoke online AND
// offline" contract: a revoke bumps the subject epoch so a session recorded
// before it is denied even with Redis unreachable; a fresh post-revoke record
// serves again.
func TestOfflineSession_RevokedEpochDeniedOffline(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	c := newTestOfflineSessionCache(t, fc, nil)

	c.Record(tCookie, testBlob(tSubj, 0))
	c.Revoke(tSubj) // session-kill / CAEP / role loss arrives

	fc.Advance(1 * time.Minute) // well within budget, but epoch-stale
	if _, ok := c.Serve(tCookie, false); ok {
		t.Fatal("revoked subject must be denied offline")
	}

	// Re-authorised (Redis reachable again): a fresh record is stamped at the
	// new epoch and serves.
	c.Record(tCookie, testBlob(tSubj, 0))
	fc.Advance(1 * time.Minute)
	if _, ok := c.Serve(tCookie, false); !ok {
		t.Fatal("post-revoke fresh session should serve")
	}
}

// TestOfflineSession_AbsentFailsClosed: a cookie never recorded (e.g. Redis
// was already down when the session was first seen) is not served.
func TestOfflineSession_AbsentFailsClosed(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeSessionMetrics{}
	c := newTestOfflineSessionCache(t, fc, m)

	if b, ok := c.Serve("never-recorded", false); ok || b != nil {
		t.Fatalf("absent cookie must fail closed, got (%v, %v)", b, ok)
	}
	if m.denied != 1 {
		t.Fatalf("expected 1 denied metric, got %+v", m)
	}
}

// TestOfflineSession_PastHardExpiryFailsClosed: grace must never resurrect a
// session past its own hard expiry (Blob.Exp), even when still inside the
// staleness budget.
func TestOfflineSession_PastHardExpiryFailsClosed(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	c := newTestOfflineSessionCache(t, fc, nil)

	exp := fc.Now().Add(10 * time.Minute).Unix() // session hard-expires in 10m
	c.Record(tCookie, testBlob(tSubj, exp))

	fc.Advance(12 * time.Minute) // within the 15m budget, but past the 10m expiry
	if b, ok := c.Serve(tCookie, false); ok || b != nil {
		t.Fatal("grace must not resurrect a session past its own hard expiry")
	}
}

// TestOfflineSession_ServesFullBlob: the served session round-trips through the
// signed decision with its identity fields intact (the blob is carried in the
// signed Claims).
func TestOfflineSession_ServesFullBlob(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	c := newTestOfflineSessionCache(t, fc, nil)

	in := &Blob{
		V: SchemaVersion, Sub: tSubj, Email: "u@example.com",
		Roles: []string{"platform_admin", "iam_admin"}, TenantID: "t-1",
		SID: "sid-9", DeviceClaims: map[string]string{"device_id": "d-1"},
	}
	c.Record(tCookie, in)
	fc.Advance(1 * time.Minute)

	out, ok := c.Serve(tCookie, false)
	if !ok {
		t.Fatal("expected served")
	}
	if out.Sub != in.Sub || out.Email != in.Email || out.TenantID != in.TenantID || out.SID != in.SID {
		t.Fatalf("scalar blob fields not preserved: %+v", out)
	}
	if !reflect.DeepEqual(out.Roles, in.Roles) {
		t.Fatalf("roles not preserved: got %v want %v", out.Roles, in.Roles)
	}
	if out.DeviceClaims["device_id"] != "d-1" {
		t.Fatalf("device claims not preserved: %v", out.DeviceClaims)
	}
}

// TestOfflineSession_InvalidateBySubjectRevokes wires the cache through the
// SubjectInvalidator/MultiInvalidator seam the Store's revoke fan-out uses and
// confirms it revokes offline.
func TestOfflineSession_InvalidateBySubjectRevokes(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	c := newTestOfflineSessionCache(t, fc, nil)

	c.Record(tCookie, testBlob(tSubj, 0))

	var inv SubjectInvalidator = MultiInvalidator{c}
	if n := inv.InvalidateBySubject(tSubj, "session_revoke"); n != 1 {
		t.Fatalf("MultiInvalidator fan-out count=%d, want 1", n)
	}

	fc.Advance(1 * time.Minute)
	if _, ok := c.Serve(tCookie, false); ok {
		t.Fatal("session must be denied offline after InvalidateBySubject")
	}
}

// TestIsUnavailable: only an infrastructure error (transport / breaker-open) is
// eligible for offline-serve; genuine session sentinels stay fail-closed.
func TestIsUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"not-found", ErrNotFound, false},
		{"revoked", ErrRevoked, false},
		{"expired", ErrExpired, false},
		{"auth-failed", ErrAuthFailed, false},
		{"wrapped-not-found", fmt.Errorf("redis get: %w", ErrNotFound), false},
		{"redis transport", errors.New("redis pipeline: dial tcp: connection refused"), true},
		{"breaker-open", fmt.Errorf("session store: redis unavailable: %w", resilient.ErrBreakerOpen), true},
	}
	for _, tc := range cases {
		if got := IsUnavailable(tc.err); got != tc.want {
			t.Errorf("%s: IsUnavailable=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestOfflineSession_NilSafe: the zero/nil cache is safe to call (feature-off
// path passes nil around).
func TestOfflineSession_NilSafe(t *testing.T) {
	var c *OfflineSessionCache
	c.Record(tCookie, testBlob(tSubj, 0)) // must not panic
	if b, ok := c.Serve(tCookie, false); ok || b != nil {
		t.Fatal("nil cache Serve must return (nil, false)")
	}
	c.Revoke(tSubj) // must not panic
}
