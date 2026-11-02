// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"testing"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

type fakeOfflineMetrics struct {
	servedAllow int
	servedDeny  int
	denied      int
}

func (m *fakeOfflineMetrics) OnOfflineServed(allowed bool) {
	if allowed {
		m.servedAllow++
	} else {
		m.servedDeny++
	}
}
func (m *fakeOfflineMetrics) OnOfflineDenied() { m.denied++ }

func newTestOfflinePDP(t *testing.T, fc *resilient.FakeClock, m OfflinePDPMetrics) *OfflinePDP {
	t.Helper()
	o, err := NewOfflinePDP(OfflinePDPConfig{
		StandardBudget:   15 * time.Minute,
		PrivilegedBudget: 5 * time.Minute,
		Clock:            fc,
		Metrics:          m,
	})
	if err != nil {
		t.Fatalf("NewOfflinePDP: %v", err)
	}
	return o
}

const (
	tHost = "argocd.internal.example.com"
	tSub  = "user-123"
	tPerm = "access"
)

// TestOffline_ServedWithinBudget is the P3.1 happy path: a recorded live
// decision is served offline while it is inside the tier budget.
func TestOffline_ServedWithinBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeOfflineMetrics{}
	o := newTestOfflinePDP(t, fc, m)

	o.Record(tHost, tSub, tPerm, false /*standard*/, true /*allowed*/)

	// +14min: within the 15m standard budget → served.
	fc.Advance(14 * time.Minute)
	allowed, ok := o.Serve(tHost, tSub, tPerm, false)
	if !ok || !allowed {
		t.Fatalf("within budget: want (allow, served), got (allowed=%v, ok=%v)", allowed, ok)
	}
	if m.servedAllow != 1 {
		t.Fatalf("expected 1 served-allow metric, got %+v", m)
	}
}

// TestOffline_DeniedAfterBudget: past the budget the cached decision is no
// longer honoured and the PDP falls through to fail-closed.
func TestOffline_DeniedAfterBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeOfflineMetrics{}
	o := newTestOfflinePDP(t, fc, m)

	o.Record(tHost, tSub, tPerm, false, true)

	// +16min: past the 15m standard budget → not served (fail closed).
	fc.Advance(16 * time.Minute)
	if allowed, ok := o.Serve(tHost, tSub, tPerm, false); ok || allowed {
		t.Fatalf("past budget: want (deny, not-served), got (allowed=%v, ok=%v)", allowed, ok)
	}
	if m.denied != 1 {
		t.Fatalf("expected 1 offline-denied metric, got %+v", m)
	}
}

// TestOffline_PrivilegedShorterBudget: the same instant that a standard
// route would still serve, a privileged route is already past its 5m budget.
func TestOffline_PrivilegedShorterBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	o := newTestOfflinePDP(t, fc, nil)

	o.Record(tHost, tSub, tPerm, true /*privileged*/, true)
	fc.Advance(6 * time.Minute) // > 5m privileged budget, < 15m standard
	if _, ok := o.Serve(tHost, tSub, tPerm, true); ok {
		t.Fatal("privileged route should be past its 5m budget at +6m")
	}
}

// TestOffline_RevokedEpochDeniedOffline is the "revoke online AND offline"
// contract: a revoke bumps the subject epoch so a cached decision issued
// before it is denied even with SpiceDB unreachable.
func TestOffline_RevokedEpochDeniedOffline(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeOfflineMetrics{}
	o := newTestOfflinePDP(t, fc, m)

	o.Record(tHost, tSub, tPerm, false, true)

	// A revoke arrives (session-kill / CAEP / role loss) while offline.
	o.Revoke(tSub)

	// Still well within the time budget, but the decision is epoch-stale.
	fc.Advance(1 * time.Minute)
	if allowed, ok := o.Serve(tHost, tSub, tPerm, false); ok || allowed {
		t.Fatalf("revoked subject must be denied offline, got (allowed=%v, ok=%v)", allowed, ok)
	}

	// A fresh live decision recorded AFTER the revoke (SpiceDB reachable
	// again, subject re-authorised) is stamped at the new epoch and serves.
	o.Record(tHost, tSub, tPerm, false, true)
	fc.Advance(1 * time.Minute)
	if allowed, ok := o.Serve(tHost, tSub, tPerm, false); !ok || !allowed {
		t.Fatalf("post-revoke fresh decision should serve, got (allowed=%v, ok=%v)", allowed, ok)
	}
}

// TestOffline_AbsentDecisionFailsClosed: no recorded decision → not served.
func TestOffline_AbsentDecisionFailsClosed(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	o := newTestOfflinePDP(t, fc, nil)
	if allowed, ok := o.Serve(tHost, "never-seen", tPerm, false); ok || allowed {
		t.Fatalf("absent decision must fail closed, got (allowed=%v, ok=%v)", allowed, ok)
	}
}

// TestOffline_DenyVerdictServedWithinBudget: a cached DENY is served as a
// deny (not a miss) within budget — the offline PDP caches both verdicts.
func TestOffline_DenyVerdictServedWithinBudget(t *testing.T) {
	fc := resilient.NewFakeClock(time.Now())
	m := &fakeOfflineMetrics{}
	o := newTestOfflinePDP(t, fc, m)

	o.Record(tHost, tSub, tPerm, false, false /*deny*/)
	fc.Advance(1 * time.Minute)
	allowed, ok := o.Serve(tHost, tSub, tPerm, false)
	if !ok {
		t.Fatal("cached deny should be served (ok=true) within budget")
	}
	if allowed {
		t.Fatal("cached deny served as allow")
	}
	if m.servedDeny != 1 {
		t.Fatalf("expected 1 served-deny metric, got %+v", m)
	}
}
