// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import "sync"

// compliance.go — minimal compliance evaluation + per-device transition
// tracking so the CAEP transmitter (ADR 0043) emits a
// device-compliance-change SET only when a device CROSSES the boundary,
// not on every heartbeat.

// isCompliant reports whether every required key is present in the posture
// compliance map AND set to boolean true. An empty requiredKeys list means
// no baseline is configured → always compliant (nothing can fail).
func isCompliant(compliance map[string]any, requiredKeys []string) bool {
	for _, k := range requiredKeys {
		v, ok := compliance[k]
		if !ok {
			return false
		}
		b, ok := v.(bool)
		if !ok || !b {
			return false
		}
	}
	return true
}

// complianceTracker remembers the last observed compliance status per
// device. It is in-memory and intentionally NOT persisted: on a pod
// restart the baseline is re-established silently (no emit) so a restart
// can't spam device-compliance-change for every device's first heartbeat.
type complianceTracker struct {
	mu   sync.Mutex
	last map[string]bool
}

func newComplianceTracker() *complianceTracker {
	return &complianceTracker{last: make(map[string]bool)}
}

// observe records device's new compliance status and reports whether it
// changed since the last observation. The FIRST observation of a device
// returns false (establish baseline, don't emit) — only genuine
// transitions (compliant↔not-compliant) return true.
func (c *complianceTracker) observe(deviceUUID string, compliant bool) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, seen := c.last[deviceUUID]
	c.last[deviceUUID] = compliant
	return seen && prev != compliant
}
