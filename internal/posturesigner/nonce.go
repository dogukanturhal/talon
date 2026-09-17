// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"sync"
	"time"
)

// nonceTTL is the dedup window. It must be at least 2× the TIER_CORP
// heartbeat cadence (5min) so a replayed nonce from the previous
// heartbeat is still in the cache when the next heartbeat arrives.
// 10 minutes provides comfortable headroom while keeping memory bounded.
const nonceTTL = 10 * time.Minute

// nonceGCInterval is how often the background goroutine sweeps expired
// entries. 10 min matches nonceTTL so the worst-case cache size is the
// number of heartbeats received in one TTL window.
const nonceGCInterval = 10 * time.Minute

// NonceCache is a thread-safe single-use nonce store. A nonce is
// accepted at most once within the nonceTTL window; a second presentation
// of the same nonce within the window is rejected. Entries older than
// nonceTTL are eligible for GC.
//
// Memory model: sync.Map for concurrent reads/writes without a global
// mutex. GC runs via a background goroutine started by NewNonceCache;
// callers must call Stop() to release the goroutine.
type NonceCache struct {
	m        sync.Map // key: string (nonce hex/b64), val: time.Time (accepted at)
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once // guards against double-Stop panicking on close-of-closed-channel
	now  func() time.Time // injectable for tests
}

// NewNonceCache constructs and starts the background GC goroutine.
// Stop must be called when the cache is no longer needed.
func NewNonceCache() *NonceCache {
	c := &NonceCache{
		stop: make(chan struct{}),
		done: make(chan struct{}),
		now:  time.Now,
	}
	go c.gc()
	return c
}

// newNonceCacheWithClock is used by tests to inject a custom clock.
func newNonceCacheWithClock(clockFn func() time.Time) *NonceCache {
	c := &NonceCache{
		stop: make(chan struct{}),
		done: make(chan struct{}),
		now:  clockFn,
	}
	go c.gc()
	return c
}

// Accept records the nonce and returns true if it has NOT been seen
// within the nonceTTL window. Returns false (replay detected) if the
// nonce was already accepted and the original entry has not expired.
//
// This function is safe for concurrent use. If two goroutines race with
// the same nonce, exactly one will see true and the other false —
// sync.Map.LoadOrStore provides the linearization point.
func (c *NonceCache) Accept(nonce string) bool {
	ts := c.now()
	actual, loaded := c.m.LoadOrStore(nonce, ts)
	if !loaded {
		// First time we see this nonce in the map.
		return true
	}
	// The nonce was already in the map. Check if the original entry
	// has expired — if so, it is eligible for reuse (the previous GC
	// cycle just hasn't swept it yet).
	storedAt := actual.(time.Time)
	if ts.Sub(storedAt) > nonceTTL {
		// Expired: overwrite atomically and accept.
		c.m.Store(nonce, ts)
		return true
	}
	// Within the TTL window: this is a replay, reject.
	return false
}

// Size returns the current number of entries in the cache (including
// entries that have expired but not yet been GC'd). Used as a Prometheus
// gauge for memory-pressure observability.
func (c *NonceCache) Size() int {
	var n int
	c.m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// Stop halts the background GC goroutine and waits for it to finish.
// Idempotent: subsequent calls are no-ops (gated by sync.Once). This
// is defense-in-depth against the call-site invariant being violated
// during refactors — a panicking Stop would crash the pod during
// graceful shutdown and trigger a SIGKILL from the kubelet.
func (c *NonceCache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
}

// gc is the background sweep loop. It runs every nonceGCInterval and
// deletes entries older than nonceTTL. Using sync.Map.Range + Delete is
// safe because Range snapshots the set of keys at the start of the call;
// concurrent inserts during the sweep may be missed but that is
// acceptable — they'll be swept on the next interval.
func (c *NonceCache) gc() {
	defer close(c.done)
	ticker := time.NewTicker(nonceGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *NonceCache) sweep() {
	deadline := c.now().Add(-nonceTTL)
	c.m.Range(func(k, v any) bool {
		if v.(time.Time).Before(deadline) {
			c.m.Delete(k)
		}
		return true
	})
}
