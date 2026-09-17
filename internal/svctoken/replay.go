// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"container/list"
	"sync"
	"time"
)

// replayLRU is the built-in in-memory ReplayCache. Bounded by entry
// count with simple LRU eviction; each entry also carries an absolute
// expiry so stale jtis evict regardless of access pattern.
//
// Concurrency: a single mutex guards the LRU list + map. The map ↔
// list invariant means lock-free read isn't viable; for verify-path
// throughput a sharded variant could land later (Phase 6).
type replayLRU struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	index   map[string]*list.Element
}

type replayEntry struct {
	jti       string
	expiresAt time.Time
}

func newReplayLRU(size int) *replayLRU {
	if size <= 0 {
		size = 1024
	}
	return &replayLRU{
		maxSize: size,
		ll:      list.New(),
		index:   make(map[string]*list.Element, size),
	}
}

// SeenOrAdd records jti with the given TTL. Returns true if jti was
// ALREADY present with a still-valid expiry (= replay detected); false
// if this is the first sighting.
//
// Expired entries are reaped opportunistically: an expired hit is
// treated as a first sighting (the slot is re-used). Lazy eviction
// avoids a background goroutine and matches the cache's per-process
// scope.
func (c *replayLRU) SeenOrAdd(jti string, ttl time.Duration) bool {
	if jti == "" {
		// An empty jti is unusable for replay tracking; treat as fresh.
		// Falcon-ID always emits jti per
		// oauth_provider_service_tokens.go:195-212, so this only fires
		// on tokens minted by something other than Falcon-ID.
		return false
	}
	now := time.Now()
	expires := now.Add(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[jti]; ok {
		entry := el.Value.(*replayEntry)
		if now.Before(entry.expiresAt) {
			// Still-valid prior sighting → replay.
			c.ll.MoveToFront(el)
			return true
		}
		// Expired prior sighting → recycle.
		entry.expiresAt = expires
		c.ll.MoveToFront(el)
		return false
	}

	// New entry. Evict oldest if at capacity.
	if c.ll.Len() >= c.maxSize {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.index, oldest.Value.(*replayEntry).jti)
		}
	}
	el := c.ll.PushFront(&replayEntry{jti: jti, expiresAt: expires})
	c.index[jti] = el
	return false
}

// Len returns the current entry count. Test helper.
func (c *replayLRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
