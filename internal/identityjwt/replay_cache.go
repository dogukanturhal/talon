// SPDX-License-Identifier: AGPL-3.0-or-later

// replay_cache.go — bounded in-memory LRU implementation of the
// ReplayCache interface. Production deployments behind multiple pods
// should wire a shared-storage implementation (Redis SET NX EX or
// equivalent) via VerifierConfig.ReplayCache instead — see
// verifier.go for the interface contract.
//
// Implementation notes
// --------------------
// The cache is intentionally simple: a map keyed by jti plus a
// doubly-linked list for LRU eviction order. When the map size
// reaches the configured cap, the least-recently-added entry is
// dropped. Each entry carries an expiresAt; SeenOrAdd lazily prunes
// any expired entry it encounters before declaring a hit.
//
// We deliberately do NOT use the well-trodden hashicorp/golang-lru
// dependency — keeping the dependency surface small in identityjwt
// is a tier-1 supply-chain hygiene preference, and the algorithm fits
// in ~50 lines.
package identityjwt

import (
	"container/list"
	"sync"
	"time"
)

// replayLRU is the built-in in-memory implementation of ReplayCache.
// Safe for concurrent calls.
type replayLRU struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List // front = newest, back = oldest
}

type replayEntry struct {
	jti       string
	expiresAt time.Time
}

func newReplayLRU(maxSize int) *replayLRU {
	if maxSize <= 0 {
		maxSize = 1 // pathological config; one slot is better than zero
	}
	return &replayLRU{
		maxSize: maxSize,
		items:   make(map[string]*list.Element, maxSize),
		order:   list.New(),
	}
}

// SeenOrAdd implements the ReplayCache interface contract: atomic
// check-and-set returning true on replay (jti already seen within
// TTL). Expired entries are pruned lazily.
func (c *replayLRU) SeenOrAdd(jti string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if el, ok := c.items[jti]; ok {
		entry := el.Value.(*replayEntry)
		if now.Before(entry.expiresAt) {
			// Live hit — replay.
			return true
		}
		// Stale entry — fall through and refresh.
		c.order.Remove(el)
		delete(c.items, jti)
	}
	// Evict the oldest entry if at capacity. Note we evict BEFORE
	// adding, not after, so we can never temporarily exceed cap (which
	// would matter in degenerate burst-then-quiet patterns).
	for len(c.items) >= c.maxSize {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*replayEntry).jti)
	}
	el := c.order.PushFront(&replayEntry{jti: jti, expiresAt: now.Add(ttl)})
	c.items[jti] = el
	return false
}

// Len returns the current entry count. Test-only affordance —
// production callers should not rely on size for any control flow.
func (c *replayLRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
