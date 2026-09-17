// SPDX-License-Identifier: AGPL-3.0-or-later

package dpop

import (
	"container/list"
	"sync"
	"time"
)

// MemoryCache is the in-memory LRU + lazy-TTL implementation of
// ReplayCache. Suitable for single-replica development. Production
// multi-replica deployments should wire a Redis-backed cache (the
// svctoken package's replayLRU pattern can be lifted to Redis with
// SETNX EX; see internal/svctoken/replay.go for the in-memory
// reference and the design note for the Redis variant).
//
// Concurrency: a single mutex guards both list + map. Verify-path
// throughput is dominated by JWT signature verification, not cache
// access, so contention here is rarely the hot path.
type MemoryCache struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	index   map[string]*list.Element
}

type memEntry struct {
	jti       string
	expiresAt time.Time
}

// NewMemoryCache returns an LRU-bounded cache. size=0 picks 4096
// (suitable for ~100 RPS w/ 60s proof TTL).
func NewMemoryCache(size int) *MemoryCache {
	if size <= 0 {
		size = 4096
	}
	return &MemoryCache{
		maxSize: size,
		ll:      list.New(),
		index:   make(map[string]*list.Element, size),
	}
}

// SeenOrAdd implements ReplayCache. Returns true if jti has been
// seen and is still within TTL (= replay); false if first sighting.
func (c *MemoryCache) SeenOrAdd(jti string, ttl time.Duration) bool {
	if jti == "" {
		return false
	}
	now := time.Now()
	expires := now.Add(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[jti]; ok {
		entry := el.Value.(*memEntry)
		if now.Before(entry.expiresAt) {
			c.ll.MoveToFront(el)
			return true
		}
		entry.expiresAt = expires
		c.ll.MoveToFront(el)
		return false
	}

	if c.ll.Len() >= c.maxSize {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.index, oldest.Value.(*memEntry).jti)
		}
	}
	el := c.ll.PushFront(&memEntry{jti: jti, expiresAt: expires})
	c.index[jti] = el
	return false
}

// Len returns current entry count; test helper.
func (c *MemoryCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
