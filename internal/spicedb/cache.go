// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb — cache.go is the in-process LRU+TTL cache fronting
// CheckPermission per ADR 0001 §7.b. Two failure modes the cache must
// handle:
//
//   - allow → deny revoke: bounded by TTL (admin loses access within
//     <= TTL after permission removal). Default 30s; tunable via Config.
//   - SpiceDB outage: cache survives; misses fail-closed in PE.
//
// Subject index: every (host, subject, perm) entry is also indexed by
// subject so revocation can flush every active entry for a single user
// in one call (the decision cache must be
// invalidated by the streaming revocation webhook + the existing
// session.Revoke path). The subject is the OIDC sub claim, ID-stable
// across sessions.
package spicedb

import (
	"container/list"
	"sync"
	"time"
)

// Cache is a small thread-safe LRU+TTL of CheckPermission results.
// Used to amortise SpiceDB load + smooth transient latency.
type Cache struct {
	mu         sync.Mutex
	items      map[cacheKey]*list.Element
	subjectIdx map[string]map[*list.Element]struct{}
	ll         *list.List
	max        int
	ttl        time.Duration
	now        func() time.Time // injectable for tests
}

type cacheKey struct {
	host    string
	subject string
	perm    string
}

type cacheEntry struct {
	key       cacheKey
	allowed   bool
	expiresAt time.Time
}

// NewCache returns a Cache with the given capacity (LRU evictions
// kick in past max) and TTL (entries older than ttl are treated as
// missing). Pass max=0 to disable the cache.
func NewCache(max int, ttl time.Duration) *Cache {
	if max < 0 {
		max = 0
	}
	return &Cache{
		items:      make(map[cacheKey]*list.Element, max),
		subjectIdx: make(map[string]map[*list.Element]struct{}),
		ll:         list.New(),
		max:        max,
		ttl:        ttl,
		now:        time.Now,
	}
}

// removeElement evicts el from both the LRU and the subject index.
// Caller holds c.mu.
func (c *Cache) removeElement(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.ll.Remove(el)
	delete(c.items, e.key)
	if set := c.subjectIdx[e.key.subject]; set != nil {
		delete(set, el)
		if len(set) == 0 {
			delete(c.subjectIdx, e.key.subject)
		}
	}
}

// Get returns (allowed, hit). hit=false means caller must call SpiceDB.
func (c *Cache) Get(host, subject, perm string) (bool, bool) {
	if c == nil || c.max == 0 {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := cacheKey{host: host, subject: subject, perm: perm}
	el, ok := c.items[k]
	if !ok {
		return false, false
	}
	e := el.Value.(*cacheEntry)
	if c.now().After(e.expiresAt) {
		c.removeElement(el)
		return false, false
	}
	c.ll.MoveToFront(el)
	return e.allowed, true
}

// Put records the (allowed) decision for the key with TTL applied.
func (c *Cache) Put(host, subject, perm string, allowed bool) {
	if c == nil || c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := cacheKey{host: host, subject: subject, perm: perm}
	if el, ok := c.items[k]; ok {
		c.ll.MoveToFront(el)
		e := el.Value.(*cacheEntry)
		e.allowed = allowed
		e.expiresAt = c.now().Add(c.ttl)
		return
	}
	e := &cacheEntry{key: k, allowed: allowed, expiresAt: c.now().Add(c.ttl)}
	el := c.ll.PushFront(e)
	c.items[k] = el
	if c.subjectIdx[subject] == nil {
		c.subjectIdx[subject] = make(map[*list.Element]struct{})
	}
	c.subjectIdx[subject][el] = struct{}{}
	// Evict if over capacity.
	for c.ll.Len() > c.max {
		victim := c.ll.Back()
		if victim == nil {
			break
		}
		c.removeElement(victim)
	}
}

// InvalidateBySubject removes every cache entry for the given subject.
// Returns the number of entries dropped. Used by the session-revoke
// path so a kicked user cannot pass policy on a stale 30 s cached
// allow.
func (c *Cache) InvalidateBySubject(subject string) int {
	if c == nil || c.max == 0 || subject == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.subjectIdx[subject]
	if len(set) == 0 {
		return 0
	}
	dropped := 0
	for el := range set {
		c.ll.Remove(el)
		delete(c.items, el.Value.(*cacheEntry).key)
		dropped++
	}
	delete(c.subjectIdx, subject)
	return dropped
}

// Len returns the number of cached entries (testing aid).
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
