// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb — check_cached.go layers the cache on top of
// raw CheckPermission. Hot path goes Cache.Get → return; cold path
// calls SpiceDB (under a circuit breaker) then Cache.Put. On a live
// failure the DDIL offline PDP (P3.1) serves a signed last-known-good
// decision within budget; absent that, errors fail-closed (PE deny).
package spicedb

import (
	"context"
	"errors"
	"fmt"

	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// CacheMetrics is the optional metric sink CachedClient calls per Check
// to expose hit / miss / invalidate counts (feeds
// `talon_decision_cache_hit_ratio`). Wired by the binary at startup;
// nil here keeps the package import-cycle-free and lets unit tests
// run without a Prometheus registry.
type CacheMetrics interface {
	OnCacheHit()
	OnCacheMiss()
	OnCacheInvalidate(dropped int, reason string)
}

// CachedClient pairs a Client with an LRU cache. The PE uses this; the
// reconciler uses Client directly (no caching for write-side operations).
type CachedClient struct {
	*Client
	cache   *Cache
	metrics CacheMetrics       // nil-safe via every callsite
	breaker *resilient.Breaker // nil = no breaker (P3.11); guards the live call
	offline *OfflinePDP        // nil = DDIL offline PDP disabled (fail-closed at t=0)
}

// NewCachedClient constructs a CachedClient.
func NewCachedClient(c *Client, cache *Cache) *CachedClient {
	return &CachedClient{Client: c, cache: cache}
}

// SetMetrics wires the metrics sink. Nil disables metrics emission.
// Called once from cmd/talon after observability.New so the spicedb
// package doesn't depend on prometheus.
func (c *CachedClient) SetMetrics(m CacheMetrics) {
	c.metrics = m
}

// SetBreaker wires the DDIL P3.11 circuit breaker guarding the live
// SpiceDB CheckPermission call. When SpiceDB is sustained-unreachable
// the breaker opens and live calls are shed (fast-fail) instead of
// retry-storming, so the offline PDP / fail-closed path takes over
// immediately. Nil = no breaker (every miss hits SpiceDB).
func (c *CachedClient) SetBreaker(b *resilient.Breaker) { c.breaker = b }

// SetOfflinePDP wires the DDIL P3.1 governed-degrade decision cache.
// Nil (default) preserves the fail-closed-at-t=0 behaviour on a SpiceDB
// outage. When set, a live-call failure serves a signed last-known-good
// decision within budget before failing closed.
func (c *CachedClient) SetOfflinePDP(o *OfflinePDP) { c.offline = o }

// Check fronts CheckPermission with the 30s decision cache, a circuit
// breaker, and the DDIL offline PDP:
//
//  1. 30s LRU hit → return (tier A, unchanged hot path).
//  2. miss → live CheckPermission under the breaker.
//     - success → cache (30s LRU) + record a signed last-known-good
//     decision for the offline PDP, return.
//     - failure (SpiceDB down / breaker open) → serve a cached signed
//     decision within budget (P3.1); absent one, fail closed (return
//     the error, the pre-P3.1 behaviour).
func (c *CachedClient) Check(ctx context.Context, req CheckRequest) (bool, error) {
	req = req.Default()
	if allowed, hit := c.cache.Get(req.Host, req.Subject, req.Permission); hit {
		if c.metrics != nil {
			c.metrics.OnCacheHit()
		}
		return allowed, nil
	}
	if c.metrics != nil {
		c.metrics.OnCacheMiss()
	}
	allowed, err := c.checkLive(ctx, req)
	if err != nil {
		// DDIL P3.1 governed-degrade: SpiceDB unreachable → serve a
		// signed last-known-good decision within budget, honouring the
		// revocation epoch; otherwise fail closed with the live error.
		if c.offline != nil {
			if a, ok := c.offline.Serve(req.Host, req.Subject, req.Permission, req.Privileged); ok {
				return a, nil
			}
		}
		return false, err
	}
	c.cache.Put(req.Host, req.Subject, req.Permission, allowed)
	if c.offline != nil {
		c.offline.Record(req.Host, req.Subject, req.Permission, req.Privileged, allowed)
	}
	return allowed, nil
}

// checkLive runs the live SpiceDB CheckPermission under the circuit
// breaker (P3.11). CheckPermission keeps its own per-call deadline
// (req.Deadline); the breaker adds load-shedding without any in-request
// retry (an authz check is latency-critical, and the offline PDP already
// absorbs the failure — so there is deliberately no backoff-retry here).
func (c *CachedClient) checkLive(ctx context.Context, req CheckRequest) (bool, error) {
	if c.breaker == nil {
		return c.CheckPermission(ctx, req)
	}
	var allowed bool
	err := c.breaker.Do(ctx, func(ctx context.Context) error {
		a, e := c.CheckPermission(ctx, req)
		if e != nil {
			return e
		}
		allowed = a
		return nil
	})
	if err != nil {
		if errors.Is(err, resilient.ErrBreakerOpen) {
			return false, fmt.Errorf("spicedb CheckPermission shed: %w", err)
		}
		return false, err
	}
	return allowed, nil
}

// InvalidateBySubject flushes every cached decision for the given
// OIDC subject and emits the decision-cache-invalidate metric.
// Returns the count of entries dropped. Called by session.Store.Revoke
// (which all three revoke paths funnel through: operator break-glass,
// continuous-verification invalidate, RP-Initiated Logout).
func (c *CachedClient) InvalidateBySubject(subject, reason string) int {
	dropped := c.cache.InvalidateBySubject(subject)
	if dropped > 0 && c.metrics != nil {
		c.metrics.OnCacheInvalidate(dropped, reason)
	}
	// DDIL "revoke online AND offline": bump the offline PDP's revocation
	// epoch so every signed last-known-good decision issued before now is
	// denied even with SpiceDB unreachable. Unconditional (not gated on
	// `dropped`) because a subject may have no live 30s-LRU entry yet still
	// hold a cached offline decision to void.
	if c.offline != nil {
		c.offline.Revoke(subject)
	}
	return dropped
}
