// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers groups the small one-off HTTP endpoints (/healthz,
// /readyz, /metrics handler wiring) that don't fit naturally elsewhere.
package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Health tracks readiness signals (Redis ping, OIDC discovery successful)
// for /readyz.
type Health struct {
	redis      *redis.Client
	ready      atomic.Bool
	lastReady  atomic.Int64 // unix seconds of last successful ping

	// iapCheck is an optional health probe for the IAP identity-token
	// signing path. When the Vault projection lands a malformed PEM,
	// Talon today silently degrades to "unsigned headers only" and
	// every Phase B SDK 401s with no health signal. Wiring this delegate
	// from main.go after the signer is constructed lets the malformed-
	// key state surface as a readiness failure that kube-proxy + the
	// metrics scraper can act on. Nil = unconfigured (Phase A
	// pre-rollout); /readyz behaves exactly as before.
	iapCheck atomic.Value // func() error
}

// NewHealth returns a Health checker that pings Redis on demand.
func NewHealth(rc *redis.Client) *Health {
	h := &Health{redis: rc}
	h.ready.Store(false)
	return h
}

// MarkReady is called once OIDC discovery has completed successfully.
func (h *Health) MarkReady() { h.ready.Store(true) }

// SetIAPHealthCheck registers a probe the /readyz handler invokes
// before reporting Ready. fn should be cheap (a few microseconds);
// the readiness path is on the kubelet's probe interval (typically
// 10s) so this is fine. nil fn clears any previous registration.
//
// Wiring is from main.go right after identityjwt.NewSignerFromPEM
// succeeds: pass signer.HealthCheck. When the signer fails to load
// (malformed Vault projection), main.go skips this registration AND
// fails the boot — readiness reflects the failure indirectly via
// the rest of the OIDC-discovery / Redis-ping signals.
func (h *Health) SetIAPHealthCheck(fn func() error) {
	if fn == nil {
		h.iapCheck.Store((func() error)(nil))
		return
	}
	h.iapCheck.Store(fn)
}

// Liveness is /healthz — the binary is up. Always 200 unless the process
// is wedged hard enough that net/http itself fails.
func (h *Health) Liveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// Readiness is /readyz — Talon can serve traffic. Requires:
//
//   - OIDC discovery completed (MarkReady called), AND
//   - Redis PING within the last 30s.
//
// Probe failures pull the pod out of Service rotation but do not restart
// it (ADR 0001 §10.a — Redis outage degrades to OIDC-per-request, not
// pod-restart).
func (h *Health) Readiness(w http.ResponseWriter, r *http.Request) {
	if !h.ready.Load() {
		http.Error(w, "oidc discovery not yet complete", http.StatusServiceUnavailable)
		return
	}
	last := h.lastReady.Load()
	now := time.Now().Unix()
	if now-last > 30 {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := h.redis.Ping(ctx).Err(); err != nil {
			http.Error(w, "redis ping failed", http.StatusServiceUnavailable)
			return
		}
		h.lastReady.Store(now)
	}
	// IAP identity-token signer health — only invoked when the operator
	// wired the probe (= signer was successfully constructed at boot).
	// Stays cheap: one RSA-2048 mint + one RSA-2048 verify (single-
	// digit microseconds). Failure here means the signer is loaded
	// but broken — typically a corrupted key, a clock-related anomaly,
	// or a bug. Either way, /readyz must reflect it so kube-proxy
	// pulls the pod and ops dashboards see a non-Ready Talon rather
	// than a cascading 401 storm from Phase B SDKs.
	if v := h.iapCheck.Load(); v != nil {
		if fn, ok := v.(func() error); ok && fn != nil {
			if err := fn(); err != nil {
				http.Error(w, "iap signer unhealthy: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}
