// SPDX-License-Identifier: AGPL-3.0-or-later

// Package observability registers Prometheus metrics for Talon. Per ADR
// 0001 §6 the minimal set is:
//
//	talon_request_total{route,method,decision,status}
//	talon_auth_decision_total{route,decision,reason}
//	  decision: allow | deny | error | would_deny | would_error
//	  would_deny/would_error are audit-only (soak) would-have-denied/errored
//	  outcomes that fall through to allow — EXCLUDED from real deny/error
//	  rates (e.g. TalonAuthFailureRate) so soaks don't trip the alert.
//	talon_session_active_gauge
//	talon_oidc_handshake_total{step,outcome}
//
// Audit log events go to stdout JSON via internal/log; metrics are aggregate
// counters/gauges that don't carry per-user identifiers.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus collectors for Talon.
type Metrics struct {
	RequestTotal    *prometheus.CounterVec
	AuthDecision    *prometheus.CounterVec
	SessionActive   prometheus.Gauge
	OIDCHandshake   *prometheus.CounterVec
	UpstreamLatency *prometheus.HistogramVec

	// DecisionCache tracks the SpiceDB decision-cache hit ratio (boot
	// prompt §4 Gap 6 acceptance metric). Labels:
	//   result=hit              — cache served the answer
	//   result=miss              — cache forwarded to SpiceDB
	//   result=invalidate_subject — N entries dropped by revoke fan-out
	// `talon_decision_cache_hit_ratio` is a recording rule on top of
	// hit / (hit + miss).
	DecisionCache *prometheus.CounterVec

	// AuthzDecision counts decisions made by the v1beta1 pathRules
	// matcher (Phase 6b-3). Labels:
	//   rule   — PathRule.Name (the operator-authored identifier on
	//            the matched rule; empty when no rule matched and
	//            the host-default policy applied)
	//   action — "allow" | "deny" | "stepup" (the routing decision
	//            after policy overlay)
	//   route  — request host (so a single rule name shared across
	//            multiple hosts doesn't collide)
	//
	// Without this counter, operators can't tell in production which
	// rule fired — load-bearing for incident triage on routes that
	// have many overlapping rules (e.g., a 6-pathRule TalonRoute on
	// github.com).
	AuthzDecision *prometheus.CounterVec

	// EdgeRevokeBlock counts incoming requests blocked at Talon's edge
	// because the cookie's session is on a tombstone (talon:revoked:<cookieID>).
	// Tombstones are written by the BCL/FCL receivers when Falcon-ID
	// fans out a Sign Out via the revoke-by-sub / revoke-by-sid index
	// (per internal engineering notes memory).
	//
	// Labels:
	//   route — request host (e.g., "internal.example.com")
	//
	// Used by the post-Sign-Out E2E synthetic to assert the cascade
	// actually blocks subsequent requests within <5s of fan-out
	// (see talon/e2e/playwright/tests/slo-cascade.spec.ts).
	EdgeRevokeBlock *prometheus.CounterVec

	// IAPTokenSign counts every IAP identity-token mint attempt
	// (internal/identityjwt.Signer.Sign). Labels:
	//   route  — protected upstream (= JWT audience)
	//   result — "success" | "fail"
	//   kid    — the active signing kid (= JWS kid header on success)
	//
	// SOC + ops correlate this with the iap.token.mint_failed audit
	// events (Item 2) — a non-zero `fail` count + a sustained low
	// `success` rate on the same kid indicates a key-misload at
	// startup. Joins to the SDK's `iap.verify.*` Loki events through
	// the kid label during a rotation overlap window.
	IAPTokenSign *prometheus.CounterVec

	// IAPJWKSRequest counts every GET on Talon's
	// /.well-known/jwks.json endpoint. Labels:
	//   result — "success" | "unconfigured" | "error"
	// "unconfigured" fires the 503 path (signing key not provisioned;
	// JWKSHandler emits 503 from the nil-signer guard). Sustained
	// "unconfigured" on a prod cluster = Vault → ESO → Secret pipeline
	// broken.
	IAPJWKSRequest *prometheus.CounterVec

	// IAPActiveKid surfaces the current active signing kid as a label
	// on a constant-1 gauge — `talon_iap_active_kid{kid="…"} 1`. Lets
	// dashboards and alerting rules answer "which kid is signing right
	// now?" without scraping JWKS or grepping logs. Updated once at
	// startup; rotates by setting the new kid to 1 and the old to 0
	// after a rolling restart (single instance per kid in normal
	// operation; multiple temporarily during the overlap window).
	IAPActiveKid *prometheus.GaugeVec

	// IAPRetiredKidsPublished gauges the count of retired keys
	// currently published on JWKS alongside the active key (= the
	// rotation overlap window). Steady state == 0. Alert if this is
	// non-zero for longer than the documented 6-minute overlap.
	IAPRetiredKidsPublished prometheus.Gauge

	// DDILDegraded counts DDIL (Denied/Degraded/Intermittent/Limited-
	// connectivity) governed-degrade events — the Phase-3 fail-directions
	// where a central dependency is unreachable and Talon serves a signed,
	// time-boxed last-known-good decision instead of denying at t=0.
	// Labels:
	//   dependency — "jwks_svctoken" | "spicedb_pdp" | "session_store" | "posture"
	//   outcome    — "stale_served"   (JWKS: last-good keys served within budget;
	//                                   posture: a past-exp device posture served
	//                                   DEGRADED within the governed grace budget
	//                                   on a low/medium route — DDIL P3.10)
	//              | "offline_served" (PDP/session: cached decision served within budget)
	//              | "offline_denied" (PDP/session: no valid cached decision → fail closed;
	//                                   posture: a degraded posture DENIED on a
	//                                   critical/high route — governed downgrade)
	//              | "fail_closed"    (budget exhausted / breaker + no cache;
	//                                   posture: rejected past its grace deadline)
	// Steady state == 0. Any sustained non-zero rate means a central dependency
	// (Falcon-ID JWKS / SpiceDB / Redis) is unreachable, or devices are failing
	// to re-attest their posture in time; alert on it.
	DDILDegraded *prometheus.CounterVec
}

// New constructs and registers all Talon metrics with the given registry.
// Pass prometheus.DefaultRegisterer to expose them on /metrics.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RequestTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "request_total",
			Help:      "Total HTTP requests handled by Talon, by route/method/decision/status.",
		}, []string{"route", "method", "decision", "status"}),

		AuthDecision: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "auth_decision_total",
			Help:      "Total auth decisions per route. decision=allow|deny|error|would_deny|would_error (would_* = audit-only soak fall-throughs, excluded from real deny/error rates). reason set for deny/error/would_*.",
		}, []string{"route", "decision", "reason"}),

		SessionActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Name:      "session_active",
			Help:      "Number of currently-active sessions (best-effort gauge sampled every minute).",
		}),

		OIDCHandshake: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "oidc_handshake_total",
			Help:      "OIDC handshake step outcomes (start, callback, token_exchange, claims_validate).",
		}, []string{"step", "outcome"}),

		UpstreamLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "talon",
			Name:      "upstream_latency_seconds",
			Help:      "Latency of upstream proxy responses, in seconds, by route.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"route"}),

		DecisionCache: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "decision_cache_total",
			Help:      "SpiceDB decision-cache events: hits, misses, invalidations (count entries dropped per invalidate event).",
		}, []string{"result"}),

		EdgeRevokeBlock: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "edge_revoke_block_total",
			Help:      "Total requests blocked at Talon's edge by a session tombstone (BCL/FCL fan-out cascade — Phase 5b of 2026-05-10 tier-1 SLO restoration).",
		}, []string{"route"}),

		AuthzDecision: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "authz_decision_total",
			Help:      "Phase 6b-3 per-pathRule decisions: rule=name action=allow|deny|stepup route=host. Empty rule label = no pathRule matched, host-default applied.",
		}, []string{"rule", "action", "route"}),

		IAPTokenSign: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "iap_token_sign_total",
			Help:      "Total X-Talon-Identity-Token JWT sign attempts, by route/result/kid. Counts both successes (= every proxied request when signer is wired) and failures (rare; correlate with iap.token.mint_failed audit events).",
		}, []string{"route", "result", "kid"}),

		IAPJWKSRequest: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "iap_jwks_request_total",
			Help:      "Total GET requests on /.well-known/jwks.json. result=success when the active key was served, result=unconfigured when the signer wasn't wired (503), result=error on JSON marshal failure.",
		}, []string{"result"}),

		IAPActiveKid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "talon",
			Name:      "iap_active_kid",
			Help:      "Constant-1 gauge surfacing the currently-active IAP signing kid as a label. Dashboards/alerts read `kid` directly. Rotated by setting the new kid to 1 and decommissioning the old after the overlap window.",
		}, []string{"kid"}),

		IAPRetiredKidsPublished: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Name:      "iap_retired_kids_published",
			Help:      "Number of retired IAP signing keys currently published on JWKS alongside the active key (rotation overlap). Steady state == 0; alert if non-zero for > 6 minutes (Cloudflare-style N+1 overlap window).",
		}),

		DDILDegraded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Name:      "ddil_degraded_total",
			Help:      "DDIL Phase-3 governed-degrade events by dependency (jwks_svctoken|spicedb_pdp|session_store|posture) and outcome (stale_served|offline_served|offline_denied|fail_closed). Steady state == 0; a sustained non-zero rate means Falcon-ID JWKS, SpiceDB, or the Redis session store is unreachable, or devices are failing to re-attest their posture in time (posture: stale_served=degraded served on low/medium route, offline_denied=degraded denied on critical/high, fail_closed=past grace).",
		}, []string{"dependency", "outcome"}),
	}
	reg.MustRegister(
		m.RequestTotal, m.AuthDecision, m.SessionActive,
		m.OIDCHandshake, m.UpstreamLatency, m.DecisionCache,
		m.EdgeRevokeBlock, m.AuthzDecision,
		m.IAPTokenSign, m.IAPJWKSRequest, m.IAPActiveKid, m.IAPRetiredKidsPublished,
		m.DDILDegraded,
	)
	return m
}

// DDIL degraded-mode outcome label constants, shared by the JWKS stale
// window (P3.1) and the offline SpiceDB PDP (P3.1) wiring.
const (
	DDILDepJWKSSvctoken = "jwks_svctoken" //nolint:gosec // G101 false positive: Prometheus metric label value, not a credential
	DDILDepSpiceDBPDP   = "spicedb_pdp"
	DDILDepSessionStore = "session_store"
	DDILDepPosture      = "posture"

	DDILOutcomeStaleServed   = "stale_served"
	DDILOutcomeOfflineServed = "offline_served"
	DDILOutcomeOfflineDenied = "offline_denied"
	DDILOutcomeFailClosed    = "fail_closed"
)

// OnCacheHit / OnCacheMiss / OnCacheInvalidate implement the
// spicedb.CacheMetrics interface so the binary can wire *Metrics
// directly as the cache's metrics sink (cmd/talon).
func (m *Metrics) OnCacheHit()  { m.DecisionCache.WithLabelValues("hit").Inc() }
func (m *Metrics) OnCacheMiss() { m.DecisionCache.WithLabelValues("miss").Inc() }
func (m *Metrics) OnCacheInvalidate(dropped int, _ string) {
	m.DecisionCache.WithLabelValues("invalidate_subject").Add(float64(dropped))
}

// OnOfflineServed / OnOfflineDenied implement the spicedb.OfflinePDPMetrics
// interface so the binary can wire *Metrics directly as the DDIL offline
// PDP's sink. A served event means a signed last-known-good decision was
// honoured during a SpiceDB outage (within budget); a denied event means
// no valid cached decision existed and the PDP fell through to fail-closed.
func (m *Metrics) OnOfflineServed(_ bool) {
	m.DDILDegraded.WithLabelValues(DDILDepSpiceDBPDP, DDILOutcomeOfflineServed).Inc()
}
func (m *Metrics) OnOfflineDenied() {
	m.DDILDegraded.WithLabelValues(DDILDepSpiceDBPDP, DDILOutcomeOfflineDenied).Inc()
}

// OnSessionOfflineServed / OnSessionOfflineDenied implement the
// session.OfflineSessionMetrics interface (session-scoped method names so a
// single *Metrics can also satisfy spicedb.OfflinePDPMetrics without a clash)
// so the binary can wire *Metrics directly as the DDIL P3.1 offline
// session-cache sink. A served event means a signed last-known-good session
// was honoured during a Redis outage (within budget); a denied event means no
// valid cached session existed and the read fell through to fail-closed.
func (m *Metrics) OnSessionOfflineServed() {
	m.DDILDegraded.WithLabelValues(DDILDepSessionStore, DDILOutcomeOfflineServed).Inc()
}
func (m *Metrics) OnSessionOfflineDenied() {
	m.DDILDegraded.WithLabelValues(DDILDepSessionStore, DDILOutcomeOfflineDenied).Inc()
}

// Handler returns the http.Handler that exposes /metrics in prometheus
// text format, scoped to the registry the binary actually registered
// its metrics on.
//
// The previous (bug) implementation returned `promhttp.Handler()` which
// is bound to the DEFAULT (global) prometheus registry. cmd/talon
// creates a fresh `reg := prometheus.NewRegistry()` and registers all
// talon_* metrics on `reg`, NOT the default registry — so every
// `talon_*` series was unscrapeable from /metrics. Found during
// Phase 4 svctoken canary verify when the verification gate
// (`talon_auth_decision_total{reason=svctoken,...}` > 0) appeared
// permanently stuck at zero despite live decisions being made.
//
// Callers MUST pass the same *prometheus.Registry they handed to
// New() so the scoped HandlerFor renders the registered series.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
}
