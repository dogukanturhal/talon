// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"github.com/prometheus/client_golang/prometheus"
)

// SignOutcome enumerates the outcome label values for the sign counter.
// Using typed constants prevents label-string typos scattered across the codebase.
type SignOutcome string

const (
	OutcomeOK              SignOutcome = "ok"
	OutcomeNonceReplay     SignOutcome = "nonce_replay"
	OutcomeDeviceCertInval SignOutcome = "device_cert_invalid"
	OutcomeTierInvalid     SignOutcome = "tier_invalid"
	OutcomeClockSkew       SignOutcome = "clock_skew"
	OutcomeVaultError      SignOutcome = "vault_error"
	OutcomeValidationError SignOutcome = "validation_error"
)

// ReconcileOutcome enumerates the outcome label values for the reconcile
// counter (POST /v1/reconcile-posture — the offline-spool replay path).
// Typed constants prevent label-string typos.
type ReconcileOutcome string

const (
	// OutcomeReconcileOK — a historical posture observation was accepted and
	// recorded to the audit stream (HTTP 202).
	OutcomeReconcileOK ReconcileOutcome = "ok"
	// OutcomeReconcileDuplicate — an already-seen (device, seq) was replayed;
	// idempotently accepted WITHOUT re-recording the audit line (HTTP 409).
	OutcomeReconcileDuplicate ReconcileOutcome = "duplicate"
	// OutcomeReconcileValidationError — JSON schema / field validation failed
	// (HTTP 400). NB: unlike the live path there is NO clock_skew outcome —
	// reconcile records are intentionally historical.
	OutcomeReconcileValidationError ReconcileOutcome = "validation_error"
	// OutcomeReconcileDeviceCertInval — device-cert chain / SPIFFE-SAN / EKU
	// check failed, incl. body/cert device_uuid mismatch (HTTP 401/403).
	OutcomeReconcileDeviceCertInval ReconcileOutcome = "device_cert_invalid"
)

// Metrics holds all Prometheus collectors for the posture-signer service.
// The naming prefix `talon_posture_signer_*` follows the convention
// established in internal/observability/metrics.go (`talon_*` namespace,
// component infix, snake_case suffix).
type Metrics struct {
	// SignTotal counts every POST /v1/sign-posture attempt, labelled by
	// outcome. On-call triage: a non-zero vault_error rate = Vault
	// Transit unreachable; a non-zero nonce_replay rate = abnormal
	// (could indicate a replay attack or a mis-configured agent clock).
	SignTotal *prometheus.CounterVec

	// SignDuration measures end-to-end latency of the sign RPC, which
	// is dominated by the Vault Transit round-trip. Alert threshold:
	// p99 > 200ms = Vault latency regression (Vault HA internal network
	// issue or heavy Transit load from another service).
	SignDuration *prometheus.HistogramVec

	// JWKSCacheAge tracks how many seconds since the JWKS pubkey set was
	// last refreshed from Vault Transit `keys/posture-signer`. If this
	// grows beyond ~600s (twice the refresh interval) it means Vault is
	// unreachable AND the in-memory cache is coasting on stale keys —
	// alert before the cache crosses the key rotation boundary.
	JWKSCacheAge prometheus.Gauge

	// NonceCacheSize is the current number of entries in the nonce dedup
	// cache. Steady-state ≈ (heartbeats-per-10min). A sudden spike
	// (e.g. 10x baseline) at low sign throughput indicates a stuck GC
	// or a nonce-flood attack.
	NonceCacheSize prometheus.Gauge

	// ReconcileTotal counts every POST /v1/reconcile-posture attempt (the
	// offline-spool replay path), labelled by outcome. Mirrors SignTotal.
	// On-call triage: a non-zero device_cert_invalid rate = spool being
	// replayed from a de-authorised device; a high duplicate:ok ratio =
	// an agent whose flush ack is being lost (retry storm), not fatal but
	// worth correlating with reconcile_dedup_size growth.
	ReconcileTotal *prometheus.CounterVec

	// ReconcileDuration measures end-to-end latency of the reconcile RPC.
	// It has NO Vault round-trip (no JWS is minted — a reconciled record is
	// audited, not signed), so p99 should be sub-millisecond; a regression
	// here points at audit-sink or dedup-map contention, not Vault.
	ReconcileDuration *prometheus.HistogramVec

	// ReconcileDedupSize is the current number of (device, seq) idempotency
	// keys held in the reconcile dedup cache. Steady-state ≈ 0 (reconcile is
	// bursty: it spikes when a previously-offline fleet reconnects, then
	// drains as entries age past the dedup TTL). A monotonically climbing
	// value at low reconcile throughput indicates a stuck GC.
	ReconcileDedupSize prometheus.Gauge
}

// NewMetrics constructs and registers all posture-signer metrics with the
// given registerer. Pass prometheus.DefaultRegisterer to expose them on
// the shared /metrics endpoint, or a fresh prometheus.Registry for
// isolation (used in unit tests).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		SignTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "sign_total",
			Help: "Total POST /v1/sign-posture attempts by outcome. " +
				"outcome=ok: JWS issued. " +
				"outcome=nonce_replay: duplicate nonce within 10min dedup window (replay attempt or misconfigured agent). " +
				"outcome=device_cert_invalid: leaf cert chain / SAN / EKU check failed. " +
				"outcome=tier_invalid: unknown tier string in heartbeat body. " +
				"outcome=clock_skew: agent iat more than ±30s from server clock. " +
				"outcome=vault_error: Vault Transit sign call failed. " +
				"outcome=validation_error: JSON schema / field validation failed.",
		}, []string{"outcome"}),

		SignDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "sign_duration_seconds",
			Help: "End-to-end latency of POST /v1/sign-posture (Vault Transit round-trip dominant). " +
				"p99 > 200ms indicates Vault latency regression.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0},
		}, []string{"outcome"}),

		JWKSCacheAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "jwks_cache_age_seconds",
			Help: "Seconds since the JWKS public key set was last refreshed from Vault Transit. " +
				"Alert if > 600s (2× the 5-minute refresh interval): indicates Vault unreachable " +
				"and the service is coasting on potentially stale keys.",
		}),

		NonceCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "nonce_cache_size",
			Help: "Current number of entries in the nonce dedup cache. " +
				"Steady state ≈ (active_devices × heartbeats_per_10min). " +
				"Spike without matching sign_total increase = nonce-flood or GC failure.",
		}),

		ReconcileTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "reconcile_total",
			Help: "Total POST /v1/reconcile-posture attempts by outcome (offline-spool replay). " +
				"outcome=ok: historical observation recorded to the audit stream. " +
				"outcome=duplicate: already-seen (device,seq) idempotently accepted, not re-recorded. " +
				"outcome=device_cert_invalid: leaf cert chain / SPIFFE-SAN / EKU check failed (incl. device mismatch). " +
				"outcome=validation_error: JSON schema / field / captured_at validation failed.",
		}, []string{"outcome"}),

		ReconcileDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "reconcile_duration_seconds",
			Help: "End-to-end latency of POST /v1/reconcile-posture. " +
				"No Vault round-trip (no JWS minted); p99 should be sub-millisecond.",
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
		}, []string{"outcome"}),

		ReconcileDedupSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Subsystem: "posture_signer",
			Name:      "reconcile_dedup_size",
			Help: "Current number of (device, seq) idempotency keys in the reconcile dedup cache. " +
				"Bursty: spikes on fleet reconnect, drains as entries age past the dedup TTL. " +
				"Monotonic climb at low reconcile_total rate = GC failure.",
		}),
	}

	reg.MustRegister(
		m.SignTotal,
		m.SignDuration,
		m.JWKSCacheAge,
		m.NonceCacheSize,
		m.ReconcileTotal,
		m.ReconcileDuration,
		m.ReconcileDedupSize,
	)
	return m
}

// RecordSign records the outcome and duration of a sign attempt.
func (m *Metrics) RecordSign(outcome SignOutcome, durationSeconds float64) {
	m.SignTotal.WithLabelValues(string(outcome)).Inc()
	m.SignDuration.WithLabelValues(string(outcome)).Observe(durationSeconds)
}

// RecordReconcile records the outcome and duration of a reconcile attempt.
func (m *Metrics) RecordReconcile(outcome ReconcileOutcome, durationSeconds float64) {
	m.ReconcileTotal.WithLabelValues(string(outcome)).Inc()
	m.ReconcileDuration.WithLabelValues(string(outcome)).Observe(durationSeconds)
}
