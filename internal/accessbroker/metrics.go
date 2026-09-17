// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"github.com/prometheus/client_golang/prometheus"
)

// SessionOutcome enumerates the outcome label for the session counter.
// Typed constants prevent label-string typos across the codebase.
type SessionOutcome string

const (
	// OutcomeOK — a session was authenticated, brokered, and closed
	// cleanly (client close, backend EOF, or absolute-TTL deadline).
	OutcomeOK SessionOutcome = "ok"
	// OutcomeUnauthenticated — the IAP identity token was missing or did
	// not verify (no relay opened).
	OutcomeUnauthenticated SessionOutcome = "unauthenticated"
	// OutcomeWrongChannel — the verified session was not channel=clientless
	// (the broker only serves agentless sessions; agent sessions use the
	// native client).
	OutcomeWrongChannel SessionOutcome = "wrong_channel"
	// OutcomeBackendUnavailable — the jess SSH backend could not be
	// dialled (ErrBackendNotWired in the scaffold, or a real dial error).
	OutcomeBackendUnavailable SessionOutcome = "backend_unavailable"
	// OutcomeUpgradeFailed — the WebSocket handshake/hijack failed.
	OutcomeUpgradeFailed SessionOutcome = "upgrade_failed"
	// OutcomeRelayError — a transport error broke an established relay.
	OutcomeRelayError SessionOutcome = "relay_error"
)

// Metrics holds the Prometheus collectors for the access-broker. The
// naming prefix `talon_access_broker_*` follows the convention in
// internal/observability/metrics.go (`talon_*` namespace, component
// infix, snake_case suffix).
type Metrics struct {
	// SessionTotal counts every brokered-session attempt by outcome.
	// On-call triage: a non-zero backend_unavailable rate while traffic
	// is expected = the jess SSH broker is unreachable; a non-zero
	// unauthenticated rate at a steady-state route = a misconfigured
	// IAP verifier or probing.
	SessionTotal *prometheus.CounterVec

	// SessionsActive is the current number of live brokered relays.
	// Capacity-planning signal; also catches goroutine/relay leaks if it
	// climbs without a matching client count.
	SessionsActive prometheus.Gauge

	// BytesRelayed counts relayed bytes by direction
	// (direction=to_backend|to_client). Useful for data-exfil dashboards
	// (ADR 0044 calls out the relay as the policy point for download
	// volume) and capacity planning.
	BytesRelayed *prometheus.CounterVec

	// SessionDuration measures brokered-session wall-clock lifetime in
	// seconds — distribution of how long agentless terminal sessions run.
	SessionDuration prometheus.Histogram

	// PolicyDrops counts clipboard/file-transfer events dropped at the
	// relay edge by the RDP data policy (ADR 0044 "Data exfil"), labelled
	// by reason (clipboard_to_client|clipboard_to_server|file_to_client|
	// file_to_server). A non-zero rate is a security signal: a clientless
	// user attempting to copy/paste/exfiltrate against a route whose policy
	// forbids it. nil-safe (the RDP relay no-ops when Metrics is nil).
	PolicyDrops *prometheus.CounterVec
}

// NewMetrics constructs and registers all access-broker metrics with the
// given registerer. Pass a fresh prometheus.Registry for isolation
// (used in unit tests), or the process registry in cmd/access-broker.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		SessionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Subsystem: "access_broker",
			Name:      "session_total",
			Help: "Total clientless brokered-session attempts by outcome. " +
				"outcome=ok: session brokered + closed cleanly. " +
				"outcome=unauthenticated: IAP identity token missing/invalid. " +
				"outcome=wrong_channel: verified session was not channel=clientless. " +
				"outcome=backend_unavailable: jess SSH backend dial failed. " +
				"outcome=upgrade_failed: WebSocket handshake/hijack failed. " +
				"outcome=relay_error: transport error broke an established relay.",
		}, []string{"outcome"}),
		SessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "talon",
			Subsystem: "access_broker",
			Name:      "sessions_active",
			Help:      "Current number of live clientless brokered relays.",
		}),
		BytesRelayed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Subsystem: "access_broker",
			Name:      "bytes_relayed_total",
			Help:      "Total bytes relayed by direction (to_backend|to_client).",
		}, []string{"direction"}),
		SessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "talon",
			Subsystem: "access_broker",
			Name:      "session_duration_seconds",
			Help:      "Wall-clock lifetime of a brokered clientless session.",
			Buckets:   []float64{1, 5, 15, 60, 300, 900, 1800, 3600},
		}),
		PolicyDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "talon",
			Subsystem: "access_broker",
			Name:      "policy_drops_total",
			Help: "Clipboard/file-transfer events dropped at the RDP relay edge by " +
				"the data policy (ADR 0044 data-exfil control), by reason " +
				"(clipboard_to_client|clipboard_to_server|file_to_client|file_to_server).",
		}, []string{"reason"}),
	}
	reg.MustRegister(
		m.SessionTotal,
		m.SessionsActive,
		m.BytesRelayed,
		m.SessionDuration,
		m.PolicyDrops,
	)
	return m
}
