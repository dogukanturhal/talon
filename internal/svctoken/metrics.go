// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

// VerifierMetrics is the observability sink invoked on every verify
// outcome. Implementations are Prom-backed in production. The interface
// is deliberately narrow + dep-free (no prometheus/client_golang
// import) so the package stays portable and tests can use a fake.
//
// Wire shape per outcome:
//
//	talon_svctoken_verify_total{host, client, kid, reason}
//
// Cardinality budget (label combinations bounded):
//   - host: per Talon-fronted upstream (~20)
//   - client: per registered service client (~30)
//   - kid: per active+retired JWKS key (1-3 during rotation, else 1)
//   - reason: enum Reason (~14 values)
//
// At steady state ≈ 20×30×1×14 ≈ 8400 series. Within Prom's safe
// per-job cardinality envelope.
type VerifierMetrics interface {
	RecordVerify(s VerifyMetricSample)
}

// VerifyMetricSample is the bag of labels recorded per verify outcome.
// Empty strings are valid (e.g., a malformed token may have no kid).
type VerifyMetricSample struct {
	Host     string
	ClientID string
	Kid      string
	Reason   Reason
}

// noopMetrics is the zero-allocation default used when
// VerifierConfig.Metrics is nil.
type noopMetrics struct{}

func (noopMetrics) RecordVerify(VerifyMetricSample) {}
