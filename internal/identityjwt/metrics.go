// SPDX-License-Identifier: AGPL-3.0-or-later

// metrics.go — observability interface for the verifier path.
//
// Why a custom interface instead of a direct prometheus dependency
// ----------------------------------------------------------------
// identityjwt is consumed by Go upstreams behind Talon. Pulling
// prometheus/client_golang into this package would force every
// upstream to take that dep (or fight the build to exclude it).
// Tier-1 supply-chain hygiene says: define a tiny interface here,
// let consumers wire a real Prometheus-backed implementation in
// their main package. The default is a no-op so upstreams that
// don't care pay nothing.
//
// Symmetry with the mint side
// ---------------------------
// Talon's `observability.Metrics` emits the canonical sign-side
// counters (`talon_iap_token_sign_total`, `talon_iap_jwks_request_total`,
// `talon_iap_active_kid`). This interface is the matching verify-
// side surface. SOC dashboards correlate both sides on the `kid`
// label during a rotation window.
//
// Suggested Prometheus shape for upstream services adopting the
// interface (see examples/iap-upstream-go for a wiring reference):
//
//	myservice_iap_verify_total{audience, result, reason, kid} counter
//	myservice_iap_jwks_fetch_total{result}                     counter
//	myservice_iap_replay_blocked_total{audience}               counter
package identityjwt

// VerifierMetrics is the optional observability sink the Verifier
// invokes on each verify path decision. All methods MUST be cheap
// (microseconds — they fire on every protected request) and
// safe for concurrent calls. nil implementations are tolerated
// via the noopMetrics fallback.
type VerifierMetrics interface {
	// OnVerifySuccess fires when a token verified cleanly. kid is
	// the JWS header kid; useful for correlating verifier load
	// against a specific key generation during rotation.
	OnVerifySuccess(audience, kid string)

	// OnVerifyFailure fires when a token failed verification.
	// reason maps to the IapVerifyReason taxonomy shared with the
	// TypeScript SDK (signature_failed / expired / issuer_mismatch /
	// audience_mismatch / not_yet_valid / alg_not_allowed /
	// jwt_invalid / unknown / replay).
	OnVerifyFailure(audience, kid, reason string)

	// OnJWKSFetch fires after every JWKS HTTP round-trip. result is
	// "success" or "failure". Counts both cold-start fetches and
	// TTL-expiry refetches.
	OnJWKSFetch(result string)

	// OnReplayBlocked fires when the replay cache rejected a token
	// whose jti was seen recently. Only fires when replay protection
	// is enabled via VerifierConfig.ReplayCacheSize or
	// VerifierConfig.ReplayCache.
	OnReplayBlocked(audience string)
}

// noopMetrics is the zero-cost default used when
// VerifierConfig.Metrics is nil. All methods are inline-friendly
// no-ops; the Go compiler typically eliminates the call entirely
// after inlining.
type noopMetrics struct{}

func (noopMetrics) OnVerifySuccess(string, string)         {}
func (noopMetrics) OnVerifyFailure(string, string, string) {}
func (noopMetrics) OnJWKSFetch(string)                     {}
func (noopMetrics) OnReplayBlocked(string)                 {}
