// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/talon/internal/caep"
)

const (
	// maxRequestBody is the hard limit on incoming JSON bodies. 32 KB is
	// more than enough for a heartbeat with a rich compliance map (typical
	// size is ~500 bytes); a body exceeding this limit indicates a
	// mis-configured agent or an attempted payload-size DoS.
	maxRequestBody = 32 * 1024

	// JWKSRefreshInterval is how often the background loop in
	// cmd/posture-signer calls RefreshJWKS to pick up Vault Transit key
	// rotations (90-day auto-rotate period per posture-signer-key.tf).
	// 5 minutes ensures fresh keys are published before the JWKSCacheAge
	// alert fires at 600 seconds. Exported so cmd/posture-signer can use
	// the same constant (single source of truth — the docstring above
	// references this exact value via the JWKSCacheAge alert threshold).
	JWKSRefreshInterval = 5 * time.Minute

	// requestDeadline is the per-request context deadline. Vault Transit
	// p99 is typically <50ms on the LAN; 5s is generous and prevents a
	// stalled Vault round-trip from holding the goroutine indefinitely.
	requestDeadline = 5 * time.Second
)

// Server is the posture-signer HTTP server. It exposes:
//   - POST /v1/sign-posture     — heartbeat acceptance + JWS issuance
//   - GET  /.well-known/jwks.json — public key publication
//   - GET  /healthz              — liveness (always 200 once started)
//   - GET  /readyz               — readiness (200 only after JWKS loaded)
type Server struct {
	log            *zap.Logger
	issuer         *JWSIssuer
	nonces         *NonceCache
	deviceVerifier *DeviceCertVerifier
	metrics        *Metrics
	mux            *http.ServeMux

	// CAEP transmitter (ADR 0043). nil = disabled (no emission). When set,
	// the server emits a device-compliance-change SET on a compliance
	// transition. complianceKeys defines the baseline; tracker dedupes.
	caep           *caep.Transmitter
	complianceKeys []string
	tracker        *complianceTracker

	// dedup is the (device, seq) idempotency cache for POST
	// /v1/reconcile-posture (offline-spool replay). Server-owned; its GC
	// goroutine is started in NewServer and stopped by Close.
	dedup *reconcileDedup

	// emitWG tracks the in-flight CAEP emission goroutines spawned by
	// maybeEmitComplianceChange so Close can drain them. Without it those
	// goroutines are fire-and-forget: a compliance transition emitted just
	// before shutdown is lost, and in tests the goroutine can outlive the
	// test function and log into a finished *testing.T (a real DATA RACE
	// against testing's own state — observed on main 2026-08-05 in
	// TestMaybeEmitComplianceChange_EmitsOnTransitionOnly).
	emitWG sync.WaitGroup
}

// ServerConfig groups the Server dependencies.
type ServerConfig struct {
	Logger         *zap.Logger
	Issuer         *JWSIssuer
	Nonces         *NonceCache
	DeviceVerifier *DeviceCertVerifier
	Metrics        *Metrics
	// CAEP, when non-nil, turns on CAEP device-compliance-change emission.
	CAEP *caep.Transmitter
	// RequiredComplianceKeys is the compliance baseline (keys that must be
	// boolean-true for a device to count as compliant).
	RequiredComplianceKeys []string
}

// NewServer constructs the HTTP server and registers all routes.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		log:            cfg.Logger,
		issuer:         cfg.Issuer,
		nonces:         cfg.Nonces,
		deviceVerifier: cfg.DeviceVerifier,
		metrics:        cfg.Metrics,
		mux:            http.NewServeMux(),
		caep:           cfg.CAEP,
		complianceKeys: cfg.RequiredComplianceKeys,
		tracker:        newComplianceTracker(),
		dedup:          newReconcileDedup(),
	}
	s.mux.HandleFunc("/v1/sign-posture", s.handleSignPosture)
	s.mux.HandleFunc("/v1/reconcile-posture", s.handleReconcilePosture)
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	return s
}

// Handler returns the root http.Handler. Intended to be passed to
// http.Server.Handler so integration tests can use httptest.NewServer.
func (s *Server) Handler() http.Handler { return s.mux }

// Close releases server-owned background resources — the reconcile
// idempotency cache's GC goroutine, and any in-flight CAEP emission. It
// BLOCKS until outstanding emissions finish (each is bounded by its own
// 5s context timeout, so Close is bounded too). Idempotent. Call during
// graceful shutdown (cmd/posture-signer) after the HTTP listener has
// drained, so a compliance transition emitted on the last request is not
// dropped.
func (s *Server) Close() {
	if s.dedup != nil {
		s.dedup.stopGC()
	}
	s.emitWG.Wait()
}

// handleSignPosture handles POST /v1/sign-posture.
func (s *Server) handleSignPosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is accepted")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
	defer cancel()

	start := time.Now()
	log := s.log.With(
		zap.String("handler", "sign-posture"),
		zap.String("remote_addr", r.RemoteAddr),
	)

	// Strict JSON decoder: DisallowUnknownFields prevents silently
	// ignoring a fat-fingered field name in the agent payload.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req HeartbeatRequest
	if err := dec.Decode(&req); err != nil {
		log.Warn("heartbeat JSON decode failed", zap.Error(err))
		s.metrics.RecordSign(OutcomeValidationError, time.Since(start).Seconds())
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	// Field-level validation.
	if err := req.Validate(time.Now()); err != nil {
		log.Warn("heartbeat validation failed", zap.Error(err), zap.String("device", redactDeviceUUID(req.DeviceUUID)))
		// Clock-skew and tier errors have distinct outcome labels for
		// alerting precision.
		outcome := OutcomeValidationError
		if isClockSkewError(err) {
			outcome = OutcomeClockSkew
		} else if isTierError(err) {
			outcome = OutcomeTierInvalid
		}
		s.metrics.RecordSign(outcome, time.Since(start).Seconds())
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	// Device certificate chain + SPIFFE SAN validation. Source-aware:
	// production behind Envoy Gateway → X-Forwarded-Client-Cert header
	// carries the device cert; dev/test direct-mTLS → r.TLS.PeerCertificates.
	// VerifyRequest picks the right source (XFCC-first, fail-closed if
	// XFCC malformed) and returns the verified leaf for cnf-claim binding.
	leaf, err := s.deviceVerifier.VerifyRequest(r, req.DeviceUUID)
	if err != nil {
		log.Warn("device cert verification failed",
			zap.Error(err), zap.String("device", redactDeviceUUID(req.DeviceUUID)))
		s.metrics.RecordSign(OutcomeDeviceCertInval, time.Since(start).Seconds())
		status := http.StatusUnauthorized
		code := "device_cert_invalid"
		switch {
		case errors.Is(err, ErrSANMismatch):
			status = http.StatusForbidden
			code = "device_cert_uuid_mismatch"
		case errors.Is(err, ErrXFCCMissing):
			code = "xfcc_missing"
		case errors.Is(err, ErrXFCCMalformed), errors.Is(err, ErrXFCCMissingCert):
			status = http.StatusBadRequest
			code = "xfcc_invalid"
		}
		writeError(w, status, code, err.Error())
		return
	}

	// Replay guard: nonce must be unique within the 10-minute window.
	if !s.nonces.Accept(req.Nonce) {
		log.Warn("nonce replay detected", zap.String("device", redactDeviceUUID(req.DeviceUUID)))
		s.metrics.RecordSign(OutcomeNonceReplay, time.Since(start).Seconds())
		writeError(w, http.StatusUnauthorized, "nonce_replay",
			"nonce was already consumed within the dedup window")
		return
	}

	// Issue JWS via Vault Transit, binding it to the device cert
	// thumbprint (RFC 8705 cnf.x5t#S256). This proves the JWS was
	// minted in the SAME mTLS exchange that authenticated this
	// specific device cert — downstream verifiers (Talon) that see
	// the inbound device cert can match its SHA-256 against the
	// cnf claim and reject mismatches. Closes the JWS-replay-onto-
	// different-mTLS attack class.
	req.deviceCertThumbprint = computeX5tS256(leaf)
	// Tier and device_cert_valid are server-attested from the verified cert,
	// overriding whatever the agent put in compliance.
	applyAttestedCompliance(&req, leaf)
	// user_sub is likewise server-attested: overwrite the agent's value with
	// the cert CN (jess-stamped Falcon-ID sub), warning on a mismatch.
	if cn := attestedUserSub(leaf); cn != "" {
		if req.UserSub != cn {
			log.Warn("agent user_sub differs from device cert CN; using cert CN",
				zap.String("device", redactDeviceUUID(req.DeviceUUID)))
		}
		req.UserSub = cn
	}
	jws, expiresAt, err := s.issuer.IssueJWS(ctx, &req)
	if err != nil {
		log.Error("vault transit sign failed", zap.Error(err), zap.String("device", redactDeviceUUID(req.DeviceUUID)))
		s.metrics.RecordSign(OutcomeVaultError, time.Since(start).Seconds())
		writeError(w, http.StatusServiceUnavailable, "vault_error",
			"signing backend temporarily unavailable")
		return
	}

	s.metrics.RecordSign(OutcomeOK, time.Since(start).Seconds())
	s.metrics.NonceCacheSize.Set(float64(s.nonces.Size()))

	log.Info("posture JWS issued",
		zap.String("device", redactDeviceUUID(req.DeviceUUID)),
		zap.String("tier", string(req.Tier)),
		zap.Duration("elapsed", time.Since(start)),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HeartbeatResponse{ //nolint:errcheck,gosec // G104: w.Write/Encode errors on response writers are intentionally unhandled per Go std lib idiom (the client's transport already detected the disconnect)
		JWS:       jws,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})

	// ADR 0043 — CAEP transmitter: emit a device-compliance-change SET when
	// (and only when) this device crosses the compliance boundary. Done
	// after the response + in a goroutine so it never delays or fails the
	// heartbeat; losing one audit event is acceptable, a slow heartbeat is not.
	s.maybeEmitComplianceChange(&req)
}

// maybeEmitComplianceChange evaluates the heartbeat's compliance, and on a
// transition (vs the last observed status for this device) fires a CAEP
// device-compliance-change SET to the receiver. No-op when CAEP is disabled.
func (s *Server) maybeEmitComplianceChange(req *HeartbeatRequest) {
	if s.caep == nil {
		return
	}
	compliant := isCompliant(req.Compliance, s.complianceKeys)
	if !s.tracker.observe(req.DeviceUUID, compliant) {
		return // first observation or no change
	}
	set := s.caep.BuildDeviceComplianceChange(req.UserSub, req.DeviceUUID, compliant)
	device := redactDeviceUUID(req.DeviceUUID)
	s.emitWG.Add(1)
	go func() {
		defer s.emitWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.caep.Emit(ctx, set); err != nil {
			s.log.Warn("CAEP device-compliance-change emit failed", zap.String("device", device), zap.Error(err))
			return
		}
		s.log.Info("CAEP device-compliance-change emitted", zap.String("device", device), zap.Bool("compliant", compliant))
	}()
}

// handleJWKS serves GET /.well-known/jwks.json.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is accepted")
		return
	}
	jwks := s.issuer.JWKS()
	// Update cache-age gauge so the alert can fire if Vault is unreachable.
	s.metrics.JWKSCacheAge.Set(s.issuer.JWKSCacheAge().Seconds())

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(jwks) //nolint:errcheck,gosec // G104: w.Write/Encode errors on response writers are intentionally unhandled per Go std lib idiom (the client's transport already detected the disconnect)
}

// handleHealthz is the liveness probe. Returns 200 as soon as the
// server is up and its goroutines are running.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok")) //nolint:errcheck,gosec // G104: w.Write/Encode errors on response writers are intentionally unhandled per Go std lib idiom (the client's transport already detected the disconnect)
}

// handleReadyz is the readiness probe. Returns 503 until the JWKS
// cache has been populated (i.e. Vault Transit is reachable). Kubernetes
// will not send traffic to this pod until /readyz returns 200.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.issuer.IsJWKSStale() {
		writeError(w, http.StatusServiceUnavailable, "jwks_not_ready",
			"JWKS cache not yet populated from Vault Transit")
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok")) //nolint:errcheck,gosec // G104: w.Write/Encode errors on response writers are intentionally unhandled per Go std lib idiom (the client's transport already detected the disconnect)
}

// writeError writes a JSON error body with a consistent shape:
//
//	{"error": "<code>", "message": "<detail>"}
func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck,gosec // G104: w.Write/Encode errors on response writers are intentionally unhandled per Go std lib idiom (the client's transport already detected the disconnect)
		"error":   code,
		"message": msg,
	})
}

// isClockSkewError returns true if err is a clock-skew validation
// failure from HeartbeatRequest.Validate. Uses errors.Is against the
// sentinel — robust to wrapping + message changes (string-matching the
// "iat:" prefix breaks the moment the error message is reformatted).
func isClockSkewError(err error) bool {
	return errors.Is(err, ErrClockSkew)
}

// isTierError returns true if err is a tier validation failure.
func isTierError(err error) bool {
	return errors.Is(err, ErrTierInvalid)
}

// redactDeviceUUID truncates a device UUID for log output. UUIDs are
// pseudo-PII under GDPR (linkable to a natural person via the
// iam_devices.user_sub join). Truncate to the first 8 hex chars +
// last 4 — enough for an operator to correlate with audit logs but
// not enough to enumerate or doxx.
func redactDeviceUUID(uuid string) string {
	if len(uuid) < 14 {
		return "<short>"
	}
	return uuid[:8] + "…" + uuid[len(uuid)-4:]
}
