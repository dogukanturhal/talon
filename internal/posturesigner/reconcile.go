// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

// reconcile.go — POST /v1/reconcile-posture: the server side of the HexxLock
// Access agent's offline posture spool (DDIL Phase 3.7).
//
// When the posture-signer is unreachable the agent cannot complete the live
// /v1/sign-posture exchange (that path enforces a tight ±30s iat-freshness
// window a stale report can never satisfy). Instead the agent durably spools
// each report and, on reconnect, replays them one-at-a-time here. This
// endpoint mirrors sign-posture's auth (device-cert mTLS / XFCC + SPIFFE-SAN
// binding), metrics, and structured logging, but with four deliberate
// differences:
//
//  1. It accepts a historical ReconcileRecord (report + captured_at + seq),
//     NOT a live heartbeat.
//  2. It applies NO iat-freshness gate — the record is explicitly historical.
//  3. It does NOT mint a posture JWS: the purpose is audit/compliance fidelity
//     of PAST device state, not granting CURRENT access. The observation is
//     recorded to the audit stream with observed_at = captured_at.
//  4. It never advances the device's "current" freshness/last-seen (no nonce
//     is consumed in the live cache, no CAEP compliance-transition is emitted),
//     so a 2-hour-old report can never make a device look freshly checked-in.
//
// Idempotency: the agent's flush is at-least-once (a lost ack causes a retry).
// The receiver dedups on (device_uuid, seq) so a replayed record is accepted
// (HTTP 409, treated as success by the agent) WITHOUT duplicating the audit
// record — at-least-once sender + idempotent receiver = effectively-once.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// EventPostureReconcile is the audit discriminator stamped on every
	// recorded historical posture observation. SOC/Wazuh rules grep this
	// marker to tell a reconciled (offline-spool) observation apart from a
	// live sign-posture heartbeat. Mirrors the `event` discriminator
	// convention of internal/audit.
	EventPostureReconcile = "posture.reconcile"

	// reconcileDedupTTL bounds how long a (device, seq) idempotency key is
	// remembered. A retried flush lands within seconds (in-session retry) to
	// at most an agent-restart-during-flush window; 24h is generous headroom
	// while keeping the map bounded by (unique offline reports flushed in a
	// day). A record whose key has aged out and is somehow re-flushed would
	// be re-recorded — an append-only audit stream tolerates that rare
	// double-count; it never grants access.
	reconcileDedupTTL = 24 * time.Hour

	// reconcileDedupGCInterval is how often the background sweep evicts
	// entries older than reconcileDedupTTL.
	reconcileDedupGCInterval = time.Hour
)

// ReconcileRecord is one durably-spooled offline posture report replayed to
// POST /v1/reconcile-posture. Its JSON shape MUST match the agent's Rust
// `ReconcileRecord` (access-agent crates/heartbeat-client) EXACTLY — the
// decoder runs DisallowUnknownFields, so field names and nesting are load-
// bearing:
//
//		{ "seq": <u64>, "captured_at": "<RFC3339>", "report": <HeartbeatRequest> }
//
//	  - seq         — device-monotonic sequence; the (device, seq) idempotency key.
//	  - captured_at — RFC3339 time the posture was actually collected offline;
//	    used as the audit observation time (observed_at), NOT time.Now().
//	  - report      — the ORIGINAL HeartbeatRequest verbatim (its own nonce/iat
//	    preserved for audit fidelity). Same struct + json tags the live path
//	    decodes, so user_sub stays omitempty-compatible.
type ReconcileRecord struct {
	Seq        uint64           `json:"seq"`
	CapturedAt string           `json:"captured_at"`
	Report     HeartbeatRequest `json:"report"`
}

// reconcileDedup is a thread-safe, TTL-bounded set of (device, seq)
// idempotency keys. It mirrors NonceCache's memory model (sync.Map +
// background GC goroutine guarded by sync.Once) so a replayed flush is
// deduped without an external store. The endpoint owns one; Server.Close
// stops the GC goroutine at shutdown.
type reconcileDedup struct {
	m        sync.Map // key: string "device:seq", val: time.Time (first seen)
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	now      func() time.Time // injectable for tests
}

// newReconcileDedup constructs the cache and starts its GC goroutine.
// stop() must be called when it is no longer needed.
func newReconcileDedup() *reconcileDedup {
	c := &reconcileDedup{
		stop: make(chan struct{}),
		done: make(chan struct{}),
		now:  time.Now,
	}
	go c.gc()
	return c
}

// dedupKey is the idempotency key for a record: device_uuid + ":" + seq.
func dedupKey(deviceUUID string, seq uint64) string {
	return deviceUUID + ":" + strconv.FormatUint(seq, 10)
}

// firstSeen records key and returns true iff this is the FIRST time it has
// been seen within the TTL window. A return of false means the record is a
// duplicate (retried flush) and must NOT be re-recorded to the audit stream.
// Safe for concurrent use: sync.Map.LoadOrStore is the linearization point,
// so a racing double-flush yields exactly one true.
func (c *reconcileDedup) firstSeen(key string) bool {
	ts := c.now()
	actual, loaded := c.m.LoadOrStore(key, ts)
	if !loaded {
		return true
	}
	// Already present — accept as new only if the prior entry has aged out
	// (a GC cycle just hasn't swept it yet).
	if ts.Sub(actual.(time.Time)) > reconcileDedupTTL {
		c.m.Store(key, ts)
		return true
	}
	return false
}

// size returns the current entry count (incl. not-yet-swept expired entries).
func (c *reconcileDedup) size() int {
	var n int
	c.m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// stopGC halts the background sweep goroutine. Idempotent (sync.Once) so a
// double stop during shutdown can't panic on close-of-closed-channel.
func (c *reconcileDedup) stopGC() {
	c.stopOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
}

func (c *reconcileDedup) gc() {
	defer close(c.done)
	ticker := time.NewTicker(reconcileDedupGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *reconcileDedup) sweep() {
	deadline := c.now().Add(-reconcileDedupTTL)
	c.m.Range(func(k, v any) bool {
		if v.(time.Time).Before(deadline) {
			c.m.Delete(k)
		}
		return true
	})
}

// handleReconcilePosture handles POST /v1/reconcile-posture. It records a
// historical posture observation for audit/compliance fidelity and never
// issues a JWS. See the package/file docs for the four differences vs the
// live sign-posture path. Fails closed on any auth doubt.
func (s *Server) handleReconcilePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is accepted")
		return
	}

	// No request context/deadline is created here: unlike the live path there
	// is no Vault Transit round-trip to bound. Slow-body clients are already
	// capped by the server's ReadTimeout (cmd/posture-signer) and MaxBytesReader.
	start := time.Now()
	log := s.log.With(
		zap.String("handler", "reconcile-posture"),
		zap.String("remote_addr", r.RemoteAddr),
	)

	// Strict JSON decoder: DisallowUnknownFields keeps the wire contract with
	// the agent's Rust ReconcileRecord tight (a fat-fingered field is a 400,
	// not a silent drop).
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var rec ReconcileRecord
	if err := dec.Decode(&rec); err != nil {
		log.Warn("reconcile JSON decode failed", zap.Error(err))
		s.metrics.RecordReconcile(OutcomeReconcileValidationError, time.Since(start).Seconds())
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	// captured_at is the historical observation time. It MUST be a valid
	// RFC3339 timestamp (that is the whole point of this path) — but it is
	// explicitly NOT freshness-gated.
	capturedAt, err := time.Parse(time.RFC3339, rec.CapturedAt)
	if err != nil {
		log.Warn("reconcile captured_at parse failed",
			zap.String("captured_at", rec.CapturedAt), zap.Error(err))
		s.metrics.RecordReconcile(OutcomeReconcileValidationError, time.Since(start).Seconds())
		writeError(w, http.StatusBadRequest, "invalid_captured_at",
			"captured_at must be an RFC3339 timestamp: "+err.Error())
		return
	}

	// Field-level validation of the embedded report — the SAME checks as the
	// live path MINUS the iat clock-skew window (a historical report's iat is
	// intentionally stale).
	if err := rec.Report.ValidateHistorical(); err != nil {
		log.Warn("reconcile report validation failed",
			zap.Error(err), zap.String("device", redactDeviceUUID(rec.Report.DeviceUUID)))
		s.metrics.RecordReconcile(OutcomeReconcileValidationError, time.Since(start).Seconds())
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	// Device certificate chain + SPIFFE-SAN binding. IDENTICAL auth to the
	// live path: the verified cert's device SAN must equal the record's
	// report.device_uuid, so a stolen spool file cannot be replayed under a
	// different device's cert. Same XFCC-first / r.TLS-fallback source
	// selection, same fail-closed error mapping.
	if _, err := s.deviceVerifier.VerifyRequest(r, rec.Report.DeviceUUID); err != nil {
		log.Warn("reconcile device cert verification failed",
			zap.Error(err), zap.String("device", redactDeviceUUID(rec.Report.DeviceUUID)))
		s.metrics.RecordReconcile(OutcomeReconcileDeviceCertInval, time.Since(start).Seconds())
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

	// Idempotency: dedup on (device, seq). A retried flush (lost ack) is
	// accepted 409 WITHOUT re-recording the audit line. Checked AFTER auth so
	// an unauthenticated caller can never probe which seqs have landed.
	key := dedupKey(rec.Report.DeviceUUID, rec.Seq)
	if !s.dedup.firstSeen(key) {
		s.metrics.RecordReconcile(OutcomeReconcileDuplicate, time.Since(start).Seconds())
		s.metrics.ReconcileDedupSize.Set(float64(s.dedup.size()))
		log.Info("reconcile duplicate — already recorded, idempotent accept",
			zap.String("device", redactDeviceUUID(rec.Report.DeviceUUID)),
			zap.Uint64("seq", rec.Seq),
		)
		// 409: the agent treats this as Accepted and drops its local copy.
		s.writeReconcileStatus(w, http.StatusConflict, "duplicate", rec.Seq)
		return
	}

	// Record the historical observation to the audit stream. posture-signer is
	// stateless (no tamper-evident chain sink is wired into this service — it
	// mints JWS and forgets), so the audit sink IS the structured stdout log
	// shipped to Loki/Wazuh, same as internal/audit's model. observed_at is
	// captured_at (NOT now): the record reflects when the posture was actually
	// collected offline. No JWS is issued and the live nonce cache / CAEP
	// tracker are untouched, so this never advances the device's current
	// freshness.
	compliant := isCompliant(rec.Report.Compliance, s.complianceKeys)
	log.Info("posture reconcile recorded",
		zap.String("event", EventPostureReconcile),
		zap.String("device", redactDeviceUUID(rec.Report.DeviceUUID)),
		zap.String("tier", string(rec.Report.Tier)),
		zap.Uint64("seq", rec.Seq),
		zap.Time("observed_at", capturedAt.UTC()),
		zap.Int64("report_iat", rec.Report.IAT),
		zap.Bool("compliant", compliant),
		zap.Duration("elapsed", time.Since(start)),
	)

	s.metrics.RecordReconcile(OutcomeReconcileOK, time.Since(start).Seconds())
	s.metrics.ReconcileDedupSize.Set(float64(s.dedup.size()))

	s.writeReconcileStatus(w, http.StatusAccepted, "accepted", rec.Seq)
}

// writeReconcileStatus writes the small JSON acknowledgement body. The agent
// treats any of 200/201/202/204/409 as Accepted and does not parse the body,
// but a stable shape keeps the endpoint curl-friendly for operators.
func (s *Server) writeReconcileStatus(w http.ResponseWriter, status int, state string, seq uint64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec // G104: response-writer encode errors are intentionally unhandled per Go std lib idiom (client transport already detected any disconnect)
		"status": state,
		"seq":    seq,
	})
}
