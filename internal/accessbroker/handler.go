// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/hexxlock/talon/internal/identityjwt"
)

// requiredChannel is the only session channel the broker will serve. A
// clientless (agentless) browser session carries no device cert; the
// broker is the agentless terminal path, so an agent/cookie or bearer
// session token MUST NOT be replayed into it. The gate is enforced
// cryptographically off the verified IAP token's `channel` claim
// (identityjwt.IdentityClaims.Channel), never off a client-supplied
// header — see ADR 0044 "Trust model".
const requiredChannel = "clientless"

// Authenticator verifies the inbound Talon IAP identity token and
// returns its claims. It is satisfied by *identityjwt.Verifier
// (VerifyRequest), but is kept an interface so the handler's auth gate
// can be unit-tested against a fake without standing up a JWKS server.
//
// The handler ONLY trusts the returned claims — subject, channel, sid,
// sso_chain_id, tenant, email — never the raw request headers the
// browser could forge. This is the same trust split every upstream
// behind Talon uses (internal/identityjwt verifier contract).
type Authenticator interface {
	VerifyRequest(r *http.Request) (*identityjwt.IdentityClaims, error)
}

// RecordSinkFactory opens a per-session recording sink (the tee to jess
// session recording, ADR 0030). The returned WriteCloser receives every
// backend->terminal output byte; Close is called when the session ends.
// A nil factory (or a factory returning a nil writer) disables the tee —
// jess remains the durable recording authority, the relay-edge tee is a
// best-effort secondary. Implementations MUST be safe for concurrent
// per-session calls.
type RecordSinkFactory interface {
	OpenRecording(ctx context.Context, req DialRequest) (io.WriteCloser, error)
}

// TargetResolver maps an inbound HTTP request to the SSH target + login
// the session should be brokered to. Splitting this out keeps the
// handler agnostic to how a deployment encodes the target (query string,
// path segment, a TalonRoute annotation, a per-session JIT grant). The
// default resolver (queryTargetResolver) reads ?target= and ?user= for
// the dev/scaffold path; production wires a resolver that consults the
// JIT grant + jess target catalogue.
type TargetResolver interface {
	Resolve(r *http.Request, claims *identityjwt.IdentityClaims) (target, user string, ok bool)
}

// HandlerConfig parameterises the access-broker WebSocket handler.
type HandlerConfig struct {
	// Auth verifies the Talon IAP identity token on every upgrade. REQUIRED
	// — a nil Auth fails every request closed (the broker never serves an
	// unauthenticated terminal).
	Auth Authenticator

	// Backend opens the backend SSH stream once auth + channel pass.
	// REQUIRED. In the Phase 2 scaffold this is NewJessBackend, whose
	// production dial is stubbed (ErrBackendNotWired) until the jess SSH
	// broker (ADR 0049) is reachable from talon.
	Backend Backend

	// Resolver maps the request to a target + login. nil -> the query
	// resolver (?target=&user=).
	Resolver TargetResolver

	// RecordSinks opens the per-session recording tee. nil disables the
	// relay-edge tee (jess still records authoritatively).
	RecordSinks RecordSinkFactory

	// Metrics is the broker's Prometheus sink. nil -> a discard sink
	// (handler still works, just unobserved — used in tests).
	Metrics *Metrics

	// IdleTimeout is the per-frame read deadline on the WebSocket (a
	// wedged client cannot pin a goroutine forever). Zero -> 2 minutes,
	// comfortably longer than the xterm.js keepalive ping cadence.
	IdleTimeout time.Duration

	// MaxSessionDuration is the clientless absolute TTL (ADR 0044): the
	// hard cap on a single brokered terminal session regardless of
	// activity. Zero -> 1 hour. The relay closes both sides with a 1000
	// normal closure when it elapses.
	MaxSessionDuration time.Duration

	// Logf is an optional structured-ish log hook (printf shape). nil ->
	// no logging. Kept minimal so the package carries no logger dep; the
	// cmd wires log.Printf or the project logger.
	Logf func(format string, args ...any)
}

// Handler is the access-broker HTTP handler. It serves exactly one route:
// an authenticated WebSocket-upgrade endpoint that bridges a clientless
// browser terminal to a backend SSH session. Mount it (typically at
// /access/ssh) behind Talon's access-zone IAP. Stateless +
// horizontally scalable: each upgrade owns its own goroutines and holds
// no cross-request state.
type Handler struct {
	cfg HandlerConfig
}

// NewHandler validates the config and returns the broker handler.
// Auth and Backend are required; everything else has a safe default.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Auth == nil {
		return nil, errNilAuth
	}
	if cfg.Backend == nil {
		return nil, errNilBackend
	}
	if cfg.Resolver == nil {
		cfg.Resolver = queryTargetResolver{}
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxSessionDuration <= 0 {
		cfg.MaxSessionDuration = time.Hour
	}
	return &Handler{cfg: cfg}, nil
}

// ServeHTTP implements the upgrade -> auth -> channel-gate -> dial ->
// relay pipeline. Each failure step is observed on the metrics sink and
// surfaced to the client as either an HTTP error (before upgrade) or a
// WebSocket close with a descriptive reason (after upgrade). It never
// silently hangs.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1) Auth gate — verify the Talon IAP identity token BEFORE upgrading.
	//    A failed verify is a plain 401 (the browser never gets a socket).
	claims, err := h.cfg.Auth.VerifyRequest(r)
	if err != nil || claims == nil {
		h.observe(OutcomeUnauthenticated)
		h.logf("accessbroker: auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2) Channel gate — only clientless (agentless) sessions may use the
	//    broker. An agent/cookie/bearer token is rejected even though it
	//    verified, because the broker is the no-device-cert terminal path.
	if claims.Channel != requiredChannel {
		h.observe(OutcomeWrongChannel)
		h.logf("accessbroker: wrong channel %q (want %q) sub=%s", claims.Channel, requiredChannel, claims.Subject)
		http.Error(w, "clientless channel required", http.StatusForbidden)
		return
	}

	// 3) Resolve the SSH target + login from the request.
	target, user, ok := h.cfg.Resolver.Resolve(r, claims)
	if !ok || target == "" {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker: no target resolved sub=%s", claims.Subject)
		http.Error(w, "no ssh target", http.StatusBadRequest)
		return
	}

	dreq := DialRequest{
		Subject:    claims.Subject,
		Email:      claims.Email,
		TenantID:   claims.TenantID,
		SessionID:  claims.SID,
		SSOChainID: claims.SSOChainID,
		Target:     target,
		User:       user,
		Cols:       parseGeom(r.URL.Query().Get("cols"), 80),
		Rows:       parseGeom(r.URL.Query().Get("rows"), 24),
	}

	// 4) Upgrade the connection to a WebSocket. Done AFTER auth so an
	//    unauthenticated client never gets a hijacked socket.
	ws, err := acceptWebSocket(w, r, h.cfg.IdleTimeout)
	if err != nil {
		h.observe(OutcomeUpgradeFailed)
		h.logf("accessbroker: websocket upgrade failed: %v", err)
		// acceptWebSocket only fails before the 101 is committed, so a
		// plain HTTP error is still valid here for the non-hijack cases.
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	defer func() { _ = ws.Close() }()

	// 5) Open the backend SSH stream via the (jess) Backend. A failure
	//    here is reported to the now-upgraded client as a 1011 close with
	//    the dial error reason — never a silent hang.
	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	backend, err := h.cfg.Backend.Dial(dialCtx, dreq)
	cancel()
	if err != nil {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker: backend dial failed sub=%s target=%s: %v", claims.Subject, target, err)
		_ = ws.WriteClose(closeInternalErr, truncateReason("backend unavailable: "+err.Error()))
		return
	}
	defer func() { _ = backend.Close() }()

	// 6) Optional recording tee (best-effort; jess is authoritative).
	var recSink io.Writer
	if h.cfg.RecordSinks != nil {
		if wc, rerr := h.cfg.RecordSinks.OpenRecording(r.Context(), dreq); rerr == nil && wc != nil {
			defer func() { _ = wc.Close() }()
			recSink = wc
		} else if rerr != nil {
			// A recording-open failure is logged but does NOT block the
			// session — the durable recording lives in jess; this tee is a
			// secondary copy at the relay edge.
			h.logf("accessbroker: open recording failed (continuing) sub=%s: %v", claims.Subject, rerr)
		}
	}

	// 7) Relay until either side closes or the absolute TTL elapses.
	h.metricsActiveInc()
	defer h.metricsActiveDec()
	start := time.Now()
	res := runRelay(r.Context(), ws, backend, RelayConfig{
		RecordSink:  recSink,
		MaxDuration: h.cfg.MaxSessionDuration,
	})
	h.recordRelayResult(res, time.Since(start))
	h.logf("accessbroker: session ended sub=%s target=%s reason=%s toBackend=%d toClient=%d err=%v",
		claims.Subject, target, res.Reason, res.BytesToBackend, res.BytesToClient, res.Err)
}

// recordRelayResult maps a relayResult onto the metrics sink: an outcome
// counter, the byte counters, and the duration histogram.
func (h *Handler) recordRelayResult(res relayResult, dur time.Duration) {
	if res.Reason == "error" {
		h.observe(OutcomeRelayError)
	} else {
		h.observe(OutcomeOK)
	}
	if h.cfg.Metrics == nil {
		return
	}
	h.cfg.Metrics.BytesRelayed.WithLabelValues("to_backend").Add(float64(res.BytesToBackend))
	h.cfg.Metrics.BytesRelayed.WithLabelValues("to_client").Add(float64(res.BytesToClient))
	h.cfg.Metrics.SessionDuration.Observe(dur.Seconds())
}

func (h *Handler) observe(outcome SessionOutcome) {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionTotal.WithLabelValues(string(outcome)).Inc()
	}
}

func (h *Handler) metricsActiveInc() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Inc()
	}
}

func (h *Handler) metricsActiveDec() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Dec()
	}
}

func (h *Handler) logf(format string, args ...any) {
	if h.cfg.Logf != nil {
		h.cfg.Logf(format, args...)
	}
}

// queryTargetResolver is the default TargetResolver: it reads ?target=
// and ?user= from the request URL. Suitable for the dev/scaffold path
// and for deployments that front the broker with a route that has
// already authorised a fixed target. Production wires a resolver that
// binds the target to a JIT grant + the jess target catalogue.
type queryTargetResolver struct{}

func (queryTargetResolver) Resolve(r *http.Request, _ *identityjwt.IdentityClaims) (string, string, bool) {
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		return "", "", false
	}
	return target, q.Get("user"), true
}

// parseGeom parses a terminal-geometry query param, falling back to def
// on anything malformed. Bounds are re-clamped in the backend
// (normalizeGeometry), so this only needs to not panic.
func parseGeom(s string, def uint16) uint16 {
	if s == "" {
		return def
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return def
		}
	}
	if n == 0 {
		return def
	}
	return uint16(n)
}

// truncateReason clamps a close-frame reason to the RFC 6455 control-
// frame payload budget (125 bytes total; 2 are the status code).
func truncateReason(s string) string {
	const maxReason = 123
	if len(s) > maxReason {
		return s[:maxReason]
	}
	return s
}
