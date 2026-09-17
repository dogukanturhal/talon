// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/dogukanturhal/talon/internal/identityjwt"
)

// RDPTargetResolver maps an inbound HTTP request to the RDP target +
// login + data policy the session should be brokered to. It is the RDP
// analogue of TargetResolver, additionally returning the clipboard/file
// policy so the relay-edge enforcement is bound to the resolved route/JIT
// grant rather than to anything the client supplies. The default resolver
// (rdpQueryTargetResolver) reads ?target=/?user= and a deny-all policy for
// the dev/scaffold path; production wires a resolver that consults the JIT
// grant + the jess target catalogue + the route's clipboard/file policy.
type RDPTargetResolver interface {
	Resolve(r *http.Request, claims *identityjwt.IdentityClaims) (target, user string, policy RDPDataPolicy, ok bool)
}

// RDPHandlerConfig parameterises the access-broker RDP WebSocket handler.
// It mirrors HandlerConfig (the SSH handler) field-for-field where the two
// share behaviour, so the cmd wiring + ops dashboards stay symmetrical.
type RDPHandlerConfig struct {
	// Auth verifies the Talon IAP identity token on every upgrade. REQUIRED
	// — a nil Auth fails every request closed.
	Auth Authenticator

	// Backend opens the backend RDP stream once auth + channel pass.
	// REQUIRED. In the Phase 3 scaffold this is NewJessRDPBackend, whose
	// production dial is stubbed (ErrRDPBackendNotWired) until the jess RDP
	// broker is reachable from talon.
	Backend RDPBackend

	// Resolver maps the request to a target + login + data policy. nil ->
	// the query resolver (?target=&user=) with a deny-all data policy.
	Resolver RDPTargetResolver

	// RecordSinks opens the per-session recording tee. nil disables the
	// relay-edge tee (jess still records authoritatively). Reuses the SSH
	// RecordSinkFactory shape (the DialRequest fields it needs overlap).
	RecordSinks RecordSinkFactory

	// Metrics is the broker's Prometheus sink. nil -> unobserved (tests).
	Metrics *Metrics

	// IdleTimeout is the per-frame WebSocket read deadline. Zero -> 2 min.
	IdleTimeout time.Duration

	// MaxSessionDuration is the clientless absolute TTL (ADR 0044). Zero ->
	// 1 hour.
	MaxSessionDuration time.Duration

	// Logf is an optional printf-shape log hook. nil -> no logging.
	Logf func(format string, args ...any)
}

// RDPHandler is the access-broker RDP HTTP handler. It serves exactly one
// route: an authenticated WebSocket-upgrade endpoint that bridges a
// clientless browser canvas to a backend RDP session, enforcing the
// clipboard/file-transfer policy at the relay edge. Mount it (typically at
// /access/rdp) behind Talon's access-zone IAP. Stateless + horizontally
// scalable; each upgrade owns its own goroutines.
type RDPHandler struct {
	cfg RDPHandlerConfig
}

// NewRDPHandler validates the config and returns the RDP broker handler.
// Auth and Backend are required; everything else has a safe default.
func NewRDPHandler(cfg RDPHandlerConfig) (*RDPHandler, error) {
	if cfg.Auth == nil {
		return nil, errNilAuth
	}
	if cfg.Backend == nil {
		return nil, errNilRDPBackend
	}
	if cfg.Resolver == nil {
		cfg.Resolver = rdpQueryTargetResolver{}
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxSessionDuration <= 0 {
		cfg.MaxSessionDuration = time.Hour
	}
	return &RDPHandler{cfg: cfg}, nil
}

// ServeHTTP implements the upgrade -> auth -> channel-gate -> dial ->
// relay pipeline for RDP. It is the structural twin of Handler.ServeHTTP;
// the differences are the RDP backend, the RDP relay, and the resolved
// clipboard/file policy threaded into both the dial request and the relay.
func (h *RDPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1) Auth gate — verify the Talon IAP identity token BEFORE upgrading.
	claims, err := h.cfg.Auth.VerifyRequest(r)
	if err != nil || claims == nil {
		h.observe(OutcomeUnauthenticated)
		h.logf("accessbroker rdp: auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2) Channel gate — only clientless (agentless) sessions may use the
	//    broker (same trust split as the SSH path).
	if claims.Channel != requiredChannel {
		h.observe(OutcomeWrongChannel)
		h.logf("accessbroker rdp: wrong channel %q (want %q) sub=%s", claims.Channel, requiredChannel, claims.Subject)
		http.Error(w, "clientless channel required", http.StatusForbidden)
		return
	}

	// 3) Resolve the RDP target + login + clipboard/file policy.
	target, user, policy, ok := h.cfg.Resolver.Resolve(r, claims)
	if !ok || target == "" {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker rdp: no target resolved sub=%s", claims.Subject)
		http.Error(w, "no rdp target", http.StatusBadRequest)
		return
	}

	dreq := RDPDialRequest{
		Subject:    claims.Subject,
		Email:      claims.Email,
		TenantID:   claims.TenantID,
		SessionID:  claims.SID,
		SSOChainID: claims.SSOChainID,
		Target:     target,
		User:       user,
		Width:      parseGeom(r.URL.Query().Get("w"), 1280),
		Height:     parseGeom(r.URL.Query().Get("h"), 720),
		Policy:     policy,
	}

	// 4) Upgrade to a WebSocket (AFTER auth).
	ws, err := acceptWebSocket(w, r, h.cfg.IdleTimeout)
	if err != nil {
		h.observe(OutcomeUpgradeFailed)
		h.logf("accessbroker rdp: websocket upgrade failed: %v", err)
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	defer func() { _ = ws.Close() }()

	// 5) Open the backend RDP stream via the (jess) RDPBackend. A failure
	//    here is reported to the upgraded client as a 1011 close with the
	//    dial error reason — never a silent hang.
	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	backend, err := h.cfg.Backend.DialRDP(dialCtx, dreq)
	cancel()
	if err != nil {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker rdp: backend dial failed sub=%s target=%s: %v", claims.Subject, target, err)
		_ = ws.WriteClose(closeInternalErr, truncateReason("backend unavailable: "+err.Error()))
		return
	}
	defer func() { _ = backend.Close() }()

	// 6) Optional recording tee (best-effort; jess is authoritative). The
	//    RDP record sink receives the server->canvas wire envelopes. The
	//    factory takes the SSH DialRequest shape; project the overlapping
	//    identity/target fields so the same RecordSinkFactory serves both.
	var recSink io.Writer
	if h.cfg.RecordSinks != nil {
		rsReq := DialRequest{
			Subject:    dreq.Subject,
			Email:      dreq.Email,
			TenantID:   dreq.TenantID,
			SessionID:  dreq.SessionID,
			SSOChainID: dreq.SSOChainID,
			Target:     dreq.Target,
			User:       dreq.User,
		}
		if wc, rerr := h.cfg.RecordSinks.OpenRecording(r.Context(), rsReq); rerr == nil && wc != nil {
			defer func() { _ = wc.Close() }()
			recSink = wc
		} else if rerr != nil {
			h.logf("accessbroker rdp: open recording failed (continuing) sub=%s: %v", claims.Subject, rerr)
		}
	}

	// 7) Relay until either side closes or the absolute TTL elapses. The
	//    resolved policy is enforced at the relay edge in both directions.
	h.metricsActiveInc()
	defer h.metricsActiveDec()
	start := time.Now()
	res := runRDPRelay(r.Context(), ws, backend, RDPRelayConfig{
		Policy:      rdpPolicyGate{p: policy},
		RecordSink:  recSink,
		MaxDuration: h.cfg.MaxSessionDuration,
		Metrics:     h.cfg.Metrics,
	})
	h.recordRelayResult(res, time.Since(start))
	h.logf("accessbroker rdp: session ended sub=%s target=%s reason=%s toBackend=%d toClient=%d err=%v",
		claims.Subject, target, res.Reason, res.BytesToBackend, res.BytesToClient, res.Err)
}

// recordRelayResult / observe / metricsActive* / logf reuse the SSH
// handler's metrics helpers via the shared *Metrics so the two handlers
// emit the same series. They are re-declared here as thin wrappers because
// RDPHandler holds its own cfg.

func (h *RDPHandler) recordRelayResult(res relayResult, dur time.Duration) {
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

func (h *RDPHandler) observe(outcome SessionOutcome) {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionTotal.WithLabelValues(string(outcome)).Inc()
	}
}

func (h *RDPHandler) metricsActiveInc() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Inc()
	}
}

func (h *RDPHandler) metricsActiveDec() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Dec()
	}
}

func (h *RDPHandler) logf(format string, args ...any) {
	if h.cfg.Logf != nil {
		h.cfg.Logf(format, args...)
	}
}

// rdpQueryTargetResolver is the default RDPTargetResolver: it reads
// ?target= and ?user= from the request URL and returns a DENY-ALL data
// policy (fail closed — the dev/scaffold path never silently enables
// clipboard or file transfer). Production wires a resolver that binds the
// target to a JIT grant + the route's clipboard/file policy.
type rdpQueryTargetResolver struct{}

func (rdpQueryTargetResolver) Resolve(r *http.Request, _ *identityjwt.IdentityClaims) (string, string, RDPDataPolicy, bool) {
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		return "", "", RDPDataPolicy{}, false
	}
	// Deny-all policy by default; the production resolver supplies the real
	// per-route policy. (The zero RDPDataPolicy denies clipboard + files.)
	return target, q.Get("user"), RDPDataPolicy{}, true
}
