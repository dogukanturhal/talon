// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hexxlock/talon/internal/identityjwt"
)

// K8sTargetResolver maps an inbound HTTP request to the kubectl target the
// exec/logs terminal should be brokered to. Like the SSH/DB resolvers it
// keeps the handler agnostic to how a deployment encodes the target. The
// default resolver (queryK8sTargetResolver) reads
// ?verb=&cluster=&namespace=&pod=&container=&command= for the dev/scaffold
// path; production wires a resolver bound to a JIT grant + the jess k8s
// target catalogue.
type K8sTargetResolver interface {
	Resolve(r *http.Request, claims *identityjwt.IdentityClaims) (req K8sDialRequest, ok bool)
}

// K8sHandlerConfig parameterises the access-broker kubectl-terminal handler.
// It mirrors HandlerConfig (SSH); the k8s console reuses the byte-stream
// relay (runRelay) and the same xterm.js front-end.
type K8sHandlerConfig struct {
	// Auth verifies the Talon IAP identity token on every upgrade. REQUIRED.
	Auth Authenticator
	// Backend opens the brokered exec/logs stream. REQUIRED. In Phase 4 this
	// is NewJessK8sBackend, whose production dial is stubbed
	// (ErrK8sBackendNotWired) until the jess k8s broker (ADR 0049) is
	// reachable from talon.
	Backend K8sBackend
	// Resolver maps the request to a k8s target. nil -> the query resolver.
	Resolver K8sTargetResolver
	// RecordSinks opens the per-session recording tee. nil disables it.
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

// K8sHandler is the access-broker kubectl-terminal HTTP handler. One route:
// an authenticated WebSocket-upgrade endpoint that bridges a clientless
// browser xterm to a jess-brokered `kubectl exec`/`logs` stream. Mount it
// (typically at /access/k8s) behind Talon's access-zone IAP.
type K8sHandler struct {
	cfg K8sHandlerConfig
}

// NewK8sHandler validates the config and returns the kubectl-terminal
// handler. Auth and Backend are required; everything else has a default.
func NewK8sHandler(cfg K8sHandlerConfig) (*K8sHandler, error) {
	if cfg.Auth == nil {
		return nil, errNilAuth
	}
	if cfg.Backend == nil {
		return nil, errNilK8sBackend
	}
	if cfg.Resolver == nil {
		cfg.Resolver = queryK8sTargetResolver{}
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxSessionDuration <= 0 {
		cfg.MaxSessionDuration = time.Hour
	}
	return &K8sHandler{cfg: cfg}, nil
}

// ServeHTTP runs the upgrade -> auth -> channel-gate -> resolve -> dial ->
// relay pipeline (byte-stream relay, reused from the SSH console).
func (h *K8sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, err := h.cfg.Auth.VerifyRequest(r)
	if err != nil || claims == nil {
		h.observe(OutcomeUnauthenticated)
		h.logf("accessbroker[k8s]: auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.Channel != requiredChannel {
		h.observe(OutcomeWrongChannel)
		h.logf("accessbroker[k8s]: wrong channel %q (want %q) sub=%s", claims.Channel, requiredChannel, claims.Subject)
		http.Error(w, "clientless channel required", http.StatusForbidden)
		return
	}

	dreq, ok := h.cfg.Resolver.Resolve(r, claims)
	if !ok || dreq.Pod == "" || dreq.Namespace == "" || !validK8sVerb(dreq.Verb) {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker[k8s]: no/invalid target sub=%s verb=%q ns=%q pod=%q", claims.Subject, dreq.Verb, dreq.Namespace, dreq.Pod)
		http.Error(w, "no/invalid k8s target", http.StatusBadRequest)
		return
	}
	dreq.Subject = claims.Subject
	dreq.Email = claims.Email
	dreq.TenantID = claims.TenantID
	dreq.SessionID = claims.SID
	dreq.SSOChainID = claims.SSOChainID
	dreq.Cols = parseGeom(r.URL.Query().Get("cols"), 80)
	dreq.Rows = parseGeom(r.URL.Query().Get("rows"), 24)

	ws, err := acceptWebSocket(w, r, h.cfg.IdleTimeout)
	if err != nil {
		h.observe(OutcomeUpgradeFailed)
		h.logf("accessbroker[k8s]: websocket upgrade failed: %v", err)
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	defer func() { _ = ws.Close() }()

	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	backend, err := h.cfg.Backend.Dial(dialCtx, dreq)
	cancel()
	if err != nil {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker[k8s]: backend dial failed sub=%s ns=%s pod=%s verb=%s: %v", claims.Subject, dreq.Namespace, dreq.Pod, dreq.Verb, err)
		_ = ws.WriteClose(closeInternalErr, truncateReason("k8s backend unavailable: "+err.Error()))
		return
	}
	defer func() { _ = backend.Close() }()

	var recSink io.Writer
	if h.cfg.RecordSinks != nil {
		rdreq := DialRequest{
			Subject: dreq.Subject, Email: dreq.Email, TenantID: dreq.TenantID,
			SessionID: dreq.SessionID, SSOChainID: dreq.SSOChainID,
			Target: k8sRecordTarget(dreq),
			User:   string(dreq.Verb),
		}
		if wc, rerr := h.cfg.RecordSinks.OpenRecording(r.Context(), rdreq); rerr == nil && wc != nil {
			defer func() { _ = wc.Close() }()
			recSink = wc
		} else if rerr != nil {
			h.logf("accessbroker[k8s]: open recording failed (continuing) sub=%s: %v", claims.Subject, rerr)
		}
	}

	h.metricsActiveInc()
	defer h.metricsActiveDec()
	start := time.Now()
	res := runRelay(r.Context(), ws, backend, RelayConfig{
		RecordSink:  recSink,
		MaxDuration: h.cfg.MaxSessionDuration,
	})
	h.recordRelayResult(res, time.Since(start))
	h.logf("accessbroker[k8s]: session ended sub=%s verb=%s ns=%s pod=%s reason=%s toBackend=%d toClient=%d err=%v",
		claims.Subject, dreq.Verb, dreq.Namespace, dreq.Pod, res.Reason, res.BytesToBackend, res.BytesToClient, res.Err)
}

// k8sRecordTarget builds a stable recording-target label for a k8s session,
// e.g. "exec cluster/ns/pod[/container]".
func k8sRecordTarget(d K8sDialRequest) string {
	t := string(d.Verb) + " " + d.Cluster + "/" + d.Namespace + "/" + d.Pod
	if d.Container != "" {
		t += "/" + d.Container
	}
	return t
}

func (h *K8sHandler) recordRelayResult(res relayResult, dur time.Duration) {
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

func (h *K8sHandler) observe(outcome SessionOutcome) {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionTotal.WithLabelValues(string(outcome)).Inc()
	}
}

func (h *K8sHandler) metricsActiveInc() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Inc()
	}
}

func (h *K8sHandler) metricsActiveDec() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Dec()
	}
}

func (h *K8sHandler) logf(format string, args ...any) {
	if h.cfg.Logf != nil {
		h.cfg.Logf(format, args...)
	}
}

// queryK8sTargetResolver is the default K8sTargetResolver: it reads
// ?verb=&cluster=&namespace=&pod=&container=&command= from the URL. The
// command is space-split (sufficient for the scaffold; production binds the
// command to the JIT grant). Suitable for the dev/scaffold path.
type queryK8sTargetResolver struct{}

func (queryK8sTargetResolver) Resolve(r *http.Request, _ *identityjwt.IdentityClaims) (K8sDialRequest, bool) {
	q := r.URL.Query()
	pod := q.Get("pod")
	ns := q.Get("namespace")
	if pod == "" || ns == "" {
		return K8sDialRequest{}, false
	}
	verb := K8sVerb(q.Get("verb"))
	if verb == "" {
		verb = VerbExec
	}
	var cmd []string
	if c := strings.TrimSpace(q.Get("command")); c != "" {
		cmd = strings.Fields(c)
	}
	return K8sDialRequest{
		Verb:      verb,
		Cluster:   q.Get("cluster"),
		Namespace: ns,
		Pod:       pod,
		Container: q.Get("container"),
		Command:   cmd,
	}, true
}
