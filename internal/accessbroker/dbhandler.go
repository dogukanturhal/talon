// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/hexxlock/talon/internal/identityjwt"
)

// DBTargetResolver maps an inbound HTTP request to the database engine +
// target + initial database the SQL console should be brokered to. Like the
// SSH TargetResolver, splitting this out keeps the handler agnostic to how a
// deployment encodes the target. The default resolver (queryDBTargetResolver)
// reads ?engine=&target=&db= for the dev/scaffold path; production wires a
// resolver that consults the JIT grant + jess DB target catalogue.
type DBTargetResolver interface {
	Resolve(r *http.Request, claims *identityjwt.IdentityClaims) (req DBDialRequest, ok bool)
}

// DBHandlerConfig parameterises the access-broker SQL-console handler. It
// mirrors HandlerConfig (SSH) field-for-field where the semantics are the
// same, so the two consoles are configured and reasoned about identically.
type DBHandlerConfig struct {
	// Auth verifies the Talon IAP identity token on every upgrade. REQUIRED.
	Auth Authenticator

	// Backend opens the brokered DBSession once auth + channel pass.
	// REQUIRED. In the Phase 4 scaffold this is NewJessDBBackend, whose
	// production open is stubbed (ErrDBBackendNotWired) until the jess SQL
	// brokers (ADR 0049) are reachable from talon.
	Backend DBBackend

	// Resolver maps the request to an engine + target. nil -> the query
	// resolver (?engine=&target=&db=).
	Resolver DBTargetResolver

	// RecordSinks opens the per-session recording tee (per-statement JSON
	// audit). nil disables the relay-edge tee (jess still records
	// authoritatively).
	RecordSinks RecordSinkFactory

	// Metrics is the broker's Prometheus sink. nil -> unobserved (tests).
	Metrics *Metrics

	// IdleTimeout is the per-frame read deadline on the WebSocket. Zero ->
	// 5 minutes (a SQL console sits idle between statements far longer than a
	// terminal, so the default is more generous than the SSH side).
	IdleTimeout time.Duration

	// MaxSessionDuration is the clientless absolute TTL (ADR 0044). Zero ->
	// 1 hour.
	MaxSessionDuration time.Duration

	// QueryTimeout bounds a single statement's execution. Zero -> 30s.
	QueryTimeout time.Duration

	// Logf is an optional printf-shape log hook. nil -> no logging.
	Logf func(format string, args ...any)
}

// DBHandler is the access-broker SQL-console HTTP handler. It serves one
// route: an authenticated WebSocket-upgrade endpoint that bridges a
// clientless browser SQL console to a jess-brokered database session. Mount
// it (typically at /access/db) behind Talon's access-zone IAP. Stateless +
// horizontally scalable — each upgrade owns its own goroutine.
type DBHandler struct {
	cfg DBHandlerConfig
}

// NewDBHandler validates the config and returns the SQL-console handler.
// Auth and Backend are required; everything else has a safe default.
func NewDBHandler(cfg DBHandlerConfig) (*DBHandler, error) {
	if cfg.Auth == nil {
		return nil, errNilAuth
	}
	if cfg.Backend == nil {
		return nil, errNilDBBackend
	}
	if cfg.Resolver == nil {
		cfg.Resolver = queryDBTargetResolver{}
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxSessionDuration <= 0 {
		cfg.MaxSessionDuration = time.Hour
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 30 * time.Second
	}
	return &DBHandler{cfg: cfg}, nil
}

// ServeHTTP runs the upgrade -> auth -> channel-gate -> resolve -> open ->
// relay pipeline, mirroring Handler.ServeHTTP. Each failure step is observed
// on the metrics sink and surfaced to the client as an HTTP error (before
// upgrade) or a WebSocket close with a descriptive reason (after upgrade).
func (h *DBHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1) Auth gate — verify the Talon IAP identity token BEFORE upgrading.
	claims, err := h.cfg.Auth.VerifyRequest(r)
	if err != nil || claims == nil {
		h.observe(OutcomeUnauthenticated)
		h.logf("accessbroker[db]: auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2) Channel gate — only clientless (agentless) sessions may use the
	//    broker (same cryptographic gate as the SSH console).
	if claims.Channel != requiredChannel {
		h.observe(OutcomeWrongChannel)
		h.logf("accessbroker[db]: wrong channel %q (want %q) sub=%s", claims.Channel, requiredChannel, claims.Subject)
		http.Error(w, "clientless channel required", http.StatusForbidden)
		return
	}

	// 3) Resolve the engine + target + database.
	dreq, ok := h.cfg.Resolver.Resolve(r, claims)
	if !ok || dreq.Target == "" || !validDBEngine(dreq.Engine) {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker[db]: no/invalid target resolved sub=%s engine=%q target=%q", claims.Subject, dreq.Engine, dreq.Target)
		http.Error(w, "no/invalid db target", http.StatusBadRequest)
		return
	}
	// Stamp the verified identity onto the request (never trusted from the
	// client) so jess binds the recording + JIT to the real subject.
	dreq.Subject = claims.Subject
	dreq.Email = claims.Email
	dreq.TenantID = claims.TenantID
	dreq.SessionID = claims.SID
	dreq.SSOChainID = claims.SSOChainID

	// 4) Upgrade to a WebSocket (after auth, so an unauthenticated client
	//    never gets a hijacked socket).
	ws, err := acceptWebSocket(w, r, h.cfg.IdleTimeout)
	if err != nil {
		h.observe(OutcomeUpgradeFailed)
		h.logf("accessbroker[db]: websocket upgrade failed: %v", err)
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	defer func() { _ = ws.Close() }()

	// 5) Open the brokered DB session. A failure is reported to the now-
	//    upgraded client as a 1011 close with the reason — never a hang.
	openCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	sess, err := h.cfg.Backend.Open(openCtx, dreq)
	cancel()
	if err != nil {
		h.observe(OutcomeBackendUnavailable)
		h.logf("accessbroker[db]: backend open failed sub=%s engine=%s target=%s: %v", claims.Subject, dreq.Engine, dreq.Target, err)
		_ = ws.WriteClose(closeInternalErr, truncateReason("db backend unavailable: "+err.Error()))
		return
	}
	defer func() { _ = sess.Close() }()

	// 6) Optional recording tee (best-effort; jess is authoritative).
	var recSink io.Writer
	if h.cfg.RecordSinks != nil {
		// Reuse the SSH-side DialRequest shape for the recording metadata so
		// a single RecordSinkFactory serves both consoles.
		rdreq := DialRequest{
			Subject: dreq.Subject, Email: dreq.Email, TenantID: dreq.TenantID,
			SessionID: dreq.SessionID, SSOChainID: dreq.SSOChainID,
			Target: string(dreq.Engine) + ":" + dreq.Target,
		}
		if wc, rerr := h.cfg.RecordSinks.OpenRecording(r.Context(), rdreq); rerr == nil && wc != nil {
			defer func() { _ = wc.Close() }()
			recSink = wc
		} else if rerr != nil {
			h.logf("accessbroker[db]: open recording failed (continuing) sub=%s: %v", claims.Subject, rerr)
		}
	}

	// 7) Relay statements <-> result sets until close / TTL.
	h.metricsActiveInc()
	defer h.metricsActiveDec()
	start := time.Now()
	res := runDBRelay(r.Context(), ws, sess, DBRelayConfig{
		RecordSink:   recSink,
		MaxDuration:  h.cfg.MaxSessionDuration,
		QueryTimeout: h.cfg.QueryTimeout,
	})
	h.recordRelayResult(res, time.Since(start))
	h.logf("accessbroker[db]: session ended sub=%s engine=%s target=%s reason=%s stmtsBytes=%d resultBytes=%d err=%v",
		claims.Subject, dreq.Engine, dreq.Target, res.Reason, res.BytesToBackend, res.BytesToClient, res.Err)
}

// recordRelayResult / observe / metricsActive* / logf mirror Handler's so
// the SQL console reports on the same metrics surface as the SSH console.
func (h *DBHandler) recordRelayResult(res relayResult, dur time.Duration) {
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

func (h *DBHandler) observe(outcome SessionOutcome) {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionTotal.WithLabelValues(string(outcome)).Inc()
	}
}

func (h *DBHandler) metricsActiveInc() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Inc()
	}
}

func (h *DBHandler) metricsActiveDec() {
	if h.cfg.Metrics != nil {
		h.cfg.Metrics.SessionsActive.Dec()
	}
}

func (h *DBHandler) logf(format string, args ...any) {
	if h.cfg.Logf != nil {
		h.cfg.Logf(format, args...)
	}
}

// queryDBTargetResolver is the default DBTargetResolver: it reads ?engine=,
// ?target= and ?db= from the request URL. Suitable for the dev/scaffold
// path; production wires a resolver that binds the target to a JIT grant +
// the jess DB target catalogue.
type queryDBTargetResolver struct{}

func (queryDBTargetResolver) Resolve(r *http.Request, _ *identityjwt.IdentityClaims) (DBDialRequest, bool) {
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		return DBDialRequest{}, false
	}
	engine := DBEngine(q.Get("engine"))
	if engine == "" {
		engine = EnginePostgres // sensible default for the scaffold
	}
	return DBDialRequest{Engine: engine, Target: target, Database: q.Get("db")}, true
}
