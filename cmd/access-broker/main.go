// SPDX-License-Identifier: AGPL-3.0-or-later

// Command access-broker is the Talon clientless access-broker (ADR 0044
// Phase 2). It terminates the in-browser xterm.js WebSocket of an
// agentless ("clientless") session, authenticates the Talon IAP identity
// token (X-Talon-Identity-Token, verified against Talon's JWKS by
// internal/identityjwt), enforces channel=clientless, opens the backend
// SSH stream via the jess broker (internal/accessbroker.Backend), relays
// frames, and tees the stream to jess session recording (ADR 0030).
//
// Architecture:
//   - Transport: HTTP/WebSocket over Linkerd mTLS (no gRPC dependency).
//     TLS termination is the mesh sidecar's job in production; the binary
//     speaks plain HTTP and trusts the verified IAP token, never the
//     network position (same trust model as every upstream behind Talon).
//   - Auth: the IAP identity JWT is the ONLY trusted identity source. The
//     broker mounts behind Talon's access-zone IAP, which has already
//     authenticated + step-up'd the user and stamped channel=clientless.
//   - Backend: internal/accessbroker.NewJessBackend. The production jess
//     SSH-broker dial (ADR 0049) is STUBBED until jess exposes a callable
//     interface from talon; a --dev-loopback-addr exercises the full real
//     WebSocket<->SSH relay against any sshd for local/e2e testing.
//   - Stateless + horizontally scalable: each upgrade owns its goroutines.
//
// HONEST SCAFFOLD STATE: this binary + the relay/auth/framing/recording
// seam are real and tested. The jess production dial is the single
// clearly-marked stub (see internal/accessbroker/jessbackend.go).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dogukanturhal/talon/internal/accessbroker"
	"github.com/dogukanturhal/talon/internal/accessbroker/web"
	"github.com/dogukanturhal/talon/internal/identityjwt"
)

func main() {
	fs := flag.NewFlagSet("access-broker", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "address to listen on for the broker HTTP/WebSocket endpoint")
	metricsListen := fs.String("metrics-listen", ":9090", "address to listen on for /metrics (Prometheus)")
	jwksURL := fs.String("jwks-url", "https://internal.example.com/.well-known/jwks.json",
		"Talon JWKS endpoint used to verify the X-Talon-Identity-Token")
	issuer := fs.String("issuer", "https://internal.example.com",
		"expected iss claim on the IAP identity token (must match Talon's signer issuer)")
	audience := fs.String("audience", "",
		"expected aud claim on the IAP identity token (this broker's access-zone host, e.g. ssh.access.hexxlock.com) — REQUIRED")
	brokerAddr := fs.String("jess-broker-addr", "",
		"jess SSH-broker address (ADR 0049, mTLS) — production dial is STUBBED until jess exposes it")
	jessControllerAddr := fs.String("jess-controller-addr", "",
		"jess controller OPERATOR address host:port (mTLS) — the SQL console dials this and runs the operator ceremony (wire.OperatorRequest + raw pgwire/MySQL). Empty -> SQL console fails closed (ErrDBBackendNotWired).")
	jessClientCert := fs.String("jess-client-cert", "",
		"client cert (PEM) for the jess controller operator mTLS port (the access-broker's SPIFFE/SA identity)")
	jessClientKey := fs.String("jess-client-key", "",
		"client key (PEM) for the jess controller operator mTLS port")
	jessCAPool := fs.String("jess-ca", "",
		"CA bundle (PEM) used to verify the jess controller operator server cert")
	clientlessAudience := fs.String("clientless-assertion-audience", "",
		"the jess clientless audience the Talon-vouched assertion is scoped to (ADR 0050, e.g. https://internal.example.com/clientless) — REQUIRED to wire the SQL console")
	iapSignerKey := fs.String("iap-signer-key", "",
		"PEM path of Talon's IAP identity-token RSA private key (mints the clientless-access assertion, jess ADR 0050). REQUIRED to wire the SQL console.")
	iapSignerIssuer := fs.String("iap-signer-issuer", "https://internal.example.com",
		"iss claim for the minted clientless assertion (must match Talon's IAP signer issuer / jess's expected Talon issuer)")
	k8sBrokerAddr := fs.String("jess-k8s-broker-addr", "",
		"jess k8s-broker address (ADR 0049/0044 Phase 4, mTLS) — kubectl exec/logs dial is STUBBED until jess exposes it")
	queryTimeout := fs.Duration("db-query-timeout", 30*time.Second, "per-statement execution timeout for the SQL console")
	devLoopbackAddr := fs.String("dev-loopback-addr", "",
		"DEV ONLY: dial a plain sshd at host:port instead of the (unwired) jess broker, exercising the full real relay. NEVER set in production.")
	devLoopbackUser := fs.String("dev-loopback-user", "", "DEV ONLY: default SSH login for --dev-loopback-addr")
	devLoopbackPass := fs.String("dev-loopback-password", "", "DEV ONLY: SSH password for --dev-loopback-addr")
	rdpBrokerAddr := fs.String("jess-rdp-broker-addr", "",
		"jess RDP-broker address (ADR 0044 Phase 3, mTLS) — production dial is STUBBED until jess exposes it")
	devRDPSynthetic := fs.Bool("dev-rdp-synthetic", false,
		"DEV ONLY: serve a synthetic in-process RDP canvas stream instead of the (unwired) jess RDP broker, exercising the full real relay + canvas client. NEVER set in production.")
	maxSession := fs.Duration("max-session", time.Hour, "clientless absolute TTL: hard cap on a single brokered terminal session")
	idleTimeout := fs.Duration("idle-timeout", 2*time.Minute, "per-frame WebSocket read deadline")
	jwksStaleThreshold := fs.Duration("jwks-stale-threshold", identityjwt.DefaultJWKSStaleThreshold,
		"DDIL P3.1 governed-degrade budget: keep serving the last-good IAP JWKS this long after refreshes fail, then fail closed. 0 disables (strict fail-closed at TTL).")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	_ = fs.Parse(os.Args[1:])

	log := buildLogger(*logLevel)
	defer func() { _ = log.Sync() }()
	fatal := func(msg string, fields ...zap.Field) {
		log.Error(msg, fields...)
		_ = log.Sync()
		os.Exit(1)
	}

	// audience is operator-required: without it the IAP verifier cannot
	// enforce RFC 8725 §3.1 audience binding, so a token minted for a
	// different access-zone host would verify here. Fail closed at boot.
	if strings.TrimSpace(*audience) == "" {
		if env := strings.TrimSpace(os.Getenv("ACCESS_BROKER_AUDIENCE")); env != "" {
			*audience = env
		} else {
			fatal("access-broker: --audience (or ACCESS_BROKER_AUDIENCE) is required")
		}
	}

	log.Info("access-broker starting",
		zap.String("listen", *listen),
		zap.String("metrics_listen", *metricsListen),
		zap.String("jwks_url", *jwksURL),
		zap.String("issuer", *issuer),
		zap.String("audience", *audience),
		zap.Bool("dev_loopback", *devLoopbackAddr != ""),
	)
	if *devLoopbackAddr != "" {
		log.Warn("DEV LOOPBACK ENABLED — bypassing jess policy + recording; do NOT use in production",
			zap.String("addr", *devLoopbackAddr))
	} else {
		log.Warn("jess SSH-broker dial is STUBBED (ADR 0049 not yet wired) — sessions will close with ErrBackendNotWired until a backend is reachable")
	}
	if *jessControllerAddr == "" {
		log.Warn("jess DB SQL-console is NOT wired (no --jess-controller-addr) — /access/db relay is real + tested but a live session closes with ErrDBBackendNotWired until the controller operator addr + mTLS + IAP signer are configured (jess ADR 0050)")
	} else {
		log.Info("jess DB SQL-console wired", zap.String("jess_controller_addr", *jessControllerAddr), zap.String("clientless_audience", *clientlessAudience))
	}
	log.Warn("jess k8s broker is STUBBED (ADR 0044 Phase 4 scaffold) — /access/k8s relay is real + tested but a live session closes with ErrK8sBackendNotWired until the jess k8s broker (ADR 0049) is reachable from talon")

	// IAP identity-token verifier — the broker's only trusted identity
	// source. Replay protection on by default (the 60s exp + per-process
	// jti cache); a multi-pod deployment relies primarily on the 60s exp.
	verifier, err := identityjwt.NewVerifier(identityjwt.VerifierConfig{
		JWKSURL:            *jwksURL,
		ExpectedIssuer:     *issuer,
		ExpectedAudience:   *audience,
		ReplayCacheSize:    8192,
		JWKSStaleThreshold: *jwksStaleThreshold, // DDIL P3.1 governed stale window
		OnJWKSStale: func(staleFor time.Duration) {
			// Governed-degrade signal: the broker is verifying identity
			// tokens against a STALE (last-good) Talon JWKS within budget.
			log.Warn("serving STALE Talon JWKS (DDIL P3.1 governed-degrade) — refresh failing, within stale budget",
				zap.Duration("stale_for", staleFor),
				zap.Duration("stale_budget", *jwksStaleThreshold),
				zap.String("jwks_url", *jwksURL))
		},
	})
	if err != nil {
		fatal("access-broker: construct IAP verifier", zap.Error(err))
	}

	// Prometheus registry (isolated, per the observability pattern).
	reg := prometheus.NewRegistry()
	metrics := accessbroker.NewMetrics(reg)

	backend := accessbroker.NewJessBackend(accessbroker.JessBackendConfig{
		BrokerAddr:          *brokerAddr,
		DevLoopbackAddr:     *devLoopbackAddr,
		DevLoopbackUser:     *devLoopbackUser,
		DevLoopbackPassword: *devLoopbackPass,
	})

	sugarLogf := func(format string, args ...any) { log.Sugar().Infof(format, args...) }

	brokerHandler, err := accessbroker.NewHandler(accessbroker.HandlerConfig{
		Auth:               verifier,
		Backend:            backend,
		Metrics:            metrics,
		IdleTimeout:        *idleTimeout,
		MaxSessionDuration: *maxSession,
		Logf:               sugarLogf,
	})
	if err != nil {
		fatal("access-broker: construct handler", zap.Error(err))
	}

	// RDP broker (ADR 0044 Phase 3). Mirrors the SSH handler: same auth +
	// channel gate + metrics, an RDP backend whose production jess dial is
	// STUBBED (ErrRDPBackendNotWired) until jess exposes it, and a
	// clipboard/file-transfer policy enforced at the relay edge.
	if *devRDPSynthetic {
		log.Warn("DEV RDP SYNTHETIC ENABLED — paints a synthetic canvas, no real desktop; bypasses jess policy + recording; do NOT use in production")
	} else if *rdpBrokerAddr == "" {
		log.Warn("jess RDP-broker dial is STUBBED (Phase 3 not yet wired) — /access/rdp sessions close with ErrRDPBackendNotWired until a backend is reachable")
	}
	rdpBackend := accessbroker.NewJessRDPBackend(accessbroker.JessRDPBackendConfig{
		BrokerAddr:   *rdpBrokerAddr,
		DevSynthetic: *devRDPSynthetic,
	})
	rdpHandler, err := accessbroker.NewRDPHandler(accessbroker.RDPHandlerConfig{
		Auth:               verifier,
		Backend:            rdpBackend,
		Metrics:            metrics,
		IdleTimeout:        *idleTimeout,
		MaxSessionDuration: *maxSession,
		Logf:               func(format string, args ...any) { log.Sugar().Infof(format, args...) },
	})
	if err != nil {
		fatal("access-broker: construct rdp handler", zap.Error(err))
	}

	// Phase 4 — SQL console (jess ADR 0050 clientless-operator credentials).
	// The backend runs the jess operator ceremony: mint a Talon-vouched
	// clientless-access assertion, dial the controller operator port over
	// mTLS, write the wire.OperatorRequest, then speak raw pgwire/MySQL to the
	// target THROUGH the jess relay (jess injects the ephemeral Vault cred,
	// enforces per-statement policy, and WORM-records server-side). When the
	// controller addr / mTLS / signer are not configured, the backend fails
	// closed (ErrDBBackendNotWired or a clear error) — never a plaintext or
	// silent open.
	dbBackend := accessbroker.NewJessDBBackend(buildDBBackendConfig(log,
		*jessControllerAddr, *jessClientCert, *jessClientKey, *jessCAPool,
		*iapSignerKey, *iapSignerIssuer, *clientlessAudience))
	dbHandler, err := accessbroker.NewDBHandler(accessbroker.DBHandlerConfig{
		Auth:               verifier,
		Backend:            dbBackend,
		Metrics:            metrics,
		IdleTimeout:        *idleTimeout,
		MaxSessionDuration: *maxSession,
		QueryTimeout:       *queryTimeout,
		Logf:               sugarLogf,
	})
	if err != nil {
		fatal("access-broker: construct db handler", zap.Error(err))
	}

	// Phase 4 — kubectl exec/logs terminal. Reuses the byte-stream relay +
	// the xterm.js front-end. The jess k8s broker (ADR 0049) is not yet
	// reachable, so the dial is STUBBED (ErrK8sBackendNotWired).
	k8sHandler, err := accessbroker.NewK8sHandler(accessbroker.K8sHandlerConfig{
		Auth: verifier,
		Backend: accessbroker.NewJessK8sBackend(accessbroker.JessK8sBackendConfig{
			BrokerAddr: *k8sBrokerAddr,
		}),
		Metrics:            metrics,
		IdleTimeout:        *idleTimeout,
		MaxSessionDuration: *maxSession,
		Logf:               sugarLogf,
	})
	if err != nil {
		fatal("access-broker: construct k8s handler", zap.Error(err))
	}

	mux := http.NewServeMux()
	// The authenticated WebSocket-upgrade endpoints.
	mux.Handle("/access/ssh", brokerHandler) // Phase 2 — SSH terminal
	mux.Handle("/access/rdp", rdpHandler)    // Phase 3 — RDP canvas
	mux.Handle("/access/db", dbHandler)      // Phase 4 — SQL console
	mux.Handle("/access/k8s", k8sHandler)    // Phase 4 — kubectl exec/logs terminal
	// The embedded front-ends (static): index.html (SSH terminal), rdp.html
	// (HTML5-canvas desktop), db.html (SQL console), k8s.html (kubectl).
	mux.Handle("/", http.FileServer(http.FS(web.FS())))
	// Liveness/readiness. Readiness reflects JWKS reachability so the pod
	// leaves Service rotation when Talon's JWKS endpoint is unreachable.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if herr := verifier.HealthCheck(ctx); herr != nil {
			http.Error(w, "not ready: "+herr.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	mainSrv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// NB: no WriteTimeout — a long-lived WebSocket relay must not be
		// killed by a server write deadline. The relay enforces its own
		// idle + absolute-TTL bounds (idle-timeout, max-session).
	}
	metricsSrv := &http.Server{
		Addr:              *metricsListen,
		Handler:           promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- mainSrv.ListenAndServe() }()
	go func() { errCh <- metricsSrv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		log.Info("received shutdown signal", zap.String("signal", sig.String()))
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", zap.Error(err))
		}
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	if err := mainSrv.Shutdown(shutCtx); err != nil {
		log.Error("main server shutdown", zap.Error(err))
	}
	if err := metricsSrv.Shutdown(shutCtx); err != nil {
		log.Error("metrics server shutdown", zap.Error(err))
	}
	log.Info("access-broker stopped")
}

// buildDBBackendConfig assembles the jess DB backend config from the operator
// flags. When the controller addr is empty it returns a zero-addr config so
// the backend fails closed with ErrDBBackendNotWired (the deploy hasn't wired
// the SQL console yet). When it IS set, the mTLS cert/key/CA + IAP signer +
// audience are REQUIRED; a missing one is a fatal misconfiguration (we refuse
// to serve an undialable or plaintext SQL console).
func buildDBBackendConfig(log *zap.Logger, controllerAddr, clientCert, clientKey, caPath, signerKey, signerIssuer, audience string) accessbroker.JessDBBackendConfig {
	if strings.TrimSpace(controllerAddr) == "" {
		return accessbroker.JessDBBackendConfig{} // not wired -> ErrDBBackendNotWired
	}
	fatalf := func(msg string) {
		log.Error("access-broker: " + msg)
		_ = log.Sync()
		os.Exit(1)
	}
	if clientCert == "" || clientKey == "" {
		fatalf("--jess-controller-addr is set but --jess-client-cert/--jess-client-key are missing (operator mTLS required)")
	}
	if caPath == "" {
		fatalf("--jess-controller-addr is set but --jess-ca is missing (cannot verify the controller server cert)")
	}
	if audience == "" {
		fatalf("--jess-controller-addr is set but --clientless-assertion-audience is missing (jess ADR 0050 audience pin required)")
	}
	if signerKey == "" {
		fatalf("--jess-controller-addr is set but --iap-signer-key is missing (cannot mint the clientless-access assertion)")
	}

	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		fatalf("load jess operator client cert/key: " + err.Error())
	}
	caPEM, err := os.ReadFile(caPath) //nolint:gosec // G304: path is from an operator-controlled CLI flag
	if err != nil {
		fatalf("read jess CA bundle: " + err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fatalf("no valid certificates in --jess-ca bundle")
	}
	signerPEM, err := os.ReadFile(signerKey) //nolint:gosec // G304: path is from an operator-controlled CLI flag
	if err != nil {
		fatalf("read IAP signer key: " + err.Error())
	}
	signer, err := identityjwt.NewSignerFromPEM(signerPEM, signerIssuer)
	if err != nil {
		fatalf("construct IAP assertion signer: " + err.Error())
	}

	return accessbroker.JessDBBackendConfig{
		ControllerAddr: controllerAddr,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		},
		Assertion: accessbroker.SignerAssertionMinter{Signer: signer, Audience: audience},
	}
}

// buildLogger constructs a production zap logger at the given level.
// Mirrors cmd/posture-signer's logger setup so the two access-plane
// binaries emit the same structured-log shape.
func buildLogger(level string) *zap.Logger {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	l, err := cfg.Build()
	if err != nil {
		return zap.NewNop()
	}
	return l
}
