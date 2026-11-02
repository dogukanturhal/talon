// SPDX-License-Identifier: AGPL-3.0-or-later

// Command posture-signer is the ZTNA Phase 4 JWS issuer for device-posture
// heartbeats. It receives mTLS-authenticated heartbeats from Access Agent
// agents, validates the device certificate chain, and mints RS256 JWS tokens
// backed by Vault Transit so agents can present X-Talon-Posture on their
// requests (verified by internal/posture in the Talon proxy).
//
// Architecture (ADR 0040 D-003, D-006; posture-signer-key.tf):
//   - Transport: HTTP/JSON over Linkerd mTLS (no gRPC dependency)
//   - Signing: Vault Transit `posture-signer` rsa-2048 RS256 — private key
//     NEVER materialised on disk
//   - Auth: device-cert (jess-device-ca) at connection layer + Linkerd mTLS
//     pod identity at the mesh layer
//   - Replay defence: iat ±30s clock window + 10-minute nonce dedup cache
//
// Vault token lifecycle: The Vault Agent Injector sidecar renews the token
// and writes it to --vault-token-path before the TTL expires. The binary
// re-reads the file on every sign call so it always uses the fresh token.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"net"
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

	"github.com/dogukanturhal/talon/internal/caep"
	"github.com/dogukanturhal/talon/internal/posturesigner"
)

func main() {
	fs := flag.NewFlagSet("posture-signer", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "address to listen on for heartbeat HTTP requests")
	metricsListen := fs.String("metrics-listen", ":9090", "address to listen on for /metrics (Prometheus)")
	vaultAddr := fs.String("vault-addr", "http://vault-ha.vault.svc.cluster.local:8200", "Vault server address")
	vaultKey := fs.String("vault-key", "posture-signer", "Vault Transit key name")
	vaultTokenPath := fs.String("vault-token-path", "/vault/secrets/token",
		"path to the Vault token file written by the Vault Agent Injector sidecar")
	deviceCAPool := fs.String("device-ca-pool", "/etc/posture-signer/device-ca.pem",
		"path to PEM file containing jess-device-ca root certificate(s)")
	issuer := fs.String("issuer", "https://posture.example.com",
		"iss claim for minted JWS tokens (must match TrustedIssuers in Talon's verifier config)")
	audience := fs.String("audience", "https://auth.internal.example.com",
		"aud claim for minted JWS tokens (must match ExpectedAudience in Talon's verifier config)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	_ = fs.Parse(os.Args[1:])

	log := buildLogger(*logLevel)
	defer func() { _ = log.Sync() }()
	// fatal logs at FATAL level + flushes log + exits. Replacement for
	// log.Fatal which calls os.Exit BEFORE deferred log.Sync runs (the
	// gocritic exitAfterDefer warning). Wrapping the trio means startup
	// errors get the same fan-out to stderr as steady-state errors.
	fatal := func(msg string, fields ...zap.Field) {
		log.Error(msg, fields...)
		_ = log.Sync()
		os.Exit(1)
	}

	log.Info("posture-signer starting",
		zap.String("listen", *listen),
		zap.String("metrics_listen", *metricsListen),
		zap.String("vault_addr", *vaultAddr),
		zap.String("vault_key", *vaultKey),
		zap.String("issuer", *issuer),
	)

	// Load jess-device-ca trust pool.
	pool, err := loadCertPool(*deviceCAPool)
	if err != nil {
		fatal("load device CA pool", zap.Error(err))
	}

	// Construct Vault Transit JWS issuer.
	issuerSvc, err := posturesigner.NewJWSIssuer(posturesigner.JWSIssuerConfig{
		VaultAddr: *vaultAddr,
		KeyName:   *vaultKey,
		Issuer:    *issuer,
		Audience:  *audience,
		TokenPath: *vaultTokenPath,
	})
	if err != nil {
		fatal("create JWS issuer", zap.Error(err))
	}

	// Initial JWKS refresh — readiness probe is blocked until this succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := issuerSvc.RefreshJWKS(ctx); err != nil {
		cancel()
		fatal("initial JWKS refresh from Vault Transit failed", zap.Error(err))
	}
	cancel()

	// Device certificate verifier.
	deviceVerifier, err := posturesigner.NewDeviceCertVerifier(pool)
	if err != nil {
		fatal("create device cert verifier", zap.Error(err))
	}

	// Prometheus registry (isolated; not global default, per observability
	// pattern in internal/observability/metrics.go).
	reg := prometheus.NewRegistry()
	metrics := posturesigner.NewMetrics(reg)

	// Nonce dedup cache. We do NOT `defer nonces.Stop()` here — the
	// graceful-shutdown block below calls Stop() explicitly. A second
	// Stop from a defer would close-an-already-closed channel and
	// panic. (NonceCache.Stop() is idempotent at the channel-close
	// layer only if guarded with sync.Once, which the substrate does
	// NOT do — keep the call site disciplined instead so the
	// invariant is local.)
	nonces := posturesigner.NewNonceCache()

	// ADR 0043 — optional CAEP transmitter. Off unless POSTURE_CAEP_ENABLED
	// + a receiver URL are set, so this is a safe no-op until Talon's CAEP
	// receiver is configured to trust this issuer. SetIssuer = our own iss
	// (Talon verifies SETs against our JWKS); SubjectIssuer = Falcon-ID (the
	// user-session owner Talon revokes on).
	var caepTx *caep.Transmitter
	var caepKeys []string
	if os.Getenv("POSTURE_CAEP_ENABLED") == "true" {
		tx, terr := caep.NewTransmitter(caep.TransmitterConfig{
			SetIssuer:     *issuer,
			SubjectIssuer: envOr("POSTURE_CAEP_SUBJECT_ISSUER", "https://id.example.com"),
			Audience:      envOr("POSTURE_CAEP_AUDIENCE", *audience),
			ReceiverURL:   os.Getenv("POSTURE_CAEP_RECEIVER_URL"),
		}, issuerSvc)
		if terr != nil {
			fatal("posture-signer: CAEP transmitter init failed", zap.Error(terr))
		}
		caepTx = tx
		caepKeys = splitCSV(envOr("POSTURE_CAEP_REQUIRED_KEYS", "disk_encryption"))
		log.Info("CAEP transmitter ENABLED",
			zap.String("set_iss", *issuer),
			zap.String("receiver", os.Getenv("POSTURE_CAEP_RECEIVER_URL")),
			zap.Strings("required_keys", caepKeys))
	}

	// Construct and start HTTP server.
	srv := posturesigner.NewServer(posturesigner.ServerConfig{
		Logger:                 log,
		Issuer:                 issuerSvc,
		Nonces:                 nonces,
		DeviceVerifier:         deviceVerifier,
		Metrics:                metrics,
		CAEP:                   caepTx,
		RequiredComplianceKeys: caepKeys,
	})

	// Metrics server (separate port; not publicly exposed — scraped by
	// Prometheus in-cluster via the Service port 9090).
	metricsSrv := &http.Server{
		Addr:              *metricsListen,
		Handler:           promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Main server: plain HTTP (TLS handled by Linkerd mTLS sidecar and the
	// Envoy Gateway device-cert termination layer). The device cert is
	// forwarded from Envoy as a client cert on the inner Linkerd connection.
	mainSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		// Require client TLS auth when run as plain HTTPS (development mode
		// without Linkerd). In production Linkerd proxy injects mutual TLS
		// and the server sees the device cert in r.TLS.PeerCertificates.
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			ClientCAs:  pool,
			MinVersion: tls.VersionTLS13,
		},
	}

	// Background JWKS refresh loop — keeps the /jwks.json cache fresh
	// so key rotation does not cause a gap.
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	defer refreshCancel()
	go func() {
		ticker := time.NewTicker(posturesigner.JWKSRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(refreshCtx, 10*time.Second)
				if err := issuerSvc.RefreshJWKS(ctx); err != nil {
					log.Warn("JWKS refresh failed", zap.Error(err))
				} else {
					log.Debug("JWKS refreshed from Vault Transit")
				}
				cancel()
				metrics.JWKSCacheAge.Set(issuerSvc.JWKSCacheAge().Seconds())
				metrics.NonceCacheSize.Set(float64(nonces.Size()))
			}
		}
	}()

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

	// Graceful shutdown: drain in-flight requests, then stop background loops.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	refreshCancel()
	nonces.Stop()
	// Stop server-owned background loops (reconcile idempotency-cache GC).
	srv.Close()

	if err := mainSrv.Shutdown(shutCtx); err != nil {
		log.Error("main server shutdown", zap.Error(err))
	}
	if err := metricsSrv.Shutdown(shutCtx); err != nil {
		log.Error("metrics server shutdown", zap.Error(err))
	}
	log.Info("posture-signer stopped")
}

// loadCertPool reads the PEM file at path and constructs an x509.CertPool
// containing all certificates found. Returns an error if the file is missing
// or contains no valid certificates.
func loadCertPool(path string) (*x509.CertPool, error) {
	// path is from --device-ca-pool flag (operator-controlled at deploy
	// time via the Helm chart's command args), never user input — the
	// gosec G304 false-positive does not apply here.
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is from operator-controlled CLI flag
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, &net.AddrError{Err: "no valid certificates found in PEM file", Addr: path}
	}
	return pool, nil
}

// envOr returns the trimmed value of env var name, or fallback when it is
// unset or empty.
func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// splitCSV splits a comma-separated env value into trimmed, non-empty
// items. Used for POSTURE_CAEP_REQUIRED_KEYS (the compliance baseline).
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildLogger creates a production zap logger with the given level.
func buildLogger(levelStr string) *zap.Logger {
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(levelStr)); err != nil {
		level = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	log, err := cfg.Build()
	if err != nil {
		// Should not happen with production config.
		panic("failed to build zap logger: " + err.Error())
	}
	return log
}
