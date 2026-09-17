// SPDX-License-Identifier: AGPL-3.0-or-later

// Reference upstream service for the Talon IAP identity-token
// pattern. Copy this file as the starting point for any new Go
// service that sits behind Talon and wants cryptographic IAP trust
// instead of relying solely on Linkerd network-layer policy.
//
// What this service does
// ----------------------
//   - Mounts identityjwt.Middleware on /api/* so every protected
//     request is verified against Talon's JWKS before it reaches the
//     handler.
//   - Implements /readyz that fails when Talon's JWKS endpoint is
//     unreachable — kube-proxy pulls the pod from Service rotation
//     so callers get a clean 503 instead of cascading 401s.
//   - Exposes /healthz independently so kubelet never RESTARTS the
//     pod on IAP misconfig (readiness is enough).
//   - Reads the verified identity from request context via
//     ClaimsFromContext and echoes it on /api/whoami.
//
// Run locally
// -----------
//
//	TALON_JWKS_URL='https://internal.example.com/.well-known/jwks.json' \
//	TALON_EXPECTED_ISSUER='https://internal.example.com' \
//	TALON_EXPECTED_AUDIENCE='internal.example.com' \
//	LISTEN_ADDR=':8080' \
//	go run ./examples/iap-upstream-go
//
// Then mint a test token via Talon's own e2e harness or by signing
// one in a test using identityjwt.Signer.Sign — see signer_test.go
// for the pattern. Pass it via:
//
//	curl -H 'X-Talon-Identity-Token: <jwt>' http://localhost:8080/api/whoami
//
// Production deploy
// -----------------
// 1. Add a TalonRoute pointing at your service's ClusterIP.
// 2. Add a Linkerd AuthorizationPolicy + MeshTLSAuthentication so
//    only Talon's ServiceAccount can reach the upstream Service
//    (defense-in-depth — the IAP JWT is the cryptographic layer;
//    Linkerd is the network layer).
// 3. Confirm your readiness probe is the /readyz path below.
//
// See docs/architecture/0005-iap-identity-token.md for the
// full trust model + claim schema.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hexxlock/talon/internal/identityjwt"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}

	verifier, err := identityjwt.NewVerifier(identityjwt.VerifierConfig{
		JWKSURL:          cfg.JWKSURL,
		ExpectedIssuer:   cfg.ExpectedIssuer,
		ExpectedAudience: cfg.ExpectedAudience,
		// Optional replay protection — enable for defense-in-depth
		// against intercepted-token replay within the 60s exp
		// window. Per-pod cache; for cross-pod uniqueness wire a
		// shared backend via VerifierConfig.ReplayCache. Disabled
		// here to keep the example minimal.
		// ReplayCacheSize: 8192,
	})
	if err != nil {
		logger.Error("identityjwt.NewVerifier", "err", err)
		os.Exit(1)
	}

	// Eagerly fetch JWKS at startup so the first request doesn't
	// pay the cold-start cost. Failure here is NOT fatal — the pod
	// boots fine and /readyz reflects the unreachable JWKS until
	// it recovers.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := verifier.PrefetchJWKS(ctx); err != nil {
		logger.Warn("JWKS prefetch failed — pod will boot but /readyz stays 503 until Talon is reachable",
			"err", err)
	}
	cancel()

	mux := http.NewServeMux()

	// /healthz — liveness. Always 200. Kubelet must never RESTART
	// the pod on IAP misconfig; readiness is the right signal.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// /readyz — readiness. 503 when Talon's JWKS is unreachable, so
	// kube-proxy pulls the pod from Service rotation rather than
	// letting requests pile up as cascading 401s with no health
	// signal pointing at the root cause.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := verifier.HealthCheck(ctx); err != nil {
			http.Error(w, "iap verifier unhealthy: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready"))
	})

	// Protected API surface — every /api/* request must carry a
	// valid X-Talon-Identity-Token. The default fail-closed policy
	// matches the SDK side; opt into AllowMissing for back-compat
	// during a Phase A rollout.
	api := http.NewServeMux()
	api.HandleFunc("/api/whoami", whoamiHandler)
	api.HandleFunc("/api/echo", echoHandler)
	mux.Handle("/api/", identityjwt.Middleware(verifier)(api))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	logger.Info("iap-upstream-go listening",
		"addr", cfg.ListenAddr,
		"jwks_url", cfg.JWKSURL,
		"audience", cfg.ExpectedAudience)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server", "err", err)
		os.Exit(1)
	}
}

// whoamiHandler returns the verified identity. Demonstrates the
// canonical claims-reading pattern: pull *IdentityClaims out of the
// request context via ClaimsFromContext.
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	claims := identityjwt.ClaimsFromContext(r.Context())
	if claims == nil {
		// Defensive — the middleware fails closed, so this should
		// be unreachable in production. A nil here would mean someone
		// mounted the handler outside the middleware chain.
		http.Error(w, "internal: middleware not mounted", http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"sub":          claims.Subject,
		"email":        claims.Email,
		"groups":       claims.Groups,
		"tenant_id":    claims.TenantID,
		"sso_chain_id": claims.SSOChainID,
		"audience":     claims.Audience,
		"issuer":       claims.Issuer,
		"jti":          claims.JTI,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// echoHandler shows how to gate on specific groups inside the handler
// chain (the middleware verifies the token; authorization decisions
// stay in your service). RBAC strategy is up to the upstream — here
// we demand "platform_admin" for write methods.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	claims := identityjwt.ClaimsFromContext(r.Context())
	if r.Method == http.MethodPost && !hasGroup(claims, "platform_admin") {
		http.Error(w, "forbidden: requires platform_admin", http.StatusForbidden)
		return
	}
	_, _ = w.Write([]byte("echo ok\n"))
}

func hasGroup(claims *identityjwt.IdentityClaims, want string) bool {
	if claims == nil {
		return false
	}
	for _, g := range claims.Groups {
		if g == want {
			return true
		}
	}
	return false
}

type config struct {
	JWKSURL          string
	ExpectedIssuer   string
	ExpectedAudience string
	ListenAddr       string
}

func loadConfig() (config, error) {
	c := config{
		JWKSURL:          os.Getenv("TALON_JWKS_URL"),
		ExpectedIssuer:   os.Getenv("TALON_EXPECTED_ISSUER"),
		ExpectedAudience: os.Getenv("TALON_EXPECTED_AUDIENCE"),
		ListenAddr:       envOr("LISTEN_ADDR", ":8080"),
	}
	if c.JWKSURL == "" || c.ExpectedIssuer == "" || c.ExpectedAudience == "" {
		return config{}, missingEnvErr("TALON_JWKS_URL, TALON_EXPECTED_ISSUER, TALON_EXPECTED_AUDIENCE required")
	}
	return c, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

type missingEnvErr string

func (e missingEnvErr) Error() string { return string(e) }
