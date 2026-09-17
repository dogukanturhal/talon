// SPDX-License-Identifier: AGPL-3.0-or-later

// Command talon is the entry point for the Talon identity-aware proxy.
// See ADR 0001 in docs/architecture/ for the full design contract.
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	gatewayv1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
	gatewayv1beta1 "github.com/hexxlock/talon/api/v1beta1"
	"github.com/hexxlock/talon/internal/audit"
	"github.com/hexxlock/talon/internal/caep"
	"github.com/hexxlock/talon/internal/config"
	"github.com/hexxlock/talon/internal/controller"
	"github.com/hexxlock/talon/internal/conversion"
	"github.com/hexxlock/talon/internal/credexchange"
	"github.com/hexxlock/talon/internal/cv"
	"github.com/hexxlock/talon/internal/extauthz"
	"github.com/hexxlock/talon/internal/handlers"
	"github.com/hexxlock/talon/internal/identityjwt"
	tlog "github.com/hexxlock/talon/internal/log"
	"github.com/hexxlock/talon/internal/observability"
	"github.com/hexxlock/talon/internal/oidc"
	"github.com/hexxlock/talon/internal/policy"
	"github.com/hexxlock/talon/internal/posture"
	"github.com/hexxlock/talon/internal/proxy"
	"github.com/hexxlock/talon/internal/router"
	"github.com/hexxlock/talon/internal/security"
	"github.com/hexxlock/talon/internal/session"
	"github.com/hexxlock/talon/internal/spicedb"
	"github.com/hexxlock/talon/internal/svctoken"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// build-time injected via -ldflags -X.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	// Subcommand dispatch — `talon evidence …` is a CLI tool that doesn't
	// boot the daemon. Other subcommands (test, version, etc.) plug in
	// here. Default (no subcommand or unknown) falls through to runDaemon.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "evidence":
			os.Exit(runEvidence(os.Args[2:]))
		case "version":
			_, _ = os.Stdout.WriteString("talon " + version + " " + commit + " " + buildDate + "\n")
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		// stderr without a logger — config failure is the one place we
		// can't rely on slog.
		_, _ = os.Stderr.WriteString("talon: config load failed: " + err.Error() + "\n")
		os.Exit(2)
	}

	logger := tlog.New(cfg.LogLevel, cfg.LogFormat)
	logger.Info("talon starting",
		"version", version, "commit", commit, "buildDate", buildDate,
		"externalURL", cfg.ExternalURL.String(), "cookieDomain", cfg.CookieDomain,
		"issuer", cfg.IssuerURL, "internalIssuer", cfg.InternalIssuerURL,
		"requiredRole", cfg.RequiredRole, "roleGateMode", cfg.RoleGateMode, "sessionTTL", cfg.SessionHardTTL,
	)

	rc := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	{
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := rc.Ping(pingCtx).Err(); err != nil {
			logger.Warn("redis initial ping failed; continuing — readiness will fail-closed",
				"addr", cfg.RedisAddr, "err", err)
		}
		cancel()
	}

	store, err := session.NewStore(rc, cfg.CookieEncryptKey, nil, cfg.SessionHardTTL, cfg.SessionRefreshMin)
	if err != nil {
		logger.Error("session store init failed", "err", err)
		os.Exit(2)
	}
	// DDIL P3.11 — circuit breaker on the per-request Redis session reads
	// so a sustained Redis outage sheds load (fast fail-closed 503) instead
	// of every request stalling on a dead dependency's dial/read timeout.
	store.SetRedisBreaker(resilient.NewBreaker(resilient.BreakerConfig{}))

	// Reserve the default Prometheus registry to start clean.
	reg := prometheus.NewRegistry()
	metrics := observability.New(reg)

	// DDIL P3.1 — governed offline session-grace on the read-hot path. On a
	// Redis session-store outage, serve a signed, time-boxed last-known-good
	// session within budget (same operating-spec 15m/5m tiers as the authz
	// PDP) then fail closed; revocation is honoured offline via a per-subject
	// epoch bumped on every revoke (wired into the invalidator fan-out below).
	// Without it the SpiceDB privileged offline budget is unreachable during a
	// Redis outage because the session read fails first.
	var offlineSessions *session.OfflineSessionCache
	if cfg.DDILOfflineSessionEnabled {
		osc, err := session.NewOfflineSessionCache(session.OfflineSessionConfig{
			StandardBudget:   cfg.DDILOfflineStandardBudget,
			PrivilegedBudget: cfg.DDILOfflinePrivilegedBudget,
			Metrics:          metrics,
			Logger:           logger,
		})
		if err != nil {
			logger.Error("offline session cache init failed", "err", err)
			os.Exit(2)
		}
		offlineSessions = osc
		logger.Info("offline session-grace enabled (DDIL P3.1 governed-degrade)",
			"standard_budget", cfg.DDILOfflineStandardBudget.String(),
			"privileged_budget", cfg.DDILOfflinePrivilegedBudget.String())
	} else {
		logger.Info("offline session-grace disabled (TALON_DDIL_OFFLINE_SESSION=false) — strict fail-closed at t=0 on Redis outage")
	}

	discoveryCtx, cancelDiscovery := context.WithTimeout(context.Background(), 30*time.Second)
	rp, err := oidc.New(discoveryCtx, cfg, store)
	cancelDiscovery()
	if err != nil {
		logger.Error("oidc init failed", "err", err)
		os.Exit(2)
	}
	logger.Info("oidc discovery ok", "issuer", cfg.IssuerURL)

	roleFilter := policy.NewRoleFilter(cfg.RequiredRole)

	// SpiceDB client — optional (cluster may not have one in dev).
	// Phase 2.1: schema verification at startup + per-request
	// CheckPermission in the PE.
	var spiceCachedClient *spicedb.CachedClient
	var spiceClient *spicedb.Client
	if cfg.SpiceDBAddr != "" && cfg.SpiceDBToken != "" {
		c, err := spicedb.NewClient(cfg.SpiceDBAddr, cfg.SpiceDBToken)
		if err != nil {
			logger.Error("spicedb client init failed", "err", err)
			os.Exit(2)
		}
		spiceClient = c
		// Read-only verification that the live cluster schema (owned
		// exclusively by the spicedb-schema Argo CD Application — see
		// internal/spicedb/client.go's schemaZed doc comment / an internal incident)
		// contains every definition Talon requires. Talon never calls
		// WriteSchema itself any more.
		schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 30*time.Second)
		zedToken, err := spiceClient.EnsureSchema(schemaCtx)
		schemaCancel()
		if err != nil {
			logger.Error("spicedb EnsureSchema failed", "err", err)
			os.Exit(2)
		}
		logger.Info("spicedb schema verified", "zedToken", zedToken)
		// 30s TTL, 1024-entry LRU cache (per ADR 0001 §7.b).
		spiceCachedClient = spicedb.NewCachedClient(spiceClient, spicedb.NewCache(1024, 30*time.Second))
		// Wire decision-cache hit/miss/invalidate metrics + the
		// session-revoke fan-out. Together these turn the cache from
		// a TTL-only smoother into a Tier-1 perf primitive: revoked
		// users lose access in ~0 s instead of waiting up to 30 s for
		// the entry to age out (boot prompt §4 Gap 6).
		spiceCachedClient.SetMetrics(metrics)
		// DDIL P3.11 — circuit breaker on the live SpiceDB CheckPermission
		// so a sustained SpiceDB outage sheds load (fast-fail into the
		// offline PDP / fail-closed) instead of retry-storming. Shared
		// across every authz check == one breaker per SpiceDB dependency.
		spiceCachedClient.SetBreaker(resilient.NewBreaker(resilient.BreakerConfig{}))
		// DDIL P3.1 — offline authorization PDP. On a SpiceDB partition,
		// serve a signed, time-boxed last-known-good decision within budget
		// (15m standard / 5m privileged) then fail closed; revocation is
		// honoured offline via a per-subject epoch bumped on every revoke.
		if cfg.DDILOfflinePDPEnabled {
			offlinePDP, err := spicedb.NewOfflinePDP(spicedb.OfflinePDPConfig{
				StandardBudget:   cfg.DDILOfflineStandardBudget,
				PrivilegedBudget: cfg.DDILOfflinePrivilegedBudget,
				Metrics:          metrics,
				Logger:           logger,
			})
			if err != nil {
				logger.Error("spicedb offline PDP init failed", "err", err)
				os.Exit(2)
			}
			spiceCachedClient.SetOfflinePDP(offlinePDP)
			logger.Info("spicedb offline PDP enabled (DDIL P3.1 governed-degrade)",
				"standard_budget", cfg.DDILOfflineStandardBudget.String(),
				"privileged_budget", cfg.DDILOfflinePrivilegedBudget.String())
		} else {
			logger.Info("spicedb offline PDP disabled (TALON_DDIL_OFFLINE_PDP=false) — strict fail-closed at t=0 on SpiceDB outage")
		}
		// Inject the SpiceDB writer into the OIDC RP so successful
		// callbacks TOUCH `group:<role>#member@user:<sub>` for every
		// role on the JWT. Closes the missing edge between the
		// TalonRoute reconciler-seeded route→group edges and the
		// per-request user-subject CheckPermission. Without this hook
		// every protected route returns no_permission post-login —
		// the 2026-05-08 outage on internal.example.com.
		rp.SetSpiceDB(spiceClient)
	} else {
		logger.Warn("spicedb disabled (TALON_SPICEDB_ADDR or TALON_SPICEDB_TOKEN empty); role filter only")
	}

	// Wire per-subject revocation fan-out to every decision cache that must
	// honour a kick — the SpiceDB decision cache (when enabled) AND the DDIL
	// P3.1 offline session cache — so a revoke bumps each cache's epoch and a
	// kicked user cannot pass on a stale cached allow OR a stale cached
	// session (online or offline). Only non-nil members are added (a typed-nil
	// interface would panic on fan-out).
	var invalidators session.MultiInvalidator
	if spiceCachedClient != nil {
		invalidators = append(invalidators, spiceCachedClient)
	}
	if offlineSessions != nil {
		invalidators = append(invalidators, offlineSessions)
	}
	if len(invalidators) > 0 {
		store.SetSubjectInvalidator(invalidators)
	}

	pe := policy.NewCompositePolicy(roleFilter, spiceCachedClient, policy.ParseRoleGateMode(cfg.RoleGateMode))
	health := handlers.NewHealth(rc)
	health.MarkReady()

	auditEmitter := audit.New(logger, version)
	adminAPI := &handlers.Admin{
		Store:        store,
		Redis:        rc,
		RequiredRole: cfg.RequiredRole,
		CookieName:   oidc.SessionCookieName,
		Audit:        auditEmitter,
	}

	rt := router.New(cfg, rp, store, pe, metrics, health, auditEmitter, adminAPI)
	// DDIL P3.1 — wire the governed offline session-grace cache (nil when
	// TALON_DDIL_OFFLINE_SESSION=false, in which case the router keeps the
	// strict fail-closed-at-t=0 behaviour).
	rt.SetOfflineSessions(offlineSessions)

	// Global ZTNA baseline policy (secure-by-default). When
	// TALON_DEFAULT_POLICY_REGO_FILE is set, every route with no own
	// policyRego inherits this compiled baseline instead of skipping the
	// posture gate. A compile error is logged loudly and leaves the
	// baseline unwired (routes degrade to legacy opt-in, never fail-open
	// silently). Routes opt OUT via an explicit permissive policyRego.
	if cfg.DefaultPolicyRego != "" {
		defRego, err := policy.CompileRego(context.Background(), cfg.DefaultPolicyRego)
		if err != nil {
			logger.Error("compile TALON_DEFAULT_POLICY_REGO_FILE failed — ZTNA baseline NOT applied", "err", err)
		} else {
			rt.SetDefaultPolicyRego(defRego)
			logger.Info("ZTNA baseline default policy wired — applies to every route with no own policyRego")
		}
	}

	// IAP identity-token signer — RS256 JWT stamped on every proxied
	// request (X-Talon-Identity-Token). Phase A: optional; when the
	// signing key isn't provisioned yet (TALON_IAP_SIGNING_KEY_PEM
	// empty) Talon proxies with the unsigned X-Talon-* fallback so the
	// SDK verifier path is invisible. Once the matching SDK ships,
	// flip Phase B: SDK refuses requests without a verified token
	// (defense-in-depth — survives any future Linkerd authz misconfig).
	// See internal/identityjwt for trust model, claims schema, and
	// reference vendors (Google Cloud IAP, Cloudflare Access, Pomerium).
	if cfg.IAPIdentityTokenSigningKeyPEM != "" {
		iapSigner, signerErr := identityjwt.NewSignerFromPEM(
			[]byte(cfg.IAPIdentityTokenSigningKeyPEM),
			cfg.ExternalURL.String(),
		)
		if signerErr != nil {
			logger.Error("IAP identity-token signer init failed — Talon will run with unsigned-headers-only fallback",
				"err", signerErr)
		} else {
			// Optional previous-key registration for zero-downtime rotation:
			// publish the retired public key on the JWKS endpoint so JWTs
			// signed by the old key during the rolling cutover are still
			// honoured (~6-minute overlap = 60s JWT lifetime + 300s JWKS
			// cache). Empty in steady state. Matches Cloudflare Access's
			// N+1 JWKS rotation pattern.
			if cfg.IAPIdentityTokenPreviousKeyPEM != "" {
				if prevErr := iapSigner.AddPreviousPublicKeyFromPEM(
					[]byte(cfg.IAPIdentityTokenPreviousKeyPEM),
				); prevErr != nil {
					logger.Error("IAP identity-token previous-key registration failed — JWKS will publish active key only",
						"err", prevErr)
				} else {
					logger.Info("IAP identity-token previous-key registered for rotation overlap",
						"retired_kids", func() []string {
							prev := iapSigner.PreviousPublicKeys()
							out := make([]string, 0, len(prev))
							for _, rk := range prev {
								out = append(out, rk.Kid)
							}
							return out
						}())
				}
			}
			rt.SetIAPSigner(iapSigner)
			logger.Info("IAP identity-token signer enabled",
				"kid", iapSigner.Kid(),
				"issuer", iapSigner.Issuer(),
				"jwks_url", cfg.ExternalURL.String()+"/.well-known/jwks.json",
				"retired_keys", len(iapSigner.PreviousPublicKeys()))
			// Surface the active kid as a Prometheus label (Item 3
			// dashboarding affordance) + the retired-key count as a
			// gauge. talon_iap_active_kid{kid="…"} stays at 1 for the
			// life of this process; rotations bring up a new process
			// with the new kid label. talon_iap_retired_kids_published
			// is non-zero only during the overlap window.
			metrics.IAPActiveKid.WithLabelValues(iapSigner.Kid()).Set(1)
			metrics.IAPRetiredKidsPublished.Set(float64(len(iapSigner.PreviousPublicKeys())))
			// Gate /readyz on the signer being functional (Item 6).
			// Closes the silent-degrade failure mode where a malformed
			// Vault projection → unsigned-only proxying → Phase B SDK
			// 401-storm with no health signal. The probe synthesises a
			// mint+verify roundtrip; non-nil error fails /readyz.
			health.SetIAPHealthCheck(iapSigner.HealthCheck)
		}
	} else {
		logger.Info("IAP identity-token signing disabled (TALON_IAP_SIGNING_KEY_PEM empty) — proxying with unsigned X-Talon-* headers only")
	}

	// Streaming revocation webhook — wired iff allow-list is non-empty.
	// The the GitOps repository Linkerd AuthorizationPolicy + MTA gate the
	// network path; this allow-list is defence-in-depth at the application
	// layer + audit identity stamp.
	if len(cfg.RevokeWebhookAllowedIdentities) > 0 {
		revokeWebhook := &handlers.RevokeWebhook{
			Store:             store,
			Redis:             rc,
			Audit:             auditEmitter,
			AllowedIdentities: cfg.RevokeWebhookAllowedIdentities,
			RateLimitPerSec:   cfg.RevokeWebhookRateLimitPerSec,
		}
		rt.SetRevokeWebhook(revokeWebhook)
		logger.Info("streaming revocation webhook enabled",
			"allowed_identities", len(cfg.RevokeWebhookAllowedIdentities),
			"rate_limit_per_sec", cfg.RevokeWebhookRateLimitPerSec)
	} else {
		logger.Warn("streaming revocation webhook disabled (TALON_REVOKE_WEBHOOK_ALLOWED_IDENTITIES empty)")
	}

	// OIDC Back-Channel Logout 1.0 receiver — POST /auth/backchannel-logout
	// on the auth host. Wired unconditionally because the JWT itself
	// authenticates per spec §2.6; Linkerd MTA + AuthorizationPolicy
	// (deploy/helm/talon/templates/authorizationpolicy.yaml) gate the
	// wire path. Reuses rp's IDTokenVerifier — same JWKS + iss + aud
	// constraints as the id_token verification path.
	backchannelLogout := &handlers.BackchannelLogout{
		Verifier:   rp.IDTokenVerifier(),
		Store:      store,
		Redis:      rc,
		Audit:      auditEmitter,
		MaxIATSkew: cfg.BackchannelLogoutMaxIATSkew,
		IssuerURL:  rp.IssuerURL(),
	}
	rt.SetBackchannelLogout(backchannelLogout)
	logger.Info("backchannel logout receiver enabled",
		"max_iat_skew", cfg.BackchannelLogoutMaxIATSkew,
		"issuer", rp.IssuerURL())

	// OIDC Front-Channel Logout 1.0 receiver — GET /auth/frontchannel-logout
	// on the auth host. Browser-driven complement to BCL: the OP's
	// RP-initiated logout page renders an iframe pointing here, the
	// iframe load fires from the user's browser, and we revoke the
	// matching Talon session via the per-OP-session sid index. The
	// `iss` query parameter validates the request per spec §5.4; CSP
	// frame-ancestors locks embedding to the OP's logout-page origin
	// to prevent hostile force-logout sites.
	frontchannelLogout := &handlers.FrontchannelLogout{
		Store:         store,
		Redis:         rc,
		Audit:         auditEmitter,
		IssuerURL:     rp.IssuerURL(),
		FrameAncestor: cfg.FrontchannelLogoutFrameAncestor,
	}
	rt.SetFrontchannelLogout(frontchannelLogout)
	logger.Info("frontchannel logout receiver enabled",
		"issuer", rp.IssuerURL(),
		"frame_ancestor", cfg.FrontchannelLogoutFrameAncestor)
	// talon-service-tokens Phase 3 — feature-flagged Bearer middleware.
	// When TALON_SVCTOKEN_ENABLED=true, instantiate the verifier against
	// Falcon-ID's JWKS + issuer and wire it into the Router. Server CRs
	// with authMode=bearer or authMode=both then consult it BEFORE the
	// cookie path; AuthModeCookie hosts pay zero extra work. Default OFF
	// in this cluster until the pilot consumer (ArgoCD repo-server,
	// Phase 4) is verified.
	if cfg.SvctokenEnabled {
		// Parse federated issuer PEM keys (Phase 5+ multi-trust).
		// Empty / nil = federated trust disabled; verifier behaves
		// exactly as before. Per-issuer parse failures are operator
		// misconfig — surface at startup, not at first verify miss.
		var federated []svctoken.FederatedIssuerConfig
		for i, e := range cfg.SvctokenFederatedIssuers {
			if e.StaticPublicKeyPEM == "" && e.JWKSURL == "" {
				logger.Error("svctoken federated issuer missing key material",
					"index", i, "issuer", e.Issuer)
				os.Exit(2)
			}
			var pub *rsa.PublicKey
			if e.StaticPublicKeyPEM != "" {
				parsed, err := svctoken.ParseRSAPublicKeyPEM([]byte(e.StaticPublicKeyPEM))
				if err != nil {
					logger.Error("svctoken federated issuer PEM parse failed",
						"index", i, "issuer", e.Issuer, "err", err)
					os.Exit(2)
				}
				pub = parsed
			}
			federated = append(federated, svctoken.FederatedIssuerConfig{
				Issuer:          e.Issuer,
				StaticPublicKey: pub,
				JWKSURL:         e.JWKSURL,
				AllowedHosts:    e.AllowedHosts,
			})
		}
		svcVerifier, err := svctoken.NewVerifier(svctoken.VerifierConfig{
			JWKSURL:            cfg.SvctokenJWKSURL,
			ExpectedIssuer:     cfg.SvctokenIssuer,
			ReplayCacheSize:    cfg.SvctokenReplayCacheSize,
			FederatedIssuers:   federated,
			JWKSStaleThreshold: cfg.SvctokenJWKSStaleThreshold, // DDIL P3.1 governed stale window
			// Governed-degrade observability: WARN + metric each time a
			// verify is served from stale (last-good) JWKS during a
			// Falcon-ID outage, within the stale budget.
			OnJWKSStale: func(staleFor time.Duration) {
				metrics.DDILDegraded.WithLabelValues(
					observability.DDILDepJWKSSvctoken, observability.DDILOutcomeStaleServed).Inc()
				logger.Warn("svctoken: serving STALE Falcon-ID JWKS (DDIL P3.1 governed-degrade) — refresh failing, within stale budget",
					"stale_for", staleFor.String(),
					"stale_budget", cfg.SvctokenJWKSStaleThreshold.String(),
					"jwks_url", cfg.SvctokenJWKSURL)
			},
		})
		if err != nil {
			logger.Error("svctoken verifier construction failed", "err", err)
			os.Exit(2)
		}
		// Eagerly fetch JWKS so a Falcon-ID outage fails fast at startup
		// instead of every first verify attempt.
		ctxPrefetch, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := svcVerifier.PrefetchJWKS(ctxPrefetch); err != nil {
			cancel()
			logger.Warn("svctoken JWKS prefetch failed; will retry lazily",
				"jwks_url", cfg.SvctokenJWKSURL, "err", err)
		} else {
			cancel()
			logger.Info("svctoken JWKS prefetch ok",
				"jwks_url", cfg.SvctokenJWKSURL, "issuer", cfg.SvctokenIssuer)
		}
		rt.SetSvctokenVerifier(svcVerifier)
		logger.Info("svctoken Bearer middleware enabled (talon-service-tokens Phase 3)",
			"jwks_url", cfg.SvctokenJWKSURL,
			"issuer", cfg.SvctokenIssuer,
			"replay_cache_size", cfg.SvctokenReplayCacheSize)

		// Phase 5+ federated multi-trust — positive confirmation log so
		// operators can read Talon's startup output and verify which
		// secondary issuers are loaded without having to inspect the
		// rendered Helm values or the env var. Before this log existed,
		// the only signal that federated trust was wired was indirect
		// (env var inspection or live request testing) — easy to miss
		// a config typo or stale ESO Secret. Emits one structured line
		// per configured federated issuer. Empty federated list emits
		// nothing — keeps the startup log clean when the feature is
		// not in use.
		for _, e := range cfg.SvctokenFederatedIssuers {
			logger.Info("svctoken federated issuer registered (Phase 5+)",
				"issuer", e.Issuer,
				"static_pem_present", e.StaticPublicKeyPEM != "",
				"jwks_url", e.JWKSURL,
				"allowed_hosts", e.AllowedHosts)
		}

		// talon-service-tokens Phase 4.5 — credential exchange. Wires
		// the per-host upstream credential loader so routes with
		// AuthModeBearerOrBasicWithCredentialExchange substitute the
		// inbound verified-svctoken for the upstream-shaped credential
		// (PAT / robot account) sourced from a Kubernetes Secret in
		// the talon namespace.
		//
		// The loader is unconditionally wired when svctoken is on; if
		// no per-host Secret exists, Load returns ErrNoCredential and
		// the router preserves the original Authorization (graceful
		// degradation) and increments the
		// svctoken_credential_exchange_uncfg counter so operators can
		// alert on opt-in-without-Secret drift.
		k8sCfg, err := ctrl.GetConfig()
		if err != nil {
			logger.Error("credexchange: GetConfig", "err", err)
			os.Exit(2)
		}
		cs, err := kubernetes.NewForConfig(k8sCfg)
		if err != nil {
			logger.Error("credexchange: kubernetes client", "err", err)
			os.Exit(2)
		}
		credLoader := credexchange.NewK8sSecretLoader(cs, cfg.PodNamespace, 30*time.Second)
		rt.SetCredentialExchangeLoader(credLoader)
		logger.Info("svctoken credential exchange loader enabled (Phase 4.5)",
			"secret_namespace", cfg.PodNamespace,
			"cache_ttl", "30s")
	} else {
		logger.Info("svctoken Bearer middleware DISABLED (default; flip TALON_SVCTOKEN_ENABLED=true to enable)")
	}

	// Phase 1: register protected upstreams from TALON_PROTECTED_HOSTS_JSON.
	// Phase 2 replaces with TalonRoute CRD reconciler doing the same
	// RegisterUpstream calls dynamically on watch events.
	for _, h := range cfg.ProtectedHosts {
		rt.RegisterUpstream(h.Host, router.RegisterUpstreamParams{
			Handler:     proxy.NewHandler(h.Host, proxy.Upstream{Service: h.Upstream, Scheme: h.Scheme}, metrics),
			Permission:  h.Permission,
			AuthMode:    svctoken.AuthMode(h.AuthMode),
			PublicPaths: h.PublicPaths,
			// Env-var entries are the early-boot fallback — they intentionally
			// inherit cluster defaults for everything: no MFA, no per-route
			// CV, no Rego, no per-host TTL/idle/IP-rebind, no device claims,
			// not in audit-only. Production routes go through the TalonRoute
			// CRD reconciler which carries the per-host knobs.
		})
		logger.Info("registered protected upstream (static env)",
			"host", h.Host, "upstream", h.Upstream, "permission", h.Permission, "scheme", h.Scheme)
	}

	// CAEP receiver wiring — ADR 0011 Part A. Mounted on the auth host
	// at POST /caep/events. Reuses the svctoken JWKS fetcher for
	// transmitter trust (Falcon-ID's JWKS is the same one svctoken
	// verifies against — same iss, same keypair). When the env flag is
	// false, the route returns 503 explicitly (vs 404) so SIEM can
	// distinguish "intentionally disabled" from "route-typo".
	if cfg.CAEPEnabled {
		caepCache := caepReplayCache()
		// The SET signature is verified against the transmitter's JWKS. By
		// default that's derived from the issuer URL, but the posture-signer
		// transmitter's issuer (posture.hexxlock.com) is mTLS-gated and
		// unreachable from this pod, so CAEPTransmitterJWKSURL points the
		// fetch at the in-cluster Service. The `iss` claim is still checked
		// against CAEPTransmitterIssuer regardless of the fetch location.
		caepJWKSURL := cfg.CAEPTransmitterJWKSURL
		if caepJWKSURL == "" {
			caepJWKSURL = cfg.CAEPTransmitterIssuer + "/.well-known/jwks.json"
		}
		caepReceiver, caepErr := caep.NewReceiver(caep.ReceiverConfig{
			ExpectedIssuer:   cfg.CAEPTransmitterIssuer,
			ExpectedAudience: cfg.CAEPAudience,
			Resolver:         newSimpleJWKSResolver(caepJWKSURL),
			Revoker:          &caepRevoker{store: store},
			Replay:           caepCache,
			Audit:            &caepAuditAdapter{emitter: auditEmitter},
		})
		if caepErr != nil {
			logger.Error("CAEP receiver init failed — /caep/events will be unmounted", "err", caepErr)
		} else {
			rt.SetCAEPHandler(caep.HTTPHandler(caepReceiver))
			logger.Info("CAEP receiver enabled",
				"iss", cfg.CAEPTransmitterIssuer,
				"aud", cfg.CAEPAudience,
				"jwks_url", caepJWKSURL)
		}
	}

	// Posture verifier wiring — ADR 0011 Part B. The router consumes
	// X-Talon-Posture headers only after this is wired; nil keeps the
	// posture-check path inert (routes that declare `requirePosture`
	// log a warning + allow until the chart toggles this on).
	if cfg.PostureEnabled {
		pv, pvErr := posture.NewVerifier(posture.VerifierConfig{
			TrustedIssuers:   cfg.PostureTrustedIssuers,
			ExpectedAudience: cfg.PostureAudience,
			MaxAge:           cfg.PostureMaxAge,
			// DDIL P3.10 governed posture-grace budgets (0 = disabled = hard
			// fail-closed at exp, the backward-compatible default).
			GraceCorp: cfg.PostureGraceCorp,
			GraceByod: cfg.PostureGraceByod,
			Resolver:  newPostureJWKSResolver(cfg.PostureTrustedIssuers, cfg.PostureJWKSURL),
		})
		if pvErr != nil {
			logger.Error("posture verifier init failed — X-Talon-Posture will be ignored", "err", pvErr)
		} else {
			rt.SetPostureVerifier(pv)
			logger.Info("posture verifier enabled",
				"trusted_issuers", cfg.PostureTrustedIssuers,
				"aud", cfg.PostureAudience,
				"max_age", cfg.PostureMaxAge,
				"grace_corp", cfg.PostureGraceCorp,
				"grace_byod", cfg.PostureGraceByod)
		}
	}

	// Two listeners: HTTPS for browser traffic, plain HTTP for /metrics
	// scraping (kept off the TLS port to avoid TLS-handshake pollution
	// in the metrics path).
	//
	// security.Headers wraps the router so every response Talon writes
	// (auth callbacks, deny pages, /caep/events errors) carries the
	// tier-1 baseline: HSTS preload + X-Frame-Options + Referrer-Policy
	// + Permissions-Policy. Downstream handlers (FCL iframe) can still
	// override CSP / X-Frame-Options before WriteHeader.
	mainServer := &http.Server{
		Addr:              cfg.ListenHTTPS,
		Handler:           security.Headers(security.Options{SkipCOOPHosts: cfg.SkipCOOPHosts}, rt),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", observability.Handler(reg))
	metricsMux.HandleFunc("/healthz", health.Liveness)
	metricsServer := &http.Server{
		Addr:              cfg.ListenMetrics,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 3)
	mgrCtx, mgrCancel := context.WithCancel(context.Background())
	// mgrCancel is invoked in the shutdown sequence below — not via
	// `defer` because this function calls os.Exit on fatal init paths,
	// which bypasses defers (gocritic exitAfterDefer).

	// TalonRoute controller-runtime manager. Phase 2 ships alongside
	// the static TALON_PROTECTED_HOSTS_JSON; both populate the same
	// router. Per ADR 0003 §4.3 leader election is enabled in the
	// talon ns so only one pod writes Status.
	if cfg.EnableController {
		log.SetLogger(zap.New(zap.UseDevMode(false)))
		k8sCfg, err := ctrl.GetConfig()
		if err != nil {
			logger.Error("controller: GetConfig", "err", err)
			os.Exit(2)
		}
		// Compose scheme: client-go core + our v1alpha1 + v1beta1.
		// Both versions need to be registered so the reconciler can
		// fetch either shape — v1alpha1 is the watched-and-storage
		// version (Phase 7.3.b); v1beta1 fetched in-reconcile when
		// the operator-enabled conversion webhook (Phase 6a.2) lets
		// the API server up-convert so pathRules surface for the
		// matcher engine.
		schm := clientgoscheme.Scheme
		if err := gatewayv1alpha1.AddToScheme(schm); err != nil {
			logger.Error("controller: v1alpha1 AddToScheme", "err", err)
			os.Exit(2)
		}
		if err := gatewayv1beta1.AddToScheme(schm); err != nil {
			logger.Error("controller: v1beta1 AddToScheme", "err", err)
			os.Exit(2)
		}
		mgr, err := ctrl.NewManager(k8sCfg, manager.Options{
			Scheme:                  schm,
			LeaderElection:          true,
			LeaderElectionID:        "talon-controller-leader.gateway.talon.hexxlock.com",
			LeaderElectionNamespace: cfg.PodNamespace,
			HealthProbeBindAddress:  "0", // probes already served by /healthz on the data-plane listener
			Metrics:                 metricsserver.Options{BindAddress: "0"},
		})
		if err != nil {
			logger.Error("controller: NewManager", "err", err)
			os.Exit(2)
		}
		if err := (&controller.TalonRouteReconciler{
			Client:  mgr.GetClient(),
			Scheme:  mgr.GetScheme(),
			Router:  rt,
			Metrics: metrics,
			SpiceDB: spiceClient,
			SecurityPolicyTranslator: controller.SecurityPolicyTranslatorConfig{
				Enabled:                  cfg.SecurityPolicyEnabled,
				Namespace:                cfg.SecurityPolicyNamespace,
				ExtAuthzServiceName:      cfg.ExtAuthzServiceName,
				ExtAuthzServiceNamespace: cfg.ExtAuthzServiceNamespace,
				ExtAuthzPort:             cfg.ExtAuthzPort,
				HTTPRouteNamespace:       cfg.SecurityPolicyNamespace,
			},
		}).SetupWithManager(mgr); err != nil {
			logger.Error("controller: SetupWithManager", "err", err)
			os.Exit(2)
		}
		// Continuous verification — leader-only Runnable per ADR 0001 §6.
		// Phase 4.1 — proper refresh-token grant + userinfo dance per
		// internal/cv/runner.go header comment. The IDP exposes both
		// /oauth/token + /oauth/userinfo on the cluster-internal issuer;
		// no public hop, no mTLS extra step (Linkerd handles it).
		cvRunner := &cv.Runner{
			Store:        store,
			Redis:        rc,
			TokenURL:     cfg.InternalIssuerURL + "/oauth/token",
			UserInfoURL:  cfg.InternalIssuerURL + "/oauth/userinfo",
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Interval:     cfg.ContinuousVerifyInterval,
			RequiredRole: cfg.RequiredRole,
			Audit:        auditEmitter,
		}
		if err := mgr.Add(cvRunner); err != nil {
			logger.Error("controller: failed to register cv.Runner", "err", err)
			os.Exit(2)
		}
		// Wire the runner into the router so per-route inline CV
		// (TalonRoute.spec.continuousVerifyMinutes) can fire on any pod
		// — VerifyOneInline doesn't require leader election (only the
		// periodic tick does, to avoid N× IdP load).
		rt.SetCVRunner(cvRunner)
		go func() {
			logger.Info("controller-runtime manager starting", "leaseNamespace", cfg.PodNamespace)
			if err := mgr.Start(mgrCtx); err != nil {
				errCh <- err
			}
		}()
	} else {
		logger.Info("controller disabled (TALON_ENABLE_CONTROLLER=false)")
	}

	go func() {
		logger.Info("https listener", "addr", mainServer.Addr)
		if err := mainServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("metrics listener", "addr", metricsServer.Addr)
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Phase 6a.2 — CRD conversion webhook HTTPS listener. When
	// TALON_LISTEN_CONVERSION_WEBHOOK is set, expose /convert on
	// the configured port; kube-apiserver POSTs ConversionReview
	// requests here whenever a client reads/writes a TalonRoute in
	// a version different from the storage version (v1alpha1 stays
	// storage; v1beta1 is the up-converted served version).
	//
	// MUST be TLS — kube-apiserver requires HTTPS for webhooks.
	// Cert defaults to the main TLS material (same cert-manager
	// ClusterIssuer); ConversionWebhookCertFile/-KeyFile let
	// operators provide a distinct cert if needed (e.g., to scope
	// the webhook SAN list separately).
	var convWebhookServer *http.Server
	if cfg.ListenConversionWebhook != "" {
		convCert := cfg.ConversionWebhookCertFile
		if convCert == "" {
			convCert = cfg.TLSCertFile
		}
		convKey := cfg.ConversionWebhookKeyFile
		if convKey == "" {
			convKey = cfg.TLSKeyFile
		}
		convMux := http.NewServeMux()
		convMux.HandleFunc("/convert", conversion.Handler())
		convMux.HandleFunc("/healthz", health.Liveness)
		convWebhookServer = &http.Server{
			Addr:              cfg.ListenConversionWebhook,
			Handler:           convMux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		go func() {
			logger.Info("conversion-webhook listener", "addr", convWebhookServer.Addr)
			if err := convWebhookServer.ListenAndServeTLS(convCert, convKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	} else {
		logger.Info("conversion-webhook listener disabled (TALON_LISTEN_CONVERSION_WEBHOOK empty)")
	}

	// Phase 7.1 — Envoy ext_authz gRPC listener for the shared-PDP
	// shape (GEP-1494 alignment). When TALON_LISTEN_EXTAUTHZ is set,
	// expose envoy.service.auth.v3.Authorization on the configured
	// port; data planes (Envoy Gateway, Istio, APISIX via ext-plugin,
	// Cilium PoC) call Check() per request and get the same decision
	// the HTTP /auth/verify forward-auth path produces (both share
	// router.Verify). Empty config disables — operators opt in once
	// the consumer side is ready.
	//
	// Linkerd MeshTLS terminates the transport — the gRPC server
	// itself runs plain h2c on this port. AuthorizationPolicy in the
	// talon ns gates which SA identities may call.
	var extAuthzServer *grpc.Server
	if cfg.ListenExtAuthz != "" {
		extAuthzServer = grpc.NewServer()
		authv3.RegisterAuthorizationServer(extAuthzServer, extauthz.NewServer(rt))
		lis, err := net.Listen("tcp", cfg.ListenExtAuthz)
		if err != nil {
			logger.Error("extauthz: listen", "addr", cfg.ListenExtAuthz, "err", err)
			os.Exit(2)
		}
		go func() {
			logger.Info("extauthz listener", "addr", cfg.ListenExtAuthz)
			if err := extAuthzServer.Serve(lis); err != nil {
				errCh <- err
			}
		}()
	} else {
		logger.Info("extauthz listener disabled (TALON_LISTEN_EXTAUTHZ empty)")
	}

	// Wait for SIGINT/SIGTERM or a fatal listener error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("signal received, shutting down", "signal", sig.String())
	case err := <-errCh:
		logger.Error("listener fatal", "err", err)
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgrCancel()
	_ = mainServer.Shutdown(shutCtx)
	_ = metricsServer.Shutdown(shutCtx)
	if convWebhookServer != nil {
		_ = convWebhookServer.Shutdown(shutCtx)
	}
	if extAuthzServer != nil {
		// GracefulStop drains in-flight Check() RPCs before returning.
		// Bounded by shutCtx via the parent goroutine — if drain takes
		// longer than the deadline, Stop() in the deferred path will
		// hard-close any remaining streams. Same shutdown discipline
		// as the HTTP servers above.
		stopped := make(chan struct{})
		go func() {
			extAuthzServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-shutCtx.Done():
			extAuthzServer.Stop()
		}
	}
	_ = rc.Close()
	if spiceClient != nil {
		_ = spiceClient.Close()
	}
	logger.Info("shutdown complete")
}
