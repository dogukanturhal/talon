// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads Talon runtime configuration from environment
// variables. All settings are documented in deploy/helm/talon/values.yaml
// (the chart wires them into the Deployment as TALON_*).
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ProtectedHost is a single static-routing entry consumed by router at
// startup. Phase 2 replaces this static config with TalonRoute CRD
// reconciler-driven dynamic registration; the env var stays as a
// break-glass for early-boot sanity routes.
type ProtectedHost struct {
	// Public host the IngressRoute matches on (e.g. internal.example.com).
	Host string `json:"host"`
	// Cluster-internal host:port to forward to.
	Upstream string `json:"upstream"`
	// Optional permission name for SpiceDB CheckPermission (Phase 2). Phase 1
	// ignores; group filter alone gates access.
	Permission string `json:"permission,omitempty"`
	// Optional URL scheme for the upstream dial. Defaults to `http`. Use
	// `https` for upstreams that terminate TLS at the application layer
	// (e.g. SafeLine mgt nginx on :1443 which returns a JS-redirect on
	// plain HTTP). Pairs with the same field on the TalonRoute CR's
	// Upstream type — both static (env-var) and dynamic (CR) wiring honor
	// this knob via proxy.Upstream.Scheme.
	Scheme string `json:"scheme,omitempty"`
	// AuthMode controls how this host accepts identity (talon-service-tokens
	// Phase 3). Recognised values: "cookie" (default — browser-only, OIDC
	// dance), "bearer" (machine-only, no OIDC dance), "both" (mixed:
	// Bearer-first with cookie fallback for hosts like github.com
	// and ghcr.io/dogukanturhal that serve human browsers AND CI/registry
	// clients on the same hostname). When the Svctoken verifier is not
	// wired (cluster default off), any value other than "" is treated
	// as "cookie" — the bearer path is skipped silently.
	//
	// See talon/docs/specs/talon-service-tokens.md §"Per-Server-CR
	// authMode" for the decision rationale.
	AuthMode string `json:"authMode,omitempty"`
	// PublicPaths are method+exact-path routes on this host that bypass the
	// Talon session gate (ZTNA enrollment-bootstrap carve-out). The upstream
	// MUST self-authenticate these requests (e.g. jess verifies a WebAuthn
	// witness JWS on /device-cert/attest). Empty = fully gated.
	PublicPaths []PublicRoute `json:"publicPaths,omitempty"`
}

// PublicRoute is a method + exact-path pair on a ProtectedHost that bypasses
// Talon's session gate. Match is exact path (after NormalizePath) +
// case-insensitive method. See ProtectedHost.PublicPaths.
type PublicRoute struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// upstreamRegexp validates that Upstream is a service-form host:port
// (k8s service DNS form, no IP). Defends against SSRF via TalonRoute
// hijack — same rule as ADR 0001 §7.a.
var upstreamRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*(\.svc(\.cluster\.local)?)?:[0-9]{1,5}$`)

// Config is the validated runtime configuration. Treat as immutable after
// Load() returns.
type Config struct {
	// Public-facing URL Talon listens on (e.g. https://internal.example.com).
	// Used to derive cookie domain anchors and OIDC redirect_uri.
	ExternalURL *url.URL

	// Cookie Domain attribute for talon_session. Must be a suffix of
	// ExternalURL.Host (RFC 6265 §5.3.6) — see ADR 0002 §3.1.
	CookieDomain string

	// Public OIDC issuer URL (the iss claim Talon validates against).
	IssuerURL string

	// Internal in-cluster issuer URL used for /oauth/token, JWKS, /oauth/userinfo
	// to skip the public Traefik hop. JWT iss claim still validates against
	// IssuerURL, not this one.
	InternalIssuerURL string

	// OIDC client credentials, mounted from k8s Secret talon-oidc-client.
	OIDCClientID     string
	OIDCClientSecret string

	// Space- or comma-separated scope list requested at /oauth/authorize.
	OIDCScopes []string

	// Redis address for session store + handshake cookies (talon: namespace).
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// SpiceDB gRPC address for permission checks (Phase 2+ — set up empty
	// at Phase 1; group filter alone gates access until SpiceDB is wired).
	SpiceDBAddr     string
	SpiceDBToken    string
	SpiceDBPermName string

	// DDILOfflinePDPEnabled gates the DDIL P3.1 offline authorization PDP.
	// When true (default), a SpiceDB outage serves a signed, time-boxed
	// last-known-good CheckPermission decision within budget before
	// failing closed; when false, Talon keeps the pre-P3.1 fail-closed-at-
	// t=0 behaviour (a SpiceDB miss during an outage denies immediately).
	// Env TALON_DDIL_OFFLINE_PDP (default "true"; "false" disables).
	DDILOfflinePDPEnabled bool

	// DDILOfflineStandardBudget / DDILOfflinePrivilegedBudget bound how
	// long a cached SpiceDB decision is honoured offline, per route tier.
	// Operating-spec defaults: 15m standard, 5m privileged/step-up
	// (critical|high sensitivity). Env
	// TALON_DDIL_OFFLINE_PDP_STANDARD_BUDGET_SECONDS /
	// TALON_DDIL_OFFLINE_PDP_PRIVILEGED_BUDGET_SECONDS (seconds).
	DDILOfflineStandardBudget   time.Duration
	DDILOfflinePrivilegedBudget time.Duration

	// DDILOfflineSessionEnabled gates the DDIL P3.1 governed offline
	// session-grace on the read-hot path. When true (default), a Redis
	// session-store outage serves a signed, time-boxed last-known-good
	// session within budget (reusing DDILOfflineStandardBudget /
	// DDILOfflinePrivilegedBudget — same operating-spec 15m/5m tiers as the
	// authz PDP) before failing closed; when false, Talon keeps the pre-P3.1
	// fail-closed-at-t=0 behaviour (a Redis blip 503s every request). This is
	// the complement of DDILOfflinePDPEnabled: without it the SpiceDB
	// privileged offline budget is unreachable during a Redis outage because
	// the session read fails first. Env TALON_DDIL_OFFLINE_SESSION (default
	// "true"; "false" disables).
	DDILOfflineSessionEnabled bool

	// RequiredRole is the role string Talon's PE filters on against the
	// Falcon-ID `roles` claim. Defence-in-depth: PE also checks the
	// `groups` claim for the same string (no-op when iam_groups is
	// empty, the platform default). Empty = no filter (forbidden in prod).
	RequiredRole string

	// RoleGateMode governs the cluster-wide RequiredRole filter:
	// "enforce" (default, legacy), "shadow" (evaluate + log, SpiceDB
	// decides), "off" (SpiceDB is sole authority). See
	// policy.RoleGateMode for why this exists.
	RoleGateMode string

	// ProtectedHostSuffixes is the list of admin-tier DNS zone suffixes
	// (each starting with a dot) Talon's TalonRoute admission validator
	// AND the OIDC RP's rd-validation accept. Sourced from
	// TALON_PROTECTED_HOST_SUFFIXES env var (comma-separated). Empty
	// list falls back to the legacy single-zone behaviour driven from
	// CookieDomain (preserves existing deployments unchanged on
	// upgrade). Multi-zone support added 2026-05-03 to enable Track 2
	// Phase 7 migrations onto apps.hexxlock.com.
	ProtectedHostSuffixes []string

	// ClientlessHostSuffixes is the list of access-zone DNS suffixes (each
	// starting with a dot, e.g. ".access.hexxlock.com") whose requests Talon
	// tags as the agentless `channel=clientless` (ADR 0044). A session on one
	// of these hosts carries no device cert, so it is projected into Rego as
	// `input.session.channel="clientless"` and is HARD-DENIED on any route
	// with Sensitivity=critical unless that TalonRoute sets allowClientless.
	// Sourced from TALON_CLIENTLESS_HOST_SUFFIXES (comma-separated). Empty =
	// clientless tier disabled (every session is the default agent channel),
	// so existing deployments are unchanged on upgrade.
	ClientlessHostSuffixes []string

	// AccessHelpURL is the remediation/enrollment landing URL shown on the
	// branded access-denied page when a request is blocked for device-posture
	// reasons (e.g. no HexxLock Access agent → no X-Talon-Posture). Points
	// users at how to enroll / install + enable HexxLock Access. Empty = the
	// denied page shows the guidance text without a button.
	// Env: TALON_ACCESS_HELP_URL
	AccessHelpURL string

	// 32-byte AES-256-GCM key for session blob envelope (ADR 0002 §4.2).
	// Loaded from the talon-cookie-encrypt-key Secret as base64.
	CookieEncryptKey []byte

	// Session TTLs.
	SessionHardTTL    time.Duration
	SessionRefreshMin time.Duration

	// Continuous verification cadence (Phase 4).
	ContinuousVerifyInterval time.Duration

	// RevokeWebhookAllowedIdentities is the SPIFFE-style Linkerd
	// identity allow-list for POST /admin/revoke (Tier-1 Gap 2 streaming
	// revocation). Empty list disables the endpoint. Loaded from
	// TALON_REVOKE_WEBHOOK_ALLOWED_IDENTITIES (comma-separated).
	RevokeWebhookAllowedIdentities []string

	// RevokeWebhookRateLimitPerSec caps the webhook's request rate;
	// burst caps at 2× this. 0 disables. Default 100/sec.
	RevokeWebhookRateLimitPerSec int

	// BackchannelLogoutMaxIATSkew bounds how stale an incoming OIDC
	// Back-Channel Logout 1.0 logout_token can be (spec §2.6). Doubles
	// as the jti replay-defense Redis SETNX TTL window. Default 5min;
	// loaded from TALON_BCL_MAX_IAT_SKEW_SECONDS.
	BackchannelLogoutMaxIATSkew time.Duration

	// FrontchannelLogoutFrameAncestor is the OP origin allowed to embed
	// the FCL iframe via Content-Security-Policy: frame-ancestors. Spec
	// §5 requires the RP to refuse iframe embedding from anywhere except
	// the OP's logout page; this header IS that refusal. Empty falls
	// back to "frame-ancestors 'self' https:" — still safe but less
	// restrictive. Loaded from TALON_FCL_FRAME_ANCESTOR; production
	// value is the Falcon-ID public origin (e.g.
	// "https://id.hexxlock.com").
	FrontchannelLogoutFrameAncestor string

	// Listen ports.
	ListenHTTPS   string // e.g. :8443
	ListenMetrics string // e.g. :9090
	// ListenExtAuthz is the gRPC endpoint for the Envoy ext_authz
	// (envoy.service.auth.v3.Authorization) server. Phase 7.1 of the
	// shared-PDP architecture per ADR-Phase7 (GEP-1494 alignment) —
	// data planes that speak ext_authz natively (Envoy Gateway,
	// Istio, APISIX via ext-plugin, Cilium PoC) call this endpoint
	// instead of the HTTP /auth/verify forward-auth. Both surfaces
	// coexist during transition.
	//
	// Empty disables the ext_authz listener (default — operators
	// opt-in once APISIX-side migration is ready). Linkerd MeshTLS
	// terminates the connection; the gRPC server itself runs
	// h2c-plain on this port (no per-listener TLS plumbing).
	ListenExtAuthz string // e.g. :9001; empty disables

	// ListenConversionWebhook is the HTTPS endpoint that serves the
	// TalonRoute CRD conversion webhook (Phase 6a.2). kube-apiserver
	// POSTs `apiextensions.k8s.io/v1.ConversionReview` to /convert
	// whenever a client reads/writes a CR in a version different
	// from the storage version (v1alpha1 stays storage, v1beta1 is
	// the served-and-converted version after this phase ships).
	//
	// Empty disables (default — operators opt-in via Helm when the
	// chart-side cert-manager Certificate + Service + CRD conversion
	// strategy are also wired). MUST be TLS — kube-apiserver requires
	// HTTPS for webhook endpoints. Cert paths reuse TLSCertFile /
	// TLSKeyFile by convention; a per-webhook cert can be wired via
	// ConversionWebhookCertFile / -KeyFile when set.
	ListenConversionWebhook string // e.g. :9443; empty disables

	// ConversionWebhookCertFile / -KeyFile let operators provide a
	// distinct TLS cert for the conversion webhook (the kube-apiserver
	// validates against the CRD's spec.conversion.webhook.client
	// Config.caBundle). When empty, fall back to TLSCertFile /
	// TLSKeyFile — same TLS material as the main HTTPS listener,
	// which is fine when both certs are issued from the same
	// cert-manager ClusterIssuer.
	ConversionWebhookCertFile string
	ConversionWebhookKeyFile  string

	// TLS certificate paths (cert-manager mounted).
	TLSCertFile string
	TLSKeyFile  string

	// Logging.
	LogLevel  string // debug|info|warn|error
	LogFormat string // json|text

	// Static protected hosts (Phase 1 form; Phase 2 supersedes via CRD).
	// Loaded from TALON_PROTECTED_HOSTS_JSON.
	ProtectedHosts []ProtectedHost

	// EnableController turns the controller-runtime TalonRoute
	// reconciler on. Default true; set TALON_ENABLE_CONTROLLER=false
	// to fall back to static-only routing (e.g. local dev).
	EnableController bool

	// CAEPEnabled toggles the OpenID CAEP 1.0 SET receiver mount at
	// `POST /caep/events` on the auth host. When false, the path
	// returns 503 (explicit disabled state, vs 404 which would imply
	// route-not-found). Default false until the Falcon-ID CAEP
	// transmitter ships; per ADR 0011 the receiver is harmless to
	// enable early because it fail-closes on unknown issuers.
	//
	// Env: TALON_CAEP_ENABLED=true
	CAEPEnabled bool

	// CAEPTransmitterIssuer is the iss claim Talon expects on every
	// inbound SET. Typically the Falcon-ID OIDC issuer URL. Required
	// when CAEPEnabled=true.
	//
	// Env: TALON_CAEP_TRANSMITTER_ISSUER
	CAEPTransmitterIssuer string

	// CAEPAudience is the aud value Talon expects on every inbound
	// SET. Typically `https://<auth-host>/caep/events`. Required when
	// CAEPEnabled=true.
	//
	// Env: TALON_CAEP_AUDIENCE
	CAEPAudience string

	// CAEPTransmitterJWKSURL optionally overrides where Talon fetches the
	// transmitter's JWKS for SET signature verification. Default is
	// `<CAEPTransmitterIssuer>/.well-known/jwks.json`. Override it when the
	// issuer's public JWKS URL is unreachable from the receiver pod: the
	// posture-signer transmitter's issuer (https://posture.hexxlock.com) is
	// fronted by Envoy device-cert mTLS, so the receiver instead fetches the
	// in-cluster Service JWKS
	// (http://posture-signer.talon.svc.cluster.local:8080/.well-known/jwks.json).
	// The SET `iss` is still verified against CAEPTransmitterIssuer — only
	// the fetch location changes.
	//
	// Env: TALON_CAEP_TRANSMITTER_JWKS_URL
	CAEPTransmitterJWKSURL string

	// PostureEnabled toggles the X-Talon-Posture header verifier path.
	// When false, no posture header is consulted and routes that
	// declare requirePosture on Talon side fail open with a logged
	// warning. Default false.
	//
	// Env: TALON_POSTURE_ENABLED=true
	PostureEnabled bool

	// PostureTrustedIssuers lists the iss values Talon accepts on
	// X-Talon-Posture JWS assertions. Comma-separated. The posture-
	// issuer trust chain is INTENTIONALLY DISTINCT from the OIDC IdP
	// (see ADR 0011); typical values point at a separate posture
	// daemon URL, NOT at Falcon-ID.
	//
	// Env: TALON_POSTURE_TRUSTED_ISSUERS=https://posture.hexxlock.com
	PostureTrustedIssuers []string

	// PostureAudience is the aud value Talon expects on posture JWS
	// assertions. Typically the auth host URL.
	//
	// Env: TALON_POSTURE_AUDIENCE
	PostureAudience string

	// SkipCOOPHosts is the set of request Hosts that should NOT receive
	// the Cross-Origin-Opener-Policy response header. Carve-out for
	// upstreams whose UI runs popup-based OAuth/OIDC (HashiCorp Vault
	// UI is the textbook case — its OIDC popup chain is broken by any
	// non-`unsafe-none` COOP, see vault#18648 and web.dev cross-origin
	// isolation guide for the upstream consensus). See
	// internal/security.Options.SkipCOOPHosts for the full security
	// rationale + the bounded scope of the lost COOP isolation benefit.
	//
	// Comma-separated. Lower-cased + trimmed on entry; port suffixes
	// stripped at match time so list entries stay simple hostnames.
	//
	// Env: TALON_SKIP_COOP_HOSTS=internal.example.com,other.host
	SkipCOOPHosts []string

	// PostureMaxAge bounds the (now - iat) freshness window on a
	// posture JWS. Default 1h. Cloudflare WARP uses ≤5min on
	// WAN-bound clients; we keep 1h as a generous default to absorb
	// posture-daemon refresh-cadence variance.
	//
	// Env: TALON_POSTURE_MAX_AGE_SECONDS=3600
	PostureMaxAge time.Duration

	// PostureJWKSURL optionally overrides where Talon fetches the posture
	// issuer's JWKS for X-Talon-Posture signature verification. Default is
	// `<iss>/.well-known/jwks.json` for each trusted issuer. Override it when
	// the issuer's public JWKS URL is unreachable from the Talon pod: the
	// posture-signer's public issuer (https://posture.hexxlock.com) is fronted
	// by Envoy device-cert mTLS, which Talon (no device cert) cannot complete —
	// point this at the in-cluster Service JWKS
	// (http://posture-signer.talon.svc.cluster.local:8080/.well-known/jwks.json).
	// Mirrors CAEPTransmitterJWKSURL. When set, it is used for ALL trusted
	// issuers (the `iss` claim is still verified against PostureTrustedIssuers).
	//
	// Env: TALON_POSTURE_JWKS_URL
	PostureJWKSURL string

	// PostureGraceCorp / PostureGraceByod are the DDIL P3.10 governed
	// posture-grace budgets: how long past its hard `exp` (and past
	// iat+MaxAge) a TPM-attested device posture is honored in a graceful-
	// DEGRADED mode before it fails closed. The grace is CONSUMER-governed —
	// Talon (the PEP) decides the budget and the degraded scope (admissible
	// for low/medium routes, denied on critical/high); a device never self-
	// grants it, and grace never bypasses the signature/attestation check.
	// PostureGraceCorp applies to TIER_CORP devices, PostureGraceByod to every
	// other tier (BYOD, breakglass, unknown).
	//
	// Default 0 for BOTH = grace DISABLED = the pre-P3.10 hard fail-closed-
	// at-exp behaviour (backward compatible; the safe, fail-closed-biased
	// default). The reviewed PACE-aligned opt-in values are 10m (corp) / 30m
	// (byod) — see posture.RecommendedGraceCorp/Byod and ADR 0010.
	//
	// Env: TALON_POSTURE_GRACE_CORP_SECONDS / TALON_POSTURE_GRACE_BYOD_SECONDS
	PostureGraceCorp time.Duration
	PostureGraceByod time.Duration

	// DefaultPolicyRego is the global ZTNA baseline OPA Rego module
	// applied to EVERY protected route that does not declare its own
	// TalonRoute.spec.policyRego — device-posture enforcement becomes
	// SECURE-BY-DEFAULT across all *.ops hosts instead of opt-in per
	// route (a new route can no longer silently ship with no posture
	// gate). The per-route `sensitivity` enum feeds `route_sensitivity`,
	// so ONE baseline covers every route with per-route tuning; operators
	// never copy Rego. A route opts OUT by declaring an explicit
	// permissive policyRego (`default allow := true`), per the baseline's
	// documented public-surface carve-out. Empty = legacy opt-in.
	//
	// Loaded from the file named by TALON_DEFAULT_POLICY_REGO_FILE
	// (mounted from a ConfigMap holding docs/policy/ztna/ztna_baseline.rego).
	//
	// Env: TALON_DEFAULT_POLICY_REGO_FILE=/etc/talon/ztna/baseline.rego
	DefaultPolicyRego string

	// SecurityPolicyEnabled toggles the Envoy Gateway SecurityPolicy
	// translator. When true, the TalonRoute reconciler emits an
	// Envoy Gateway SecurityPolicy CR per TalonRoute so EG's data
	// plane delegates auth decisions to Talon's ext_authz gRPC via
	// the canonical Gateway API extension shape (see
	// internal/controller/securitypolicy_translator.go for the full
	// rationale). Default false until Envoy Gateway is wired into
	// the operator's data plane.
	//
	// Env: TALON_SECURITY_POLICY_ENABLED=true
	SecurityPolicyEnabled bool

	// SecurityPolicyNamespace is where SecurityPolicy CRs are written.
	// MUST match the namespace of the HTTPRoute / Gateway targetRefs
	// per Envoy Gateway semantics. Typically `envoy-gateway-system`.
	//
	// Env: TALON_SECURITY_POLICY_NAMESPACE
	SecurityPolicyNamespace string

	// ExtAuthzServiceName is the Talon ext_authz Service the
	// SecurityPolicy backendRefs targets. Typically `talon-talon`.
	//
	// Env: TALON_EXTAUTHZ_SERVICE_NAME
	ExtAuthzServiceName string

	// ExtAuthzServiceNamespace is the namespace of ExtAuthzServiceName.
	// Typically the talon ns.
	//
	// Env: TALON_EXTAUTHZ_SERVICE_NAMESPACE
	ExtAuthzServiceNamespace string

	// ExtAuthzPort is the ext_authz gRPC listener port. Default 9001
	// per Phase 7 chart values.
	//
	// Env: TALON_EXTAUTHZ_PORT
	ExtAuthzPort int32

	// PodNamespace is the namespace this pod is running in
	// (POD_NAMESPACE env, set by downward API). Used as the
	// leader-election lease namespace.
	PodNamespace string

	// IAPIdentityTokenSigningKeyPEM is the PEM-encoded RSA private key
	// (PKCS#1 "RSA PRIVATE KEY" or PKCS#8 "PRIVATE KEY", ≥2048 bits)
	// used to sign the X-Talon-Identity-Token RFC 7519 JWT stamped on
	// every proxied request to upstream services. Loaded from the env
	// var TALON_IAP_SIGNING_KEY_PEM (typically projected from Vault
	// via ExternalSecret → Secret → env). When empty, Talon skips
	// signed-token injection and proxies with only the unsigned
	// X-Talon-* convenience headers (Phase A pre-rollout behaviour);
	// SDK verifiers see no token → fall back to the unsigned path.
	// See internal/identityjwt for the full trust model.
	IAPIdentityTokenSigningKeyPEM string

	// IAPIdentityTokenPreviousKeyPEM is an optional PEM-encoded key
	// (private OR public form accepted) whose public half is published
	// on the JWKS endpoint alongside the active signing key during a
	// rotation overlap window. Loaded from the env var
	// TALON_IAP_PREVIOUS_SIGNING_KEY_PEM. Empty in steady state;
	// populated for ~6 minutes (JWT lifetime + JWKS cache TTL) after a
	// rotation. Never used for signing — Talon mints fresh JWTs only
	// with the active key. Matches Cloudflare Access's N+1 JWKS pattern.
	IAPIdentityTokenPreviousKeyPEM string

	// RequireSignedIdentityToken is the FLEET-WIDE fail-closed floor for
	// IAP identity-token minting (ASVS 5.0 V9). When false (the default),
	// a route whose signed X-Talon-Identity-Token cannot be minted proxies
	// with the unsigned X-Talon-* fallback (fail open) — the deliberate
	// Phase A/B transitional posture while downstreams migrate to the SDK
	// verifier. When true, EVERY route fails closed (denies 5xx) on a mint
	// failure, and individual routes can no longer drop below that floor.
	//
	// Composition: the effective per-route value is this global default
	// OR'd with TalonRoute.spec.requireSignedIdentityToken (see
	// router.RegisterUpstream) — so an operator drives the migration by
	// flipping routes on individually, then trips this global flag once the
	// LAST downstream is verifying signed tokens. It also applies to the
	// static TALON_PROTECTED_HOSTS_JSON break-glass routes, which carry no
	// per-route knob.
	//
	// Env: TALON_REQUIRE_SIGNED_IDENTITY_TOKEN=true
	RequireSignedIdentityToken bool

	// Svctoken feature flag — when true, Talon instantiates the
	// internal/svctoken.Verifier against Falcon-ID's JWKS and consults
	// it on every protected-route request whose Server CR sets
	// authMode=bearer or authMode=both. Default OFF.
	//
	// Phase 3 of the talon-service-tokens spec. See
	// docs/specs/talon-service-tokens.md for the architectural
	// reasoning + migration plan; the flag exists so the cluster can
	// land the code without changing request semantics until the
	// pilot consumer (ArgoCD repo-server, Phase 4) is ready.
	SvctokenEnabled bool

	// SvctokenJWKSURL — Falcon-ID's published key set. Defaults to
	// https://id.hexxlock.com/.well-known/jwks.json. Only consulted
	// when SvctokenEnabled is true.
	SvctokenJWKSURL string

	// SvctokenIssuer — Falcon-ID's issuer URL. Pinned on every
	// service-token JWT. Defaults to https://id.hexxlock.com (matches
	// the IssuerURL field — kept separate for forward-compat with
	// deployments that proxy Falcon-ID under a different external URL
	// than the issuer claim).
	SvctokenIssuer string

	// SvctokenReplayCacheSize — when > 0, the svctoken.Verifier keeps
	// an in-memory LRU of jti claims for replay protection (RFC 7519
	// §4.1.7). Zero disables — token exp window provides the primary
	// defense, replay is opt-in defense-in-depth. Default 8192 covers
	// 100 req/s sustained with 1h token TTL. Multi-pod Talon
	// deployments may want a Redis-backed ReplayCache instead
	// (Phase 6).
	SvctokenReplayCacheSize int

	// SvctokenFederatedIssuers — Phase 5+ federated trust. When
	// non-empty, the svctoken.Verifier admits Bearer tokens signed by
	// these SECONDARY issuers (in addition to the primary Falcon-ID
	// JWKS) on routes whose AuthMode is bearer_or_federated_passthrough.
	// Wire format: JSON-serialised []SvctokenFederatedIssuer. Loaded
	// from env TALON_SVCTOKEN_FEDERATED_ISSUERS_JSON. Each entry
	// declares an Issuer (exact `iss` claim match) + a PEM-encoded
	// RSA public key (StaticPublicKeyPEM) + optional AllowedHosts
	// (host-prefix scoping). See FederatedIssuerConfig docs in
	// internal/svctoken/federated.go for the full safety semantics.
	//
	// Empty (default) disables federated trust entirely — verifier
	// behaves exactly as before; routes that request the federated
	// AuthMode without any federated issuer configured silently
	// degrade to bearer_or_passthrough semantics (every Bearer must
	// verify against Falcon-ID).
	SvctokenFederatedIssuers []SvctokenFederatedIssuer

	// SvctokenJWKSStaleThreshold — DDIL P3.1 governed-degrade budget for
	// the svctoken (Falcon-ID) JWKS. After the 5-min cache TTL, if a
	// refresh fails, the verifier keeps serving the last-good key set
	// until it is this old, then fails closed with ErrJWKSUnavailable.
	// Falcon-ID signing keys rotate every 90d so the 1h operating-spec
	// default cannot outlive a key generation. Env
	// TALON_JWKS_STALE_THRESHOLD_SECONDS: unset = 1h default; an explicit
	// 0 DISABLES the stale window (strict fail-closed at TTL, pre-P3.1
	// behaviour); >0 sets the budget in seconds.
	SvctokenJWKSStaleThreshold time.Duration
}

// SvctokenFederatedIssuer is the on-the-wire shape for one entry of
// SvctokenFederatedIssuers. Marshalled in/out of JSON for the
// TALON_SVCTOKEN_FEDERATED_ISSUERS_JSON env var. The verifier-side
// FederatedIssuerConfig (internal/svctoken/federated.go) is the
// parsed equivalent — held separate from this config-layer wire
// shape so the verifier package doesn't depend on the env/JSON
// loading machinery.
type SvctokenFederatedIssuer struct {
	// Issuer — exact match against the JWT's `iss` claim. Required.
	Issuer string `json:"issuer"`

	// StaticPublicKeyPEM — PEM-encoded RSA public key (PKIX `BEGIN
	// PUBLIC KEY` or PKCS#1 `BEGIN RSA PUBLIC KEY`). Required when
	// JWKSURL is empty. Use `openssl rsa -in private_key.pem -pubout`
	// to extract from an issuer that doesn't publish a JWKS endpoint
	// (Harbor is the canonical example — private_key.pem in
	// /etc/core/ inside the harbor-core pod).
	StaticPublicKeyPEM string `json:"staticPublicKeyPem,omitempty"`

	// JWKSURL — reserved for forward-compat; not yet supported.
	JWKSURL string `json:"jwksUrl,omitempty"`

	// AllowedHosts — optional host-prefix scoping. Empty (default)
	// = applies everywhere. Lower-cased + trimmed at parse time.
	AllowedHosts []string `json:"allowedHosts,omitempty"`
}

// Load parses TALON_* env vars into a validated Config. Returns the first
// validation error encountered.
func Load() (*Config, error) {
	c := &Config{
		IssuerURL:         getEnv("TALON_OIDC_ISSUER_URL", "https://id.hexxlock.com"),
		InternalIssuerURL: getEnv("TALON_OIDC_INTERNAL_ISSUER_URL", ""),
		OIDCClientID:      os.Getenv("TALON_OIDC_CLIENT_ID"),
		OIDCClientSecret:  os.Getenv("TALON_OIDC_CLIENT_SECRET"),
		RedisAddr:         getEnv("TALON_REDIS_ADDR", "falcon-id-redis-master.falcon-id.svc.cluster.local:6379"),
		RedisPassword:     os.Getenv("TALON_REDIS_PASSWORD"),
		SpiceDBAddr:       os.Getenv("TALON_SPICEDB_ADDR"),
		SpiceDBToken:      os.Getenv("TALON_SPICEDB_TOKEN"),
		SpiceDBPermName:   getEnv("TALON_SPICEDB_PERMISSION", "access"),
		// Required role for access. Talon's PE checks this string against
		// the id_token `roles` claim (Falcon-ID emits role names there).
		// Defaults to platform_admin (matches Falcon-ID iam_roles convention).
		RequiredRole:  getEnv("TALON_REQUIRED_ROLE", "platform_admin"),
		RoleGateMode:  getEnv("TALON_ROLE_GATE_MODE", "enforce"),
		ListenHTTPS:   getEnv("TALON_LISTEN_HTTPS", ":8443"),
		ListenMetrics: getEnv("TALON_LISTEN_METRICS", ":9090"),
		// ListenExtAuthz default empty = ext_authz disabled. Operators
		// opt in via TALON_LISTEN_EXTAUTHZ=:9001 once APISIX-side
		// migration is ready (Phase 7.2).
		ListenExtAuthz: getEnv("TALON_LISTEN_EXTAUTHZ", ""),
		// ListenConversionWebhook default empty = CRD conversion
		// webhook disabled. Operators opt in via
		// TALON_LISTEN_CONVERSION_WEBHOOK=:9443 once the chart-side
		// cert-manager Certificate + Service + CRD manifest update
		// land (Phase 6a.2 <gitops-bootstrap-repo> MR). Until then, the
		// CRD serves v1alpha1 only and v1beta1 reads return 415.
		ListenConversionWebhook:   getEnv("TALON_LISTEN_CONVERSION_WEBHOOK", ""),
		ConversionWebhookCertFile: getEnv("TALON_CONVERSION_WEBHOOK_CERT_FILE", ""),
		ConversionWebhookKeyFile:  getEnv("TALON_CONVERSION_WEBHOOK_KEY_FILE", ""),
		TLSCertFile:               getEnv("TALON_TLS_CERT_FILE", "/etc/talon/tls/tls.crt"),
		TLSKeyFile:                getEnv("TALON_TLS_KEY_FILE", "/etc/talon/tls/tls.key"),
		LogLevel:                  getEnv("TALON_LOG_LEVEL", "info"),
		LogFormat:                 getEnv("TALON_LOG_FORMAT", "json"),
	}
	c.RedisDB, _ = strconv.Atoi(getEnv("TALON_REDIS_DB", "0"))

	// DDIL P3.1 offline authorization PDP — default ENABLED with the
	// operating-spec budgets. Disable via TALON_DDIL_OFFLINE_PDP=false to
	// restore strict fail-closed-at-t=0 on a SpiceDB outage.
	c.DDILOfflinePDPEnabled = getEnv("TALON_DDIL_OFFLINE_PDP", "true") != "false"
	c.DDILOfflineStandardBudget = parseDurationSeconds("TALON_DDIL_OFFLINE_PDP_STANDARD_BUDGET_SECONDS", 15*time.Minute)
	c.DDILOfflinePrivilegedBudget = parseDurationSeconds("TALON_DDIL_OFFLINE_PDP_PRIVILEGED_BUDGET_SECONDS", 5*time.Minute)
	c.DDILOfflineSessionEnabled = getEnv("TALON_DDIL_OFFLINE_SESSION", "true") != "false"

	// Controller toggle + pod namespace.
	c.EnableController = getEnv("TALON_ENABLE_CONTROLLER", "true") != "false"
	c.PodNamespace = getEnv("POD_NAMESPACE", "talon")

	// IAP identity-token signing key — empty in Phase A pre-rollout,
	// populated from Vault → ExternalSecret → Secret → env once the
	// new Vault path example/platform/talon/iap-identity-key lands.
	c.IAPIdentityTokenSigningKeyPEM = os.Getenv("TALON_IAP_SIGNING_KEY_PEM")
	c.IAPIdentityTokenPreviousKeyPEM = os.Getenv("TALON_IAP_PREVIOUS_SIGNING_KEY_PEM")
	// ASVS 5.0 V9 — fleet-wide fail-closed floor for identity-token minting.
	// Default false preserves the Phase A/B fail-open unsigned-header
	// fallback; flip to true once every downstream verifies the signed token.
	c.RequireSignedIdentityToken = strings.EqualFold(getEnv("TALON_REQUIRE_SIGNED_IDENTITY_TOKEN", "false"), "true")

	// Svctoken feature flag (Phase 3 talon-service-tokens). Default
	// OFF — the verifier is only constructed + wired when this is
	// explicitly true. Defaults for the supporting URLs match the
	// platform's canonical Falcon-ID deployment so an operator only
	// needs to flip SvctokenEnabled=true in 99% of cases.
	c.SvctokenEnabled = getEnv("TALON_SVCTOKEN_ENABLED", "false") == "true"
	c.SvctokenJWKSURL = getEnv("TALON_SVCTOKEN_JWKS_URL", "https://id.hexxlock.com/.well-known/jwks.json")
	c.SvctokenIssuer = getEnv("TALON_SVCTOKEN_ISSUER", "https://id.hexxlock.com")
	if v, err := strconv.Atoi(getEnv("TALON_SVCTOKEN_REPLAY_CACHE_SIZE", "8192")); err == nil {
		c.SvctokenReplayCacheSize = v
	}
	// Federated issuers — JSON list. Empty / unset disables.
	if raw := os.Getenv("TALON_SVCTOKEN_FEDERATED_ISSUERS_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.SvctokenFederatedIssuers); err != nil {
			return nil, fmt.Errorf("TALON_SVCTOKEN_FEDERATED_ISSUERS_JSON: %w", err)
		}
	}
	// DDIL P3.1 JWKS stale window. Unset = operating-spec 1h default; an
	// explicit "0" disables it (mapped to a negative so the verifier —
	// which treats <=0 as disabled — sees the operator's intent, not the
	// default). >0 = seconds.
	if raw, ok := os.LookupEnv("TALON_JWKS_STALE_THRESHOLD_SECONDS"); ok && strings.TrimSpace(raw) != "" {
		n, perr := strconv.Atoi(strings.TrimSpace(raw))
		if perr != nil {
			return nil, fmt.Errorf("TALON_JWKS_STALE_THRESHOLD_SECONDS must be an integer number of seconds: %w", perr)
		}
		if n <= 0 {
			c.SvctokenJWKSStaleThreshold = -1 // explicit disable (strict fail-closed at TTL)
		} else {
			c.SvctokenJWKSStaleThreshold = time.Duration(n) * time.Second
		}
	} else {
		// Operating-spec default (== svctoken.DefaultJWKSStaleThreshold);
		// kept as a literal here so config does not import svctoken.
		c.SvctokenJWKSStaleThreshold = time.Hour
	}

	extURL, err := url.Parse(getEnv("TALON_EXTERNAL_URL", "https://internal.example.com"))
	if err != nil {
		return nil, fmt.Errorf("invalid TALON_EXTERNAL_URL: %w", err)
	}
	c.ExternalURL = extURL

	c.CookieDomain = getEnv("TALON_COOKIE_DOMAIN", "")
	if c.CookieDomain == "" {
		// Default: leading-dot of ExternalURL host's parent (internal.example.com → internal.example.com)
		host := extURL.Hostname()
		if i := strings.IndexByte(host, '.'); i > 0 {
			c.CookieDomain = "." + host[i+1:]
		} else {
			c.CookieDomain = "." + host
		}
	}

	scopesRaw := getEnv("TALON_OIDC_SCOPES", "openid,profile,email,groups,roles")
	c.OIDCScopes = splitAndTrim(scopesRaw, ",")

	c.SessionHardTTL = parseDurationSeconds("TALON_SESSION_TTL_SECONDS", 8*time.Hour)
	c.SessionRefreshMin = parseDurationSeconds("TALON_SESSION_REFRESH_SECONDS", 60*time.Second)
	// Default 5 min matches Cloudflare Access posture-check cadence
	// (boot prompt §4 Gap 2). Tunable via env; per-route override via
	// TalonRoute.spec.continuousVerifyMinutes is plumbed separately.
	c.ContinuousVerifyInterval = parseDurationMinutes("TALON_CONTINUOUS_VERIFY_MINUTES", 5*time.Minute)

	// Revocation webhook allow-list — typical entry:
	// falcon-id.falcon-id.serviceaccount.identity.linkerd.cluster.local
	revokeAllowed := getEnv("TALON_REVOKE_WEBHOOK_ALLOWED_IDENTITIES", "")
	if revokeAllowed != "" {
		c.RevokeWebhookAllowedIdentities = splitAndTrim(revokeAllowed, ",")
	}
	c.RevokeWebhookRateLimitPerSec, _ = strconv.Atoi(getEnv("TALON_REVOKE_WEBHOOK_RATE_LIMIT", "100"))

	// Protected-host suffix allow-list — drives both TalonRoute admission
	// validation (controller) and rd-validation in the OIDC RP. Empty
	// list = legacy single-zone fallback (TalonRoute uses "internal.example.com",
	// rd-validation uses CookieDomain). Multi-zone support: comma-separated,
	// each entry starts with a dot.
	suffixesRaw := getEnv("TALON_PROTECTED_HOST_SUFFIXES", "")
	if suffixesRaw != "" {
		c.ProtectedHostSuffixes = splitAndTrim(suffixesRaw, ",")
	}

	// Access-zone suffixes for the agentless clientless tier (ADR 0044).
	if v := strings.TrimSpace(getEnv("TALON_CLIENTLESS_HOST_SUFFIXES", "")); v != "" {
		c.ClientlessHostSuffixes = splitAndTrim(v, ",")
	}
	c.AccessHelpURL = strings.TrimSpace(getEnv("TALON_ACCESS_HELP_URL", ""))

	c.BackchannelLogoutMaxIATSkew = parseDurationSeconds("TALON_BCL_MAX_IAT_SKEW_SECONDS", 5*time.Minute)

	// CAEP receiver wiring — Phase 7 IAP tier-1 hardening (ADR 0011).
	c.CAEPEnabled = strings.EqualFold(getEnv("TALON_CAEP_ENABLED", "false"), "true")
	c.CAEPTransmitterIssuer = strings.TrimSpace(getEnv("TALON_CAEP_TRANSMITTER_ISSUER", ""))
	c.CAEPAudience = strings.TrimSpace(getEnv("TALON_CAEP_AUDIENCE", ""))
	c.CAEPTransmitterJWKSURL = strings.TrimSpace(getEnv("TALON_CAEP_TRANSMITTER_JWKS_URL", ""))
	if c.CAEPEnabled {
		if c.CAEPTransmitterIssuer == "" {
			return nil, errors.New("TALON_CAEP_TRANSMITTER_ISSUER is required when TALON_CAEP_ENABLED=true")
		}
		if c.CAEPAudience == "" {
			return nil, errors.New("TALON_CAEP_AUDIENCE is required when TALON_CAEP_ENABLED=true")
		}
	}

	// SecurityPolicy translator wiring — Envoy Gateway GEP-1494-ish
	// SecurityPolicy emission per TalonRoute.
	c.SecurityPolicyEnabled = strings.EqualFold(getEnv("TALON_SECURITY_POLICY_ENABLED", "false"), "true")
	c.SecurityPolicyNamespace = strings.TrimSpace(getEnv("TALON_SECURITY_POLICY_NAMESPACE", "envoy-gateway-system"))
	c.ExtAuthzServiceName = strings.TrimSpace(getEnv("TALON_EXTAUTHZ_SERVICE_NAME", "talon-talon"))
	c.ExtAuthzServiceNamespace = strings.TrimSpace(getEnv("TALON_EXTAUTHZ_SERVICE_NAMESPACE", "talon"))
	if portStr := getEnv("TALON_EXTAUTHZ_PORT", "9001"); portStr != "" {
		// ParseInt with bitSize=32 returns an int64 that fits in int32,
		// so the subsequent narrowing is overflow-safe (closes gosec G109).
		if p, perr := strconv.ParseInt(portStr, 10, 32); perr == nil {
			c.ExtAuthzPort = int32(p)
		}
	}
	if c.SecurityPolicyEnabled {
		if c.SecurityPolicyNamespace == "" {
			return nil, errors.New("TALON_SECURITY_POLICY_NAMESPACE is required when TALON_SECURITY_POLICY_ENABLED=true")
		}
		if c.ExtAuthzServiceName == "" {
			return nil, errors.New("TALON_EXTAUTHZ_SERVICE_NAME is required when TALON_SECURITY_POLICY_ENABLED=true")
		}
		if c.ExtAuthzServiceNamespace == "" {
			return nil, errors.New("TALON_EXTAUTHZ_SERVICE_NAMESPACE is required when TALON_SECURITY_POLICY_ENABLED=true")
		}
		if c.ExtAuthzPort == 0 {
			return nil, errors.New("TALON_EXTAUTHZ_PORT must be set when TALON_SECURITY_POLICY_ENABLED=true")
		}
	}

	// Posture verifier wiring — ADR 0011 Part B.
	c.PostureEnabled = strings.EqualFold(getEnv("TALON_POSTURE_ENABLED", "false"), "true")
	if v := strings.TrimSpace(getEnv("TALON_POSTURE_TRUSTED_ISSUERS", "")); v != "" {
		c.PostureTrustedIssuers = splitAndTrim(v, ",")
	}
	c.PostureAudience = strings.TrimSpace(getEnv("TALON_POSTURE_AUDIENCE", ""))
	c.PostureJWKSURL = strings.TrimSpace(getEnv("TALON_POSTURE_JWKS_URL", ""))

	if v := strings.TrimSpace(getEnv("TALON_SKIP_COOP_HOSTS", "")); v != "" {
		c.SkipCOOPHosts = splitAndTrim(v, ",")
	}
	c.PostureMaxAge = parseDurationSeconds("TALON_POSTURE_MAX_AGE_SECONDS", time.Hour)
	// DDIL P3.10 governed posture-grace budgets. Default 0 = grace OFF (the
	// pre-P3.10 hard fail-closed-at-exp behaviour); reviewed opt-in values are
	// 10m (corp) / 30m (byod). See config.PostureGraceCorp/Byod docs.
	c.PostureGraceCorp = parseDurationSeconds("TALON_POSTURE_GRACE_CORP_SECONDS", 0)
	c.PostureGraceByod = parseDurationSeconds("TALON_POSTURE_GRACE_BYOD_SECONDS", 0)
	if c.PostureEnabled {
		if len(c.PostureTrustedIssuers) == 0 {
			return nil, errors.New("TALON_POSTURE_TRUSTED_ISSUERS is required when TALON_POSTURE_ENABLED=true")
		}
		if c.PostureAudience == "" {
			return nil, errors.New("TALON_POSTURE_AUDIENCE is required when TALON_POSTURE_ENABLED=true")
		}
	}

	c.FrontchannelLogoutFrameAncestor = strings.TrimSpace(getEnv("TALON_FCL_FRAME_ANCESTOR", ""))

	keyB64 := os.Getenv("TALON_COOKIE_ENCRYPT_KEY")
	if keyB64 == "" {
		return nil, errors.New("TALON_COOKIE_ENCRYPT_KEY is required")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return nil, fmt.Errorf("TALON_COOKIE_ENCRYPT_KEY must be base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("TALON_COOKIE_ENCRYPT_KEY must decode to 32 bytes, got %d", len(key))
	}
	c.CookieEncryptKey = key

	if c.OIDCClientID == "" || c.OIDCClientSecret == "" {
		return nil, errors.New("TALON_OIDC_CLIENT_ID and TALON_OIDC_CLIENT_SECRET are required")
	}
	if c.RequiredRole == "" {
		return nil, errors.New("TALON_REQUIRED_ROLE must not be empty in production")
	}
	if !strings.HasSuffix(extURL.Hostname(), strings.TrimPrefix(c.CookieDomain, ".")) {
		return nil, fmt.Errorf("TALON_COOKIE_DOMAIN %q must be a suffix of TALON_EXTERNAL_URL host %q (RFC 6265 §5.3.6)", c.CookieDomain, extURL.Hostname())
	}

	// Optional protected-hosts JSON. Empty = auth host only.
	if raw := os.Getenv("TALON_PROTECTED_HOSTS_JSON"); raw != "" {
		var hosts []ProtectedHost
		if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
			return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON parse: %w", err)
		}
		seen := map[string]struct{}{}
		for i, h := range hosts {
			if h.Host == "" || h.Upstream == "" {
				return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON[%d]: host and upstream are required", i)
			}
			if !upstreamRegexp.MatchString(h.Upstream) {
				return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON[%d].upstream %q must be k8s service form like svc.ns.svc.cluster.local:port (no IPs, no external)", i, h.Upstream)
			}
			if _, dup := seen[h.Host]; dup {
				return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON: duplicate host %q", h.Host)
			}
			seen[h.Host] = struct{}{}
			for j := range hosts[i].PublicPaths {
				pr := &hosts[i].PublicPaths[j]
				pr.Method = strings.ToUpper(strings.TrimSpace(pr.Method))
				if pr.Method == "" {
					return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON[%d].publicPaths[%d]: method is required", i, j)
				}
				if !strings.HasPrefix(pr.Path, "/") {
					return nil, fmt.Errorf("TALON_PROTECTED_HOSTS_JSON[%d].publicPaths[%d]: path must start with /", i, j)
				}
			}
		}
		c.ProtectedHosts = hosts
	}

	// Global ZTNA baseline (secure-by-default). Read the Rego module from
	// the file named by TALON_DEFAULT_POLICY_REGO_FILE (mounted from a
	// ConfigMap). Fail loudly if the file is named but unreadable so a
	// misconfigured mount doesn't silently drop posture enforcement.
	if f := strings.TrimSpace(getEnv("TALON_DEFAULT_POLICY_REGO_FILE", "")); f != "" {
		// Require an absolute path. The value names a ConfigMap mount chosen
		// by the operator in the Deployment — nothing a request can influence,
		// and anyone able to set Talon's env has already replaced the process.
		// But a relative path would resolve against whatever the working
		// directory happens to be at startup, which is not something this
		// process controls, so reject it rather than read an unexpected file.
		if !filepath.IsAbs(f) {
			return nil, fmt.Errorf("TALON_DEFAULT_POLICY_REGO_FILE %q must be an absolute path", f)
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: operator-supplied ConfigMap mount path, asserted absolute above
		if err != nil {
			return nil, fmt.Errorf("read TALON_DEFAULT_POLICY_REGO_FILE %q: %w", f, err)
		}
		c.DefaultPolicyRego = string(b)
	}

	return c, nil
}

// CallbackURL returns the OIDC redirect_uri Talon registers with Falcon-ID.
// Must match the value seeded into iam_oauth_clients.redirect_uris.
func (c *Config) CallbackURL() string {
	u := *c.ExternalURL
	u.Path = "/auth/callback"
	return u.String()
}

// LogoutRedirectURL returns the URL Falcon-ID redirects to after RP-initiated
// logout. Must match iam_oauth_clients.post_logout_redirect_uris.
func (c *Config) LogoutRedirectURL() string {
	u := *c.ExternalURL
	u.Path = "/auth/logged-out"
	return u.String()
}

// SafeRandHex returns n random bytes as a hex string. Panics on read failure
// (crypto/rand failures are fatal and shouldn't be papered over).
func SafeRandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0x0f]
	}
	return string(out)
}

func getEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDurationSeconds(env string, def time.Duration) time.Duration {
	v := os.Getenv(env)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

func parseDurationMinutes(env string, def time.Duration) time.Duration {
	v := os.Getenv(env)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Minute
}
