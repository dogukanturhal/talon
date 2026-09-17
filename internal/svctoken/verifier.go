// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// DefaultClockTolerance matches identityjwt.DefaultClockTolerance —
// the slack applied to iat/nbf/exp during verification. Chrony keeps
// RKE2 nodes within ~10ms; 5s is generous against drift, tight enough
// that a replayed token >> 5s past exp still rejects.
const DefaultClockTolerance = 5 * time.Second

// DefaultJWKSCacheTTL — how long a successfully fetched JWKS is reused
// before a re-fetch. 5min matches Falcon-ID's Cache-Control: max-age
// header on its JWKS endpoint and every reference IAP's default.
const DefaultJWKSCacheTTL = 5 * time.Minute

// jwksRefreshCooldown — minimum interval between forced JWKS fetches
// triggered by an unknown-kid token. Matches jose-js default (30s).
// Prevents a malformed token from DoSing the JWKS endpoint.
const jwksRefreshCooldown = 30 * time.Second

// DefaultJWKSStaleThreshold is the DDIL P3.1 governed-degrade budget:
// how long the verifier keeps serving the last successfully-fetched
// JWKS after refreshes begin failing, measured from that last good
// fetch. Beyond it, getJWKS fails closed with ErrJWKSUnavailable.
//
// 1h is safe because Falcon-ID's signing keys rotate on a 90-day
// cadence — a 1h stale window cannot outlive a key generation, so a
// revoked/rotated key is never honoured past its overlap. The value is
// the operating-spec baseline (2026-07-19-ddil-degraded-mode-operating-
// spec.md §2). Callers set VerifierConfig.JWKSStaleThreshold; a value
// <= 0 disables the stale window (strict fail-closed at TTL — the
// pre-P3.1 behaviour).
const DefaultJWKSStaleThreshold = 1 * time.Hour

// allowedAlgorithms — RFC 8725 §3.3 whitelist. RS256 only. Adding
// another algorithm requires a deliberate code change AND coordinated
// Falcon-ID-side signer changes.
var allowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}

// AudienceMapper computes the expected `aud` claim from a request's
// Host header. Defaults to expectedAudienceForHost (https://<host>).
// Operators wire a custom mapper when a deployment uses a non-canonical
// audience form (e.g., port-qualified for non-:443 hosts).
type AudienceMapper func(host string) string

// VerifierConfig parameterises NewVerifier. All required fields are
// validated at construction.
type VerifierConfig struct {
	// JWKSURL — Falcon-ID's published key set, typically
	// "https://id.hexxlock.com/.well-known/jwks.json".
	JWKSURL string

	// ExpectedIssuer — Falcon-ID's issuer URL, typically
	// "https://id.hexxlock.com". Pinned at construction.
	ExpectedIssuer string

	// AudienceMapper — computes expected `aud` from request Host.
	// nil = expectedAudienceForHost (the canonical "https://<host>" form).
	AudienceMapper AudienceMapper

	// ClockTolerance — overrides DefaultClockTolerance.
	ClockTolerance time.Duration

	// JWKSCacheTTL — overrides DefaultJWKSCacheTTL.
	JWKSCacheTTL time.Duration

	// JWKSStaleThreshold — DDIL P3.1 governed-degrade budget. When > 0,
	// a JWKS refresh failure AFTER the TTL keeps serving the last-good
	// key set until the last successful fetch is this old, then fails
	// closed (ErrJWKSUnavailable). <= 0 disables the window (strict
	// fail-closed at TTL). Callers typically pass DefaultJWKSStaleThreshold
	// (1h). See the const doc for the safety argument.
	JWKSStaleThreshold time.Duration

	// Clock overrides the wall-clock source used for JWKS freshness /
	// stale-window / cooldown / breaker timing. nil = resilient.SystemClock.
	// Injected as a resilient.Clock so degraded-mode timing is
	// deterministically testable and can later ride a defence-SKU
	// trusted-time source (P3.3/P4.8) without touching call sites.
	Clock resilient.Clock

	// OnJWKSStale — optional callback invoked exactly once per verify
	// that is served from a STALE (last-good) JWKS after a refresh
	// failure, within JWKSStaleThreshold. staleFor is the age of the
	// served key set (now - last successful fetch). Wire it to a WARN
	// log + a Prometheus counter so operators see the governed-degrade
	// window open. nil = no-op. Keeps this package free of a logger /
	// prometheus dependency (same rationale as VerifierMetrics).
	OnJWKSStale func(staleFor time.Duration)

	// HTTPClient — overrides the default http.Client used for JWKS
	// fetches. Useful for tests + Linkerd-mTLS-aware transports.
	HTTPClient *http.Client

	// ReplayCacheSize — enables per-process replay protection on jti.
	// Zero disables (default; exp window provides primary defense).
	// Sizing: peak mint rate × (TTL + clock tolerance). 8192 covers
	// 100 RPS sustained.
	ReplayCacheSize int

	// ReplayCache — shared-store override. When non-nil, ReplayCacheSize
	// is ignored. Use this for multi-pod Talon deployments where
	// per-process replay protection is insufficient.
	ReplayCache ReplayCache

	// RevocationStore — optional per-jti revocation list. When non-nil,
	// every successful crypto verification consults the store; a hit
	// returns ErrRevoked. nil = revocation disabled (defense-in-depth
	// only; the cookie session-revocation path is unaffected).
	RevocationStore RevocationStore

	// Metrics — optional Prom-backed sink. nil = no-op (default).
	Metrics VerifierMetrics

	// FederatedIssuers — OPTIONAL secondary issuers whose JWTs Talon
	// will signature-verify (sig + exp only — NOT audience / scope /
	// Falcon-ID-specific claim shape) and proxy as-is on routes whose
	// AuthMode is AuthModeBearerOrFederatedPassthrough. Empty (default)
	// disables federated trust entirely; the verifier behaves exactly
	// as before. See FederatedIssuerConfig docs (federated.go) for the
	// full motivation + safety properties (Envoy CVE-2021-21378
	// invariant preserved: unknown iss → 401, never passthrough-
	// eligible).
	FederatedIssuers []FederatedIssuerConfig
}

// ReplayCache — abstraction over jti replay protection. Implementations
// must be safe for concurrent use.
type ReplayCache interface {
	// SeenOrAdd records jti as seen with the given TTL and returns
	// true if jti was ALREADY present (= replay), false if first sight.
	// The check-and-set MUST be atomic relative to concurrent calls
	// for the same jti.
	SeenOrAdd(jti string, ttl time.Duration) bool
}

// RevocationStore — abstraction over the per-jti revocation list.
// Implementations must be safe for concurrent use. Talon pulls
// delta-updates from Falcon-ID's /oauth/revoked endpoint on a
// background tick (separate from this interface — the store just
// answers "is this jti revoked?" at verify time).
type RevocationStore interface {
	// IsRevoked returns true if jti has been revoked.
	IsRevoked(ctx context.Context, jti string) bool
}

// Verifier verifies Falcon-ID-issued client_credentials JWTs.
// Thread-safe by construction.
type Verifier struct {
	cfg               VerifierConfig
	audienceMapper    AudienceMapper
	httpClient        *http.Client
	jwksCacheTTL      time.Duration
	clockTolerance    time.Duration
	clock             resilient.Clock
	staleThreshold    time.Duration      // DDIL P3.1; <=0 = disabled
	jwksBreaker       *resilient.Breaker // P3.11 load-shed on the JWKS dependency
	onJWKSStale       func(staleFor time.Duration)
	mu                sync.Mutex
	jwks              *jose.JSONWebKeySet
	jwksAt            time.Time
	jwksCooldownUntil time.Time
	replay            ReplayCache     // nil = disabled
	revocation        RevocationStore // nil = disabled
	metrics           VerifierMetrics
	federated         *federatedRegistry // nil/empty = federated trust disabled
}

// NewVerifier validates config and returns a ready-to-use Verifier.
// Does NOT eagerly fetch JWKS — the first Verify call populates the
// cache. Use PrefetchJWKS() for fail-fast startup behaviour.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("svctoken: VerifierConfig.JWKSURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("svctoken: VerifierConfig.ExpectedIssuer required")
	}
	mapper := cfg.AudienceMapper
	if mapper == nil {
		mapper = expectedAudienceForHost
	}
	clockTol := cfg.ClockTolerance
	if clockTol == 0 {
		clockTol = DefaultClockTolerance
	}
	jwksTTL := cfg.JWKSCacheTTL
	if jwksTTL == 0 {
		jwksTTL = DefaultJWKSCacheTTL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var replay ReplayCache
	switch {
	case cfg.ReplayCache != nil:
		replay = cfg.ReplayCache
	case cfg.ReplayCacheSize > 0:
		replay = newReplayLRU(cfg.ReplayCacheSize)
	}
	var metrics VerifierMetrics = noopMetrics{}
	if cfg.Metrics != nil {
		metrics = cfg.Metrics
	}
	clock := cfg.Clock
	if clock == nil {
		clock = resilient.SystemClock{}
	}
	// Negative disables the stale window explicitly; zero means the
	// caller did not opt in (strict fail-closed at TTL). The talon
	// config layer supplies the operating-spec 1h default.
	staleThreshold := cfg.JWKSStaleThreshold
	if staleThreshold < 0 {
		staleThreshold = 0
	}
	// One breaker per verifier == one per JWKS dependency, so shedding
	// is coordinated across every concurrent verify (P3.11). Defaults
	// (5 consecutive failures trip, 30s cool-down) are fine for a JWKS
	// endpoint; the injected clock keeps the cool-down testable.
	jwksBreaker := resilient.NewBreaker(resilient.BreakerConfig{Clock: clock})
	federated, err := newFederatedRegistry(cfg.FederatedIssuers)
	if err != nil {
		return nil, err
	}
	// Defense-in-depth: reject duplicate iss across primary + federated.
	// Same iss with two different signers is undefined behaviour and a
	// likely operator misconfig — surface at startup, not at first
	// verify miss.
	if _, dup := federated.issuers[cfg.ExpectedIssuer]; dup {
		return nil, fmt.Errorf("svctoken: FederatedIssuerConfig.Issuer %q conflicts with primary ExpectedIssuer", cfg.ExpectedIssuer)
	}
	return &Verifier{
		cfg:            cfg,
		audienceMapper: mapper,
		httpClient:     client,
		jwksCacheTTL:   jwksTTL,
		clockTolerance: clockTol,
		clock:          clock,
		staleThreshold: staleThreshold,
		jwksBreaker:    jwksBreaker,
		onJWKSStale:    cfg.OnJWKSStale,
		replay:         replay,
		revocation:     cfg.RevocationStore,
		metrics:        metrics,
		federated:      federated,
	}, nil
}

// PrefetchJWKS eagerly fetches the JWKS. Use during startup to fail
// fast on misconfiguration (wrong URL, unreachable Falcon-ID).
func (v *Verifier) PrefetchJWKS(ctx context.Context) error {
	_, err := v.getJWKS(ctx, true, false)
	return err
}

// HealthCheck refreshes the JWKS cache (force=true past cooldown) and
// returns nil iff the JWKS contains at least one RSA key. Suitable
// for a Talon /readyz dependency check.
func (v *Verifier) HealthCheck(ctx context.Context) error {
	// allowStale=false: the readiness probe must see a REAL fetch result,
	// never a stale-window success that masks a Falcon-ID outage.
	jwks, err := v.getJWKS(ctx, true, false)
	if err != nil {
		return err
	}
	for _, k := range jwks.Keys {
		if _, ok := k.Key.(*rsa.PublicKey); ok {
			return nil
		}
	}
	return fmt.Errorf("%w: no RSA keys in JWKS", ErrJWKSUnavailable)
}

// VerifyRequest is the convenience method for HTTP middleware. Extracts
// the Bearer token from the Authorization header and verifies it
// against the request's Host. Returns ErrNoToken when no Authorization
// header is present (caller falls through to cookie path or 401 per
// per-host authMode).
func (v *Verifier) VerifyRequest(r *http.Request) (*Claims, error) {
	if r == nil {
		return nil, errors.New("svctoken: nil http.Request")
	}
	raw, ok := extractBearer(r.Header.Get("Authorization"))
	if !ok {
		// Audit-only failure (no token) — emitted by middleware, not here.
		return nil, ErrNoToken
	}
	verb := VerbForRequest(r)
	return v.Verify(r.Context(), raw, r.Host, verb)
}

// VerifyRequestBearerOrBasic is the credential-exchange variant of
// VerifyRequest. Tries the Bearer scheme first; on miss, attempts to
// extract a JWT from the password field of an
// "Authorization: Basic base64(username:password)" header. Used by
// AuthModeBearerOrBasicWithCredentialExchange routes (e.g.
// github.com) where go-git-based consumers wire the JWT
// through the Basic password slot because they cannot send a Bearer
// header directly.
//
// Returns ErrNoToken when neither scheme yields a token. Returns any
// verification error from Verify() on the matched scheme.
func (v *Verifier) VerifyRequestBearerOrBasic(r *http.Request) (*Claims, error) {
	if r == nil {
		return nil, errors.New("svctoken: nil http.Request")
	}
	auth := r.Header.Get("Authorization")
	if raw, ok := extractBearer(auth); ok {
		return v.Verify(r.Context(), raw, r.Host, VerbForRequest(r))
	}
	if raw, ok := extractJWTFromBasicPassword(auth); ok {
		return v.Verify(r.Context(), raw, r.Host, VerbForRequest(r))
	}
	return nil, ErrNoToken
}

// Verify runs the full pipeline:
//
//  1. Parse the compact JWS, extract kid from header.
//  2. Resolve kid → public key via cached JWKS (refresh on unknown).
//  3. Verify RS256 signature.
//  4. Parse claims, enforce iss / aud / exp / nbf / scope.
//  5. Replay-cache check (opt-in).
//  6. Revocation-list check (opt-in).
//  7. Return Claims.
//
// All security gates run before any optional check; a structurally
// invalid token is rejected before it can touch the replay cache or
// revocation store.
func (v *Verifier) Verify(ctx context.Context, raw, host string, verb Verb) (*Claims, error) {
	var (
		emittedKid    string
		emittedClient string
		emittedErr    error
	)
	defer func() {
		v.metrics.RecordVerify(VerifyMetricSample{
			Host:     strings.ToLower(host),
			ClientID: emittedClient,
			Kid:      emittedKid,
			Reason:   reasonForError(emittedErr),
		})
	}()

	raw = strings.TrimSpace(raw)
	if raw == "" {
		emittedErr = fmt.Errorf("%w: empty token", ErrTokenMalformed)
		return nil, emittedErr
	}

	parsed, err := jwt.ParseSigned(raw, allowedAlgorithms)
	if err != nil {
		// jose returns errors for malformed compact form, alg outside
		// the whitelist, etc. The whitelist is enforced at parse time;
		// any token with alg != RS256 dies here. jose's alg error type
		// is unexported, so we substring-match the stable prefix —
		// same approach as identityjwt.isAlgError (verifier.go:508).
		if strings.Contains(err.Error(), "unexpected signature algorithm") {
			emittedErr = fmt.Errorf("%w: %w", ErrAlgNotAllowed, err)
		} else {
			emittedErr = fmt.Errorf("%w: %w", ErrTokenMalformed, err)
		}
		return nil, emittedErr
	}
	if len(parsed.Headers) != 1 {
		emittedErr = fmt.Errorf("%w: unexpected JWS header count %d", ErrTokenMalformed, len(parsed.Headers))
		return nil, emittedErr
	}
	hdr := parsed.Headers[0]
	emittedKid = hdr.KeyID

	// Resolve kid → public key.
	jwks, err := v.getJWKS(ctx, false, true)
	if err != nil {
		emittedErr = err
		return nil, emittedErr
	}
	keys := jwks.Key(hdr.KeyID)
	if len(keys) == 0 {
		// Unknown kid — force a refresh past cooldown and retry.
		jwks, err = v.getJWKS(ctx, true, true)
		if err != nil {
			emittedErr = err
			return nil, emittedErr
		}
		keys = jwks.Key(hdr.KeyID)
	}
	if len(keys) == 0 {
		emittedErr = fmt.Errorf("%w: kid %q not in JWKS", ErrSignatureInvalid, hdr.KeyID)
		return nil, emittedErr
	}
	pub, ok := keys[0].Key.(*rsa.PublicKey)
	if !ok {
		emittedErr = fmt.Errorf("%w: kid %q is not RSA", ErrSignatureInvalid, hdr.KeyID)
		return nil, emittedErr
	}

	// Verify signature + extract claims in one pass.
	var stdClaims jwt.Claims
	var extra extraClaims
	if err := parsed.Claims(pub, &stdClaims, &extra); err != nil {
		emittedErr = fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
		return nil, emittedErr
	}

	emittedClient = extra.ClientID

	// Issuer pin.
	if stdClaims.Issuer != v.cfg.ExpectedIssuer {
		emittedErr = fmt.Errorf("%w: got %q want %q",
			ErrIssuerMismatch, stdClaims.Issuer, v.cfg.ExpectedIssuer)
		return nil, emittedErr
	}

	// Audience pin (per-host).
	expectedAud := v.audienceMapper(host)
	if expectedAud == "" {
		emittedErr = fmt.Errorf("%w: empty expected audience for host %q", ErrAudienceMismatch, host)
		return nil, emittedErr
	}
	if !containsAudience(stdClaims.Audience, expectedAud) {
		emittedErr = fmt.Errorf("%w: token aud=%v want %q",
			ErrAudienceMismatch, stdClaims.Audience, expectedAud)
		return nil, emittedErr
	}

	// Time-bounds with clock tolerance.
	now := time.Now()
	if stdClaims.Expiry != nil && now.Add(-v.clockTolerance).After(stdClaims.Expiry.Time()) {
		emittedErr = fmt.Errorf("%w: exp=%s now=%s tol=%s",
			ErrTokenExpired, stdClaims.Expiry.Time().Format(time.RFC3339),
			now.Format(time.RFC3339), v.clockTolerance)
		return nil, emittedErr
	}
	if stdClaims.NotBefore != nil && now.Add(v.clockTolerance).Before(stdClaims.NotBefore.Time()) {
		emittedErr = fmt.Errorf("%w: nbf=%s now=%s",
			ErrTokenNotYetValid, stdClaims.NotBefore.Time().Format(time.RFC3339), now.Format(time.RFC3339))
		return nil, emittedErr
	}
	if stdClaims.IssuedAt != nil && now.Add(v.clockTolerance).Before(stdClaims.IssuedAt.Time()) {
		emittedErr = fmt.Errorf("%w: iat=%s now=%s",
			ErrTokenNotYetValid, stdClaims.IssuedAt.Time().Format(time.RFC3339), now.Format(time.RFC3339))
		return nil, emittedErr
	}

	// Build normalised claim view.
	claims := &Claims{
		Issuer:   stdClaims.Issuer,
		Subject:  stdClaims.Subject,
		Audience: expectedAud,
		ClientID: extra.ClientID,
		TenantID: extra.TenantID,
		Scopes:   parseScope(extra.Scope),
		JTI:      stdClaims.ID,

		// Zero for client_credentials — see extraClaims.
		Groups:            extra.Groups,
		Roles:             extra.Roles,
		Email:             extra.Email,
		PreferredUsername: extra.PreferredUsername,
		AMR:               extra.AMR,
		ACR:               extra.ACR,
	}
	if stdClaims.IssuedAt != nil {
		claims.IssuedAt = stdClaims.IssuedAt.Time()
	}
	if stdClaims.Expiry != nil {
		claims.ExpiresAt = stdClaims.Expiry.Time()
	}

	// Scope enforcement (host+verb). Tier-1 ABAC gate.
	if !claims.AnyScopeMatchingHostVerb(strings.ToLower(host), verb) {
		emittedErr = fmt.Errorf("%w: scope=%v host=%s verb=%s",
			ErrScopeInsufficient, claims.Scopes, host, verb)
		return nil, emittedErr
	}

	// Replay protection (opt-in).
	if v.replay != nil && claims.JTI != "" {
		ttl := time.Until(claims.ExpiresAt) + v.clockTolerance
		if ttl <= 0 {
			// Defense-in-depth: an exp-in-the-past token already
			// failed the time-bound check above; this is here in case
			// future code paths skip it.
			ttl = v.clockTolerance
		}
		if v.replay.SeenOrAdd(claims.JTI, ttl) {
			emittedErr = fmt.Errorf("%w: jti=%s", ErrReplay, claims.JTI)
			return nil, emittedErr
		}
	}

	// Revocation check (opt-in).
	if v.revocation != nil && claims.JTI != "" {
		if v.revocation.IsRevoked(ctx, claims.JTI) {
			emittedErr = fmt.Errorf("%w: jti=%s", ErrRevoked, claims.JTI)
			return nil, emittedErr
		}
	}

	return claims, nil
}

// extraClaims captures the Falcon-ID-specific fields the standard
// jwt.Claims struct doesn't surface (oauth_provider_service_tokens.go:195-212).
//
// The subject-claim block (groups/roles/email/amr/acr) is emitted only
// for end-user grants — emitSubjectClaims returns early on a nil user —
// so these stay zero-valued for every client_credentials token and the
// machine path is unchanged by their presence here.
type extraClaims struct {
	ClientID string `json:"client_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Scope    string `json:"scope,omitempty"`

	Groups            []string `json:"groups,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	ACR               string   `json:"acr,omitempty"`
}

// getJWKS returns the cached key set, refetching if force=true OR the
// cached entry exceeds TTL. Cooldown prevents stampede on unknown-kid
// from DoSing Falcon-ID.
//
// allowStale toggles the DDIL P3.1 governed-degrade window: when true
// (the request verify path), a refresh failure past the TTL serves the
// last-good key set until it ages past staleThreshold, then fails
// closed. When false (HealthCheck / PrefetchJWKS) a refresh failure is
// surfaced verbatim so the readiness probe cannot be masked by a stale
// cache — the invariant the pre-P3.1 HealthCheck already relied on.
func (v *Verifier) getJWKS(ctx context.Context, force, allowStale bool) (*jose.JSONWebKeySet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.clock.Now()
	if !force && v.jwks != nil && now.Sub(v.jwksAt) < v.jwksCacheTTL {
		return v.jwks, nil
	}
	if force && now.Before(v.jwksCooldownUntil) && v.jwks != nil {
		// Cooldown active — return cached and let the next forced fetch
		// past cooldown surface a real failure.
		return v.jwks, nil
	}

	set, err := v.fetchJWKSResilient(ctx)
	if err != nil {
		// DDIL P3.1 — governed staleness window. A refresh failure after
		// the TTL keeps the last successfully-fetched key set in service
		// until it is older than staleThreshold, then fails closed
		// (never fail-open). Falcon-ID's signing keys rotate on a 90-day
		// cadence, so a 1h window can never outlive a key generation.
		if allowStale && v.jwks != nil && v.staleThreshold > 0 &&
			!resilient.Expired(now, v.jwksAt.Add(v.staleThreshold), 0) {
			if v.onJWKSStale != nil {
				v.onJWKSStale(now.Sub(v.jwksAt))
			}
			return v.jwks, nil
		}
		return nil, err
	}

	v.jwks = set
	v.jwksAt = now
	if force {
		v.jwksCooldownUntil = now.Add(jwksRefreshCooldown)
	}
	return v.jwks, nil
}

// fetchJWKSResilient runs a single JWKS fetch under the shared circuit
// breaker (DDIL P3.11). When Falcon-ID is sustained-unreachable the
// breaker opens and further fetches are shed with ErrBreakerOpen —
// surfaced here as ErrJWKSUnavailable — so getJWKS falls to the stale
// window (or fail-closed) instead of retry-storming a dead dependency
// on every verify. There is deliberately no in-request retry/backoff:
// a Bearer verify is latency-critical and the stale window already
// absorbs the transient failure. Caller holds v.mu.
func (v *Verifier) fetchJWKSResilient(ctx context.Context) (*jose.JSONWebKeySet, error) {
	var set *jose.JSONWebKeySet
	err := v.jwksBreaker.Do(ctx, func(ctx context.Context) error {
		s, ferr := v.fetchJWKS(ctx)
		if ferr != nil {
			return ferr
		}
		set = s
		return nil
	})
	if err != nil {
		if errors.Is(err, resilient.ErrBreakerOpen) {
			return nil, fmt.Errorf("%w: jwks circuit breaker open (falcon-id sustained-unreachable)", ErrJWKSUnavailable)
		}
		return nil, err
	}
	return set, nil
}

// fetchJWKS performs one JWKS HTTP round-trip and parses the result.
// All failure paths wrap ErrJWKSUnavailable. It does no locking and no
// caching — getJWKS owns the cache under v.mu.
func (v *Verifier) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrJWKSUnavailable, err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch: %w", ErrJWKSUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrJWKSUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrJWKSUnavailable, err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("%w: parse JWKS: %w", ErrJWKSUnavailable, err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("%w: empty JWKS", ErrJWKSUnavailable)
	}
	return &jwks, nil
}

// extractBearer returns the token portion of an "Authorization: Bearer
// <token>" header value, or (empty, false) if the header is missing or
// uses a different scheme.
func extractBearer(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(authHeader[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// extractJWTFromBasicPassword decodes an "Authorization: Basic
// base64(username:password)" header value and returns the password
// field IF it has the surface shape of a compact JWS (three dot-
// separated base64url segments). Used by
// AuthModeBearerOrBasicWithCredentialExchange routes where consumers
// like ArgoCD's go-git always wire credentials through Basic auth
// (the password slot of a repoCreds Secret) and cannot send a Bearer
// header directly.
//
// The shape pre-check is intentionally cheap: it only rules out the
// obvious "Basic oauth2:glpat-AbC123" PAT case so non-svctoken  // gitleaks:allow — illustrative value in a comment
// callers fall through to the original Authorization. The real
// signature / iss / aud / exp validation is the verifier's
// downstream job — a caller can still craft a 3-segment-shape
// password that isn't a signed JWT, in which case Verify() rejects
// it like any other invalid token.
//
// Returns (token, true) on positive shape match, ("", false) for
// missing header, non-Basic scheme, malformed base64, missing colon,
// empty password, or password that doesn't look like a JWT.
func extractJWTFromBasicPassword(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	const prefix = "Basic "
	if len(authHeader) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	rawB64 := strings.TrimSpace(authHeader[len(prefix):])
	if rawB64 == "" {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return "", false
	}
	s := string(decoded)
	colon := strings.IndexByte(s, ':')
	if colon < 0 || colon == len(s)-1 {
		return "", false
	}
	password := s[colon+1:]
	if !looksLikeJWT(password) {
		return "", false
	}
	return password, true
}

// looksLikeJWT does a cheap structural check on a string: three
// dot-separated segments, each at least 10 chars, whose FIRST segment
// base64url-decodes to a JSON object carrying an "alg" member — i.e. a
// JOSE header. NOT a signature check — caller must still pass the token
// through the verifier to authenticate it.
//
// The segment count and length floor alone are NOT sufficient, and
// relying on them fails closed in a way no client can recover from.
// GitLab 18 routable CI job tokens (`glcbt-…`) are themselves three
// dot-separated segments (observed 112/327/342 chars), so a pure shape
// test reclassifies them as service tokens; Verify() then fails and the
// router answers 401 + `WWW-Authenticate: Bearer`, a challenge no
// Basic-auth client can satisfy. Symptoms were a `remote: unauthorized`
// on every `gitlab-ci-token:$CI_JOB_TOKEN` git fetch, and kaniko's
// "error checking push permissions" against the in-cluster GitLab
// registry — whose token realm is the Talon-fronted *.ops host, so the
// push egresses through this check even though the data path does not.
//
// Requiring a decodable JOSE header is the actual discriminator, and is
// preferred over denylisting GitLab's credential prefixes: per RFC 7515
// §4.1.1 "alg" is REQUIRED in the JOSE header, so this cannot
// false-reject a valid JWS, while ANY credential that merely happens to
// contain two dots — GitLab's, Harbor's, or a future issuer's — now
// falls through to the original Authorization header instead of being
// hijacked.
func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 10 {
			return false
		}
	}
	return isJOSEHeader(parts[0])
}

// isJOSEHeader reports whether seg is the base64url encoding of a JSON
// object with a non-empty "alg" member. Compact JWS uses unpadded
// base64url (RFC 7515 §2); trailing padding is tolerated so a
// non-conforming-but-valid encoder is not rejected on a technicality.
func isJOSEHeader(seg string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return false
	}
	return hdr.Alg != ""
}

// containsAudience reports whether expected ∈ aud. Per RFC 7519 §4.1.3
// aud can be a string OR a string array; jose's jwt.Audience handles both.
func containsAudience(aud jwt.Audience, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}

// parseScope splits the OAuth 2.0 scope claim (space-separated per
// RFC 6749 §3.3) into a slice. Empty input → nil slice.
func parseScope(scope string) []string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}
