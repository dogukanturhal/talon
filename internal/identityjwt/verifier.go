// SPDX-License-Identifier: AGPL-3.0-or-later

// verifier.go — Go-side counterpart to the TypeScript verifier at
// `packages/falcon-id-client/src/nextjs/iap-jwt-verifier.ts`. Lets any
// Go upstream that sits behind Talon (harbor-bcl-receiver,
// audit-archiver, falcon-id itself, future stock-OAuth2 services)
// cryptographically verify the X-Talon-Identity-Token JWT against
// Talon's published JWKS — closing Phase B for the whole platform,
// not just admin-tier Next.js apps.
//
// Contract (mirrors the TypeScript surface verbatim where it makes
// sense; deviates only where Go idiom + http.Request differ from the
// Edge Runtime's Request):
//
//	v, err := identityjwt.NewVerifier(identityjwt.VerifierConfig{
//	    JWKSURL:          "https://auth.internal.example.com/.well-known/jwks.json",
//	    ExpectedIssuer:   "https://auth.internal.example.com",
//	    ExpectedAudience: "registry.example.com",
//	})
//	claims, err := v.VerifyRequest(r)
//	if errors.Is(err, identityjwt.ErrNoToken) {
//	    // header absent — caller decides fall-back or 401
//	}
//
// Tier-1 properties enforced (RFC 8725 BCP):
//   - §3.3 alg whitelist: RS256 only. Defeats "alg=none" confused-deputy.
//   - §3.1 audience binding: aud must match operator-supplied expected.
//   - §3.7 issuer pinning: iss must match operator-supplied expected.
//   - RFC 7519 §4.1.4: exp/nbf enforced with a small (5s) clock tolerance.
//   - JWKS fetched lazily + cached with 5-minute TTL matching Cloudflare
//     Access / Google IAP defaults. Refresh-on-unknown-kid (jose's
//     cached keyfunc behaviour) handles rotation transparently.
//
// Failure-reason taxonomy mirrors the TypeScript verifier so SOC
// dashboards correlate Go-side and Edge-side verify failures with the
// same `iap_reason` discriminator (see Reason type below).
package identityjwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// DefaultClockTolerance is the slack applied to iat/nbf/exp during
// verification — generous enough to absorb cluster-node clock drift
// (chrony keeps RKE2 nodes <10ms), tight enough that a token replayed
// minutes after issue still fails.
const DefaultClockTolerance = 5 * time.Second

// DefaultJWKSCacheTTL bounds how long a successfully fetched JWKS is
// reused before re-fetching. 5 minutes matches Talon's Cache-Control
// + every reference IAP's published guidance.
const DefaultJWKSCacheTTL = 5 * time.Minute

// jwksCooldown is the minimum interval between forced JWKS fetches
// triggered by an unknown-kid token. Matches jose-js's 30s default.
const jwksCooldown = 30 * time.Second

// DefaultJWKSStaleThreshold is the DDIL P3.1 governed-degrade budget:
// how long the verifier keeps serving the last successfully-fetched
// JWKS after refreshes begin failing, measured from that last good
// fetch. Beyond it, getJWKS fails closed with ErrJWKSUnavailable.
//
// 1h is safe because Talon's IAP signing keys rotate on a 90-day
// cadence — a 1h stale window cannot outlive a key generation, so a
// rotated key is never honoured past its published overlap. The value
// is the operating-spec baseline (2026-07-19-ddil-degraded-mode-
// operating-spec.md §2). Callers set VerifierConfig.JWKSStaleThreshold;
// a value <= 0 disables the stale window (strict fail-closed at TTL,
// the pre-P3.1 behaviour).
const DefaultJWKSStaleThreshold = 1 * time.Hour

// allowedAlgorithms is the RFC 8725 §3.3 alg whitelist. Hardcoded —
// adding another algorithm requires a deliberate code change AND a
// coordinated Talon-side signer change.
var allowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256}

// Sentinel errors callers can branch on via errors.Is. All other
// failures wrap one of these so verify-time `errors.Is(err, ErrXxx)`
// works regardless of how deep the wrapping goes.
var (
	// ErrNoToken — request didn't carry an X-Talon-Identity-Token
	// header. Callers decide whether to fall back to the unsigned
	// X-Talon-* path (Phase A) or 401 (Phase B).
	ErrNoToken = errors.New("identityjwt: no X-Talon-Identity-Token header")

	// ErrSignatureInvalid — RS256 signature did not verify against any
	// kid in the cached JWKS. Could mean a forged token OR a stale
	// JWKS cache + recent rotation; the verifier re-fetches on this
	// path so a second consecutive failure is the real signal.
	ErrSignatureInvalid = errors.New("identityjwt: signature verification failed")

	// ErrTokenExpired — exp claim is in the past beyond clock
	// tolerance. Expected on a token replayed > 60s after mint.
	ErrTokenExpired = errors.New("identityjwt: token expired")

	// ErrTokenNotYetValid — nbf/iat is in the future beyond tolerance.
	// Usually means a clock-skew problem on the upstream side.
	ErrTokenNotYetValid = errors.New("identityjwt: token not yet valid")

	// ErrIssuerMismatch — iss claim didn't match VerifierConfig.ExpectedIssuer.
	// Always a configuration defect; upstream + Talon disagree on origin.
	ErrIssuerMismatch = errors.New("identityjwt: issuer mismatch")

	// ErrAudienceMismatch — aud claim didn't match VerifierConfig.ExpectedAudience.
	// Per RFC 8725 §3.1 audience binding: a token minted for falcon.ops
	// must not be accepted at argocd.ops. Always a security-relevant
	// reject.
	ErrAudienceMismatch = errors.New("identityjwt: audience mismatch")

	// ErrAlgNotAllowed — JWS header carried an alg outside the
	// whitelist. Defeats the "alg=none" confused-deputy attack
	// (RFC 8725 §3.3). Always a security-relevant reject.
	ErrAlgNotAllowed = errors.New("identityjwt: alg not allowed")

	// ErrTokenMalformed — token bytes couldn't be parsed at all
	// (not three base64url segments, header undecodable, claims
	// missing required fields).
	ErrTokenMalformed = errors.New("identityjwt: token malformed")

	// ErrJWKSUnavailable — Talon's JWKS endpoint couldn't be reached,
	// or returned a non-200, or returned a body that didn't parse as
	// a JWKS document. Real ops problem; callers should fail closed
	// in Phase B (matches Cloudflare Access / Google IAP semantics).
	ErrJWKSUnavailable = errors.New("identityjwt: jwks unavailable")

	// ErrReplay — the JWT's jti has been seen before within the
	// replay-cache TTL. Defense-in-depth against intercepted-token
	// replay within the 60s exp window. Surfaces ONLY when the
	// VerifierConfig.ReplayCacheSize > 0 (opt-in, since the
	// per-process cache doesn't catch cross-pod replay; production
	// deployments behind a multi-pod upstream may prefer to rely on
	// the 60s exp alone, or wire a shared cache via the optional
	// ReplayCache interface).
	ErrReplay = errors.New("identityjwt: jti replay detected")
)

// VerifierConfig parameterises NewVerifier. All three string fields
// are required; an empty value rejects at construction time so
// upstream misconfigurations surface at startup rather than at first
// failed request.
type VerifierConfig struct {
	// JWKSURL is Talon's published key set, typically
	// "https://auth.internal.example.com/.well-known/jwks.json".
	JWKSURL string

	// ExpectedIssuer is the operator-supplied iss value the verifier
	// will pin against — Talon's external URL (matches the issuer the
	// Signer was constructed with).
	ExpectedIssuer string

	// ExpectedAudience is THIS upstream's public host (= the protected
	// route Talon stamped on the JWT's aud claim). A JWT minted for a
	// different upstream MUST NOT verify here.
	ExpectedAudience string

	// ClockTolerance overrides DefaultClockTolerance; leave zero for
	// the 5s default (which is what every reference IAP uses).
	ClockTolerance time.Duration

	// JWKSStaleThreshold — DDIL P3.1 governed-degrade budget. When > 0,
	// a JWKS refresh failure AFTER the TTL keeps serving the last-good
	// key set until the last successful fetch is this old, then fails
	// closed (ErrJWKSUnavailable). <= 0 disables the window (strict
	// fail-closed at TTL). Callers typically pass DefaultJWKSStaleThreshold
	// (1h). See the const doc for the safety argument.
	JWKSStaleThreshold time.Duration

	// Clock overrides the wall-clock source used for JWKS freshness /
	// stale-window / cooldown / breaker timing. nil = resilient.SystemClock.
	// A resilient.Clock so degraded-mode timing is deterministically
	// testable and can later ride a trusted-time source (P3.3/P4.8).
	Clock resilient.Clock

	// OnJWKSStale — optional callback invoked once per verify served from
	// a STALE (last-good) JWKS after a refresh failure, within
	// JWKSStaleThreshold. staleFor is the age of the served key set. Wire
	// it to a WARN log + a Prometheus counter. nil = no-op. Keeps the
	// package free of a logger / prometheus dependency.
	OnJWKSStale func(staleFor time.Duration)

	// HTTPClient overrides the default http.Client used to fetch JWKS.
	// Useful for tests + for upstreams that need to thread a Linkerd-
	// mTLS-aware transport. Leave nil for the default (10s timeout).
	HTTPClient *http.Client

	// ReplayCacheSize enables per-process replay protection on the
	// JWT jti claim (RFC 7519 §4.1.7). When > 0, the verifier
	// remembers every recently-seen jti and rejects duplicates with
	// ErrReplay. Zero disables (default; the 60s exp window provides
	// the primary defense — replay protection is opt-in
	// defense-in-depth).
	//
	// Sizing guidance: at peak mint rate R req/s and 65s TTL (60s
	// exp + 5s tolerance), set ReplayCacheSize >= R * 65. For a
	// 100-req/s upstream, 8192 is comfortably large.
	//
	// CAVEAT: the cache is per-process. Multi-pod upstreams will
	// NOT catch replay across pods. Use ReplayCache (below) to plug
	// in a shared Redis-backed store when cross-pod replay
	// protection is required.
	ReplayCacheSize int

	// ReplayCache optionally overrides the built-in in-memory LRU
	// cache. Useful for shared-storage backends (Redis, memcached)
	// in deployments where per-pod replay protection is insufficient.
	// When non-nil, ReplayCacheSize is ignored.
	ReplayCache ReplayCache

	// Metrics is the optional observability sink invoked on every
	// verify-path decision. nil = no-op (default). Upstream services
	// wire a Prometheus-backed implementation (see metrics.go for the
	// interface contract + suggested label shape). Keeps identityjwt
	// free of prometheus/client_golang dep — consumers carry that
	// dep in their main package.
	Metrics VerifierMetrics
}

// ReplayCache is the abstraction the verifier consults to enforce
// jti uniqueness. The built-in in-memory LRU implementation is
// constructed automatically when VerifierConfig.ReplayCacheSize > 0.
// Implementations MUST be safe for concurrent use.
type ReplayCache interface {
	// SeenOrAdd records jti as seen with the given TTL and returns
	// true if jti was ALREADY present (= replay), false if this is
	// the first sighting. The check-and-set must be atomic relative
	// to concurrent calls for the same jti.
	SeenOrAdd(jti string, ttl time.Duration) bool
}

// Verifier verifies X-Talon-Identity-Token JWTs against Talon's JWKS.
// Thread-safe by construction (mu guards the JWKS cache; jose's
// JSONWebKeySet is read-only after parse; replay cache has its own
// internal locking).
type Verifier struct {
	cfg            VerifierConfig
	httpClient     *http.Client
	clock          resilient.Clock
	staleThreshold time.Duration      // DDIL P3.1; <=0 = disabled
	jwksBreaker    *resilient.Breaker // P3.11 load-shed on the JWKS dependency
	onJWKSStale    func(staleFor time.Duration)
	mu             sync.Mutex
	jwks           *jose.JSONWebKeySet
	jwksAt         time.Time
	jwksCooldownUntil time.Time
	replay     ReplayCache     // nil = replay protection disabled
	metrics    VerifierMetrics // never nil — defaulted to noopMetrics{}
}

// NewVerifier constructs a Verifier with the given config. Returns an
// error only on configuration defects (empty required field); does
// NOT eagerly fetch JWKS — the first VerifyRequest/VerifyToken call
// populates the cache. Callers that want to fail fast on JWKS
// unavailability can call PrefetchJWKS() right after construction.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("identityjwt: VerifierConfig.JWKSURL required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("identityjwt: VerifierConfig.ExpectedIssuer required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("identityjwt: VerifierConfig.ExpectedAudience required")
	}
	if cfg.ClockTolerance == 0 {
		cfg.ClockTolerance = DefaultClockTolerance
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
	staleThreshold := cfg.JWKSStaleThreshold
	if staleThreshold < 0 {
		staleThreshold = 0 // negative disables the stale window explicitly
	}
	jwksBreaker := resilient.NewBreaker(resilient.BreakerConfig{Clock: clock})
	return &Verifier{
		cfg:            cfg,
		httpClient:     client,
		clock:          clock,
		staleThreshold: staleThreshold,
		jwksBreaker:    jwksBreaker,
		onJWKSStale:    cfg.OnJWKSStale,
		replay:         replay,
		metrics:        metrics,
	}, nil
}

// PrefetchJWKS eagerly fetches the key set. Optional — useful for
// upstreams that want to fail fast on misconfiguration at startup
// rather than discover the JWKS is unreachable on first request.
func (v *Verifier) PrefetchJWKS(ctx context.Context) error {
	_, err := v.getJWKS(ctx, true, false)
	return err
}

// HealthCheck returns nil if the verifier is ready to verify tokens —
// JWKS is reachable, parses cleanly, and contains at least one RSA
// key. Suitable for an upstream service's /readyz handler so the pod
// fails its readiness probe when Talon's JWKS endpoint is
// unreachable. Symmetric to Talon's own Signer.HealthCheck on the
// minting side: the SOC analyst can correlate a non-Ready upstream
// with a non-Ready Talon during an outage.
//
// The implementation refreshes the JWKS cache (force=true past the
// cooldown) so a stale-cache window can't mask a real ops issue from
// the readiness probe. Microseconds in the warm path; one network
// round-trip in the cooldown-elapsed cold path.
func (v *Verifier) HealthCheck(ctx context.Context) error {
	// allowStale=false: the readiness probe must see a REAL fetch result,
	// never a stale-window success that masks a Talon JWKS outage.
	jwks, err := v.getJWKS(ctx, true, false)
	if err != nil {
		return err
	}
	// Defense-in-depth — getJWKS already rejects empty keysets, but
	// a structurally-correct JWKS with all non-RSA entries would still
	// pass that gate and silently break every verify.
	for _, k := range jwks.Keys {
		if _, ok := k.Key.(*rsa.PublicKey); ok {
			return nil
		}
	}
	return fmt.Errorf("%w: JWKS contains no RSA keys", ErrJWKSUnavailable)
}

// VerifyRequest extracts the X-Talon-Identity-Token from r.Header,
// verifies it, and returns the claims. ErrNoToken when the header is
// absent. All other verify failures return one of the typed sentinel
// errors above (callers branch on errors.Is).
func (v *Verifier) VerifyRequest(r *http.Request) (*IdentityClaims, error) {
	if r == nil {
		return nil, errors.New("identityjwt: nil http.Request")
	}
	token := r.Header.Get(HeaderName)
	if token == "" {
		return nil, ErrNoToken
	}
	return v.VerifyToken(r.Context(), token)
}

// VerifyToken verifies a raw compact JWS string. The caller-supplied
// ctx propagates to the JWKS fetch if a refresh is triggered.
func (v *Verifier) VerifyToken(ctx context.Context, token string) (*IdentityClaims, error) {
	// Capture-on-return instrumentation: every verify outcome lands
	// on the Metrics sink with a normalised label set. Audience
	// defaults to the configured ExpectedAudience so failures BEFORE
	// claim parsing (malformed token, alg violation) still carry a
	// label. kid defaults to "" when extraction failed.
	var (
		emittedKid      string
		emittedAudience = v.cfg.ExpectedAudience
		emittedErr      error
	)
	defer func() {
		if emittedErr == nil {
			v.metrics.OnVerifySuccess(emittedAudience, emittedKid)
			return
		}
		// Replay gets its own counter because operators dashboard on
		// it differently — a non-zero replay rate signals either an
		// attack OR a buggy upstream double-submitting tokens.
		if errors.Is(emittedErr, ErrReplay) {
			v.metrics.OnReplayBlocked(emittedAudience)
			return
		}
		v.metrics.OnVerifyFailure(emittedAudience, emittedKid, classifyReason(emittedErr))
	}()

	parsed, err := jwt.ParseSigned(token, allowedAlgorithms)
	if err != nil {
		// jose returns errors for malformed compact form, alg
		// outside the whitelist, etc. The whitelist is enforced
		// at parse time — any token with alg != RS256 dies here.
		if isAlgError(err) {
			emittedErr = fmt.Errorf("%w: %w", ErrAlgNotAllowed, err)
			return nil, emittedErr
		}
		emittedErr = fmt.Errorf("%w: %w", ErrTokenMalformed, err)
		return nil, emittedErr
	}
	if len(parsed.Headers) != 1 {
		emittedErr = fmt.Errorf("%w: expected single signature, got %d", ErrTokenMalformed, len(parsed.Headers))
		return nil, emittedErr
	}
	emittedKid = parsed.Headers[0].KeyID

	jwks, err := v.getJWKS(ctx, false, true)
	if err != nil {
		emittedErr = err
		return nil, emittedErr
	}
	pub, ok := selectKey(jwks, emittedKid)
	if !ok {
		// Unknown kid — could be a freshly-rotated key the cache hasn't
		// picked up. Force-refresh past cooldown and retry once.
		jwks, err = v.getJWKS(ctx, true, true)
		if err != nil {
			emittedErr = err
			return nil, emittedErr
		}
		pub, ok = selectKey(jwks, emittedKid)
		if !ok {
			emittedErr = fmt.Errorf("%w: kid %q not found in JWKS", ErrSignatureInvalid, emittedKid)
			return nil, emittedErr
		}
	}

	var claims IdentityClaims
	if err := parsed.Claims(pub, &claims); err != nil {
		emittedErr = fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
		return nil, emittedErr
	}

	if claims.Issuer != v.cfg.ExpectedIssuer {
		emittedErr = fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, claims.Issuer, v.cfg.ExpectedIssuer)
		return nil, emittedErr
	}
	if claims.Audience != v.cfg.ExpectedAudience {
		emittedErr = fmt.Errorf("%w: got %q, want %q", ErrAudienceMismatch, claims.Audience, v.cfg.ExpectedAudience)
		return nil, emittedErr
	}
	now := time.Now().UTC()
	if claims.ExpiresAt > 0 {
		exp := time.Unix(claims.ExpiresAt, 0)
		if now.After(exp.Add(v.cfg.ClockTolerance)) {
			emittedErr = fmt.Errorf("%w: exp=%s now=%s", ErrTokenExpired, exp.Format(time.RFC3339), now.Format(time.RFC3339))
			return nil, emittedErr
		}
	}
	if claims.IssuedAt > 0 {
		iat := time.Unix(claims.IssuedAt, 0)
		if iat.After(now.Add(v.cfg.ClockTolerance)) {
			emittedErr = fmt.Errorf("%w: iat=%s now=%s", ErrTokenNotYetValid, iat.Format(time.RFC3339), now.Format(time.RFC3339))
			return nil, emittedErr
		}
	}
	if claims.Subject == "" {
		emittedErr = fmt.Errorf("%w: sub missing or empty", ErrTokenMalformed)
		return nil, emittedErr
	}
	// Replay protection — last gate. Opt-in via VerifierConfig
	// (ReplayCacheSize > 0 OR ReplayCache != nil). When enabled, the
	// jti claim is required and reused jtis within the TTL window
	// return ErrReplay. Defense-in-depth atop the 60s exp window.
	if v.replay != nil {
		if claims.JTI == "" {
			emittedErr = fmt.Errorf("%w: jti claim required for replay protection", ErrTokenMalformed)
			return nil, emittedErr
		}
		// TTL = remaining exp + tolerance, capped at a sane upper
		// bound. We track entries only until they would naturally
		// expire by exp anyway, so cache pressure stays bounded by
		// the actual mint rate.
		ttl := time.Until(time.Unix(claims.ExpiresAt, 0)) + v.cfg.ClockTolerance
		if ttl <= 0 {
			// exp already past tolerance — ErrTokenExpired would have
			// fired earlier; defensive fallback.
			ttl = v.cfg.ClockTolerance
		}
		if v.replay.SeenOrAdd(claims.JTI, ttl) {
			emittedErr = fmt.Errorf("%w: jti=%s", ErrReplay, claims.JTI)
			return nil, emittedErr
		}
	}
	return &claims, nil
}

// getJWKS returns the cached JWKS, refreshing if force=true (and past
// the cooldown) or if the TTL has elapsed. Thread-safe — multiple
// concurrent verifies coalesce on a single fetch.
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
	if !force && v.jwks != nil && now.Sub(v.jwksAt) < DefaultJWKSCacheTTL {
		return v.jwks, nil
	}
	if force && now.Before(v.jwksCooldownUntil) {
		// Within cooldown — return the stale cache (if any) rather than
		// hammer Talon during a known-bad period.
		if v.jwks != nil {
			return v.jwks, nil
		}
	}
	v.jwksCooldownUntil = now.Add(jwksCooldown)

	set, err := v.fetchJWKSResilient(ctx)
	if err != nil {
		// DDIL P3.1 — governed staleness window. A refresh failure after
		// the TTL keeps the last successfully-fetched key set in service
		// until it is older than staleThreshold, then fails closed
		// (never fail-open). Talon's IAP signing keys rotate on a 90-day
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
	return v.jwks, nil
}

// fetchJWKSResilient runs a single JWKS fetch under the shared circuit
// breaker (DDIL P3.11). When Talon's JWKS endpoint is sustained-
// unreachable the breaker opens and further fetches are shed with
// ErrBreakerOpen — surfaced here as ErrJWKSUnavailable — so getJWKS
// falls to the stale window (or fail-closed) instead of retry-storming
// a dead dependency on every verify. No in-request retry/backoff: a
// request verify is latency-critical and the stale window already
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
			v.metrics.OnJWKSFetch("failure")
			return nil, fmt.Errorf("%w: jwks circuit breaker open (talon sustained-unreachable)", ErrJWKSUnavailable)
		}
		return nil, err
	}
	return set, nil
}

// fetchJWKS performs one JWKS HTTP round-trip and parses the result,
// emitting the OnJWKSFetch metric for every outcome. It does no locking
// and no caching — getJWKS owns the cache under v.mu.
func (v *Verifier) fetchJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		v.metrics.OnJWKSFetch("failure")
		return nil, fmt.Errorf("%w: build request: %w", ErrJWKSUnavailable, err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		v.metrics.OnJWKSFetch("failure")
		return nil, fmt.Errorf("%w: %w", ErrJWKSUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		v.metrics.OnJWKSFetch("failure")
		return nil, fmt.Errorf("%w: status %d", ErrJWKSUnavailable, resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		v.metrics.OnJWKSFetch("failure")
		return nil, fmt.Errorf("%w: decode jwks: %w", ErrJWKSUnavailable, err)
	}
	if len(set.Keys) == 0 {
		v.metrics.OnJWKSFetch("failure")
		return nil, fmt.Errorf("%w: empty JWKS", ErrJWKSUnavailable)
	}
	v.metrics.OnJWKSFetch("success")
	return &set, nil
}

// selectKey returns the RSA public key on the JWKS matching kid. When
// the JWS header carries an empty kid (signers may omit it), the
// function falls back to the single-key form per RFC 7517 §4.5 ("If
// there is only one key in the JWK Set, the kid parameter MAY be
// omitted").
func selectKey(jwks *jose.JSONWebKeySet, kid string) (*rsa.PublicKey, bool) {
	if jwks == nil {
		return nil, false
	}
	if kid == "" && len(jwks.Keys) == 1 {
		pub, ok := jwks.Keys[0].Key.(*rsa.PublicKey)
		return pub, ok
	}
	for _, k := range jwks.Keys {
		if k.KeyID == kid {
			pub, ok := k.Key.(*rsa.PublicKey)
			return pub, ok
		}
	}
	return nil, false
}

// isAlgError detects jose's alg-not-allowed error without depending
// on an unexported error type. jose returns
// "go-jose/go-jose: unexpected signature algorithm \"…\"; expected
// \"RS256\"" — we substring-match on the stable prefix.
func isAlgError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unexpected signature algorithm")
}
