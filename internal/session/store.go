// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session implements the AES-256-GCM-encrypted Redis-backed
// session store specified in ADR 0002. The cookie value is an opaque
// UUIDv4; the encrypted blob lives at talon:session:<uuid> in Redis.
//
// Wire format of the Redis value (per ADR 0002 §4.2):
//
//	┌─────────────┬──────────────┬───────────────────────────────────┐
//	│ KEY-VER (1) │ NONCE (12)   │ CIPHERTEXT-WITH-AUTH-TAG (var)    │
//	└─────────────┴──────────────┴───────────────────────────────────┘
//
// AAD = the cookie UUID (binds the blob to its cookie).
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/hexx-pep-core/pkg/identity"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// SchemaVersion is the current Blob.V (ADR 0002 §4.1).
const SchemaVersion = 1

// CurrentKeyVersion is the byte that prefixes envelopes encrypted with the
// current key. Bumped during rotation per ADR 0002 §6.
const CurrentKeyVersion byte = 1

// Blob is the JSON payload encrypted into Redis. Field tags match
// ADR 0002 §4.1 byte-for-byte; do not rename without bumping V and
// adding decoder shims for the old shape.
type Blob struct {
	V      int      `json:"v"`
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	// Roles is the Falcon-ID `roles` claim — names like "platform_admin",
	// "iam_admin". Distinct from Groups (which holds /path/style group
	// memberships from iam_groups). Phase 1 group-filter checks both.
	Roles    []string `json:"roles,omitempty"`
	TenantID string   `json:"tenant_id,omitempty"`
	Iss      string   `json:"iss"`
	AMR      []string `json:"amr,omitempty"`
	// ACR — Authentication Context Class Reference (OIDC Core §2,
	// RFC 8176 §1). Captured from the upstream id_token; consumed by
	// the router's step-up gate when a route configures RequireACR.
	// RFC 8176 §1 explicitly recommends `acr` over `amr` for
	// gate decisions because it's a stable business-rule reference
	// rather than a brittle method list. omitempty preserves backward
	// compat with on-disk blobs that pre-date the field — they decode
	// with an empty ACR and the gate falls back to the amr path.
	ACR             string `json:"acr,omitempty"`
	IAT             int64  `json:"iat"`
	Exp             int64  `json:"exp"`
	LastTouched     int64  `json:"last_touched"`

	// LastWebAuthnAt — unix-seconds timestamp of the most recent WebAuthn
	// (hwk / fido / passkey) assertion that produced this session. Sourced
	// from the upstream id_token `auth_time` claim when AMR contains a
	// hardware-factor marker; otherwise zero.
	//
	// The ZTNA baseline Rego policy (docs/policy/ztna/ztna_baseline.rego
	// §"WebAuthn recency") gates critical-route AAL3 step-up on
	// `amr_recency_seconds <= 3600` and high/medium AAL3 on
	// `<= 43200`. Router projects `time.Since(LastWebAuthnAt).Seconds()`
	// into RegoInput.User.AMRRecencySeconds when this field is non-zero;
	// when zero, RegoInputUser.AMRRecencySeconds stays at the default 0
	// which the Rego module treats as "fresh" — that's fine because the
	// AAL3 rules require `"hwk" in amr` separately, so a session with no
	// hardware factor never reaches the recency check.
	//
	// Per Phase K self-audit H-1 (2026-06-14): omitting this field was
	// causing the Rego module's `else := 86400` fallback to fire on EVERY
	// session, making `webauthn_fresh_1h` always false — every
	// critical-sensitivity AAL3 access denied with "WebAuthn re-auth
	// required" even for an operator who'd just touched their YubiKey.
	LastWebAuthnAt  int64  `json:"last_webauthn_at,omitempty"`
	// PasskeyStepUpAt — unix seconds when the callback completed a handshake
	// started as a passkey step-up (/auth/start?mfa=passkey); 0 otherwise.
	// Loop guard for the router's pre-Rego passkey step-up.
	PasskeyStepUpAt int64 `json:"passkey_step_up_at,omitempty"`
	SrcIP           string `json:"src_ip,omitempty"`
	UAHash          string `json:"ua_hash,omitempty"`
	CSRFToken       string `json:"csrf_token"`
	IDTokenJTI      string `json:"id_token_jti,omitempty"`
	RefreshTokenEnc string `json:"refresh_token_enc,omitempty"`

	// SSOChainID — per-session correlation handle that spans Talon ↔
	// Falcon-ID ↔ upstream-app logs (boot prompt §4 Gap 4). Generated
	// at /auth/start, persisted into the handshake state, materialised
	// here on session create. omitempty keeps the on-disk shape backward
	// compatible — old blobs decode with empty string and the audit
	// pipeline simply omits the field.
	SSOChainID string `json:"sso_chain_id,omitempty"`

	// DeviceClaims is the normalized id_token device claims captured at
	// /auth/callback (key = claim name, value = stringified). Consumed
	// by the router's per-host evaluator to enforce
	// TalonRoute.spec.requireDeviceClaims. Empty (nil) on sessions
	// minted before the IdP started emitting these claims — the
	// per-host evaluator FAILS CLOSED in that case for any route that
	// requires a device claim. omitempty keeps the on-disk shape
	// backward compatible.
	DeviceClaims map[string]string `json:"device_claims,omitempty"`

	// SID — the upstream OP's session identifier (the `sid` claim from
	// the id_token, or empty when the OP doesn't emit it). Captured at
	// /auth/callback into the blob and mirrored into a per-sid Redis
	// index so OIDC Front-Channel Logout 1.0 iframes can scope the
	// cascade to a single browser session instead of fanning out across
	// the subject. Empty on sessions minted before the upstream OP
	// started emitting `sid` — FCL falls back to a no-op cascade in
	// that case (the next request from the user re-validates and the
	// cookie ages out naturally). omitempty keeps the on-disk shape
	// backward compatible.
	SID string `json:"sid,omitempty"`
}

// Identity returns the shared hexx-pep-core view of the session subject
// (ADR 0031). Pulls Sub/Email/Roles/Groups/AMR straight from the encrypted
// Blob; Region is left empty because Falcon-ID doesn't issue a region
// claim today — future region-aware policy can populate via a separate
// claim or a per-tenant lookup. The richer session-specific fields
// (CSRFToken, IDTokenJTI, RefreshTokenEnc, etc.) stay inside Blob and
// never leak through the shared identity surface.
//
// Use this when calling into hexx-pep-core-aware code paths (a future
// shared policy library, cross-PEP audit correlation). For Talon-internal
// uses keep reading Blob fields directly — the projection adds no overhead
// but no benefit either.
func (b *Blob) Identity() identity.Identity {
	return identity.Identity{
		Subject: b.Sub,
		Email:   b.Email,
		Roles:   b.Roles,
		Groups:  b.Groups,
		AMR:     b.AMR,
	}
}

// SubjectInvalidator is called by Revoke (and the operator-driven kick-all
// path that funnels through it) to fan out per-subject decision-cache
// invalidation. Optional — nil keeps the legacy TTL-only invalidation
// posture. Wired by cmd/talon to the SpiceDB CachedClient so a kicked
// user cannot pass policy on a stale cached allow within the cache TTL.
type SubjectInvalidator interface {
	InvalidateBySubject(subject, reason string) int
}

// Store wraps the Redis client + AES-GCM cipher.
type Store struct {
	client       *redis.Client
	currentAEAD  cipher.AEAD
	previousAEAD cipher.AEAD // optional, for rotation window
	currentKeyV  byte
	previousKeyV byte
	hardTTL      time.Duration
	refreshMin   time.Duration
	cacheInv     SubjectInvalidator // optional; set via SetSubjectInvalidator
	breaker      *resilient.Breaker // optional; DDIL P3.11 load-shed on Redis
}

// SetRedisBreaker wires the DDIL P3.11 circuit breaker guarding the
// per-request Redis reads (Read / GetLastSeen / GetLastCV). When Redis
// is sustained-unreachable the breaker opens and those reads fast-fail
// (surfaced as an unavailability error → the router's fail-closed 503)
// instead of every request piling onto a dead dependency's dial/read
// timeout. Nil (default) = no breaker. Only the read-hot path is guarded:
// login/refresh/revoke writes are low-frequency and are not the
// thundering-herd concern the breaker exists to shed.
func (s *Store) SetRedisBreaker(b *resilient.Breaker) { s.breaker = b }

// redisDo runs a Redis operation under the optional breaker. fn MUST
// return nil for expected non-error outcomes (e.g. redis.Nil / cache
// miss) so a miss never trips the breaker — only real transport failures
// count. A shed (ErrBreakerOpen) is surfaced as an unavailability error,
// which the router classifies as ReasonInternal → fail-closed 503.
func (s *Store) redisDo(ctx context.Context, fn func(context.Context) error) error {
	if s.breaker == nil {
		return fn(ctx)
	}
	err := s.breaker.Do(ctx, fn)
	if errors.Is(err, resilient.ErrBreakerOpen) {
		return fmt.Errorf("session store: redis unavailable (breaker open): %w", err)
	}
	return err
}

// SetSubjectInvalidator wires the per-subject decision-cache invalidator
// (typically *spicedb.CachedClient). Called once at startup; nil disables.
func (s *Store) SetSubjectInvalidator(inv SubjectInvalidator) {
	s.cacheInv = inv
}

// NewStore returns a Store initialised with the given Redis client and
// 32-byte AES-256-GCM key. previousKey is optional (nil when no rotation
// in progress); when non-nil, reads will fall through to it on auth-tag
// failure with the current key.
func NewStore(client *redis.Client, currentKey, previousKey []byte, hardTTL, refreshMin time.Duration) (*Store, error) {
	if len(currentKey) != 32 {
		return nil, fmt.Errorf("currentKey must be 32 bytes, got %d", len(currentKey))
	}
	cur, err := newAEAD(currentKey)
	if err != nil {
		return nil, fmt.Errorf("currentKey: %w", err)
	}
	s := &Store{
		client:      client,
		currentAEAD: cur,
		currentKeyV: CurrentKeyVersion,
		hardTTL:     hardTTL,
		refreshMin:  refreshMin,
	}
	if previousKey != nil {
		if len(previousKey) != 32 {
			return nil, fmt.Errorf("previousKey must be 32 bytes, got %d", len(previousKey))
		}
		prev, err := newAEAD(previousKey)
		if err != nil {
			return nil, fmt.Errorf("previousKey: %w", err)
		}
		s.previousAEAD = prev
		s.previousKeyV = CurrentKeyVersion - 1
	}
	return s, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// Create generates a new session UUID, encrypts the blob, and writes both
// the session record and the per-sub revocation index. Returns the cookie
// value (UUID) on success.
func (s *Store) Create(ctx context.Context, b *Blob) (string, error) {
	if b.V == 0 {
		b.V = SchemaVersion
	}
	if b.IAT == 0 {
		b.IAT = time.Now().Unix()
	}
	if b.Exp == 0 {
		b.Exp = b.IAT + int64(s.hardTTL.Seconds())
	}
	if b.LastTouched == 0 {
		b.LastTouched = b.IAT
	}
	if b.CSRFToken == "" {
		b.CSRFToken = randHex(16)
	}

	cookieID := uuid.New().String()

	cipherText, err := s.encrypt(b, []byte(cookieID))
	if err != nil {
		return "", err
	}

	pipe := s.client.TxPipeline()
	pipe.Set(ctx, "talon:session:"+cookieID, cipherText, s.hardTTL)
	if b.Sub != "" {
		pipe.ZAdd(ctx, "talon:revoke-by-sub:"+b.Sub, redis.Z{Score: float64(b.Exp), Member: cookieID})
		pipe.Expire(ctx, "talon:revoke-by-sub:"+b.Sub, 30*24*time.Hour)
	}
	// Per-OP-session index — populated only when the upstream OP emits
	// `sid` on the id_token. Consumed by the FCL iframe handler at
	// GET /auth/frontchannel-logout to revoke just the Talon session(s)
	// that share this OP session, matching the OIDC Session Management
	// 1.0 / Front-Channel Logout 1.0 sid semantics.
	if b.SID != "" {
		pipe.ZAdd(ctx, "talon:revoke-by-sid:"+b.SID, redis.Z{Score: float64(b.Exp), Member: cookieID})
		pipe.Expire(ctx, "talon:revoke-by-sid:"+b.SID, 30*24*time.Hour)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("redis create: %w", err)
	}
	return cookieID, nil
}

// Read returns the session for cookieID. Returns ErrNotFound on missing/
// revoked/expired session and ErrAuthFailed if the envelope fails AEAD
// authentication (per ADR 0002 §5.2 step 4 → audit + force handshake).
//
// Both the revocation-tombstone EXISTS and the session GET are sent in
// a single Redis pipeline so the read path costs one RTT instead of two.
// Tombstone-first ordering is preserved at the application layer: even
// if a Revoke races between request-send and Redis serialising our
// commands, the tombstone EXISTS=1 result wins and we ignore the GET.
func (s *Store) Read(ctx context.Context, cookieID string) (*Blob, error) {
	if cookieID == "" {
		return nil, ErrNotFound
	}

	pipe := s.client.Pipeline()
	existsCmd := pipe.Exists(ctx, "talon:revoked:"+cookieID)
	getCmd := pipe.Get(ctx, "talon:session:"+cookieID)
	// Pipeline.Exec returns the first non-nil error; redis.Nil from GET
	// is expected on a session miss and is checked per-command below. Run
	// under the P3.11 breaker: a miss (redis.Nil) is NOT a breaker failure,
	// only a real transport error is.
	if err := s.redisDo(ctx, func(ctx context.Context) error {
		if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return err
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("redis pipeline: %w", err)
	}

	if exists, _ := existsCmd.Result(); exists == 1 {
		return nil, ErrRevoked
	}

	raw, err := getCmd.Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}

	b, err := s.decrypt(raw, []byte(cookieID))
	if err != nil {
		return nil, err
	}
	if b.Exp != 0 && time.Now().Unix() >= b.Exp {
		return nil, ErrExpired
	}
	return b, nil
}

// SlidingRefresh updates LastTouched + re-writes the encrypted blob with
// a fresh nonce, then EXTENDs the Redis TTL to (Exp - now). No-op if last
// touch was within RefreshMin.
//
// Per ADR 0002 §5.3, idempotent in steady state — concurrent refresh races
// are tolerated because the only mutating field is monotonic-ish.
func (s *Store) SlidingRefresh(ctx context.Context, cookieID string, b *Blob) error {
	now := time.Now().Unix()
	if now-b.LastTouched < int64(s.refreshMin.Seconds()) {
		return nil
	}
	b.LastTouched = now
	cipherText, err := s.encrypt(b, []byte(cookieID))
	if err != nil {
		return err
	}
	remaining := time.Until(time.Unix(b.Exp, 0))
	if remaining <= 0 {
		return ErrExpired
	}
	return s.client.Set(ctx, "talon:session:"+cookieID, cipherText, remaining).Err()
}

// Update re-encrypts and stores the blob under cookieID. Used by Phase 4.1
// continuous verification to persist a rotated refresh_token without
// touching b.LastTouched (callers that want the sliding-refresh side-effect
// should use SlidingRefresh instead).
func (s *Store) Update(ctx context.Context, cookieID string, b *Blob) error {
	cipherText, err := s.encrypt(b, []byte(cookieID))
	if err != nil {
		return err
	}
	remaining := time.Until(time.Unix(b.Exp, 0))
	if remaining <= 0 {
		return ErrExpired
	}
	return s.client.Set(ctx, "talon:session:"+cookieID, cipherText, remaining).Err()
}

// Revoke writes the per-cookie tombstone and deletes the session record.
// Tombstone outlives the session record so a delayed write cannot resurrect
// the session.
func (s *Store) Revoke(ctx context.Context, cookieID string, b *Blob) error {
	now := time.Now().Unix()
	tombTTL := time.Until(time.Unix(b.Exp, 0))
	if tombTTL <= 0 {
		tombTTL = time.Minute
	}
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, "talon:revoked:"+cookieID, "1", tombTTL)
	pipe.Del(ctx, "talon:session:"+cookieID)
	if b.Sub != "" {
		pipe.ZRem(ctx, "talon:revoke-by-sub:"+b.Sub, cookieID)
	}
	if b.SID != "" {
		// Mirror of the Create-side ZAdd — keep the per-OP-session index
		// honest so a future FCL iframe doesn't try to revoke a session
		// that's already gone.
		pipe.ZRem(ctx, "talon:revoke-by-sid:"+b.SID, cookieID)
	}
	_, err := pipe.Exec(ctx)
	_ = now
	// Fan out decision-cache invalidation. Best-effort — never fail
	// the revoke because the cache evict raced. The cache will TTL out
	// in <= 30 s anyway; this just collapses that window to ~0.
	if err == nil && b.Sub != "" && s.cacheInv != nil {
		s.cacheInv.InvalidateBySubject(b.Sub, "session_revoke")
	}
	return err
}

// RevokeBySubject revokes every active session belonging to the given
// (iss, sub) pair. Returns the count of sessions revoked.
//
// Used by the CAEP receiver (internal/caep) when an upstream
// transmitter (Falcon-ID) emits a session-revoked, credential-change,
// account-disabled, or account-purged Security Event Token. The pattern
// mirrors the operator-driven admin kick-all path: walk the per-sub
// ZSet, tombstone+delete each cookie, then fan out subject-level
// decision-cache invalidation once.
//
// The iss parameter is currently advisory — Talon's session store
// indexes by sub only (the (iss, sub) tuple is unique across HexxLock
// because Falcon-ID is the sole upstream OP). It is accepted in the
// signature so future multi-OP deployments don't need a wire-shape
// change.
//
// Idempotent: a sub with zero active sessions returns (0, nil). The
// per-sub ZSet has a 30-day TTL (from Create); cleanup happens
// naturally via that TTL even if a Revoke races.
func (s *Store) RevokeBySubject(ctx context.Context, iss, sub, reason string) (int, error) {
	if sub == "" {
		return 0, nil
	}
	_ = iss // currently advisory; future multi-OP hook
	subIndex := "talon:revoke-by-sub:" + sub
	cookieIDs, err := s.client.ZRange(ctx, subIndex, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("redis zrange revoke-by-sub: %w", err)
	}
	if len(cookieIDs) == 0 {
		return 0, nil
	}
	pipe := s.client.TxPipeline()
	// Use the hardTTL window as the tombstone duration so a revoked
	// cookie cannot be resurrected by a delayed Create even if the
	// caller has the cookie value in flight.
	for _, cid := range cookieIDs {
		pipe.Set(ctx, "talon:revoked:"+cid, "1", s.hardTTL)
		pipe.Del(ctx, "talon:session:"+cid)
	}
	// Drop the per-sub index entirely — we revoked every member.
	pipe.Del(ctx, subIndex)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis revoke-by-sub pipeline: %w", err)
	}
	if s.cacheInv != nil {
		s.cacheInv.InvalidateBySubject(sub, reason)
	}
	return len(cookieIDs), nil
}

// TouchLastSeen stamps the per-cookie "user did something" marker at
// time.Now(). Stored under talon:last-seen:<cookieID> with hardTTL so it
// ages out alongside the session itself. Used by the per-route idle-
// timeout check (TalonRoute.spec.sessionIdleSeconds): the router calls
// GetLastSeen on every protected request, denies (or audits) on idle
// breach, then TouchLastSeen on the allow path.
//
// Kept off the encrypted session blob deliberately — touching it on
// every request would re-encrypt + re-write the whole blob (~250–500
// bytes ciphertext) per hit; a separate Redis SET is one round-trip
// of an 8-byte int. Matches the MarkCV pattern.
func (s *Store) TouchLastSeen(ctx context.Context, cookieID string) error {
	if cookieID == "" {
		return nil
	}
	return s.client.Set(ctx, "talon:last-seen:"+cookieID, time.Now().Unix(), s.hardTTL).Err()
}

// GetLastSeen returns the last TouchLastSeen timestamp for cookieID.
// Returns the zero time when no marker exists (Redis miss) — first hit
// after session create, or marker aged out (which only happens after the
// session itself has aged out, so the caller will already deny on
// session.ErrNotFound). Callers compare against the route's
// SessionIdleSeconds; a zero return value means "no observed activity
// yet" which the router treats as "use blob.IAT as the floor" so a
// brand-new session isn't immediately judged idle.
func (s *Store) GetLastSeen(ctx context.Context, cookieID string) (time.Time, error) {
	if cookieID == "" {
		return time.Time{}, nil
	}
	var v int64
	err := s.redisDo(ctx, func(ctx context.Context) error {
		got, gerr := s.client.Get(ctx, "talon:last-seen:"+cookieID).Int64()
		if errors.Is(gerr, redis.Nil) {
			return nil // miss is not a breaker failure
		}
		if gerr != nil {
			return gerr
		}
		v = got
		return nil
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("redis get last-seen: %w", err)
	}
	if v == 0 {
		return time.Time{}, nil
	}
	return time.Unix(v, 0), nil
}

// MarkCV records that a continuous-verification check ran successfully
// for cookieID at time.Now(). Stored under talon:cv-last:<cookieID>
// with hardTTL so the marker ages out alongside the session itself.
// Used by the inline CV path (router checks GetLastCV before policy
// evaluation when a route has a tighter continuous-verify cadence
// than the global runner).
func (s *Store) MarkCV(ctx context.Context, cookieID string) error {
	if cookieID == "" {
		return nil
	}
	return s.client.Set(ctx, "talon:cv-last:"+cookieID, time.Now().Unix(), s.hardTTL).Err()
}

// GetLastCV returns the time of the most recent successful CV check
// for cookieID. Returns the zero time if no marker exists (Redis
// miss), which the router treats as "infinitely stale" — forces an
// inline CV on the next request to a route with an override.
func (s *Store) GetLastCV(ctx context.Context, cookieID string) (time.Time, error) {
	if cookieID == "" {
		return time.Time{}, nil
	}
	var v int64
	err := s.redisDo(ctx, func(ctx context.Context) error {
		got, gerr := s.client.Get(ctx, "talon:cv-last:"+cookieID).Int64()
		if errors.Is(gerr, redis.Nil) {
			return nil // miss is not a breaker failure
		}
		if gerr != nil {
			return gerr
		}
		v = got
		return nil
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("redis get cv-last: %w", err)
	}
	if v == 0 {
		return time.Time{}, nil
	}
	return time.Unix(v, 0), nil
}

// SaveHandshake stores the OIDC handshake state (PKCE verifier, return URL,
// source IP) keyed by the random `state` parameter, with a 5-minute TTL.
func (s *Store) SaveHandshake(ctx context.Context, state string, hs *HandshakeState) error {
	body, err := json.Marshal(hs)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, "talon:handshake:"+state, body, 5*time.Minute).Err()
}

// PopHandshake atomically reads + deletes the handshake state. Returns
// ErrNotFound if state is unknown (replay or expired).
func (s *Store) PopHandshake(ctx context.Context, state string) (*HandshakeState, error) {
	if state == "" {
		return nil, ErrNotFound
	}
	res, err := s.client.GetDel(ctx, "talon:handshake:"+state).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	hs := &HandshakeState{}
	if err := json.Unmarshal(res, hs); err != nil {
		return nil, err
	}
	return hs, nil
}

// HandshakeState is the per-OIDC-flow context cached during the round trip.
type HandshakeState struct {
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
	ReturnTo     string `json:"return_to"`
	SrcIP        string `json:"src_ip,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	// SSOChainID generated at /auth/start so the same handle spans
	// the entire OIDC handshake → callback → session-create flow.
	// Materialised into Blob.SSOChainID on successful callback.
	SSOChainID string `json:"sso_chain_id,omitempty"`
	// StepUp records the `mfa` mode /auth/start was called with ("1",
	// "passkey" or empty) so the callback knows which kind of step-up this
	// handshake was.
	StepUp string `json:"step_up,omitempty"`
}

// encrypt serialises blob, builds the envelope with a fresh nonce, and
// returns the wire bytes.
func (s *Store) encrypt(b *Blob, aad []byte) ([]byte, error) {
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal blob: %w", err)
	}
	nonce := make([]byte, s.currentAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plain)+s.currentAEAD.Overhead())
	out = append(out, s.currentKeyV)
	out = append(out, nonce...)
	out = s.currentAEAD.Seal(out, nonce, plain, aad)
	return out, nil
}

// decrypt parses the envelope and decrypts. Tries currentAEAD first; on
// auth-tag failure (non-nil err from AEAD.Open), falls back to previousAEAD
// if the version byte indicates the previous key.
func (s *Store) decrypt(raw, aad []byte) (*Blob, error) {
	if len(raw) < 1+12+16 {
		return nil, ErrAuthFailed
	}
	keyV := raw[0]
	nonce := raw[1:13]
	ct := raw[13:]

	var aead cipher.AEAD
	switch {
	case keyV == s.currentKeyV:
		aead = s.currentAEAD
	case s.previousAEAD != nil && keyV == s.previousKeyV:
		aead = s.previousAEAD
	default:
		return nil, ErrAuthFailed
	}

	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	b := &Blob{}
	if err := json.Unmarshal(plain, b); err != nil {
		return nil, fmt.Errorf("unmarshal blob: %w", err)
	}
	if b.V != SchemaVersion {
		return nil, fmt.Errorf("unsupported session schema version v=%d (expected %d)", b.V, SchemaVersion)
	}
	return b, nil
}

// Sentinel errors. Callers branch on errors.Is.
var (
	ErrNotFound   = errors.New("session: not found")
	ErrRevoked    = errors.New("session: revoked")
	ErrExpired    = errors.New("session: expired")
	ErrAuthFailed = errors.New("session: AEAD authentication failed")
)

// valueEncPrefix marks a string produced by EncryptValue. Real OIDC
// refresh_tokens are base64url (RFC 6749 Appendix A.17) and contain no
// ":" character, so the prefix is unambiguously distinguishable from a
// legacy plaintext refresh_token. DecryptValue uses this fact to fall
// through to plaintext for pre-IAP-04 session blobs so the deploy of
// field-level encryption does not invalidate every active session —
// natural rollover within hardTTL (8h) re-writes every blob through the
// new envelope on the next sliding refresh.
const valueEncPrefix = "enc:v1:"

// EncryptValue wraps a sensitive string (refresh_token, etc.) under the
// store's current AEAD with a fresh random nonce. The envelope format
// mirrors §4.2 but with no AAD (callers can't always supply the cookie
// UUID at the call site — Create() generates the UUID *after* the Blob
// is built):
//
//	"enc:v1:" + base64url-no-padding(KEY-VER(1) || NONCE(12) || CIPHERTEXT-WITH-AUTH-TAG)
//
// Per ADR 0002 §4.1, this field-level encryption is independent of the
// outer Blob AEAD. Defense-in-depth: an in-process compromise that reads
// the decrypted Blob in memory (or a debug log accidentally containing a
// JSON-marshalled Blob) cannot directly use the refresh_token without
// also having the cookie-encrypt-key.
func (s *Store) EncryptValue(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.currentAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("rand nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+s.currentAEAD.Overhead())
	out = append(out, s.currentKeyV)
	out = append(out, nonce...)
	out = s.currentAEAD.Seal(out, nonce, []byte(plaintext), nil)
	return valueEncPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// DecryptValue is the inverse of EncryptValue. Returns the input
// unchanged when it lacks the "enc:v1:" prefix (legacy plaintext from a
// pre-IAP-04 session blob — see valueEncPrefix doc for why this is safe).
// Returns ErrAuthFailed on auth-tag mismatch against both currentAEAD
// and previousAEAD (rotation window per ADR 0002 §6).
func (s *Store) DecryptValue(envelope string) (string, error) {
	if envelope == "" {
		return "", nil
	}
	if !strings.HasPrefix(envelope, valueEncPrefix) {
		// Legacy plaintext from a pre-IAP-04 session — pass through. The
		// CV runner / refresh path will re-encrypt on the next rotation,
		// or the blob ages out within hardTTL.
		return envelope, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(envelope[len(valueEncPrefix):])
	if err != nil {
		return "", fmt.Errorf("decode envelope: %w", err)
	}
	if len(raw) < 1+12+16 {
		return "", ErrAuthFailed
	}
	keyV := raw[0]
	nonce := raw[1:13]
	ct := raw[13:]
	var aead cipher.AEAD
	switch {
	case keyV == s.currentKeyV:
		aead = s.currentAEAD
	case s.previousAEAD != nil && keyV == s.previousKeyV:
		aead = s.previousAEAD
	default:
		return "", ErrAuthFailed
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrAuthFailed
	}
	return string(plain), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0x0f]
	}
	return strings.ToLower(string(out))
}
