// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cv implements continuous verification per ADR 0001 §6 +
// ADR 0002 §5.6. A leader-elected goroutine periodically polls each
// active session's identity against Falcon-ID's /oauth/userinfo, and
// invalidates the session if any of:
//
//   - refresh_token grant is refused (token revoked / client revoked)
//   - userinfo returns 401/403 (token revoked / user disabled)
//   - access_token JWT's `roles` claim no longer contains the required role
//   - userinfo returns the user with `disabled: true` claim
//
// Single-leader execution: registered as a controller-runtime Runnable
// with NeedLeaderElection=true so only one Talon pod polls at a time
// (avoids N× IdP load + duplicated invalidations).
//
// Default cadence: 5 min (boot prompt §4 Gap 2 — matches Cloudflare
// Access posture-check cadence). Tunable via TALON_CONTINUOUS_VERIFY_MINUTES;
// per-route 1-min override (vault.ops, argocd.ops) is wired through
// TalonRoute.spec.continuousVerifyMinutes by an inline-CV path. ADR 0001
// §6's earlier 15-min figure is superseded by ADR 0004.
//
// Phase 4.1 — proper OAuth refresh-token flow.
// Phase 4.2 — role-loss check reads from access_token JWT (which
// carries `roles` per internal engineering notes)
// instead of /oauth/userinfo (which doesn't, per OIDC core §5.3).
//
// Per RFC 6749 §6 the only legal way to "validate" a refresh_token is
// to attempt the refresh grant; /oauth/userinfo accepts ONLY access
// tokens (RFC 7662 / RFC 7515 alike). Phase 4 base shipped a no-op
// runner because sending refresh_token as Bearer to /oauth/userinfo
// 401s every call and would have invalidated every session on the
// first tick.
//
// The dance is:
//
//  1. Read the encrypted Blob from Redis.
//  2. POST {grant_type=refresh_token, refresh_token, client_id,
//     client_secret} to the token endpoint. On 4xx → invalidate
//     ("refresh_grant_refused"). On 5xx/timeout → leave alone (transient).
//  3. GET /oauth/userinfo with the new access_token as Bearer.
//     On 401/403 → invalidate ("userinfo_unauthorized").
//     On 5xx/timeout → leave alone.
//  4. Decode the userinfo claims. Invalidate if:
//     - sub does not match Blob.Sub (token mis-binding — paranoid check)
//     - `disabled: true` claim is present
//     - `roles` claim does not contain the required role
//  5. If the token endpoint returned a NEW refresh_token (Falcon-ID
//     rotates per OAuth 2.0 BCP §4.14), persist the rotated blob via
//     Store.Update so the next tick uses the fresh token.
package cv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dogukanturhal/talon/internal/audit"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
	"github.com/redis/go-redis/v9"
)

// Runner polls active sessions on Interval. Implements
// sigs.k8s.io/controller-runtime/pkg/manager.LeaderElectionRunnable
// so the controller-runtime manager only starts it on the leader pod.
type Runner struct {
	Store        *session.Store
	Redis        *redis.Client
	TokenURL     string // e.g. http://falcon-id-falcon-id.falcon-id.svc.cluster.local/oauth/token
	UserInfoURL  string // e.g. http://falcon-id-falcon-id.falcon-id.svc.cluster.local/oauth/userinfo
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Interval     time.Duration
	RequiredRole string
	Audit        *audit.Emitter
}

// NeedLeaderElection — controller-runtime contract. Returns true so
// only the leader pod runs CV.
func (r *Runner) NeedLeaderElection() bool { return true }

// Start blocks until ctx is cancelled, ticking every r.Interval.
func (r *Runner) Start(ctx context.Context) error {
	if r.Interval <= 0 {
		r.Interval = 5 * time.Minute
	}
	if r.HTTPClient == nil {
		r.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	logger := tlog.From(ctx).With("subsystem", "cv")
	logger.Info("continuous verification starting",
		"interval", r.Interval,
		"token_url", r.TokenURL,
		"userinfo_url", r.UserInfoURL,
		"required_role", r.RequiredRole)

	// Run a tick immediately on start (don't wait the full Interval).
	r.tick(ctx)

	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("continuous verification stopping", "err", ctx.Err())
			return nil
		case <-t.C:
			r.tick(ctx)
		}
	}
}

// tick scans all active sessions in Redis and verifies each. Errors
// per session are logged but don't fail the whole tick.
func (r *Runner) tick(ctx context.Context) {
	logger := tlog.From(ctx).With("subsystem", "cv")
	tickCtx, cancel := context.WithTimeout(ctx, r.Interval-time.Second)
	defer cancel()

	checked := 0
	invalidated := 0
	var cursor uint64
	for {
		var keys []string
		var err error
		keys, cursor, err = r.Redis.Scan(tickCtx, cursor, "talon:session:*", 200).Result()
		if err != nil {
			logger.Warn("redis SCAN failed; deferring tick", "err", err)
			return
		}
		for _, k := range keys {
			cookieID := k[len("talon:session:"):]
			ok := r.verifyOne(tickCtx, cookieID)
			checked++
			if !ok {
				invalidated++
			}
		}
		if cursor == 0 {
			break
		}
	}
	logger.Info("continuous verification tick", "checked", checked, "invalidated", invalidated)
}

// errTransient signals "leave alone, retry next tick" — callers must
// not invalidate the session on this error.
var errTransient = errors.New("transient")

// verifyOne returns true if the session is still valid (or appears to be
// — transient errors keep the session). Returns false if invalidated.
func (r *Runner) verifyOne(ctx context.Context, cookieID string) bool {
	if cookieID == "" {
		return true
	}
	logger := tlog.From(ctx).With("subsystem", "cv", "cookie_id_prefix", safePrefix(cookieID))

	blob, err := r.Store.Read(ctx, cookieID)
	if err != nil {
		// Already-revoked / expired / decrypt failure — nothing to do.
		// Don't double-invalidate.
		return true
	}
	if blob.RefreshTokenEnc == "" {
		// Pre-Phase-4.1 sessions written without a refresh token cannot
		// be CV'd; they age out by SessionHardTTL. Leave alone.
		return true
	}

	// IAP-04: refresh_token is field-level AES-GCM wrapped under the
	// cookie-encrypt-key per ADR 0002 §4.1. DecryptValue returns the input
	// unchanged for legacy plaintext blobs (pre-IAP-04 sessions still in
	// Redis at deploy time), so this path keeps working through the natural
	// rollover window.
	refreshTokenPlain, err := r.Store.DecryptValue(blob.RefreshTokenEnc)
	if err != nil {
		logger.Info("cv: refresh_token decrypt failed, invalidating", "err", err)
		r.invalidate(ctx, cookieID, blob, "refresh_token_decrypt_failed")
		return false
	}

	// Step 1: refresh the access token.
	newAccessToken, newRefreshToken, err := r.refreshAccessToken(ctx, refreshTokenPlain)
	if err != nil {
		if errors.Is(err, errTransient) {
			logger.Debug("cv: transient refresh error, leaving session alone", "err", err)
			return true
		}
		logger.Info("cv: refresh_grant_refused, invalidating", "err", err)
		r.invalidate(ctx, cookieID, blob, "refresh_grant_refused")
		return false
	}

	// Step 2 + 3: hit /oauth/userinfo with the new access token.
	claims, err := r.fetchUserInfo(ctx, newAccessToken)
	if err != nil {
		if errors.Is(err, errTransient) {
			logger.Debug("cv: transient userinfo error, leaving session alone", "err", err)
			return true
		}
		logger.Info("cv: userinfo_unauthorized, invalidating", "err", err)
		r.invalidate(ctx, cookieID, blob, "userinfo_unauthorized")
		return false
	}

	// Step 4: claim assertions.
	if claims.Sub != "" && blob.Sub != "" && claims.Sub != blob.Sub {
		logger.Warn("cv: userinfo sub mismatch, invalidating",
			"blob_sub", blob.Sub, "userinfo_sub", claims.Sub)
		r.invalidate(ctx, cookieID, blob, "sub_mismatch")
		return false
	}
	if claims.Disabled {
		r.invalidate(ctx, cookieID, blob, "user_disabled")
		return false
	}

	// Phase 4.2 role-loss check: decode the new access_token JWT we just
	// received from /oauth/token. Falcon-ID embeds the user's roles in
	// the access token;
	// /oauth/userinfo does not — it only carries the OIDC core §5.3
	// scim subset. The Phase 4.1 build read from userinfo and gated on
	// `len(claims.Roles) > 0` so the check effectively never fired in
	// production; this catches the actual revocation.
	//
	// No signature verification: the token was just minted by Falcon-ID
	// over the Linkerd-mTLS-authenticated /oauth/token call. ADR 0001 §7.d
	// trusts the IdP boundary; replay would require compromising Falcon-ID,
	// which compromises the whole RP regardless. Signature-verifying here
	// would require fanning out a JWKS-based verifier wired to the same
	// issuer the OIDC RP uses — followup if the trust boundary moves.
	if r.RequiredRole != "" {
		atRoles, err := extractAccessTokenRoles(newAccessToken)
		if err != nil {
			// Decode failures shouldn't invalidate — token may be opaque
			// from a non-Falcon-ID IdP, or claim shape may have evolved.
			// Log + leave alone; userinfo's `disabled` + the refresh-grant
			// path still gate the obvious cases.
			logger.Debug("cv: access_token JWT decode failed, skipping role-loss check", "err", err)
		} else if len(atRoles) > 0 && !contains(atRoles, r.RequiredRole) {
			logger.Info("cv: required_role_lost (access_token jwt)",
				"required", r.RequiredRole, "have", atRoles)
			r.invalidate(ctx, cookieID, blob, "required_role_lost")
			return false
		}
	}

	// Step 5: if the token endpoint rotated the refresh_token, persist
	// the new value or the next tick will use the (now-revoked) old one.
	// Compare against the decrypted plaintext (refreshTokenPlain) — the
	// stored RefreshTokenEnc is field-level encrypted (IAP-04) and would
	// always look "different" if compared directly because EncryptValue
	// uses a fresh random nonce per call.
	if newRefreshToken != "" && newRefreshToken != refreshTokenPlain {
		encNew, encErr := r.Store.EncryptValue(newRefreshToken)
		if encErr != nil {
			logger.Warn("cv: refresh_token re-encrypt failed", "err", encErr)
			// Don't invalidate — the session is still valid, we just
			// can't persist the rotated token. The OLD refresh_token is
			// already revoked at the IdP per RFC 6749 §10.4, so the next
			// tick's refresh-grant call will be refused and we'll
			// invalidate cleanly via the refresh_grant_refused branch.
		} else {
			blob.RefreshTokenEnc = encNew
			if err := r.Store.Update(ctx, cookieID, blob); err != nil {
				logger.Warn("cv: store.Update after refresh-rotation failed", "err", err)
				// Same fall-through reasoning as the encrypt-error branch.
			}
		}
	}

	// Mark this cookie's CV-freshness so per-route inline checks (router
	// path, fired when a TalonRoute has continuousVerifyMinutes < global
	// interval) skip the next round-trip if it falls inside the route's
	// override window. Best-effort — a failed Set just means the next
	// request takes the slow path, no correctness impact.
	if err := r.Store.MarkCV(ctx, cookieID); err != nil {
		logger.Warn("cv: MarkCV failed (inline check will fire on next request)", "err", err)
	}

	return true
}

// VerifyOneInline runs the same per-session verification as the global
// tick but on demand from the router (for routes with a tighter
// continuousVerifyMinutes override than the global Interval). Returns
// true if the session is still valid; false if it was invalidated.
// Safe to call from non-leader pods — verifyOne has no leadership
// requirement; the leader-elected gate is only on the periodic tick
// to avoid N× IdP load.
func (r *Runner) VerifyOneInline(ctx context.Context, cookieID string) bool {
	return r.verifyOne(ctx, cookieID)
}

// invalidate revokes the session and emits an audit event.
func (r *Runner) invalidate(ctx context.Context, cookieID string, blob *session.Blob, reason string) {
	if err := r.Store.Revoke(ctx, cookieID, blob); err != nil {
		tlog.From(ctx).Warn("cv: revoke failed",
			"cookie_id_prefix", safePrefix(cookieID), "err", err)
		return
	}
	if r.Audit != nil {
		r.Audit.CVInvalidate(ctx, audit.Record{
			Sub:        blob.Sub,
			Email:      blob.Email,
			TenantID:   blob.TenantID,
			Reason:     reason,
			SessionID:  cookieID,
			Issuer:     blob.Iss,
			SSOChainID: blob.SSOChainID,
		})
	}
}

// tokenResponse is the RFC 6749 §5.1 successful response shape. We
// accept refresh_token as optional per §5.1 (some IdPs don't rotate).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// userInfoClaims captures the subset of /oauth/userinfo claims CV
// cares about. Falcon-ID emits `roles` (internal engineering notes
// delivered_2026_04_21) and a `disabled` boolean for inactive users.
type userInfoClaims struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	Disabled bool     `json:"disabled,omitempty"`
}

// refreshAccessToken POSTs grant_type=refresh_token to TokenURL and
// returns (newAccessToken, newRefreshToken, err). The returned refresh
// token may be empty if the IdP didn't rotate — caller decides whether
// to persist.
//
// Errors:
//
//   - errTransient wrapped: 5xx, network errors, decode failures, timeouts
//   - other errors: 4xx response (refresh refused) — caller should invalidate
func (r *Runner) refreshAccessToken(ctx context.Context, refreshToken string) (string, string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", r.ClientID)
	if r.ClientSecret != "" {
		form.Set("client_secret", r.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("%w: build request: %w", errTransient, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: token POST: %w", errTransient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// fall through
	case resp.StatusCode >= 500:
		return "", "", fmt.Errorf("%w: token endpoint %d: %s",
			errTransient, resp.StatusCode, snippet(body))
	default: // 4xx — auth refused, invalidate the session
		return "", "", fmt.Errorf("token endpoint %d: %s",
			resp.StatusCode, snippet(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", "", fmt.Errorf("%w: decode token response: %w", errTransient, err)
	}
	if tr.AccessToken == "" {
		return "", "", fmt.Errorf("%w: empty access_token in response", errTransient)
	}
	return tr.AccessToken, tr.RefreshToken, nil
}

// fetchUserInfo calls /oauth/userinfo with the access token as Bearer
// and returns the decoded claims. Same transient-vs-permanent error
// classification as refreshAccessToken.
func (r *Runner) fetchUserInfo(ctx context.Context, accessToken string) (*userInfoClaims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build userinfo request: %w", errTransient, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo GET: %w", errTransient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// fall through
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: userinfo %d: %s",
			errTransient, resp.StatusCode, snippet(body))
	default: // 401/403 → invalidate
		return nil, fmt.Errorf("userinfo %d: %s",
			resp.StatusCode, snippet(body))
	}

	var uc userInfoClaims
	if err := json.Unmarshal(body, &uc); err != nil {
		return nil, fmt.Errorf("%w: decode userinfo: %w", errTransient, err)
	}
	return &uc, nil
}

// extractAccessTokenRoles decodes the JWT payload of an access token
// and returns its `roles` claim as []string. Returns an empty slice
// (no error) if the token decodes but has no `roles` claim. Returns
// an error only on malformed input. Caller must already trust the
// token's source; this function does NOT verify the JWS signature
// (rationale: Phase 4.2 trust-boundary note in verifyOne).
func extractAccessTokenRoles(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("not a JWT (missing payload segment)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fall back to standard padding — some IdPs emit padded JWTs
		// even though RFC 7519 §3 mandates the unpadded form.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
	}
	var c struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return c.Roles, nil
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func safePrefix(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

func snippet(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}
