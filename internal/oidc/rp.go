// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oidc — rp.go is Talon's OAuth 2.0 + OIDC Relying Party. The
// flow ports the Falcon-ID-trusted authorization-code-with-PKCE pattern
// from frontend/packages/falcon-id-client/src/server/oidc-rp.ts. Phase 4
// adds continuous verification (re-fetch /oauth/userinfo per session
// every 15min); for Phase 1 the dance is one-shot per sign-in.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	xoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/dogukanturhal/talon/internal/config"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
	"golang.org/x/oauth2"
)

// RP carries the OIDC client + provider plus references to the cookie
// session store.
type RP struct {
	cfg                *config.Config
	provider           *xoidc.Provider
	verifier           *xoidc.IDTokenVerifier
	oauth              *oauth2.Config
	store              *session.Store
	endSessionEndpoint string // OIDC discovery `end_session_endpoint`; empty if IdP doesn't advertise one
	// parEndpoint carries the OIDC discovery
	// `pushed_authorization_request_endpoint` (RFC 9126 §5). When
	// non-empty, HandleStart POSTs the full authorization-request
	// parameters to this URL with client_secret_basic auth and then
	// redirects the browser to /authorize with only `request_uri` +
	// `client_id`. When the IdP doesn't advertise PAR, HandleStart
	// falls back to inline-params /authorize (legacy code path) so
	// older Falcon-ID builds keep working through the cut-over.
	parEndpoint string
	// parHTTP is the HTTP client used for the back-channel POST to
	// /oauth/par. Defaults to http.DefaultClient; tests inject a
	// roundtripper. Kept on the struct so we can give it a tight
	// timeout (PAR back-channels should be sub-second).
	parHTTP *http.Client
	// spicedb is optional; when set, the post-login hook in
	// HandleCallback TOUCHes group memberships per role so the
	// per-route CheckPermission can walk user → group → route.
	// Wired via SetSpiceDB from main.go AFTER the spicedb client is
	// constructed (RP is built first so OIDC discovery + JWKS are
	// available regardless of SpiceDB readiness).
	spicedb spicedbWriter
}

// spicedbWriter is the minimum surface RP needs from internal/spicedb
// (kept narrow to avoid a cycle and to keep RP independently testable).
type spicedbWriter interface {
	WriteUserGroupMemberships(ctx context.Context, sub string, roles []string) error
	DeleteUserGroupMemberships(ctx context.Context, sub string) error
}

// SetSpiceDB injects the SpiceDB writer used by HandleCallback to seed
// per-login group memberships. Idempotent; passing nil clears the hook
// (useful in tests).
func (r *RP) SetSpiceDB(s spicedbWriter) { r.spicedb = s }

// IDTokenVerifier returns the *xoidc.IDTokenVerifier the RP uses to validate
// id_tokens. The same verifier is reused for back-channel logout tokens
// because OIDC Back-Channel Logout 1.0 §2.4 requires `aud=client_id` and
// `iss=<OP issuer>` — identical to the id_token's audience + issuer
// constraints. JWKS is cached internally by go-oidc; callers MUST NOT
// mutate the returned verifier.
func (r *RP) IDTokenVerifier() *xoidc.IDTokenVerifier { return r.verifier }

// IssuerURL returns the configured iss value the verifier validates against.
// Exposed so handlers can include it in error messages without re-parsing
// config.
func (r *RP) IssuerURL() string { return r.cfg.IssuerURL }

// New builds an OIDC RP. Discovery against IssuerURL happens once here;
// the JWKS is fetched lazily on first verify and cached internally.
func New(ctx context.Context, cfg *config.Config, store *session.Store) (*RP, error) {
	// Talk to the in-cluster issuer URL for token + userinfo + JWKS to
	// avoid the public Traefik hop. Keep IssuerURL as the iss claim
	// validator; go-oidc's NewProvider validates discovery doc's issuer
	// matches the URL passed in, so we override below if InternalIssuerURL
	// is set.
	discoveryCtx := ctx
	if cfg.InternalIssuerURL != "" {
		// xoidc.InsecureIssuerURLContext skips the issuer match check
		// (we know the discovery doc's iss is IssuerURL, but we're
		// fetching from InternalIssuerURL).
		discoveryCtx = xoidc.InsecureIssuerURLContext(ctx, cfg.IssuerURL)
	}
	issuerForDiscovery := cfg.IssuerURL
	if cfg.InternalIssuerURL != "" {
		issuerForDiscovery = cfg.InternalIssuerURL
	}
	provider, err := xoidc.NewProvider(discoveryCtx, issuerForDiscovery)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	verifier := provider.Verifier(&xoidc.Config{ClientID: cfg.OIDCClientID})

	oa := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.CallbackURL(),
		Scopes:       cfg.OIDCScopes,
	}
	// Pull discovery fields that go-oidc's public Provider doesn't
	// surface directly: end_session_endpoint (RP-Initiated Logout 1.0)
	// and pushed_authorization_request_endpoint (RFC 9126 §5).
	var disco struct {
		EndSessionEndpoint                 string `json:"end_session_endpoint"`
		PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	}
	if err := provider.Claims(&disco); err != nil {
		// Non-fatal: logout falls back to Talon-only cookie clear;
		// PAR falls back to inline-params /authorize.
		tlog.From(ctx).Warn("oidc discovery: extended fields not parseable", "err", err)
	}
	return &RP{
		cfg:                cfg,
		provider:           provider,
		verifier:           verifier,
		oauth:              oa,
		store:              store,
		endSessionEndpoint: disco.EndSessionEndpoint,
		parEndpoint:        disco.PushedAuthorizationRequestEndpoint,
		parHTTP:            &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// stepUpParams are the authorize params for step-up MFA (?mfa=1). Never
// prompt=login: Falcon-ID treats it as "end the SSO session and clear
// cookies", logging the user out everywhere. acr_values=mfa + max_age=0
// make Falcon-ID run an in-place MFA challenge instead.
var stepUpParams = map[string]string{"acr_values": "mfa", "max_age": "0"}

// HandleStart responds to GET /auth/start by emitting a state cookie,
// caching the PKCE verifier in Redis, and redirecting (HTML-scaffolded) to
// Falcon-ID's /oauth/authorize. Query param `rd` is the original return
// URL the browser was navigating to before the auth interception.
func (r *RP) HandleStart(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())

	rd := req.URL.Query().Get("rd")
	if rd == "" {
		rd = r.cfg.ExternalURL.String()
	}
	if !r.isSafeReturnURL(rd) {
		http.Error(w, "invalid rd", http.StatusBadRequest)
		return
	}

	state := randURLSafe(24)
	verifier := randURLSafe(32) // PKCE per RFC 7636 §4.1: 43–128 chars
	nonce := randURLSafe(16)
	// SSO chain ID — generated once at /auth/start, materialised onto
	// the session blob in HandleCallback, replayed onto every audit
	// event for the session's lifetime. Boot prompt §4 Gap 4.
	ssoChainID := randURLSafe(16)
	hs := &session.HandshakeState{
		CodeVerifier: verifier,
		Nonce:        nonce,
		ReturnTo:     rd,
		SrcIP:        ClientIP(req),
		CreatedAt:    time.Now().Unix(),
		SSOChainID:   ssoChainID,
	}
	if err := r.store.SaveHandshake(req.Context(), state, hs); err != nil {
		logger.Error("save handshake", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challenge := pkceChallenge(verifier)

	// "Continue as <user>": OIDC login_hint from the last-user hint cookie, so
	// Falcon-ID can prefill the identifier and offer the passkey straight away
	// after the SSO session lapsed. Presentation-only; grants no access.
	hint := lastUserHint(req)

	// RFC 9126 PAR enforcement. When Falcon-ID advertises a pushed-
	// authorization-request endpoint at discovery time, we MUST use it —
	// silently falling back to inline-params /authorize on transient PAR
	// failure would let an attacker who can disrupt the back-channel
	// (DNS poisoning, mesh ServerAuthorizationPolicy flap, IdP rolling
	// restart) downgrade every login to the unprotected wire format
	// where state/nonce/code_challenge leak via referrer + browser
	// history + intermediate proxies. Hard-fail on PAR error; never
	// downgrade. RFC 9700 §2.1.1 + RFC 9126 §6 specifically warn against
	// silent fallback once PAR is in the trust contract.
	//
	// When parEndpoint is empty (IdP doesn't advertise PAR), we never
	// negotiated PAR in the first place — inline-params is the agreed
	// protocol, not a fallback. That's a different code path below.
	if r.parEndpoint != "" {
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {r.oauth.ClientID},
			"redirect_uri":          {r.oauth.RedirectURL},
			"scope":                 {strings.Join(r.oauth.Scopes, " ")},
			"state":                 {state},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"nonce":                 {nonce},
		}
		if req.URL.Query().Get("mfa") == "1" {
			params.Set("acr_values", "mfa")
			for k, v := range stepUpParams {
				params.Set(k, v)
			}
		}
		if hint != "" {
			params.Set("login_hint", hint)
		}
		requestURI, parErr := r.pushAuthorizationRequest(req.Context(), params)
		if parErr != nil {
			logger.Error("par push failed", "err", parErr)
			http.Error(w, "authentication unavailable", http.StatusBadGateway)
			return
		}
		authURL := fmt.Sprintf(
			"%s?client_id=%s&request_uri=%s",
			r.oauth.Endpoint.AuthURL,
			url.QueryEscape(r.oauth.ClientID),
			url.QueryEscape(requestURI),
		)
		WriteHTMLRedirect(w, authURL)
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	// Step-up MFA: caller signals via ?mfa=1 (set by router when the
	// route has mfaRequired and session lacks amr=mfa). Forces Falcon-ID
	// to re-prompt for MFA per ADR 0001 §6.
	if req.URL.Query().Get("mfa") == "1" {
		for k, v := range stepUpParams {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}
	if hint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", hint))
	}
	authURL := r.oauth.AuthCodeURL(state, opts...)
	WriteHTMLRedirect(w, authURL)
}

// LastUserCookieName is the non-secret "last signed-in user" hint cookie. It
// carries only the user's email/username (a login_hint for the next sign-in)
// and grants no access; Talon never reads it for any authn/authz decision.
const LastUserCookieName = "talon_last_user"

const (
	lastUserCookieTTL = 90 * 24 * time.Hour
	maxLastUserLen    = 254
)

// validLoginHint reports whether v is safe to forward as login_hint: non-empty,
// bounded, no control characters.
func validLoginHint(v string) bool {
	if v == "" || len(v) > maxLastUserLen {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// lastUserHint returns the login_hint from the last-user cookie, or "".
func lastUserHint(req *http.Request) string {
	c, err := req.Cookie(LastUserCookieName)
	if err != nil {
		return ""
	}
	v, err := url.QueryUnescape(c.Value)
	if err != nil || !validLoginHint(v) {
		return ""
	}
	return v
}

func (r *RP) setLastUserCookie(w http.ResponseWriter, hint string) {
	if !validLoginHint(hint) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  LastUserCookieName,
		Value: url.QueryEscape(hint),
		// Host-only (no Domain): only auth.ops reads it; keeps the email off every other *.example.com host.
		Path:     "/",
		MaxAge:   int(lastUserCookieTTL.Seconds()),
		Expires:  time.Now().Add(lastUserCookieTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (r *RP) clearLastUserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:  LastUserCookieName,
		Value: "",
		// Host-only (no Domain): only auth.ops reads it; keeps the email off every other *.example.com host.
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// pushAuthorizationRequest issues an RFC 9126 §2 POST to the IdP's PAR
// endpoint with client_secret_basic auth. On success returns the
// `request_uri` (typically the `urn:ietf:params:oauth:request_uri:<id>`
// URN form) the caller redirects to /authorize with.
//
// Failure modes returned (caller falls back to inline-params /authorize):
//   - Network / timeout (parHTTP.Timeout = 5s)
//   - Non-201 status from the IdP
//   - Response body missing request_uri or malformed JSON
func (r *RP) pushAuthorizationRequest(ctx context.Context, params url.Values) (string, error) {
	body := strings.NewReader(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.parEndpoint, body)
	if err != nil {
		return "", fmt.Errorf("par request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1 client_secret_basic. RFC 9126 §2 explicitly
	// permits the same client-auth methods as /token, so Basic over
	// TLS is the canonical choice for confidential clients (which
	// Talon is — its OIDCClientSecret is provisioned via
	// ServiceClientClaim, never reaches the browser).
	req.SetBasicAuth(r.oauth.ClientID, r.oauth.ClientSecret)

	resp, err := r.parHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("par http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// RFC 9126 §2.2 — success = 201 Created. Any other status is an
	// error and the body is an RFC 6749 §5.2 error response we can
	// surface for triage.
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("par status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var parResp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&parResp); err != nil {
		return "", fmt.Errorf("par decode: %w", err)
	}
	if parResp.RequestURI == "" {
		return "", fmt.Errorf("par response missing request_uri")
	}
	return parResp.RequestURI, nil
}

// HandleCallback receives Falcon-ID's redirect-back, exchanges the code,
// validates the id_token, applies the group filter, creates a session, and
// HTML-redirects to the original return URL.
func (r *RP) HandleCallback(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())
	q := req.URL.Query()

	if errStr := q.Get("error"); errStr != "" {
		logger.Warn("oidc error from idp", "error", errStr, "desc", q.Get("error_description"))
		http.Error(w, "authentication failed at IdP", http.StatusBadGateway)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	hs, err := r.store.PopHandshake(req.Context(), state)
	if err != nil {
		logger.Warn("handshake state unknown", "err", err)
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	tok, err := r.oauth.Exchange(req.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", hs.CodeVerifier),
	)
	if err != nil {
		logger.Error("token exchange", "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "no id_token in token response", http.StatusBadGateway)
		return
	}
	idToken, err := r.verifier.Verify(req.Context(), rawIDToken)
	if err != nil {
		logger.Warn("id_token verify", "err", err)
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != hs.Nonce {
		logger.Warn("nonce mismatch", "got", idToken.Nonce, "want", hs.Nonce)
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	var claims claimsBody
	if err := idToken.Claims(&claims); err != nil {
		logger.Error("claims parse", "err", err)
		http.Error(w, "claims parse failed", http.StatusBadGateway)
		return
	}

	// Second-pass claim extraction: the typed claimsBody can't anticipate
	// every device-claim name the IdP might emit. Re-parse into a generic
	// map and lift the allowedDeviceClaimNames keys into stringified form
	// for the per-host evaluator (router/perhost.go). Booleans become
	// "true"/"false"; numbers become decimal strings; objects/arrays are
	// JSON-encoded so the comparison stays a simple string equality.
	// Missing or zero-value claims are skipped — the router treats absent
	// claims as fail-closed for any route that requires them, which is
	// the desired pre-MDM behavior.
	var rawClaims map[string]any
	deviceClaims := map[string]string{}
	if err := idToken.Claims(&rawClaims); err == nil {
		for _, name := range allowedDeviceClaimNames {
			if v, ok := rawClaims[name]; ok && v != nil {
				if s := stringifyClaim(v); s != "" {
					deviceClaims[name] = s
				}
			}
		}
	}

	// Group filter — enforced here (PE) before session create. Checks
	// BOTH the `groups` and `roles` claims because Falcon-ID emits role
	// names (e.g. platform_admin) in `roles` while `groups` holds
	// iam_group paths (often empty by default). SpiceDB CheckPermission
	// lands in Phase 2.1 alongside per-route permission labels.
	if !contains(claims.Groups, r.cfg.RequiredRole) && !contains(claims.Roles, r.cfg.RequiredRole) {
		logger.Warn("denied: missing required group/role",
			"sub", claims.Sub, "required", r.cfg.RequiredRole,
			"have_groups", claims.Groups, "have_roles", claims.Roles)
		http.Error(w, "forbidden — required group missing", http.StatusForbidden)
		return
	}

	now := time.Now().Unix()
	blob := &session.Blob{
		V:        session.SchemaVersion,
		Sub:      claims.Sub,
		Email:    claims.Email,
		Groups:   claims.Groups,
		Roles:    claims.Roles,
		TenantID: claims.TenantID,
		Iss:      idToken.Issuer,
		AMR:      claims.AMR,
		ACR:      claims.ACR,
		// LastWebAuthnAt populated when AMR carries a hardware-factor
		// marker. The ZTNA baseline Rego module uses this for
		// `webauthn_fresh_1h` / `_12h` recency gates on AAL3 routes.
		// Per Phase K self-audit H-1 (2026-06-14).
		LastWebAuthnAt: hardwareFactorAuthTime(claims.AMR, claims.AuthTime),
		IAT:            now,
		Exp:            now + int64(r.cfg.SessionHardTTL.Seconds()),
		LastTouched:    now,
		SrcIP:          ClientIP(req),
		UAHash:         hashUA(req.UserAgent()),
		IDTokenJTI:     claims.JTI,
		SSOChainID:     hs.SSOChainID,
		DeviceClaims: func() map[string]string {
			if len(deviceClaims) == 0 {
				return nil
			}
			return deviceClaims
		}(),
		SID: claims.SID,
	}
	// Field-level AES-GCM wrap of the refresh_token under the cookie-encrypt
	// key per ADR 0002 §4.1 (IAP-04). The outer Blob AEAD already protects
	// the at-rest Redis value; this second layer means an in-process compromise
	// that reads a decrypted Blob in memory cannot directly use the
	// refresh_token. Empty refresh_token (some IdPs / non-rotating clients)
	// pass through as the empty string.
	if tok.RefreshToken != "" {
		encRT, encErr := r.store.EncryptValue(tok.RefreshToken)
		if encErr != nil {
			logger.Error("encrypt refresh_token", "err", encErr)
			http.Error(w, "session create failed", http.StatusInternalServerError)
			return
		}
		blob.RefreshTokenEnc = encRT
	}
	cookieID, err := r.store.Create(req.Context(), blob)
	if err != nil {
		logger.Error("session create", "err", err)
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}

	// Bridge the OIDC `roles` claim into SpiceDB group memberships so
	// the per-route CheckPermission walk
	//     user:<sub> → group:<role>#member → talon_route#editor
	// resolves on the very next request. Without this the TalonRoute
	// reconciler's edges (talon_route#editor@group:<role>#member) are
	// the only edges in the graph and CheckPermission returns
	// no_permission for every login — the 2026-05-08 outage on
	// argocd.internal.example.com.
	//
	// Fail-open with a WARN: SpiceDB unavailability shouldn't block
	// login because the per-request CheckPermission is the
	// authoritative gate, and the relation will be re-TOUCHed on the
	// next login. SpiceDB SLO-violation surfaces via the metrics
	// emitted by CachedClient + the existing alerts on the operator
	// dashboard.
	if r.spicedb != nil && len(claims.Roles) > 0 {
		spiceCtx, spiceCancel := context.WithTimeout(req.Context(), 2*time.Second)
		if seedErr := r.spicedb.WriteUserGroupMemberships(spiceCtx, claims.Sub, claims.Roles); seedErr != nil {
			logger.Warn("spicedb seed group memberships failed (login proceeds; route-level check will deny if needed)",
				"sub", claims.Sub, "roles", claims.Roles, "err", seedErr)
		} else {
			logger.Info("spicedb group memberships seeded",
				"sub", claims.Sub, "roles", claims.Roles)
		}
		spiceCancel()
	}

	r.setSessionCookie(w, cookieID)
	hint := claims.Email
	if hint == "" {
		hint = claims.PreferredUsername
	}
	r.setLastUserCookie(w, hint)
	WriteHTMLRedirect(w, hs.ReturnTo)
}

// HandleLogout revokes the Talon session, clears the cookie, and chains
// into Falcon-ID's RP-Initiated Logout flow per OIDC RP-Initiated Logout
// 1.0 (https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
//
// Without the chain to the IdP's end_session_endpoint, logout was
// "Talon-only" — the talon_session cookie cleared but Falcon-ID's
// falcon_idp_session stayed alive. Visiting any *.ops host would
// silently re-auth via Falcon-ID's still-valid SSO cookie, making
// the logout indistinguishable from a tab close to an end user.
//
// Flow:
//  1. Revoke Talon session in Redis (audit + tombstone).
//  2. Clear talon_session cookie on the browser.
//  3. HTML-redirect to ${end_session_endpoint}?post_logout_redirect_uri=
//     ${LogoutRedirectURL}&id_token_hint=${id_token_jti}
//     Falcon-ID clears its IDP session cookie + redirects back to
//     Talon's /auth/logged-out (must be in the OAuth client's
//     registered post_logout_redirect_uris list — see
//     ServiceClientClaim.spec.postLogoutRedirectURIs).
//  4. If the IdP didn't advertise end_session_endpoint (older OIDC
//     providers, mock IdPs in tests), fall back to local-only logout.
//
// Talon's session is killed both by this flow and, when the user signs
// out at another HexxLock RP (accounts.example.com), by the OIDC
// Back-Channel Logout 1.0 receiver at POST /auth/backchannel-logout
// (handlers/backchannel_logout.go). The receiver scopes the cascade to
// `sub` because Talon does not currently capture the OP's `sid` into
// the session blob — per-sub fan-out via talon:revoke-by-sub:<sub>
// matches the Tier-1 cascade requirement of "kill admin-tier sessions
// on Sign Out at any HexxLock RP" without requiring a session-blob
// schema bump.
//
// Per-app sessions (grafana_session, argocd.token, etc.) STILL linger
// in the browser after Talon revokes its session. Talon's edge blocks
// every subsequent request to those apps so the lingering cookies are
// harmless on the cascade hot path, but defense-in-depth via per-app
// /logout chaining is tracked as gap SLO-02 in
// the internal Q2 2026 IAM/IAP audit.
func (r *RP) HandleLogout(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())
	cookie, _ := req.Cookie(SessionCookieName)
	var idTokenJTI string
	if cookie != nil && cookie.Value != "" {
		if blob, err := r.store.Read(req.Context(), cookie.Value); err == nil {
			idTokenJTI = blob.IDTokenJTI
			if err := r.store.Revoke(req.Context(), cookie.Value, blob); err != nil {
				logger.Warn("session revoke", "err", err)
			}
		}
	}
	r.clearSessionCookie(w)
	// Explicit sign-out: forget the user hint too (shared machines).
	r.clearLastUserCookie(w)

	// RP-Initiated Logout: bounce to IdP so Falcon-ID also clears its
	// SSO cookie. If the IdP didn't advertise end_session_endpoint,
	// fall back to local-only logout (cookie cleared, IdP session intact
	// — caller can clear it manually by visiting the IdP).
	dest := r.cfg.LogoutRedirectURL()
	if r.endSessionEndpoint != "" {
		q := url.Values{}
		q.Set("post_logout_redirect_uri", r.cfg.LogoutRedirectURL())
		q.Set("client_id", r.cfg.OIDCClientID)
		if idTokenJTI != "" {
			// Falcon-ID treats id_token_hint as optional but uses it to
			// scope the logout to a specific session if present. We don't
			// have the full id_token (Talon doesn't store it — only the
			// jti), but Falcon-ID accepts the jti as a hint per migration
			// 213 (see internal engineering notes).
			q.Set("id_token_hint", idTokenJTI)
		}
		dest = r.endSessionEndpoint + "?" + q.Encode()
	}
	WriteHTMLRedirect(w, dest)
}

// SessionCookieName is the cookie name per ADR 0002 §3.1.
const SessionCookieName = "talon_session"

func (r *RP) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Domain:   r.cfg.CookieDomain,
		Path:     "/",
		Expires:  time.Now().Add(r.cfg.SessionHardTTL),
		MaxAge:   int(r.cfg.SessionHardTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (r *RP) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Domain:   r.cfg.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// isSafeReturnURL returns true iff rd points back into a Talon-fronted
// admin DNS zone OR a clientless access zone. Open-redirect prevention.
//
// The allowed-zone list is the union of cfg.ProtectedHostSuffixes
// (TALON_PROTECTED_HOST_SUFFIXES env, comma-separated, e.g.
// ".internal.example.com,.apps.example.com") and cfg.ClientlessHostSuffixes
// (TALON_CLIENTLESS_HOST_SUFFIXES, ADR 0044, e.g. ".access.example.com").
// The access zone MUST be accepted here, otherwise the OIDC redirect back
// to `<app>.access.example.com` after sign-in would be rejected as an
// open-redirect and the clientless auth flow could never complete.
//
// Each entry MUST start with a dot — guards against suffix-collision
// attacks (e.g. evil-ops.com must NOT match .ops.com). When BOTH lists are
// empty the validator falls back to the legacy cookieDomain-based check
// (single-zone behaviour, preserves single-zone deployments unchanged on
// upgrade).
func (r *RP) isSafeReturnURL(rd string) bool {
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	suffixes := make([]string, 0, len(r.cfg.ProtectedHostSuffixes)+len(r.cfg.ClientlessHostSuffixes))
	suffixes = append(suffixes, r.cfg.ProtectedHostSuffixes...)
	suffixes = append(suffixes, r.cfg.ClientlessHostSuffixes...)
	if len(suffixes) > 0 {
		for _, suffix := range suffixes {
			parent := strings.TrimPrefix(suffix, ".")
			if host == parent || strings.HasSuffix(host, "."+parent) {
				return true
			}
		}
		return false
	}
	cookieParent := strings.TrimPrefix(r.cfg.CookieDomain, ".")
	return host == cookieParent || strings.HasSuffix(host, "."+cookieParent)
}

// claimsBody is the subset of id_token claims Talon consumes; matches the
// shape Falcon-ID emits (per internal engineering notes).
type claimsBody struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	// PreferredUsername — OIDC Core §5.1; fallback login_hint when no email.
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
	TenantID          string   `json:"tenant_id"`
	AMR               []string `json:"amr"`
	// ACR — Authentication Context Class Reference (OIDC Core §2,
	// RFC 8176 §1). Falcon-ID emits the AAL ladder values
	// `urn:hexxlock:aal2` / `urn:hexxlock:aal3` per its
	// docs/oidc-claims-groups-amr.md. RFC 8176 §1 explicitly recommends
	// `acr` over `amr` for gate decisions because it's a stable
	// business-rule reference rather than a brittle method list. Talon's
	// step-up gate uses this when the route configures RequireACR.
	ACR string `json:"acr,omitempty"`
	// AuthTime — unix seconds when the user authenticated at the OP, per
	// OIDC Core §2 (id_token reserved claim). Talon mirrors this into
	// session.Blob.LastWebAuthnAt when AMR contains a hardware-factor
	// marker, so the ZTNA baseline Rego can gate critical-route AAL3
	// step-up on `amr_recency_seconds <= 3600`. Per Phase K self-audit
	// H-1 (2026-06-14).
	AuthTime int64  `json:"auth_time,omitempty"`
	JTI      string `json:"jti"`
	// SID — OIDC Session Management 1.0 §5 / Front-Channel Logout 1.0 §3.
	// The OP's session identifier; included in the iframe URL on RP-
	// initiated logout so we can scope cascade-revocation to a single
	// browser session. Empty when the OP hasn't started emitting `sid`
	// — the FCL handler degrades to a no-op cascade in that case.
	SID string `json:"sid,omitempty"`
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func randURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ClientIP returns the request's originating client IP, taking the
// leftmost X-Forwarded-For hop when present and falling back to
// req.RemoteAddr's host portion. Exposed so the router can apply the
// same XFF-aware extraction the OIDC RP uses when stamping SrcIP onto
// new sessions — keeps the IP-rebind /24 comparison apples-to-apples.
func ClientIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the leftmost (original client) IP.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := req.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

func hashUA(ua string) string {
	if ua == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// _ = json keeps the import alive when claimsBody parsing is removed in tests.
var _ = json.Marshal

// allowedDeviceClaimNames is the local mirror of
// gatewayv1alpha1.AllowedDeviceClaimNames — duplicated here (rather than
// imported) to keep the OIDC package free of an api/v1alpha1 dependency.
// MUST stay in sync with the v1alpha1 var; CI grep guard recommended.
var allowedDeviceClaimNames = []string{
	"device_id",
	"device_compliant",
	"device_managed_by_mdm",
	"device_tpm_attested",
	"device_os_version",
	"device_attestation_chain",
}

// stringifyClaim normalises an arbitrary id_token claim value into the
// string form the per-host evaluator compares against. Mirrors the
// CRD's documented semantics:
//
//   - string → unchanged
//   - bool   → "true" / "false"
//   - number → decimal string (json.Number / float64)
//   - object/array → JSON-encoded so equality works on canonical form
//   - nil/empty → "" (caller drops the claim)
//
// Keeps the comparison surface a flat string so operators don't need
// to learn a claim-type DSL when authoring TalonRoute policies.
func stringifyClaim(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers decode as float64; cast cleanly to int when
		// fractional part is zero so "1.0" doesn't surprise operators
		// who wrote `equals: "1"`.
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// hardwareFactorAuthTime returns authTime when the AMR list carries a
// hardware-factor marker the ZTNA matrix considers AAL3-eligible, else 0.
// The Rego baseline interprets a zero `amr_recency_seconds` as "fresh", so
// returning 0 here for non-hardware factors means non-AAL3 sessions don't
// accidentally pass the AAL3 recency gate — but the AAL3 rules separately
// require "hwk" in amr, so the non-hardware-factor path never reaches the
// recency check anyway. The intent is to keep the field semantically
// scoped to hardware-factor sessions.
//
// AMR markers per RFC 8176 + Falcon-ID's docs/oidc-claims-groups-amr.md:
//
//	hwk  — generic hardware-key bind (operator's YubiKey, RSA card, etc.)
//	fido — FIDO U2F
//	fpt  — biometric fingerprint via SE / TPM-bound assertion
//	swk  — software hardware-token (e.g. attested passkey) — included
//	       because passkeys with attested platform authenticator chain
//	       satisfy NIST 800-63B AAL3 per §5.2.3
//	otp  — explicit OTP factor; NOT hardware, excluded
//	pwd  — password; NOT hardware, excluded
//
// Per Phase K self-audit H-1 (2026-06-14).
func hardwareFactorAuthTime(amr []string, authTime int64) int64 {
	if authTime <= 0 {
		return 0
	}
	for _, m := range amr {
		switch m {
		case "hwk", "fido", "fpt", "swk":
			return authTime
		}
	}
	return 0
}
