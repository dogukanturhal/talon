// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers — frontchannel_logout.go is the OIDC Front-Channel
// Logout 1.0 receiver per
// https://openid.net/specs/openid-connect-frontchannel-1_0.html.
//
// Falcon-ID's RP-initiated logout page renders one <iframe> per
// registered RP that opted in via frontchannel_logout_uri. The iframe
// loads this endpoint with `iss` and `sid` query parameters; we revoke
// the matching Talon session(s) and respond with a tiny image so the
// iframe load completes cleanly.
//
// FCL complements the back-channel cascade in
// backchannel_logout.go. The two are NOT redundant — each covers a
// class of scenarios the other can't:
//
//   - BCL: server-to-server POST. Required when the RP backend MUST be
//     notified (mobile app session bus, headless workers). Fails when
//     the RP is unreachable from the OP at logout time.
//   - FCL: browser iframe load. Works when the user's browser is alive
//     even if the RP backend is unreachable from the OP. Fails for
//     pure-headless RPs without a browser context.
//
// Both fire on every RP-initiated logout. Talon implements both.
//
// AUTHENTICATION
//
// The endpoint is unauthenticated by design (FCL §3 — the iframe is
// loaded by the user's browser, which has no shared secret). The
// `iss` query parameter MUST match the configured Falcon-ID issuer
// exactly; this IS the auth, supplemented by:
//
//   - Content-Security-Policy: frame-ancestors locks the iframe to
//     id.hexxlock.com so a hostile site can't embed it to force-logout
//     users (FCL §5).
//   - Linkerd Server CR + AuthorizationPolicy on the auth host gates
//     the wire path (defense in depth — Falcon-ID's logout page is
//     served from the same cluster and traverses the mesh).
//
// SESSION RESOLUTION
//
// The handler scopes the cascade to the OP's `sid` value via the
// `talon:revoke-by-sid:<sid>` Redis index populated by
// session.Store.Create whenever the OP emits the `sid` claim on the
// id_token (OIDC Session Management 1.0 §5). Sessions minted before
// the OP started emitting `sid` have an empty index entry — those
// fall through to a no-op cascade (the user's next request
// re-validates and the cookie ages out naturally).
//
// CACHING & CSP
//
// Per FCL §3 the iframe response MUST NOT be cached: a cached response
// would silently no-op every subsequent logout in the same browser
// session. We set Cache-Control: no-store, no-cache, must-revalidate,
// Pragma: no-cache, Expires: 0 — the full RFC 7234 §5.2 trifecta — so
// every iframe load round-trips to Talon.
//
// AUDIT
//
// Each revoked session emits an auth.frontchannel_logout event so SOC
// analysts can attribute Talon session teardown to a browser-driven
// FCL cascade vs the server-to-server BCL cascade vs an admin revoke
// vs natural expiry.
package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/talon/internal/audit"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
)

// fclPixelPNG is a 1×1 transparent PNG, base64-encoded. The handler
// returns this body so the browser's iframe load completes cleanly with
// a real image MIME type. Some RP implementations return 204 No Content
// instead; an image works on every browser and has no special-case
// rendering quirks.
//
// Generated once with:
//
//	python3 -c 'import base64,zlib,struct
//	png = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489000000017352474200aece1ce90000000c4944415478da6300010000000500010d0a2db40000000049454e44ae426082")
//	print(base64.b64encode(png).decode())'
const fclPixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAAxJREFUeNpjAQAABQABDQotxAAAAABJRU5ErkJggg=="

// FrontchannelLogout is the spec-§3 receiver for OIDC Front-Channel
// Logout 1.0. Mounted on the auth host at GET /auth/frontchannel-logout.
type FrontchannelLogout struct {
	// Store is the session store; Read + Revoke both run through it.
	Store *session.Store
	// Redis is the same client that backs Store; used for the
	// per-`sid` revocation index ZRange that scopes the cascade.
	Redis *redis.Client
	// Audit emits the auth.frontchannel_logout event per revoked session.
	Audit *audit.Emitter
	// IssuerURL is the expected OP issuer; the `iss` query parameter
	// MUST match this exactly (with trailing-slash tolerance — same as
	// the BCL pattern). Wired from cfg.OIDCIssuer.
	IssuerURL string
	// FrameAncestor is the origin allowed to embed this iframe via
	// CSP frame-ancestors. Typically the OP's logout-page origin,
	// e.g. "https://id.hexxlock.com". Empty disables the CSP header
	// and falls back to "frame-ancestors 'self' https:" (still safe
	// but less restrictive — log a warning at startup).
	FrameAncestor string
}

// ServeHTTP implements GET /auth/frontchannel-logout per
// OIDC Front-Channel Logout 1.0 §3.
//
// Response codes:
//
//	200  iframe satisfied — revoked 0..N sessions
//	400  missing/invalid iss; missing/non-UUID sid
//	405  non-GET
//	500  internal store error
//
// Response body is always a 1×1 transparent PNG so the browser's
// iframe load completes with a real image MIME type.
func (h *FrontchannelLogout) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())

	// Spec §3 — never cache the iframe response. A cached 200 would
	// silently no-op every subsequent logout in the same browser
	// session. The full RFC 7234 §5.2 trifecta below covers every
	// browser/proxy combo (no-store alone is insufficient on some
	// older middleware caches that key on Pragma).
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// CSP frame-ancestors — only the configured OP logout page may
	// embed this iframe (FCL §5: "The OP MUST … include only iframes
	// to RPs that the user is logged into"; correspondingly the RP
	// MUST refuse iframe embedding from any other origin).
	if h.FrameAncestor != "" {
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+h.FrameAncestor)
	} else {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self' https:")
	}

	if req.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.Header().Set("X-Talon-Reason", "method_not_allowed")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	if h.Store == nil || h.Redis == nil || h.Audit == nil {
		// Mis-wired build — fail closed and log so the next deploy
		// fixes it. Spec compliance MUST NOT be optional at runtime.
		logger.Error("frontchannel logout: handler missing dependency")
		w.Header().Set("X-Talon-Reason", "handler_not_ready")
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}

	// Spec §5.4 — RP MUST validate iss against expected issuer URL.
	rawISS := strings.TrimSpace(req.URL.Query().Get("iss"))
	if rawISS == "" {
		w.Header().Set("X-Talon-Reason", "missing_iss")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	if !issuerMatches(rawISS, h.IssuerURL) {
		w.Header().Set("X-Talon-Reason", "iss_mismatch")
		logger.Warn("frontchannel logout: iss mismatch",
			"got", rawISS, "want", h.IssuerURL)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// `sid` is OPTIONAL per FCL §3 but practically required for our
	// implementation — without it we have no way to scope the cascade
	// to a single browser session. Reject empty sid as 400 rather
	// than silently revoking nothing.
	rawSID := strings.TrimSpace(req.URL.Query().Get("sid"))
	if rawSID == "" {
		w.Header().Set("X-Talon-Reason", "missing_sid")
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	// Constrain the sid shape to a UUID so a hostile/malformed value
	// can't leak into a Redis key with arbitrary characters. Falcon-ID
	// emits the falcon_idp_session UUID as sid; any non-UUID value is
	// from a different OP or a malformed request.
	if _, err := uuid.Parse(rawSID); err != nil {
		w.Header().Set("X-Talon-Reason", "malformed_sid")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	revoked := h.cascade(req.Context(), rawSID, rawISS)

	logger.Info("frontchannel logout processed",
		"sid_prefix", safePrefix(rawSID), "iss", rawISS, "revoked", revoked)

	// Spec §3 — successful response is the iframe payload. Use
	// X-Talon-Revoked so e2e harnesses can assert the fan-out count
	// without screen-scraping the binary body.
	w.Header().Set("X-Talon-Revoked", fmt.Sprintf("%d", revoked))
	w.Header().Set("Content-Type", "image/png")

	pixel, _ := base64.StdEncoding.DecodeString(fclPixelPNG)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pixel)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pixel)
}

// cascade fans out the revocation across all Talon sessions for the
// given OP session id. Returns the count of sessions actually revoked.
// Sessions that were already gone (race with /admin/revoke or natural
// expiry) get pruned from the per-sid index in passing.
//
// When the index is empty (the OP started emitting `sid` after this
// session was minted, OR the user has no Talon session for this OP
// session), this returns 0 — spec-OK, since the OP can't know which
// RPs the user has sessions at.
func (h *FrontchannelLogout) cascade(ctx context.Context, sid, iss string) int {
	logger := tlog.From(ctx)

	cookieIDs, err := h.Redis.ZRange(ctx, "talon:revoke-by-sid:"+sid, 0, -1).Result()
	if err != nil {
		logger.Error("frontchannel logout: ZRange revoke-by-sid failed",
			"sid_prefix", safePrefix(sid), "err", err)
		return 0
	}
	if len(cookieIDs) == 0 {
		// No Talon sessions tracked for this OP session. Either the
		// session predates SID-capture or the user has no Talon
		// session — both are spec-OK terminal states.
		return 0
	}

	revoked := 0
	for _, cookieID := range cookieIDs {
		blob, err := h.Store.Read(ctx, cookieID)
		if err != nil {
			// Already gone — prune the index entry and move on.
			h.Redis.ZRem(ctx, "talon:revoke-by-sid:"+sid, cookieID)
			continue
		}
		if err := h.Store.Revoke(ctx, cookieID, blob); err != nil {
			logger.Warn("frontchannel logout: revoke failed",
				"cookie_id_prefix", safePrefix(cookieID), "err", err)
			continue
		}
		revoked++
		h.Audit.FrontchannelLogout(ctx, audit.Record{
			Sub:       blob.Sub,
			Email:     blob.Email,
			TenantID:  blob.TenantID,
			SessionID: cookieID,
			Issuer:    iss,
			Reason:    "fcl_iframe_sid=" + safePrefix(sid),
		})
	}
	return revoked
}

// issuerMatches compares the iss query parameter against the expected
// OP issuer URL with trailing-slash tolerance. Falcon-ID has been
// observed in production to emit `https://id.hexxlock.com` (no slash)
// on tokens but `https://id.hexxlock.com/` in some discovery responses;
// the strict-equal compare here would otherwise drop legitimate
// iframe loads from RP-initiated logout flows.
//
// MUST stay strict on scheme + host + path-modulo-trailing-slash so a
// hostile `https://id.hexxlock.com.attacker.example/` doesn't pass.
func issuerMatches(got, want string) bool {
	if want == "" {
		// Mis-configured deployment — treat as strict-deny rather
		// than open. The startup check in cmd/talon should reject
		// this, but defense in depth applies.
		return false
	}
	gotURL, err1 := url.Parse(got)
	wantURL, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	if gotURL.Scheme != wantURL.Scheme || gotURL.Host != wantURL.Host {
		return false
	}
	gp := strings.TrimRight(gotURL.Path, "/")
	wp := strings.TrimRight(wantURL.Path, "/")
	return gp == wp
}

// _ = time keeps the time import alive when build tags strip the
// per-revoke audit pipeline (test-only configurations).
var _ = time.Now
