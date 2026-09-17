// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers — revoke.go is the streaming-revocation webhook
// per ADR 0004 (Tier-1 Gap 2). Distinct from admin.go's
// `DELETE /admin/sessions/{sub}` which is the operator break-glass and
// authenticates via session cookie + role.
//
// This endpoint is called by:
//   - Falcon-ID server-side hooks (`user.disabled`,
//     `user.groups.changed`, `oauth.token.revoked`) to invalidate
//     Talon sessions in real time, collapsing the up-to-5-min poll-
//     cadence window to ~30 s end-to-end.
//   - SIEM active-response producers (wazuh-ar-reconciler, falco-
//     talon, manual SOC) when an attack involves user-credential
//     abuse and the offending session must be evicted alongside the
//     IP-level ban that wazuh-ar-reconciler applies to the Calico
//     GlobalNetworkSet.
//
// Authentication is via Linkerd mTLS at the network boundary (Server
// CR + AuthorizationPolicy + MeshTLSAuthentication, set in platform-
// manifests); the application also asserts the caller identity from
// the `l5d-client-id` header as defence-in-depth and for audit
// fidelity.
//
// Tier-1 Gap 4 SIEM-unification fields (`decision_id`, `source`) are
// optional in the request body and propagate end-to-end onto the
// audit.Record so a SOC analyst can grep one ULID across Falco /
// Wazuh / Talon / Falcon-ID logs.
package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/hexxlock/talon/internal/audit"
	tlog "github.com/hexxlock/talon/internal/log"
	"github.com/hexxlock/talon/internal/session"
	"github.com/redis/go-redis/v9"
)

// RevokeWebhook handles POST /admin/revoke. Body:
//
//	{ "sub":          "<falcon-id-uuid>",
//	  "reason":       "user_disabled" | "groups_changed" | "oauth_token_revoked" |
//	                  "siem_ar:<rule_id>" | "manual" | ...,
//	  "session_ids":  ["<uuid>", ...],   // optional; empty = kick all sessions for sub
//	  "decision_id":  "01HZ9D6VPK7XBQK3WZ7WQXDGAF",  // optional; ULID propagated
//	                                                  // from the originating SIEM
//	                                                  // event (Gap 4 unification).
//	  "source":       "falcon-id" | "wazuh-ar" | "falco-talon" | "manual"
//	                                                  // optional; semantic label
//	                                                  // of the caller subsystem.
//	                                                  // l5d-client-id remains the
//	                                                  // authoritative caller ID.
//	}
//
// On success returns:
//
//	{ "sub": "...", "revoked": <count>, "reason": "..." }
type RevokeWebhook struct {
	Store *session.Store
	Redis *redis.Client
	Audit *audit.Emitter
	// AllowedIdentities is the SPIFFE-style Linkerd identity allow-list.
	// Typical entry:
	//   falcon-id.falcon-id.serviceaccount.identity.linkerd.cluster.local
	// Empty list = endpoint disabled (returns 503).
	AllowedIdentities []string
	// RateLimitPerSec is the global token-bucket cap. 0 disables the
	// limit (testing only). Production cap: 100/sec; burst 200.
	RateLimitPerSec int

	mu     sync.Mutex
	bucket float64
	last   time.Time
}

type revokeReq struct {
	Sub        string   `json:"sub"`
	Reason     string   `json:"reason,omitempty"`
	SessionIDs []string `json:"session_ids,omitempty"`
	// DecisionID — optional ULID propagated from the originating SIEM
	// event (boot prompt §6.6 Gap 4). When set, copied verbatim onto
	// the audit.Record.DecisionID for every revoked session so the
	// admin.revoke events join the rest of the per-decision audit
	// trail in Wazuh / Loki / Tempo. When unset, audit.Emit auto-
	// populates from request context (a fresh ULID per call).
	DecisionID string `json:"decision_id,omitempty"`
	// Source — optional semantic label of the caller subsystem. The
	// authoritative caller identity is `l5d-client-id`; this field is
	// a friendlier audit dimension (e.g. dashboard breakdown by
	// "wazuh-ar" vs "falco-talon" vs "falcon-id"). Not used for
	// authorisation.
	Source string `json:"source,omitempty"`
}

type revokeResp struct {
	Sub     string `json:"sub"`
	Revoked int    `json:"revoked"`
	Reason  string `json:"reason,omitempty"`
}

// ServeHTTP implements POST /admin/revoke. All non-200 responses carry
// X-Talon-Reason so the caller can branch on the failure mode.
func (h *RevokeWebhook) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())
	w.Header().Set("Cache-Control", "no-store")

	if len(h.AllowedIdentities) == 0 {
		w.Header().Set("X-Talon-Reason", "endpoint_disabled")
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}

	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("X-Talon-Reason", "method_not_allowed")
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	// Linkerd identity assertion. Set by the proxy on a meshed call.
	// AuthorizationPolicy at the Server CR is the primary gate; this
	// header check is defence-in-depth and gives audit a stable caller
	// identity field.
	caller := req.Header.Get("l5d-client-id")
	if caller == "" {
		w.Header().Set("X-Talon-Reason", "off_mesh")
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	if !containsString(h.AllowedIdentities, caller) {
		logger.Warn("revoke webhook: caller not in allow-list",
			"caller", caller, "allowed_count", len(h.AllowedIdentities))
		w.Header().Set("X-Talon-Reason", "forbidden_caller")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	if !h.allowRate() {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-Talon-Reason", "rate_limited")
		http.Error(w, "", http.StatusTooManyRequests)
		return
	}

	var body revokeReq
	dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64*1024))
	if err := dec.Decode(&body); err != nil {
		w.Header().Set("X-Talon-Reason", "invalid_body")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Sub == "" {
		w.Header().Set("X-Talon-Reason", "missing_sub")
		http.Error(w, "missing sub", http.StatusBadRequest)
		return
	}
	if body.Reason == "" {
		body.Reason = "streaming_webhook"
	}

	// Resolve session IDs: explicit list wins; otherwise scan the
	// per-sub revocation index (populated on Create).
	ids := body.SessionIDs
	if len(ids) == 0 {
		found, err := h.Redis.ZRange(req.Context(), "talon:revoke-by-sub:"+body.Sub, 0, -1).Result()
		if err != nil {
			logger.Error("revoke webhook: ZRange failed", "err", err, "sub", body.Sub)
			w.Header().Set("X-Talon-Reason", "internal_error")
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		ids = found
	}

	revoked := 0
	for _, cookieID := range ids {
		blob, err := h.Store.Read(req.Context(), cookieID)
		if err != nil {
			// Already gone — clean up the per-sub index entry.
			h.Redis.ZRem(req.Context(), "talon:revoke-by-sub:"+body.Sub, cookieID)
			continue
		}
		if err := h.Store.Revoke(req.Context(), cookieID, blob); err != nil {
			logger.Warn("revoke webhook: revoke failed",
				"cookie_id_prefix", safePrefix(cookieID), "err", err)
			continue
		}
		revoked++
		h.Audit.AdminRevoke(req.Context(), audit.Record{
			Sub:        body.Sub,
			SessionID:  cookieID,
			Reason:     body.Reason,
			Issuer:     blob.Iss,
			DecisionID: body.DecisionID,
		})
	}

	logger.Info("revoke webhook: kicked sessions",
		"sub", body.Sub,
		"reason", body.Reason,
		"revoked", revoked,
		"caller", caller,
		"source", body.Source,
		"decision_id", body.DecisionID,
	)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(revokeResp{
		Sub:     body.Sub,
		Revoked: revoked,
		Reason:  body.Reason,
	})
}

// allowRate is a token-bucket rate limiter. Tokens refill at
// RateLimitPerSec and burst caps at 2× rate. Coarse — the webhook is
// expected to see one event per Falcon-ID state change, not a sustained
// flood; the bucket exists to absorb a misbehaving sender.
func (h *RevokeWebhook) allowRate() bool {
	if h.RateLimitPerSec <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if h.last.IsZero() {
		h.last = now
		h.bucket = float64(h.RateLimitPerSec)
	}
	elapsed := now.Sub(h.last).Seconds()
	h.last = now
	h.bucket += elapsed * float64(h.RateLimitPerSec)
	cap := float64(h.RateLimitPerSec * 2)
	if h.bucket > cap {
		h.bucket = cap
	}
	if h.bucket >= 1 {
		h.bucket -= 1
		return true
	}
	return false
}

func containsString(haystack []string, needle string) bool {
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
