// SPDX-License-Identifier: AGPL-3.0-or-later

// Package handlers — admin.go is the operator break-glass surface.
// Today: DELETE /admin/sessions/{sub} kicks all sessions of a user
// per ADR 0002 §5.5. Future: /admin/routes (GET / POST), /admin/cv/run.
//
// Authorization: every endpoint requires a valid talon_session cookie
// AND the configured RequiredRole (typically platform_admin). Admin
// API errors fail-closed: 403 if no session, 403 if role missing.
package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/talon/internal/audit"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
	"github.com/redis/go-redis/v9"
)

// Admin holds dependencies for admin endpoints.
type Admin struct {
	Store        *session.Store
	Redis        *redis.Client
	RequiredRole string
	CookieName   string // typically oidc.SessionCookieName
	Audit        *audit.Emitter
}

// RevokeUser is the http.HandlerFunc for `DELETE /admin/sessions/{sub}`.
// Kicks every active session for the given Falcon-ID `sub`, writes
// audit.AdminRevoke for each.
//
// Path is parsed via simple suffix split (no router framework needed
// for one endpoint).
func (a *Admin) RevokeUser(w http.ResponseWriter, req *http.Request) {
	logger := tlog.From(req.Context())

	if req.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the caller.
	cookie, _ := req.Cookie(a.CookieName)
	if cookie == nil || cookie.Value == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	caller, err := a.Store.Read(req.Context(), cookie.Value)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Require the configured role (Phase 4: platform_admin).
	if !hasString(caller.Roles, a.RequiredRole) && !hasString(caller.Groups, a.RequiredRole) {
		logger.Warn("admin: forbidden — caller lacks required role",
			"caller_sub", caller.Sub, "required", a.RequiredRole)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Parse target sub from path. Accept either /admin/sessions/<sub>
	// or /admin/sessions/by-sub/<sub>.
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/admin/sessions/"), "/")
	target := parts[len(parts)-1]
	if target == "" {
		http.Error(w, "missing sub", http.StatusBadRequest)
		return
	}

	// Look up sessions for this sub via the per-sub index.
	uuids, err := a.Redis.ZRange(req.Context(), "talon:revoke-by-sub:"+target, 0, -1).Result()
	if err != nil {
		logger.Error("admin: ZRange failed", "err", err, "sub", target)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	revoked := 0
	for _, cookieID := range uuids {
		blob, err := a.Store.Read(req.Context(), cookieID)
		if err != nil {
			// Already gone — clean up the index entry.
			a.Redis.ZRem(req.Context(), "talon:revoke-by-sub:"+target, cookieID)
			continue
		}
		if err := a.Store.Revoke(req.Context(), cookieID, blob); err != nil {
			logger.Warn("admin: revoke failed", "cookie_id_prefix", cookieID[:8], "err", err)
			continue
		}
		revoked++
		a.Audit.AdminRevoke(req.Context(), audit.Record{
			Sub:        target,
			TenantID:   blob.TenantID,
			SessionID:  cookieID,
			Reason:     "admin_revoke",
			Issuer:     blob.Iss,
			SSOChainID: blob.SSOChainID,
		})
	}

	logger.Info("admin: kicked sessions", "target_sub", target, "revoked", revoked, "caller_sub", caller.Sub)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = writeJSON(w, http.StatusOK, map[string]any{
		"target_sub": target,
		"revoked":    revoked,
		"at":         time.Now().UTC().Format(time.RFC3339),
	})
}

func hasString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, body map[string]any) error {
	w.WriteHeader(code)
	// Tiny manual JSON to avoid an encoding/json import; consistent with
	// the rest of Talon's tiny-deps style.
	first := true
	if _, err := w.Write([]byte("{")); err != nil {
		return err
	}
	for k, v := range body {
		if !first {
			_, _ = w.Write([]byte(","))
		}
		first = false
		_, _ = w.Write([]byte("\""))
		_, _ = w.Write([]byte(k))
		_, _ = w.Write([]byte("\":"))
		switch t := v.(type) {
		case string:
			_, _ = w.Write([]byte("\""))
			_, _ = w.Write([]byte(strings.ReplaceAll(t, "\"", "\\\"")))
			_, _ = w.Write([]byte("\""))
		case int:
			_, _ = w.Write([]byte(itoa(t)))
		default:
			_, _ = w.Write([]byte("null"))
		}
	}
	_, _ = w.Write([]byte("}"))
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if negative {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
