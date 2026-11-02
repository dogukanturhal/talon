// SPDX-License-Identifier: AGPL-3.0-or-later

// Package log wraps log/slog with a JSON formatter and a small set of
// helpers for adding consistent fields (request_id, route, sub) so audit
// log emit sites stay terse.
package log

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// New returns a configured *slog.Logger. format is "json" or "text"; level
// is "debug" / "info" / "warn" / "error" (case-insensitive).
func New(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

type ctxKey int

const (
	loggerKey       ctxKey = 1
	decisionIDKey   ctxKey = 2
	ssoChainIDKey   ctxKey = 3
)

// Into returns ctx with logger attached.
func Into(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// From extracts the logger from ctx, falling back to slog.Default.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// WithDecisionID attaches a per-request decision-correlation ID (ULID-like
// string; today UUIDv4) so every audit event emitted during this request
// carries the same value. `decision_id` is the
// SOC analyst's grep handle for "everything that happened on one auth
// decision."
func WithDecisionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, decisionIDKey, id)
}

// DecisionIDFrom returns the decision ID attached to ctx, or "" if none.
func DecisionIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(decisionIDKey).(string); ok {
		return v
	}
	return ""
}

// WithSSOChainID attaches the per-session SSO chain ID. Generated at
// /auth/start, persisted into the session blob, replayed onto every
// audit event for the lifetime of the session — enables cross-system
// correlation of one user's full Talon ↔ Falcon-ID ↔ upstream chain.
func WithSSOChainID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ssoChainIDKey, id)
}

// SSOChainIDFrom returns the SSO chain ID attached to ctx, or "".
func SSOChainIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ssoChainIDKey).(string); ok {
		return v
	}
	return ""
}
