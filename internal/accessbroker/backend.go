// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
	"io"
)

// Backend is the seam between the access-broker and the jess protocol
// broker (ADR 0049). The broker authenticates + upgrades the browser
// WebSocket, then asks a Backend to open a session stream to the
// requested target. Keeping this an interface lets the relay + WebSocket
// codec be exercised end-to-end against a fake backend in tests, and
// lets the real jess wiring land behind a clean boundary once jess
// ADR 0049's SSH broker exposes a callable interface from talon.
//
// HONEST STATE (Phase 2 scaffold): the production implementation
// (jessSSHBackend) is a STUB — the jess-side SSH broker API is not yet
// reachable from talon, so Dial returns ErrBackendNotWired unless an
// explicit dev loopback target is configured. Everything ABOVE this
// interface (auth, channel gate, WebSocket framing, the relay loop,
// recording tee) is real and tested. See README/remaining.
type Backend interface {
	// Dial opens a backend session stream for req. The returned
	// BackendConn is a bidirectional byte stream carrying the SSH
	// session's stdin/stdout (the broker treats it as opaque — jess
	// owns the SSH protocol + per-session recording). The caller closes
	// the BackendConn when the WebSocket relay ends.
	Dial(ctx context.Context, req DialRequest) (BackendConn, error)
}

// DialRequest carries everything the backend needs to open + audit a
// brokered session. The identity fields are projected from the verified
// Talon IAP identity token (never trusted from the client), so jess can
// bind the recording + JIT decision to the real subject.
type DialRequest struct {
	// Subject is the Falcon-ID iam_users.id (JWT sub) of the
	// authenticated user. Load-bearing for jess audit + JIT.
	Subject string
	// Email + TenantID are surfaced for the jess recording metadata.
	Email    string
	TenantID string
	// SessionID is the Talon session UUID (JWT sid) — lets jess join its
	// recording to Talon's audit trail.
	SessionID string
	// SSOChainID spans Talon <-> jess <-> recording logs.
	SSOChainID string

	// Target is the logical SSH target the user requested (e.g.
	// "bastion.internal" or a jess target handle). The broker passes it
	// through verbatim; jess resolves + authorises it.
	Target string
	// User is the remote SSH login the user requested on the target.
	User string

	// Cols/Rows are the initial PTY geometry from the browser terminal.
	Cols uint16
	Rows uint16
}

// BackendConn is the bidirectional stream to the backend SSH session.
// Reads return backend->terminal bytes (stdout/stderr); Writes carry
// terminal->backend bytes (keystrokes). Resize delivers a PTY
// window-change; backends that don't support resizing return nil.
type BackendConn interface {
	io.ReadWriteCloser
	// Resize sends a window-change to the backend PTY. A no-op (return
	// nil) is acceptable for backends without PTY support.
	Resize(cols, rows uint16) error
}

// ErrBackendNotWired is returned by the stub jess backend when no dev
// loopback target is configured. It signals "the relay path is real but
// the jess SSH broker is not reachable yet" — surfaced to the browser as
// a clean 1011 close with this reason, never a silent hang.
var ErrBackendNotWired = errors.New("accessbroker: jess SSH backend not wired (Phase 2 stub) — set a dev loopback target to test the relay")

// errNilAuth / errNilBackend are returned by NewHandler when a required
// dependency is missing. The broker fails closed at construction rather
// than serving an unauthenticated or undialable terminal at runtime.
var (
	errNilAuth    = errors.New("accessbroker: HandlerConfig.Auth is required")
	errNilBackend = errors.New("accessbroker: HandlerConfig.Backend is required")
)
