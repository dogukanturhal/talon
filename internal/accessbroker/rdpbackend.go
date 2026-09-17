// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
	"io"
	"time"
)

// RDPBackend is the seam between the access-broker and the jess RDP
// protocol broker (ADR 0049 / ADR 0044 Phase 3). It mirrors Backend (the
// SSH seam) but carries a desktop graphics stream rather than an opaque
// terminal byte stream: jess speaks RDP to the target, decodes it to a
// canvas-renderable frame stream, and accepts pointer/keyboard/clipboard
// input back. Keeping it an interface lets the relay + WebSocket codec be
// exercised end-to-end against a fake backend in tests, and lets the real
// jess wiring land behind a clean boundary once jess's RDP broker exposes
// a callable interface from talon.
//
// HONEST STATE (Phase 3 scaffold): the production implementation
// (jessRDPBackend) is a STUB — the jess-side RDP broker is not yet
// reachable from talon, so DialRDP returns ErrRDPBackendNotWired. Unlike
// the SSH path there is no universal dev-loopback equivalent (no
// ubiquitous "plain RDP server" analogous to sshd that emits a
// canvas-ready frame stream without the ironrdp/guacd decode jess owns),
// so the dev path is a synthetic frame generator gated behind an explicit
// flag — see jessRDPBackend.DialRDP. Everything ABOVE this interface
// (auth, channel gate, WebSocket framing, the relay loop, the
// clipboard/file-transfer policy seam, the recording tee) is real and
// tested. See README/remaining.
type RDPBackend interface {
	// DialRDP opens a backend RDP session for req. The returned RDPConn is
	// a bidirectional, message-framed stream: ReadFrame yields
	// server->canvas graphics/clipboard events; WriteInput delivers
	// canvas->server pointer/keyboard/clipboard events. The caller closes
	// the RDPConn when the WebSocket relay ends.
	DialRDP(ctx context.Context, req RDPDialRequest) (RDPConn, error)
}

// RDPDialRequest carries everything the backend needs to open + audit a
// brokered desktop session. The identity fields are projected from the
// verified Talon IAP identity token (never trusted from the client), so
// jess can bind the recording + JIT decision to the real subject. It is
// the RDP analogue of DialRequest.
type RDPDialRequest struct {
	// Subject is the Falcon-ID iam_users.id (JWT sub) of the authenticated
	// user. Load-bearing for jess audit + JIT.
	Subject string
	// Email + TenantID are surfaced for the jess recording metadata.
	Email    string
	TenantID string
	// SessionID is the Talon session UUID (JWT sid) — lets jess join its
	// recording to Talon's audit trail.
	SessionID string
	// SSOChainID spans Talon <-> jess <-> recording logs.
	SSOChainID string

	// Target is the logical RDP target the user requested (e.g.
	// "win-jump.internal" or a jess target handle). The broker passes it
	// through verbatim; jess resolves + authorises it.
	Target string
	// User is the remote Windows login the user requested on the target.
	User string

	// Width/Height are the initial canvas geometry (device pixels) from the
	// browser. jess negotiates the closest RDP desktop size.
	Width  uint16
	Height uint16

	// Policy is the clipboard/file-transfer policy the relay enforces at the
	// edge (ADR 0044 "Data exfil"). It is resolved from the route/JIT grant,
	// never from the client. jess MAY additionally enforce server-side; the
	// relay enforcement is defence-in-depth at the trust boundary.
	Policy RDPDataPolicy
}

// RDPConn is the bidirectional, message-framed stream to the backend RDP
// session. It is the RDP analogue of BackendConn, but message-oriented
// rather than byte-oriented: the broker never re-chunks a frame, it
// forwards each decoded backend frame as one WebSocket binary message and
// each client input event as one WriteInput call.
type RDPConn interface {
	io.Closer
	// ReadFrame returns the next server->canvas message (a graphics tile,
	// a full-frame update, a cursor change, or a server clipboard offer).
	// It blocks until a frame is available; it returns io.EOF when the
	// backend session ends.
	ReadFrame() (RDPServerMsg, error)
	// WriteInput delivers a canvas->server input event (pointer, keyboard,
	// or a client clipboard offer). The relay calls this only AFTER the
	// clipboard/file-transfer policy has admitted the event.
	WriteInput(RDPClientMsg) error
}

// RDPServerMsg is one decoded server->canvas message. Kind discriminates
// the payload. The relay forwards it verbatim to the browser (as the
// binary wire envelope; see rdprelay.go) except that clipboard/file
// messages pass through the policy seam first.
type RDPServerMsg struct {
	// Kind is one of the RDPMsg* server kinds.
	Kind RDPMsgKind
	// X/Y/W/H locate a graphics tile (Kind == RDPMsgTile) within the
	// canvas; ignored for non-tile kinds.
	X, Y, W, H uint16
	// Data carries the kind-specific payload: for RDPMsgTile / RDPMsgFrame
	// it is the encoded image bytes (jess decides the codec — PNG in the
	// scaffold synthetic path); for RDPMsgClipboard it is the offered
	// clipboard text/bytes; for RDPMsgCursor it is the cursor image.
	Data []byte
}

// RDPClientMsg is one canvas->server input event decoded from the browser
// WebSocket. Kind discriminates the payload.
type RDPClientMsg struct {
	// Kind is one of the RDPMsg* client kinds.
	Kind RDPMsgKind
	// X/Y are pointer coordinates (canvas pixels) for RDPMsgPointer.
	X, Y uint16
	// Button is the pointer button mask / wheel delta for RDPMsgPointer.
	Button uint16
	// Down is the press/release flag for pointer + key events.
	Down bool
	// KeyCode is the scancode for RDPMsgKey.
	KeyCode uint16
	// Data carries the clipboard payload for RDPMsgClipboard (client->server
	// paste) or the file chunk for RDPMsgFile.
	Data []byte
}

// RDPMsgKind enumerates the message kinds carried both ways across the
// relay. Server kinds and client kinds share the enum so the wire codec
// has a single discriminator byte; the relay validates direction.
type RDPMsgKind uint8

const (
	// RDPMsgInvalid is the zero value — an undecodable / unset message.
	RDPMsgInvalid RDPMsgKind = 0

	// --- server -> canvas ---
	// RDPMsgTile is a partial graphics update (a rectangle of the desktop).
	RDPMsgTile RDPMsgKind = 1
	// RDPMsgFrame is a full-desktop frame (e.g. the initial paint).
	RDPMsgFrame RDPMsgKind = 2
	// RDPMsgCursor is a pointer-shape change.
	RDPMsgCursor RDPMsgKind = 3
	// RDPMsgServerClipboard is a server->client clipboard offer (copy on
	// the remote desktop). Gated by the outbound clipboard policy.
	RDPMsgServerClipboard RDPMsgKind = 4

	// --- canvas -> server ---
	// RDPMsgPointer is a mouse move / button / wheel event.
	RDPMsgPointer RDPMsgKind = 10
	// RDPMsgKey is a keyboard scancode press/release.
	RDPMsgKey RDPMsgKind = 11
	// RDPMsgClientClipboard is a client->server clipboard paste. Gated by
	// the inbound clipboard policy.
	RDPMsgClientClipboard RDPMsgKind = 12
	// RDPMsgFile is a file-transfer chunk (either direction is gated). The
	// scaffold relay rejects these unless the policy admits file transfer.
	RDPMsgFile RDPMsgKind = 13
)

// RDPDataPolicy is the clipboard/file-transfer policy enforced at the
// relay edge. This is the ADR 0044 "Data exfil" control point: an
// agent-based client can't enforce it because there's no relay in the
// path, but the broker sits squarely on the wire and can drop
// clipboard/file events per direction. Default zero value is the most
// restrictive (everything denied) so a misconfigured route fails closed.
type RDPDataPolicy struct {
	// ClipboardToClient allows server->client clipboard (copy from the
	// remote desktop to the browser). Default false = denied.
	ClipboardToClient bool
	// ClipboardToServer allows client->server clipboard (paste from the
	// browser into the remote desktop). Default false = denied.
	ClipboardToServer bool
	// FileTransfer allows the (drive-redirection) file-transfer channel in
	// either direction. Default false = denied. The scaffold relay drops
	// every RDPMsgFile when this is false.
	FileTransfer bool
}

// JessRDPBackendConfig parameterises the (currently stub) jess RDP backend.
type JessRDPBackendConfig struct {
	// BrokerAddr is the jess RDP-broker address the production path will
	// dial once jess exposes it (host:port over Linkerd mTLS). Empty in the
	// Phase 3 scaffold — the production dial is STUBBED.
	BrokerAddr string

	// DevSynthetic, when true, makes DialRDP return a synthetic in-process
	// RDPConn that paints a slowly-changing canvas + echoes clipboard, so
	// the FULL real relay path (WebSocket <-> RDPConn, policy seam,
	// recording tee, canvas client) can be exercised locally WITHOUT a real
	// Windows host or the jess decode. NEVER set in production; it produces
	// no real desktop and bypasses jess policy + recording.
	DevSynthetic bool

	// DialTimeout bounds the backend connect. Zero -> 10s.
	DialTimeout time.Duration
}

// jessRDPBackend is the RDPBackend that (eventually) brokers to jess. In
// the Phase 3 scaffold it has two modes:
//
//   - dev synthetic (DevSynthetic true): an in-process synthetic RDPConn,
//     so the whole relay + canvas client is exercised end-to-end. Used for
//     local testing only; bypasses jess.
//   - production (BrokerAddr only): STUBBED — returns ErrRDPBackendNotWired,
//     because the jess RDP broker is not yet callable from talon. This is
//     the single clearly-marked stub seam.
type jessRDPBackend struct {
	cfg JessRDPBackendConfig
}

// NewJessRDPBackend constructs the jess RDP RDPBackend. See
// JessRDPBackendConfig for the dev-synthetic vs production-stub behaviour.
func NewJessRDPBackend(cfg JessRDPBackendConfig) RDPBackend {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &jessRDPBackend{cfg: cfg}
}

// DialRDP implements RDPBackend. With DevSynthetic it returns the synthetic
// canvas connection; otherwise it returns ErrRDPBackendNotWired (the jess
// broker path is the documented stub).
func (b *jessRDPBackend) DialRDP(ctx context.Context, req RDPDialRequest) (RDPConn, error) {
	if b.cfg.DevSynthetic {
		return newSyntheticRDPConn(ctx, req), nil
	}
	// PRODUCTION PATH — STUBBED. The jess RDP broker is not yet reachable
	// from talon. When it is, replace this branch with the broker dial
	// (mTLS to b.cfg.BrokerAddr, forwarding req's identity for jess JIT +
	// recording, negotiating the desktop size, then streaming the decoded
	// frame protocol). The relay above this seam needs ZERO changes.
	return nil, ErrRDPBackendNotWired
}

// ErrRDPBackendNotWired is returned by the stub jess RDP backend when no
// dev synthetic mode is configured. It signals "the relay path is real but
// the jess RDP broker is not reachable yet" — surfaced to the browser as a
// clean 1011 close with this reason, never a silent hang. It is the RDP
// analogue of ErrBackendNotWired.
var ErrRDPBackendNotWired = errors.New("accessbroker: jess RDP backend not wired (Phase 3 stub) — enable dev synthetic mode to exercise the relay")

// errNilRDPBackend is returned by NewRDPHandler when the RDP backend
// dependency is missing. The broker fails closed at construction rather
// than serving an undialable desktop at runtime.
var errNilRDPBackend = errors.New("accessbroker: RDPHandlerConfig.Backend is required")

// normalizeCanvasGeometry clamps a canvas geometry to sane bounds so a
// malformed size from the browser can't request a 0x0 or absurdly large
// desktop. Mirrors normalizeGeometry for the terminal path.
func normalizeCanvasGeometry(w, h uint16) (uint16, uint16) {
	if w == 0 || w > 8192 {
		w = 1280
	}
	if h == 0 || h > 8192 {
		h = 720
	}
	return w, h
}
