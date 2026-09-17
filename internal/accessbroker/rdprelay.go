// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

// RDP wire envelope (broker <-> browser).
//
// Graphics throughput dominates the server->client direction, so that
// direction uses a compact binary envelope rather than JSON (mirroring the
// SSH relay's choice of BINARY frames for the data path). The client->server
// direction carries small, infrequent input events and accepts BOTH the
// same binary envelope AND a JSON envelope (so a hand-written canvas client
// can speak JSON for clarity, exactly as the xterm.js client does for the
// terminal path).
//
// Binary envelope layout (network byte order):
//
//	byte  0      : kind  (RDPMsgKind)
//	bytes 1..2   : x      (uint16)   — meaningful for tiles/pointer
//	bytes 3..4   : y      (uint16)
//	bytes 5..6   : w  / button (uint16) — w for tiles, button mask for pointer
//	bytes 7..8   : h  / keyCode (uint16) — h for tiles, scancode for keys
//	byte  9      : flags  (bit0 = Down, for pointer/key press-release)
//	bytes 10..   : data   (kind-specific payload: image bytes / clipboard)
//
// A frame shorter than the 10-byte header is malformed and dropped (never
// fatal — a stray malformed message must not drop a live desktop session,
// matching the terminal relay's tolerance).
const rdpHeaderLen = 10

// rdpClientMsgJSON is the JSON envelope a canvas client MAY send on a TEXT
// frame instead of the binary envelope. base64 is used for clipboard data
// so arbitrary bytes survive the JSON+UTF-8 text round trip (same rationale
// as the terminal relay's input encoding).
type rdpClientMsgJSON struct {
	Type    string `json:"type"` // "pointer" | "key" | "clipboard" | "file"
	X       uint16 `json:"x,omitempty"`
	Y       uint16 `json:"y,omitempty"`
	Button  uint16 `json:"button,omitempty"`
	KeyCode uint16 `json:"keyCode,omitempty"`
	Down    bool   `json:"down,omitempty"`
	Data    string `json:"data,omitempty"` // base64
}

// ClipboardPolicyGate is the relay-edge enforcement seam for
// clipboard/file-transfer policy (ADR 0044 "Data exfil"). The relay calls
// it for every clipboard/file event in each direction; a false return
// drops the event before it crosses the trust boundary. Splitting it out
// (rather than inlining the policy) keeps the relay testable and lets a
// deployment swap in a richer policy (e.g. content scanning, per-tenant
// rules) without touching the relay loop. The default gate
// (rdpPolicyGate{policy}) enforces the RDPDataPolicy booleans.
type ClipboardPolicyGate interface {
	// AllowClipboardToClient reports whether a server->browser clipboard
	// offer may be forwarded (remote desktop copy -> browser).
	AllowClipboardToClient() bool
	// AllowClipboardToServer reports whether a browser->server clipboard
	// paste may be forwarded (browser paste -> remote desktop).
	AllowClipboardToServer() bool
	// AllowFileTransfer reports whether a file-transfer chunk (either
	// direction) may be forwarded.
	AllowFileTransfer() bool
}

// rdpPolicyGate is the default ClipboardPolicyGate backed by RDPDataPolicy.
type rdpPolicyGate struct{ p RDPDataPolicy }

func (g rdpPolicyGate) AllowClipboardToClient() bool { return g.p.ClipboardToClient }
func (g rdpPolicyGate) AllowClipboardToServer() bool { return g.p.ClipboardToServer }
func (g rdpPolicyGate) AllowFileTransfer() bool      { return g.p.FileTransfer }

// RDPRelayConfig parameterises a single browser<->backend RDP relay.
type RDPRelayConfig struct {
	// Policy gates clipboard/file events at the relay edge. nil -> a
	// deny-all gate (fail closed), so a relay started without an explicit
	// policy never leaks clipboard/file data.
	Policy ClipboardPolicyGate

	// RecordSink, when non-nil, receives a copy of every server->canvas
	// frame's wire envelope (the tee to jess session recording, ADR 0030).
	// Errors from the sink are swallowed — recording is best-effort at the
	// relay edge; jess is the durable authority. nil disables the tee.
	RecordSink io.Writer

	// MaxDuration, when > 0, hard-caps the brokered session lifetime (the
	// clientless absolute TTL from ADR 0044). When it elapses the relay
	// closes both sides with a 1000 normal closure.
	MaxDuration time.Duration

	// Metrics, when non-nil, counts policy-dropped clipboard/file events by
	// reason so a dashboard can show exfil attempts blocked at the edge.
	Metrics *Metrics
}

// runRDPRelay pumps messages between the WebSocket and the RDP backend
// until either side closes, an error occurs, or MaxDuration elapses. It is
// the RDP analogue of runRelay: one reader goroutine per direction, joined
// before return, writes to the wsConn serialised through a mutex. The
// clipboard/file-transfer policy is enforced inline in BOTH directions.
func runRDPRelay(parent context.Context, ws *wsConn, backend RDPConn, cfg RDPRelayConfig) relayResult {
	gate := cfg.Policy
	if gate == nil {
		// Fail closed: no policy => deny clipboard + file in both directions.
		gate = rdpPolicyGate{}
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var (
		res   relayResult
		resMu sync.Mutex
		wg    sync.WaitGroup
	)
	setReason := func(reason string, err error) {
		resMu.Lock()
		defer resMu.Unlock()
		if res.Reason == "" { // first cause wins
			res.Reason = reason
			res.Err = err
		}
	}

	// Absolute-TTL timer (ADR 0044 clientless cap). Same first-cause
	// ordering as runRelay: set "deadline" BEFORE cancel so the teardown's
	// incidental transport errors lose the race.
	if cfg.MaxDuration > 0 {
		t := time.AfterFunc(cfg.MaxDuration, func() {
			setReason("deadline", nil)
			cancel()
		})
		defer t.Stop()
	}

	var wsMu sync.Mutex
	writeWS := func(b []byte) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return ws.WriteBinary(b)
	}

	// backend -> canvas (+ recording tee, + outbound clipboard policy)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			msg, err := backend.ReadFrame()
			if err != nil {
				if errors.Is(err, io.EOF) {
					setReason("backend_eof", nil)
				} else {
					setReason("error", err)
				}
				return
			}
			// Outbound clipboard/file policy seam (remote desktop -> browser).
			if !admitServerMsg(gate, msg.Kind, cfg.Metrics) {
				continue
			}
			env := encodeServerMsg(msg)
			resMu.Lock()
			res.BytesToClient += int64(len(env))
			resMu.Unlock()
			if cfg.RecordSink != nil {
				_, _ = cfg.RecordSink.Write(env)
			}
			if werr := writeWS(env); werr != nil {
				setReason("error", werr)
				return
			}
			if ctx.Err() != nil {
				setReason(deadlineReason(parent, ctx), nil)
				return
			}
		}
	}()

	// canvas -> backend (+ inbound clipboard/file policy)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			wsMsg, err := ws.ReadMessage()
			if err != nil {
				if errors.Is(err, ErrConnClosed) {
					setReason("client_close", nil)
				} else {
					setReason("error", err)
				}
				return
			}
			cmsg, ok := decodeRDPClientFrame(wsMsg)
			if !ok {
				// Malformed event — ignore rather than kill a live desktop.
				continue
			}
			// Inbound clipboard/file policy seam (browser -> remote desktop).
			if !admitClientMsg(gate, cmsg.Kind, cfg.Metrics) {
				continue
			}
			if werr := backend.WriteInput(cmsg); werr != nil {
				setReason("error", werr)
				return
			}
			resMu.Lock()
			res.BytesToBackend += int64(rdpHeaderLen + len(cmsg.Data))
			resMu.Unlock()
		}
	}()

	// Unblock the readers on context cancel by closing both endpoints.
	go func() {
		<-ctx.Done()
		_ = backend.Close()
		_ = ws.Close()
	}()

	wg.Wait()
	if res.Reason == "" {
		res.Reason = deadlineReason(parent, ctx)
	}
	return res
}

// admitServerMsg applies the outbound (remote->browser) policy. Graphics +
// cursor are always admitted; clipboard is gated; file transfer is gated.
func admitServerMsg(gate ClipboardPolicyGate, kind RDPMsgKind, m *Metrics) bool {
	switch kind {
	case RDPMsgServerClipboard:
		if !gate.AllowClipboardToClient() {
			policyDrop(m, "clipboard_to_client")
			return false
		}
	case RDPMsgFile:
		if !gate.AllowFileTransfer() {
			policyDrop(m, "file_to_client")
			return false
		}
	}
	return true
}

// admitClientMsg applies the inbound (browser->remote) policy. Pointer +
// key are always admitted; clipboard is gated; file transfer is gated.
func admitClientMsg(gate ClipboardPolicyGate, kind RDPMsgKind, m *Metrics) bool {
	switch kind {
	case RDPMsgClientClipboard:
		if !gate.AllowClipboardToServer() {
			policyDrop(m, "clipboard_to_server")
			return false
		}
	case RDPMsgFile:
		if !gate.AllowFileTransfer() {
			policyDrop(m, "file_to_server")
			return false
		}
	}
	return true
}

// policyDrop records a relay-edge policy drop on the metrics sink (if any).
func policyDrop(m *Metrics, reason string) {
	if m != nil && m.PolicyDrops != nil {
		m.PolicyDrops.WithLabelValues(reason).Inc()
	}
}

// encodeServerMsg serialises an RDPServerMsg into the binary wire envelope.
func encodeServerMsg(msg RDPServerMsg) []byte {
	out := make([]byte, rdpHeaderLen+len(msg.Data))
	out[0] = byte(msg.Kind)
	binary.BigEndian.PutUint16(out[1:3], msg.X)
	binary.BigEndian.PutUint16(out[3:5], msg.Y)
	binary.BigEndian.PutUint16(out[5:7], msg.W)
	binary.BigEndian.PutUint16(out[7:9], msg.H)
	out[9] = 0 // flags unused server->client
	copy(out[rdpHeaderLen:], msg.Data)
	return out
}

// decodeRDPClientFrame interprets a client WebSocket message as an
// RDPClientMsg. A BINARY frame is the binary envelope; a TEXT frame is the
// JSON envelope. Returns (msg, ok); ok is false for a malformed/short frame
// (the relay then ignores it).
func decodeRDPClientFrame(wsMsg message) (RDPClientMsg, bool) {
	if wsMsg.opcode == opBinary {
		return decodeRDPBinary(wsMsg.payload)
	}
	return decodeRDPJSON(wsMsg.payload)
}

// decodeRDPBinary decodes the binary wire envelope into an RDPClientMsg.
func decodeRDPBinary(b []byte) (RDPClientMsg, bool) {
	if len(b) < rdpHeaderLen {
		return RDPClientMsg{}, false
	}
	kind := RDPMsgKind(b[0])
	if !isClientKind(kind) {
		return RDPClientMsg{}, false
	}
	return RDPClientMsg{
		Kind:    kind,
		X:       binary.BigEndian.Uint16(b[1:3]),
		Y:       binary.BigEndian.Uint16(b[3:5]),
		Button:  binary.BigEndian.Uint16(b[5:7]),
		KeyCode: binary.BigEndian.Uint16(b[7:9]),
		Down:    b[9]&0x01 != 0,
		Data:    append([]byte(nil), b[rdpHeaderLen:]...),
	}, true
}

// decodeRDPJSON decodes the JSON envelope into an RDPClientMsg.
func decodeRDPJSON(payload []byte) (RDPClientMsg, bool) {
	var m rdpClientMsgJSON
	if err := json.Unmarshal(payload, &m); err != nil {
		return RDPClientMsg{}, false
	}
	var kind RDPMsgKind
	switch m.Type {
	case "pointer":
		kind = RDPMsgPointer
	case "key":
		kind = RDPMsgKey
	case "clipboard":
		kind = RDPMsgClientClipboard
	case "file":
		kind = RDPMsgFile
	default:
		return RDPClientMsg{}, false
	}
	var data []byte
	if m.Data != "" {
		if dec, err := base64.StdEncoding.DecodeString(m.Data); err == nil {
			data = dec
		} else {
			// Tolerate a non-base64 payload as raw bytes (simple clients).
			data = []byte(m.Data)
		}
	}
	return RDPClientMsg{
		Kind:    kind,
		X:       m.X,
		Y:       m.Y,
		Button:  m.Button,
		KeyCode: m.KeyCode,
		Down:    m.Down,
		Data:    data,
	}, true
}

// isClientKind reports whether kind is a valid canvas->server kind. The
// relay rejects a binary frame claiming a server-only kind (direction
// confusion / a malicious client trying to inject a server clipboard
// offer).
func isClientKind(kind RDPMsgKind) bool {
	switch kind {
	case RDPMsgPointer, RDPMsgKey, RDPMsgClientClipboard, RDPMsgFile:
		return true
	default:
		return false
	}
}
