// SPDX-License-Identifier: AGPL-3.0-or-later

// Package accessbroker implements the Talon clientless access-broker
// (ADR 0044 Phase 2). It terminates the browser WebSocket of an
// agentless ("clientless") session, authenticates the Talon IAP
// identity token (the signed X-Talon-Identity-Token JWT minted by
// internal/identityjwt — the Phase-C bearer the desktop SDK already
// consumes), opens a backend SSH stream via the jess broker, and relays
// frames between the two while teeing the stream to jess session
// recording.
//
// The broker is deliberately a thin, stateless relay: jess remains the
// policy + recording authority (ADR 0049 / ADR 0030). The browser is a
// dumb terminal (xterm.js, served from web/); the broker never
// interprets the SSH payload, it only forwards bytes and enforces the
// auth + channel gate at the edge.
//
// This file carries a minimal, server-side-only RFC 6455 WebSocket
// implementation. We hand-roll the handshake + frame codec rather than
// pull in a third-party WebSocket library because the broker's needs are
// narrow (accept one client connection, exchange binary/text/ping/close
// frames, no client-mode, no per-message-deflate) and because Talon's
// supply chain stays smaller. The codec is fully unit-tested against the
// RFC's framing rules (FIN/opcode/mask/length wire shapes).
package accessbroker

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // RFC 6455 §1.3 mandates SHA-1 for the accept key; not a security primitive.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// wsGUID is the RFC 6455 §1.3 magic string concatenated with the
// client's Sec-WebSocket-Key before SHA-1 to derive Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket opcodes (RFC 6455 §5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxFramePayload caps a single inbound frame's payload. A browser
// terminal sends tiny keystroke frames; anything larger than 1 MiB on
// the input side is a misbehaving or hostile client, so we close rather
// than allocate. The relay's terminal->backend direction never needs
// large frames; backend->terminal output is chunked by the relay.
const maxFramePayload = 1 << 20 // 1 MiB

// Close status codes (RFC 6455 §7.4.1) used by the broker.
const (
	closeNormalClosure = 1000
	closeGoingAway     = 1001
	closeProtocolError = 1002
	closeMessageTooBig = 1009
	closeInternalErr   = 1011
)

var (
	// errNotWebSocketUpgrade is returned by Accept when the request is
	// not a well-formed WebSocket upgrade. Callers respond 400.
	errNotWebSocketUpgrade = errors.New("accessbroker: not a websocket upgrade request")

	// errResponseNotHijackable is returned when the http.ResponseWriter
	// does not implement http.Hijacker (e.g. HTTP/2). The broker requires
	// HTTP/1.1 for the raw-conn relay.
	errResponseNotHijackable = errors.New("accessbroker: response writer does not support hijacking")

	// ErrConnClosed is returned by wsConn.ReadMessage once the peer has
	// sent a Close frame (or the connection is otherwise done). Callers
	// branch on errors.Is to distinguish a clean close from a transport
	// error.
	ErrConnClosed = errors.New("accessbroker: websocket connection closed")
)

// wsConn is a server-side RFC 6455 connection over a hijacked net.Conn.
// It is NOT safe for concurrent ReadMessage calls, nor for concurrent
// WriteMessage calls; the relay loop uses exactly one reader goroutine
// and one writer goroutine, with writes serialised through a mutex held
// by the relay (see relay.go). Control frames (ping/pong/close) are
// handled inline by ReadMessage.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	// idleTimeout, when > 0, sets a read deadline before every frame
	// read so a wedged client cannot pin a goroutine forever.
	idleTimeout time.Duration

	closeSent bool
}

// isWebSocketUpgrade reports whether r carries the RFC 6455 §4.1
// client-handshake headers. Header matching is case-insensitive and
// token-aware (Connection is a comma-separated list).
func isWebSocketUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Key") == "" {
		return false
	}
	// RFC 6455 §4.1: the version MUST be 13.
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	return true
}

// headerContainsToken reports whether the comma-separated header value
// contains token (case-insensitive). Used for the Connection: upgrade
// check, which browsers may send as "keep-alive, Upgrade".
func headerContainsToken(headerValue, token string) bool {
	for _, part := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// computeAcceptKey derives the Sec-WebSocket-Accept response header from
// the client's Sec-WebSocket-Key per RFC 6455 §4.2.2 step 5.
func computeAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec // mandated by RFC 6455, not a security control.
	_, _ = io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// acceptWebSocket performs the server side of the RFC 6455 handshake on
// an already-validated upgrade request, hijacks the connection, writes
// the 101 response, and returns a ready wsConn.
//
// idleTimeout, when > 0, is applied as a read deadline before each frame
// read for the life of the connection.
func acceptWebSocket(w http.ResponseWriter, r *http.Request, idleTimeout time.Duration) (*wsConn, error) {
	if !isWebSocketUpgrade(r) {
		return nil, errNotWebSocketUpgrade
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errResponseNotHijackable
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("accessbroker: hijack: %w", err)
	}
	accept := computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
	// Write the 101 Switching Protocols handshake response by hand —
	// after Hijack the http server no longer manages this conn.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("accessbroker: write handshake: %w", err)
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("accessbroker: flush handshake: %w", err)
	}
	return &wsConn{
		conn:        conn,
		br:          brw.Reader,
		bw:          brw.Writer,
		idleTimeout: idleTimeout,
	}, nil
}

// message is a fully-reassembled application message read off the wire.
type message struct {
	opcode  byte // opText or opBinary
	payload []byte
}

// ReadMessage reads the next application (text/binary) message, handling
// control frames (ping->pong, close) inline. It blocks until a data
// message arrives or the connection closes. On a peer Close frame it
// returns ErrConnClosed (after replying with a Close of its own).
//
// Fragmentation (RFC 6455 §5.4) is supported: a sequence of
// continuation frames is reassembled into one message.
func (c *wsConn) ReadMessage() (message, error) {
	var (
		assembled  []byte
		dataOpcode byte
		inFragment bool
	)
	for {
		fr, err := c.readFrame()
		if err != nil {
			return message{}, err
		}
		switch fr.opcode {
		case opPing:
			if err := c.writeFrame(opPong, fr.payload); err != nil {
				return message{}, err
			}
		case opPong:
			// Unsolicited pong — RFC 6455 §5.5.3 allows; ignore.
		case opClose:
			c.handlePeerClose(fr.payload)
			return message{}, ErrConnClosed
		case opText, opBinary:
			if inFragment {
				return message{}, c.protocolError("data frame during fragmented message")
			}
			if fr.fin {
				return message{opcode: fr.opcode, payload: fr.payload}, nil
			}
			inFragment = true
			dataOpcode = fr.opcode
			assembled = append(assembled, fr.payload...)
		case opContinuation:
			if !inFragment {
				return message{}, c.protocolError("continuation frame outside a fragmented message")
			}
			assembled = append(assembled, fr.payload...)
			if len(assembled) > maxFramePayload {
				_ = c.WriteClose(closeMessageTooBig, "message too big")
				return message{}, ErrConnClosed
			}
			if fr.fin {
				return message{opcode: dataOpcode, payload: assembled}, nil
			}
		default:
			return message{}, c.protocolError(fmt.Sprintf("unknown opcode 0x%x", fr.opcode))
		}
	}
}

// frame is a single decoded WebSocket frame.
type frame struct {
	fin     bool
	opcode  byte
	payload []byte
}

// readFrame reads and unmasks one frame. Server-received frames MUST be
// masked (RFC 6455 §5.1); an unmasked client frame is a protocol error.
func (c *wsConn) readFrame() (frame, error) {
	if c.idleTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return frame{}, err
	}
	fin := hdr[0]&0x80 != 0
	rsv := hdr[0] & 0x70
	if rsv != 0 {
		// No extensions negotiated, so reserved bits MUST be zero.
		return frame{}, c.protocolError("reserved bits set")
	}
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	if !masked {
		return frame{}, c.protocolError("client frame not masked")
	}
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	// Control frames (>= 0x8) MUST have payload <= 125 and MUST NOT be
	// fragmented (RFC 6455 §5.5).
	if opcode >= opClose {
		if length > 125 {
			return frame{}, c.protocolError("control frame payload too large")
		}
		if !fin {
			return frame{}, c.protocolError("fragmented control frame")
		}
	}
	if length > maxFramePayload {
		_ = c.WriteClose(closeMessageTooBig, "frame too big")
		return frame{}, ErrConnClosed
	}
	var maskKey [4]byte
	if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
		return frame{}, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return frame{}, err
	}
	for i := range payload {
		payload[i] ^= maskKey[i&3]
	}
	return frame{fin: fin, opcode: opcode, payload: payload}, nil
}

// WriteMessage writes a single, unfragmented data message (text or
// binary). Server-sent frames are never masked (RFC 6455 §5.1).
func (c *wsConn) WriteMessage(opcode byte, payload []byte) error {
	return c.writeFrame(opcode, payload)
}

// WriteText is a convenience wrapper for a UTF-8 text message.
func (c *wsConn) WriteText(s string) error { return c.writeFrame(opText, []byte(s)) }

// WriteBinary is a convenience wrapper for a binary message.
func (c *wsConn) WriteBinary(b []byte) error { return c.writeFrame(opBinary, b) }

// writeFrame serialises one unmasked, FIN=1 frame to the wire.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | opcode // FIN + opcode
	n := 2
	switch {
	case len(payload) <= 125:
		hdr[1] = byte(len(payload)) //nolint:gosec // G115: guarded by the <=125 case — no overflow.
	case len(payload) <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload))) //nolint:gosec // G115: guarded by the <=0xffff case — no overflow.
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(payload)))
		n = 10
	}
	if _, err := c.bw.Write(hdr[:n]); err != nil {
		return err
	}
	if _, err := c.bw.Write(payload); err != nil {
		return err
	}
	return c.bw.Flush()
}

// WriteClose sends a Close frame with the given status code + reason and
// records that a close has been sent (so a subsequent close is a no-op).
func (c *wsConn) WriteClose(code uint16, reason string) error {
	if c.closeSent {
		return nil
	}
	c.closeSent = true
	body := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(body[:2], code)
	copy(body[2:], reason)
	return c.writeFrame(opClose, body)
}

// handlePeerClose replies to a peer Close frame with our own Close
// (echoing the peer's status code where present), per RFC 6455 §5.5.1.
func (c *wsConn) handlePeerClose(payload []byte) {
	code := uint16(closeNormalClosure)
	if len(payload) >= 2 {
		code = binary.BigEndian.Uint16(payload[:2])
	}
	_ = c.WriteClose(code, "")
}

// protocolError sends a 1002 close and returns ErrConnClosed wrapping a
// descriptive message for the caller's logs.
func (c *wsConn) protocolError(msg string) error {
	_ = c.WriteClose(closeProtocolError, msg)
	return fmt.Errorf("%w: protocol error: %s", ErrConnClosed, msg)
}

// Close closes the underlying transport. It first attempts a graceful
// WebSocket Close frame (1001 going away) if one has not been sent.
func (c *wsConn) Close() error {
	_ = c.WriteClose(closeGoingAway, "")
	return c.conn.Close()
}
