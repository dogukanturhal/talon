// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

// outputChunk is the read buffer size for backend->terminal output. 32
// KiB matches the typical SSH channel window granularity and keeps
// per-frame WebSocket overhead negligible while staying small enough
// that an interactive prompt flushes promptly.
const outputChunk = 32 * 1024

// clientMsg is the JSON envelope the browser sends on TEXT frames. Two
// types:
//
//	{"type":"input","data":"<base64 keystrokes>"}
//	{"type":"resize","cols":120,"rows":40}
//
// Input bytes are base64-encoded so arbitrary control characters survive
// the JSON+UTF-8 text-frame round trip without escaping ambiguity. The
// browser MAY instead send raw keystrokes on a BINARY frame (the relay
// accepts both); the JSON envelope is the canonical control channel for
// resize.
type clientMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// RelayConfig parameterises a single browser<->backend relay.
type RelayConfig struct {
	// RecordSink, when non-nil, receives a copy of every backend->terminal
	// output chunk (the tee to jess session recording, ADR 0030). Errors
	// from the sink are logged by the caller but never break the relay —
	// recording is best-effort at the relay edge; jess is the durable
	// authority. nil disables the tee (dev/test).
	RecordSink io.Writer

	// MaxDuration, when > 0, hard-caps the brokered session lifetime
	// (the clientless absolute TTL from ADR 0044). When it elapses the
	// relay closes both sides with a 1000 normal closure.
	MaxDuration time.Duration
}

// relayResult summarises why a relay ended, for the caller's audit log.
type relayResult struct {
	// Reason is a short machine-readable cause: "client_close",
	// "backend_eof", "deadline", "error".
	Reason string
	// Err is the underlying transport error, if any (nil on a clean
	// close / EOF / deadline).
	Err error
	// BytesToBackend / BytesToClient are the relayed byte counts (for
	// audit + metrics). Recording bytes equal BytesToClient.
	BytesToBackend int64
	BytesToClient  int64
}

// runRelay pumps bytes between the WebSocket and the backend until either
// side closes, an error occurs, or MaxDuration elapses. It owns the
// goroutine lifecycle: one reader for each direction, joined before
// return. The wsConn writer is serialised through wsMu because both the
// output pump and the inline control-frame replies (pong/close) in the
// input pump can write concurrently.
func runRelay(parent context.Context, ws *wsConn, backend BackendConn, cfg RelayConfig) relayResult {
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

	// Absolute-TTL timer (ADR 0044 clientless cap). When it fires we set
	// the reason to "deadline" BEFORE cancelling, so the read/write errors
	// the cancellation then induces in the pump goroutines lose the
	// first-cause race — the session is correctly attributed to the TTL,
	// not to the teardown's incidental transport error.
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

	// backend -> terminal (+ recording tee)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, outputChunk)
		for {
			n, err := backend.Read(buf)
			if n > 0 {
				resMu.Lock()
				res.BytesToClient += int64(n)
				resMu.Unlock()
				if cfg.RecordSink != nil {
					// Best-effort tee; a slow/broken recorder must not
					// stall the user's terminal, so we ignore its error
					// here (the caller surfaces sink health separately).
					_, _ = cfg.RecordSink.Write(buf[:n])
				}
				if werr := writeWS(buf[:n]); werr != nil {
					setReason("error", werr)
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					setReason("backend_eof", nil)
				} else {
					setReason("error", err)
				}
				return
			}
			if ctx.Err() != nil {
				setReason(deadlineReason(parent, ctx), nil)
				return
			}
		}
	}()

	// terminal -> backend
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			msg, err := ws.ReadMessage()
			if err != nil {
				if errors.Is(err, ErrConnClosed) {
					setReason("client_close", nil)
				} else {
					setReason("error", err)
				}
				return
			}
			data, resize, ok := decodeClientFrame(msg)
			if !ok {
				// Unparseable control frame — ignore rather than kill the
				// session; a stray malformed message shouldn't drop a
				// live shell.
				continue
			}
			if resize != nil {
				_ = backend.Resize(resize.Cols, resize.Rows)
				continue
			}
			if len(data) == 0 {
				continue
			}
			if _, werr := backend.Write(data); werr != nil {
				setReason("error", werr)
				return
			}
			resMu.Lock()
			res.BytesToBackend += int64(len(data))
			resMu.Unlock()
		}
	}()

	// When the context is cancelled (deadline or one side ended), unblock
	// the readers by closing both endpoints.
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

// resizeMsg is the decoded resize control.
type resizeMsg struct {
	Cols uint16
	Rows uint16
}

// decodeClientFrame interprets a client message. A BINARY frame is raw
// keystrokes. A TEXT frame is the JSON control envelope: type=input
// (base64 data) or type=resize. Returns (inputBytes, resize, ok). ok is
// false only for a malformed TEXT/JSON frame.
func decodeClientFrame(msg message) (input []byte, resize *resizeMsg, ok bool) {
	if msg.opcode == opBinary {
		return msg.payload, nil, true
	}
	// TEXT — parse the JSON envelope.
	var m clientMsg
	if err := json.Unmarshal(msg.payload, &m); err != nil {
		return nil, nil, false
	}
	switch m.Type {
	case "resize":
		return nil, &resizeMsg{Cols: m.Cols, Rows: m.Rows}, true
	case "input", "":
		if m.Data == "" {
			return nil, nil, true
		}
		decoded, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			// Tolerate a non-base64 input payload by treating it as raw
			// text (some simple clients send plain strings).
			return []byte(m.Data), nil, true
		}
		return decoded, nil, true
	default:
		return nil, nil, false
	}
}

// deadlineReason classifies a context cancellation: a parent-cancelled
// context ("client_close"/caller-driven) vs the relay's own MaxDuration
// timer ("deadline").
func deadlineReason(parent, child context.Context) string {
	if parent.Err() != nil {
		return "client_close"
	}
	if child.Err() != nil {
		return "deadline"
	}
	return "backend_eof"
}
