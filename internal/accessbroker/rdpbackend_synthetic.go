// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// syntheticRDPConn is the dev-only RDPConn used when JessRDPBackendConfig
// .DevSynthetic is set. It emits a tiny, slowly-changing synthetic frame
// stream (a heartbeat "tile" once a second carrying a textual frame
// counter) and echoes a client clipboard offer back as a server clipboard
// offer, so the FULL relay path + canvas client can be exercised end to
// end WITHOUT a real Windows host or the jess RDP decode.
//
// It deliberately does NOT render a real desktop — that is jess's job. It
// exists only to prove the relay, the policy seam, the recording tee, and
// the browser canvas wiring against a deterministic, dependency-free
// backend. NEVER reachable in production (gated by DevSynthetic, which the
// cmd flag marks dev-only and logs loudly).
type syntheticRDPConn struct {
	ctx    context.Context
	cancel context.CancelFunc

	frames chan RDPServerMsg

	mu        sync.Mutex
	closed    bool
	lastPaste []byte
}

// newSyntheticRDPConn starts the synthetic frame generator bound to ctx.
func newSyntheticRDPConn(parent context.Context, req RDPDialRequest) *syntheticRDPConn {
	ctx, cancel := context.WithCancel(parent)
	w, h := normalizeCanvasGeometry(req.Width, req.Height)
	c := &syntheticRDPConn{
		ctx:    ctx,
		cancel: cancel,
		frames: make(chan RDPServerMsg, 8),
	}
	// Initial full-frame paint so the canvas has something immediately.
	c.frames <- RDPServerMsg{
		Kind: RDPMsgFrame,
		W:    w,
		H:    h,
		Data: []byte(fmt.Sprintf("synthetic-desktop %dx%d target=%s user=%s", w, h, req.Target, req.User)),
	}
	go c.run(w, h)
	return c
}

// run emits a heartbeat tile once a second until the context is cancelled
// (relay teardown / absolute TTL) or the conn is closed.
func (c *syntheticRDPConn) run(w, h uint16) {
	defer close(c.frames)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var n int
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			n++
			msg := RDPServerMsg{
				Kind: RDPMsgTile,
				X:    0,
				Y:    0,
				W:    w,
				H:    16,
				Data: []byte(fmt.Sprintf("frame %d @ %s", n, time.Now().Format(time.RFC3339))),
			}
			select {
			case c.frames <- msg:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// ReadFrame implements RDPConn.
func (c *syntheticRDPConn) ReadFrame() (RDPServerMsg, error) {
	msg, ok := <-c.frames
	if !ok {
		return RDPServerMsg{}, io.EOF
	}
	return msg, nil
}

// WriteInput implements RDPConn. Pointer/key events are accepted and
// dropped (no real desktop to drive); a client clipboard offer is echoed
// back as a server clipboard offer on the next ReadFrame, which lets a
// round-trip clipboard test observe the policy seam in BOTH directions.
func (c *syntheticRDPConn) WriteInput(msg RDPClientMsg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	if msg.Kind == RDPMsgClientClipboard {
		c.lastPaste = append([]byte(nil), msg.Data...)
		// Echo it back as a server clipboard offer (best-effort; if the
		// frame buffer is full or the conn is closing, drop it).
		select {
		case c.frames <- RDPServerMsg{Kind: RDPMsgServerClipboard, Data: c.lastPaste}:
		default:
		}
	}
	return nil
}

// Close implements RDPConn.
func (c *syntheticRDPConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	return nil
}
