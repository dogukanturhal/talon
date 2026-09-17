// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeBackend is an in-memory BackendConn for relay tests: bytes Written
// to it are readable from a buffer the test inspects; Read returns from a
// channel the test feeds (simulating backend->terminal output). Resize is
// recorded. EOF is signalled by closing the output channel.
type fakeBackend struct {
	mu        sync.Mutex
	written   bytes.Buffer
	out       chan []byte
	pending   []byte
	resizes   []resizeMsg
	closed    bool
	closeOnce sync.Once
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{out: make(chan []byte, 16)}
}

func (f *fakeBackend) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	return f.written.Write(p)
}

func (f *fakeBackend) Read(p []byte) (int, error) {
	if len(f.pending) > 0 {
		n := copy(p, f.pending)
		f.pending = f.pending[n:]
		return n, nil
	}
	chunk, ok := <-f.out
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		f.pending = chunk[n:]
	}
	return n, nil
}

func (f *fakeBackend) Resize(cols, rows uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, resizeMsg{Cols: cols, Rows: rows})
	return nil
}

func (f *fakeBackend) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.out)
	})
	return nil
}

func (f *fakeBackend) writtenBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.written.Bytes()...)
}

func (f *fakeBackend) resizeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.resizes)
}

// --- decodeClientFrame -----------------------------------------------------

func TestDecodeClientFrame(t *testing.T) {
	bin := message{opcode: opBinary, payload: []byte{1, 2, 3}}
	if data, rs, ok := decodeClientFrame(bin); !ok || rs != nil || !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("binary: data=%v rs=%v ok=%v", data, rs, ok)
	}

	inputJSON, _ := json.Marshal(clientMsg{Type: "input", Data: base64.StdEncoding.EncodeToString([]byte("ls\n"))})
	if data, rs, ok := decodeClientFrame(message{opcode: opText, payload: inputJSON}); !ok || rs != nil || string(data) != "ls\n" {
		t.Fatalf("input json: data=%q rs=%v ok=%v", data, rs, ok)
	}

	resizeJSON, _ := json.Marshal(clientMsg{Type: "resize", Cols: 120, Rows: 40})
	if data, rs, ok := decodeClientFrame(message{opcode: opText, payload: resizeJSON}); !ok || rs == nil || data != nil || rs.Cols != 120 || rs.Rows != 40 {
		t.Fatalf("resize json: data=%v rs=%v ok=%v", data, rs, ok)
	}

	if _, _, ok := decodeClientFrame(message{opcode: opText, payload: []byte("{not json")}); ok {
		t.Fatal("malformed json should not be ok")
	}
}

// --- runRelay end-to-end with a real wsConn pair ---------------------------

// wsTestPair returns a server wsConn plus a client helper that can write
// masked frames and read server frames, over a net.Pipe.
func wsTestPair(t *testing.T) (server *wsConn, clientConn net.Conn) {
	t.Helper()
	srv, cli := net.Pipe()
	server = &wsConn{conn: srv, br: bufio.NewReader(srv), bw: bufio.NewWriter(srv)}
	return server, cli
}

// drain continuously reads (and discards) everything the server writes to
// the client side of a net.Pipe. net.Pipe writes block until read, so a
// test that doesn't read every server frame (e.g. the shutdown close
// frame) would deadlock runRelay; drain prevents that. Start it once the
// test has read whatever specific frames it needs to assert.
func drain(conn net.Conn) {
	go func() { _, _ = io.Copy(io.Discard, conn) }()
}

func TestRunRelay_TerminalToBackend(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeBackend()
	drain(cli) // discard the shutdown close frame so runRelay can exit

	done := make(chan relayResult, 1)
	go func() { done <- runRelay(context.Background(), ws, be, RelayConfig{}) }()

	// Browser sends a keystroke (JSON input envelope) then a binary frame.
	in, _ := json.Marshal(clientMsg{Type: "input", Data: base64.StdEncoding.EncodeToString([]byte("echo hi\n"))})
	if err := clientWriteFrame(cli, true, opText, in); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := clientWriteFrame(cli, true, opBinary, []byte("RAW")); err != nil {
		t.Fatalf("client write binary: %v", err)
	}

	// Give the relay a moment to drain into the backend, then end it by
	// closing the backend output (EOF) so runRelay returns.
	if !waitFor(func() bool { return bytes.Equal(be.writtenBytes(), []byte("echo hi\nRAW")) }, time.Second) {
		t.Fatalf("backend got %q, want %q", be.writtenBytes(), "echo hi\nRAW")
	}
	be.Close()

	res := <-done
	if res.BytesToBackend != int64(len("echo hi\nRAW")) {
		t.Fatalf("BytesToBackend = %d", res.BytesToBackend)
	}
}

func TestRunRelay_BackendToTerminalAndRecordTee(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeBackend()
	var rec bytes.Buffer

	done := make(chan relayResult, 1)
	go func() { done <- runRelay(context.Background(), ws, be, RelayConfig{RecordSink: &rec}) }()

	// Drain server->client frames on the client side.
	got := make(chan []byte, 1)
	go func() {
		_, payload := clientReadFrame(t, cli)
		got <- payload
	}()

	be.out <- []byte("backend output line\n")

	select {
	case p := <-got:
		if string(p) != "backend output line\n" {
			t.Fatalf("client got %q", p)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for backend->terminal frame")
	}

	drain(cli) // discard the shutdown close frame
	be.Close()
	res := <-done
	if res.Reason != "backend_eof" {
		t.Fatalf("reason = %q, want backend_eof", res.Reason)
	}
	if rec.String() != "backend output line\n" {
		t.Fatalf("record tee = %q", rec.String())
	}
	if res.BytesToClient != int64(len("backend output line\n")) {
		t.Fatalf("BytesToClient = %d", res.BytesToClient)
	}
}

func TestRunRelay_Resize(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeBackend()
	drain(cli) // discard the shutdown close frame
	done := make(chan relayResult, 1)
	go func() { done <- runRelay(context.Background(), ws, be, RelayConfig{}) }()

	rs, _ := json.Marshal(clientMsg{Type: "resize", Cols: 200, Rows: 50})
	if err := clientWriteFrame(cli, true, opText, rs); err != nil {
		t.Fatalf("write resize: %v", err)
	}
	if !waitFor(func() bool { return be.resizeCount() == 1 }, time.Second) {
		t.Fatal("backend never resized")
	}
	be.Close()
	<-done
}

func TestRunRelay_MaxDurationDeadline(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeBackend() // never produces output, never EOFs on its own
	drain(cli)             // discard the shutdown close frame
	start := time.Now()
	res := runRelay(context.Background(), ws, be, RelayConfig{MaxDuration: 60 * time.Millisecond})
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("relay returned before MaxDuration")
	}
	if res.Reason != "deadline" {
		t.Fatalf("reason = %q, want deadline", res.Reason)
	}
}

func TestRunRelay_ClientClose(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeBackend()
	done := make(chan relayResult, 1)
	go func() { done <- runRelay(context.Background(), ws, be, RelayConfig{}) }()

	body := make([]byte, 2)
	body[0], body[1] = 0x03, 0xe8 // 1000
	if err := clientWriteFrame(cli, true, opClose, body); err != nil {
		t.Fatalf("write close: %v", err)
	}
	// Drain any server close reply.
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	select {
	case res := <-done:
		if res.Reason != "client_close" {
			t.Fatalf("reason = %q, want client_close", res.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not end on client close")
	}
}

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// ensure errors.Is wiring on ErrConnClosed is stable for callers.
func TestErrConnClosedIsItself(t *testing.T) {
	if !errors.Is(ErrConnClosed, ErrConnClosed) {
		t.Fatal("ErrConnClosed identity broken")
	}
}
