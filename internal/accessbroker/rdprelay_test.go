// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fakeRDPBackend is an in-memory RDPConn for relay tests. ReadFrame drains
// a channel the test feeds (server->canvas); WriteInput records the events
// the relay admitted (so a test can assert which were admitted vs dropped
// by the policy seam). EOF is signalled by closing the frame channel.
type fakeRDPBackend struct {
	mu      sync.Mutex
	frames  chan RDPServerMsg
	written []RDPClientMsg
	closed  bool
	once    sync.Once
}

func newFakeRDPBackend() *fakeRDPBackend {
	return &fakeRDPBackend{frames: make(chan RDPServerMsg, 16)}
}

func (f *fakeRDPBackend) ReadFrame() (RDPServerMsg, error) {
	msg, ok := <-f.frames
	if !ok {
		return RDPServerMsg{}, io.EOF
	}
	return msg, nil
}

func (f *fakeRDPBackend) WriteInput(msg RDPClientMsg) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return io.ErrClosedPipe
	}
	f.written = append(f.written, msg)
	return nil
}

func (f *fakeRDPBackend) Close() error {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.frames)
	})
	return nil
}

func (f *fakeRDPBackend) inputs() []RDPClientMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RDPClientMsg(nil), f.written...)
}

// --- wire codec ------------------------------------------------------------

func TestEncodeServerMsg_RoundTripHeader(t *testing.T) {
	msg := RDPServerMsg{Kind: RDPMsgTile, X: 10, Y: 20, W: 30, H: 40, Data: []byte("pixels")}
	env := encodeServerMsg(msg)
	if len(env) != rdpHeaderLen+len("pixels") {
		t.Fatalf("envelope len = %d", len(env))
	}
	if RDPMsgKind(env[0]) != RDPMsgTile {
		t.Fatalf("kind byte = %d", env[0])
	}
	if binary.BigEndian.Uint16(env[1:3]) != 10 || binary.BigEndian.Uint16(env[3:5]) != 20 ||
		binary.BigEndian.Uint16(env[5:7]) != 30 || binary.BigEndian.Uint16(env[7:9]) != 40 {
		t.Fatalf("geometry not encoded: % x", env[1:9])
	}
	if string(env[rdpHeaderLen:]) != "pixels" {
		t.Fatalf("data = %q", env[rdpHeaderLen:])
	}
}

func TestDecodeRDPClientFrame_Binary(t *testing.T) {
	// Build a binary pointer event: kind=POINTER, x=5, y=6, button=2, down=1.
	b := make([]byte, rdpHeaderLen)
	b[0] = byte(RDPMsgPointer)
	binary.BigEndian.PutUint16(b[1:3], 5)
	binary.BigEndian.PutUint16(b[3:5], 6)
	binary.BigEndian.PutUint16(b[5:7], 2)
	b[9] = 0x01
	msg, ok := decodeRDPClientFrame(message{opcode: opBinary, payload: b})
	if !ok {
		t.Fatal("binary pointer not decoded")
	}
	if msg.Kind != RDPMsgPointer || msg.X != 5 || msg.Y != 6 || msg.Button != 2 || !msg.Down {
		t.Fatalf("decoded = %+v", msg)
	}
}

func TestDecodeRDPClientFrame_RejectsServerKind(t *testing.T) {
	// A binary frame claiming a SERVER-only kind must be rejected (direction
	// confusion / a client trying to inject a server clipboard offer).
	b := make([]byte, rdpHeaderLen)
	b[0] = byte(RDPMsgServerClipboard)
	if _, ok := decodeRDPClientFrame(message{opcode: opBinary, payload: b}); ok {
		t.Fatal("server-only kind accepted from client")
	}
}

func TestDecodeRDPClientFrame_ShortFrameDropped(t *testing.T) {
	if _, ok := decodeRDPClientFrame(message{opcode: opBinary, payload: []byte{1, 2, 3}}); ok {
		t.Fatal("short binary frame accepted")
	}
}

func TestDecodeRDPClientFrame_JSON(t *testing.T) {
	in, _ := json.Marshal(rdpClientMsgJSON{Type: "key", KeyCode: 65, Down: true})
	msg, ok := decodeRDPClientFrame(message{opcode: opText, payload: in})
	if !ok || msg.Kind != RDPMsgKey || msg.KeyCode != 65 || !msg.Down {
		t.Fatalf("json key decode: msg=%+v ok=%v", msg, ok)
	}

	clip, _ := json.Marshal(rdpClientMsgJSON{Type: "clipboard", Data: base64.StdEncoding.EncodeToString([]byte("secret"))})
	cmsg, ok := decodeRDPClientFrame(message{opcode: opText, payload: clip})
	if !ok || cmsg.Kind != RDPMsgClientClipboard || string(cmsg.Data) != "secret" {
		t.Fatalf("json clipboard decode: msg=%+v ok=%v", cmsg, ok)
	}

	if _, ok := decodeRDPClientFrame(message{opcode: opText, payload: []byte("{bad")}); ok {
		t.Fatal("malformed json accepted")
	}
	bad, _ := json.Marshal(rdpClientMsgJSON{Type: "nope"})
	if _, ok := decodeRDPClientFrame(message{opcode: opText, payload: bad}); ok {
		t.Fatal("unknown type accepted")
	}
}

// --- policy seam -----------------------------------------------------------

func TestPolicyGate_DenyAllByDefault(t *testing.T) {
	var g rdpPolicyGate // zero RDPDataPolicy
	if g.AllowClipboardToClient() || g.AllowClipboardToServer() || g.AllowFileTransfer() {
		t.Fatal("zero policy must deny everything (fail closed)")
	}
}

func TestAdmitClientMsg_ClipboardGated(t *testing.T) {
	deny := rdpPolicyGate{p: RDPDataPolicy{}}
	if admitClientMsg(deny, RDPMsgClientClipboard, nil) {
		t.Fatal("clipboard-to-server admitted under deny policy")
	}
	// Pointer + key are never gated.
	if !admitClientMsg(deny, RDPMsgPointer, nil) || !admitClientMsg(deny, RDPMsgKey, nil) {
		t.Fatal("pointer/key wrongly gated")
	}
	allow := rdpPolicyGate{p: RDPDataPolicy{ClipboardToServer: true}}
	if !admitClientMsg(allow, RDPMsgClientClipboard, nil) {
		t.Fatal("clipboard-to-server denied under allow policy")
	}
}

func TestAdmitServerMsg_ClipboardAndFileGated(t *testing.T) {
	deny := rdpPolicyGate{p: RDPDataPolicy{}}
	if admitServerMsg(deny, RDPMsgServerClipboard, nil) {
		t.Fatal("server clipboard admitted under deny policy")
	}
	if admitServerMsg(deny, RDPMsgFile, nil) {
		t.Fatal("file admitted under deny policy")
	}
	// Graphics always admitted.
	if !admitServerMsg(deny, RDPMsgTile, nil) || !admitServerMsg(deny, RDPMsgFrame, nil) {
		t.Fatal("graphics wrongly gated")
	}
}

// --- runRDPRelay end-to-end with a real wsConn pair ------------------------

func rdpWSTestPair(t *testing.T) (*wsConn, net.Conn) {
	t.Helper()
	srv, cli := net.Pipe()
	return &wsConn{conn: srv, br: bufio.NewReader(srv), bw: bufio.NewWriter(srv)}, cli
}

func TestRunRDPRelay_BackendToCanvasAndRecordTee(t *testing.T) {
	ws, cli := rdpWSTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeRDPBackend()
	var rec bytes.Buffer

	done := make(chan relayResult, 1)
	go func() {
		done <- runRDPRelay(context.Background(), ws, be, RDPRelayConfig{RecordSink: &rec})
	}()

	got := make(chan []byte, 1)
	go func() {
		_, payload := clientReadFrame(t, cli)
		got <- payload
	}()

	be.frames <- RDPServerMsg{Kind: RDPMsgTile, X: 1, Y: 2, W: 3, H: 4, Data: []byte("tiledata")}

	select {
	case p := <-got:
		if RDPMsgKind(p[0]) != RDPMsgTile || string(p[rdpHeaderLen:]) != "tiledata" {
			t.Fatalf("canvas frame = % x", p)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for backend->canvas frame")
	}

	drain(cli)
	be.Close()
	res := <-done
	if res.Reason != "backend_eof" {
		t.Fatalf("reason = %q, want backend_eof", res.Reason)
	}
	if rec.Len() == 0 || RDPMsgKind(rec.Bytes()[0]) != RDPMsgTile {
		t.Fatalf("record tee did not capture the wire envelope: % x", rec.Bytes())
	}
}

func TestRunRDPRelay_CanvasInputToBackend(t *testing.T) {
	ws, cli := rdpWSTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeRDPBackend()
	drain(cli)

	done := make(chan relayResult, 1)
	go func() { done <- runRDPRelay(context.Background(), ws, be, RDPRelayConfig{}) }()

	in, _ := json.Marshal(rdpClientMsgJSON{Type: "pointer", X: 100, Y: 200, Button: 1, Down: true})
	if err := clientWriteFrame(cli, true, opText, in); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !waitFor(func() bool {
		ins := be.inputs()
		return len(ins) == 1 && ins[0].Kind == RDPMsgPointer && ins[0].X == 100 && ins[0].Y == 200
	}, time.Second) {
		t.Fatalf("backend never got pointer input: %+v", be.inputs())
	}
	be.Close()
	<-done
}

// The relay-edge clipboard policy must DROP a paste the policy forbids
// (the security headline of Phase 3): the event is admitted to the relay
// but never reaches the backend, and a policy-drop metric increments.
func TestRunRDPRelay_ClipboardDroppedByPolicy(t *testing.T) {
	ws, cli := rdpWSTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeRDPBackend()
	drain(cli)
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	done := make(chan relayResult, 1)
	go func() {
		// Deny-all policy (zero RDPDataPolicy).
		done <- runRDPRelay(context.Background(), ws, be, RDPRelayConfig{Policy: rdpPolicyGate{}, Metrics: m})
	}()

	clip, _ := json.Marshal(rdpClientMsgJSON{Type: "clipboard", Data: base64.StdEncoding.EncodeToString([]byte("exfil"))})
	if err := clientWriteFrame(cli, true, opText, clip); err != nil {
		t.Fatalf("client write clipboard: %v", err)
	}
	// Follow with an allowed pointer event; once it lands we know the
	// clipboard event was processed (and dropped) before it.
	ptr, _ := json.Marshal(rdpClientMsgJSON{Type: "pointer", X: 1, Y: 1})
	if err := clientWriteFrame(cli, true, opText, ptr); err != nil {
		t.Fatalf("client write pointer: %v", err)
	}
	if !waitFor(func() bool {
		ins := be.inputs()
		return len(ins) == 1 && ins[0].Kind == RDPMsgPointer
	}, time.Second) {
		t.Fatalf("expected only the pointer to reach backend, got %+v", be.inputs())
	}
	// The clipboard must NOT have reached the backend.
	for _, in := range be.inputs() {
		if in.Kind == RDPMsgClientClipboard {
			t.Fatal("forbidden clipboard paste leaked to backend")
		}
	}
	be.Close()
	<-done
	if got := policyDropVal(t, reg, "clipboard_to_server"); got != 1 {
		t.Fatalf("policy drop counter = %v, want 1", got)
	}
}

// policyDropVal reads the talon_access_broker_policy_drops_total counter for
// a given reason label out of a registry (counterVal keys on the "outcome"
// label which this series does not carry).
func policyDropVal(t *testing.T, reg *prometheus.Registry, reason string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "talon_access_broker_policy_drops_total" {
			continue
		}
		for _, mtr := range mf.GetMetric() {
			for _, lp := range mtr.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == reason {
					return mtr.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestRunRDPRelay_ClipboardAllowedByPolicy(t *testing.T) {
	ws, cli := rdpWSTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeRDPBackend()
	drain(cli)

	done := make(chan relayResult, 1)
	go func() {
		done <- runRDPRelay(context.Background(), ws, be, RDPRelayConfig{
			Policy: rdpPolicyGate{p: RDPDataPolicy{ClipboardToServer: true}},
		})
	}()

	clip, _ := json.Marshal(rdpClientMsgJSON{Type: "clipboard", Data: base64.StdEncoding.EncodeToString([]byte("ok"))})
	if err := clientWriteFrame(cli, true, opText, clip); err != nil {
		t.Fatalf("client write clipboard: %v", err)
	}
	if !waitFor(func() bool {
		ins := be.inputs()
		return len(ins) == 1 && ins[0].Kind == RDPMsgClientClipboard && string(ins[0].Data) == "ok"
	}, time.Second) {
		t.Fatalf("allowed clipboard never reached backend: %+v", be.inputs())
	}
	be.Close()
	<-done
}

func TestRunRDPRelay_MaxDurationDeadline(t *testing.T) {
	ws, cli := rdpWSTestPair(t)
	defer func() { _ = cli.Close() }()
	be := newFakeRDPBackend() // never produces frames, never EOFs
	drain(cli)
	start := time.Now()
	res := runRDPRelay(context.Background(), ws, be, RDPRelayConfig{MaxDuration: 60 * time.Millisecond})
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("relay returned before MaxDuration")
	}
	if res.Reason != "deadline" {
		t.Fatalf("reason = %q, want deadline", res.Reason)
	}
}
