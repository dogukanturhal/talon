// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 6455 accept-key check, not a security primitive.
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- handshake helpers -----------------------------------------------------

func TestComputeAcceptKey(t *testing.T) {
	// RFC 6455 §1.3 worked example: key "dGhlIHNhbXBsZSBub25jZQ==" ->
	// accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := computeAcceptKey(key); got != want {
		t.Fatalf("computeAcceptKey(%q) = %q, want %q", key, got, want)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	mk := func(method string, h map[string]string) *http.Request {
		r := httptest.NewRequest(method, "/access/ssh", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	good := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "keep-alive, Upgrade",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	}
	if !isWebSocketUpgrade(mk(http.MethodGet, good)) {
		t.Fatal("valid upgrade rejected")
	}
	if isWebSocketUpgrade(mk(http.MethodPost, good)) {
		t.Fatal("non-GET accepted as upgrade")
	}
	bad := map[string]string{}
	for k, v := range good {
		bad[k] = v
	}
	bad["Sec-WebSocket-Version"] = "8"
	if isWebSocketUpgrade(mk(http.MethodGet, bad)) {
		t.Fatal("wrong version accepted")
	}
}

func TestHeaderContainsToken(t *testing.T) {
	if !headerContainsToken("keep-alive, Upgrade", "upgrade") {
		t.Fatal("token in comma list not found")
	}
	if headerContainsToken("keep-alive", "upgrade") {
		t.Fatal("absent token reported present")
	}
}

// --- frame codec -----------------------------------------------------------

// pipeWSConn returns a server-side wsConn wired to an in-memory pipe plus
// the client end of that pipe, so a test can write masked client frames
// and read the server's unmasked replies without a real socket.
func pipeWSConn(t *testing.T, idle time.Duration) (*wsConn, net.Conn) {
	t.Helper()
	srv, cli := net.Pipe()
	c := &wsConn{
		conn:        srv,
		br:          bufio.NewReader(srv),
		bw:          bufio.NewWriter(srv),
		idleTimeout: idle,
	}
	return c, cli
}

// clientWriteFrame writes a masked client frame to w (the client role
// MUST mask, RFC 6455 §5.1).
func clientWriteFrame(w io.Writer, fin bool, opcode byte, payload []byte) error {
	var hdr []byte
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	hdr = append(hdr, b0)
	switch {
	case len(payload) <= 125:
		hdr = append(hdr, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		hdr = append(hdr, 0x80|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		hdr = append(hdr, ext[:]...)
	default:
		hdr = append(hdr, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		hdr = append(hdr, ext[:]...)
	}
	mask := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	hdr = append(hdr, mask...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func TestReadMessage_TextAndBinary(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()

	go func() {
		_ = clientWriteFrame(cli, true, opText, []byte("hello"))
		_ = clientWriteFrame(cli, true, opBinary, []byte{0x01, 0x02, 0x03})
	}()

	m1, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read text: %v", err)
	}
	if m1.opcode != opText || string(m1.payload) != "hello" {
		t.Fatalf("text msg = %+v", m1)
	}
	m2, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if m2.opcode != opBinary || !bytes.Equal(m2.payload, []byte{1, 2, 3}) {
		t.Fatalf("binary msg = %+v", m2)
	}
}

func TestReadMessage_Fragmented(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()
	go func() {
		_ = clientWriteFrame(cli, false, opText, []byte("Hel"))
		_ = clientWriteFrame(cli, false, opContinuation, []byte("lo, "))
		_ = clientWriteFrame(cli, true, opContinuation, []byte("world"))
	}()
	m, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read fragmented: %v", err)
	}
	if string(m.payload) != "Hello, world" {
		t.Fatalf("reassembled = %q", m.payload)
	}
}

func TestReadMessage_PingTriggersPong(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()
	go func() {
		_ = clientWriteFrame(cli, true, opPing, []byte("pingpayload"))
		_ = clientWriteFrame(cli, true, opText, []byte("after"))
	}()
	// Drain the server's pong on the client side so the pipe doesn't block.
	pongDone := make(chan struct{})
	go func() {
		op, payload := clientReadFrame(t, cli)
		if op != opPong || string(payload) != "pingpayload" {
			t.Errorf("expected pong echo, got op=0x%x payload=%q", op, payload)
		}
		close(pongDone)
	}()
	m, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read after ping: %v", err)
	}
	if string(m.payload) != "after" {
		t.Fatalf("post-ping msg = %q", m.payload)
	}
	<-pongDone
}

func TestReadMessage_CloseReturnsErrConnClosed(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()
	go func() {
		body := make([]byte, 2)
		binary.BigEndian.PutUint16(body, closeNormalClosure)
		_ = clientWriteFrame(cli, true, opClose, body)
		// Drain server's close reply so the writer side doesn't block.
		_, _ = io.ReadAll(cli)
	}()
	_, err := c.ReadMessage()
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("close frame: err = %v, want ErrConnClosed", err)
	}
}

func TestReadFrame_RejectsUnmaskedClientFrame(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()
	go func() {
		// FIN + text, length 1, NO mask bit — illegal from a client.
		_, _ = cli.Write([]byte{0x81, 0x01, 'x'})
		_, _ = io.ReadAll(cli)
	}()
	_, err := c.ReadMessage()
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("unmasked frame: err = %v, want protocol-error ErrConnClosed", err)
	}
}

func TestWriteMessage_ServerFramesUnmasked(t *testing.T) {
	c, cli := pipeWSConn(t, 0)
	defer func() { _ = cli.Close() }()
	done := make(chan struct{})
	go func() {
		op, payload := clientReadFrame(t, cli)
		if op != opBinary {
			t.Errorf("opcode = 0x%x, want binary", op)
		}
		if string(payload) != "srv-output" {
			t.Errorf("payload = %q", payload)
		}
		close(done)
	}()
	if err := c.WriteBinary([]byte("srv-output")); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-done
}

func TestIdleTimeout_ReadDeadline(t *testing.T) {
	c, cli := pipeWSConn(t, 30*time.Millisecond)
	defer func() { _ = cli.Close() }()
	// Client never writes; the read deadline must fire.
	_, err := c.ReadMessage()
	if err == nil {
		t.Fatal("expected idle read deadline error, got nil")
	}
}

// clientReadFrame reads one (server->client, unmasked) frame off cli for
// assertions in tests. It does not unmask (server frames are not masked).
func clientReadFrame(t *testing.T, cli net.Conn) (opcode byte, payload []byte) {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(cli, hdr[:]); err != nil {
		t.Fatalf("client read header: %v", err)
	}
	opcode = hdr[0] & 0x0f
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		_, _ = io.ReadFull(cli, ext[:])
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		_, _ = io.ReadFull(cli, ext[:])
		length = binary.BigEndian.Uint64(ext[:])
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(cli, payload); err != nil {
		t.Fatalf("client read payload: %v", err)
	}
	return opcode, payload
}

// sanity: the handshake response we write is parseable and carries the
// RFC-derived accept key. Exercises acceptWebSocket end to end over a
// real loopback listener (httptest can't hijack a pipe cleanly).
func TestAcceptWebSocket_Handshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := acceptWebSocket(w, r, 0)
			if err != nil {
				t.Errorf("acceptWebSocket: %v", err)
				return
			}
			_ = ws.WriteText("ready")
			_ = ws.Close()
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET /access/ssh HTTP/1.1\r\n" +
		"Host: broker\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write req: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("status line = %q, want 101", statusLine)
	}
	var sawAccept bool
	want := computeAcceptKeyForTest(key)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			if !strings.Contains(line, want) {
				t.Fatalf("accept header = %q, want contains %q", line, want)
			}
			sawAccept = true
		}
	}
	if !sawAccept {
		t.Fatal("no Sec-WebSocket-Accept header in handshake response")
	}
}

func computeAcceptKeyForTest(key string) string {
	h := sha1.New() //nolint:gosec
	_, _ = io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
