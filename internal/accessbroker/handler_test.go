// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/talon/internal/identityjwt"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeAuth is a test Authenticator returning a fixed result.
type fakeAuth struct {
	claims *identityjwt.IdentityClaims
	err    error
}

func (f fakeAuth) VerifyRequest(*http.Request) (*identityjwt.IdentityClaims, error) {
	return f.claims, f.err
}

// fakeDialBackend returns a preset BackendConn (or error) from Dial and
// records the DialRequest it saw.
type fakeDialBackend struct {
	mu   sync.Mutex
	conn BackendConn
	err  error
	seen DialRequest
}

func (f *fakeDialBackend) Dial(_ context.Context, req DialRequest) (BackendConn, error) {
	f.mu.Lock()
	f.seen = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func (f *fakeDialBackend) seenReq() DialRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen
}

func clientlessClaims() *identityjwt.IdentityClaims {
	return &identityjwt.IdentityClaims{
		Subject:  "11111111-1111-1111-1111-111111111111",
		Email:    "auditor@example.com",
		Channel:  "clientless",
		SID:      "sess-1",
		TenantID: "tenant-1",
	}
}

// --- pre-upgrade gates (plain HTTP responses) ------------------------------

func TestHandler_AuthFailure_401(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, err := NewHandler(HandlerConfig{
		Auth:    fakeAuth{err: identityjwt.ErrNoToken},
		Backend: &fakeDialBackend{},
		Metrics: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/ssh?target=host", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "unauthenticated"); got != 1 {
		t.Fatalf("unauthenticated counter = %v", got)
	}
}

func TestHandler_WrongChannel_403(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	cl := clientlessClaims()
	cl.Channel = "cookie" // agent session — must be rejected
	h, _ := NewHandler(HandlerConfig{
		Auth:    fakeAuth{claims: cl},
		Backend: &fakeDialBackend{},
		Metrics: m,
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/ssh?target=host", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "wrong_channel"); got != 1 {
		t.Fatalf("wrong_channel counter = %v", got)
	}
}

func TestHandler_NoTarget_400(t *testing.T) {
	h, _ := NewHandler(HandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeDialBackend{},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/ssh", nil)) // no ?target=
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestNewHandler_RequiresDeps(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{Backend: &fakeDialBackend{}}); !errors.Is(err, errNilAuth) {
		t.Fatalf("missing auth: err = %v", err)
	}
	if _, err := NewHandler(HandlerConfig{Auth: fakeAuth{}}); !errors.Is(err, errNilBackend) {
		t.Fatalf("missing backend: err = %v", err)
	}
}

// --- post-upgrade: backend dial failure closes with 1011 ------------------

func TestHandler_BackendNotWired_ClosesWith1011(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, _ := NewHandler(HandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeDialBackend{err: ErrBackendNotWired},
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/ssh?target=bastion")
	defer func() { _ = conn.Close() }()

	op, payload := readServerFrameRaw(t, conn)
	if op != opClose {
		t.Fatalf("expected close frame, got opcode 0x%x", op)
	}
	if len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != closeInternalErr {
		t.Fatalf("close code = %v, want 1011", payload)
	}
	if !strings.Contains(string(payload[2:]), "backend unavailable") {
		t.Fatalf("close reason = %q", payload[2:])
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "backend_unavailable"); got != 1 {
		t.Fatalf("backend_unavailable counter = %v", got)
	}
}

// --- post-upgrade: full happy-path relay with a fake backend --------------

func TestHandler_HappyPath_Relay(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	be := newFakeBackend()
	bd := &fakeDialBackend{conn: be}
	h, _ := NewHandler(HandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: bd,
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/ssh?target=bastion&user=root&cols=120&rows=40")
	defer func() { _ = conn.Close() }()

	// ServeHTTP runs concurrently with this test goroutine — wait until the
	// handler has called Backend.Dial before asserting on the request it saw.
	if !waitFor(func() bool { return bd.seenReq().Subject != "" }, 2*time.Second) {
		t.Fatal("handler never dialed the backend")
	}
	// The DialRequest must carry verified-claim identity + the resolved
	// target/user/geometry (never client-forged identity).
	seen := bd.seenReq()
	if seen.Subject != clientlessClaims().Subject || seen.Target != "bastion" || seen.User != "root" {
		t.Fatalf("dial req = %+v", seen)
	}
	if seen.Cols != 120 || seen.Rows != 40 {
		t.Fatalf("geometry not threaded: %+v", seen)
	}

	// Browser keystroke -> backend.
	in, _ := json.Marshal(clientMsg{Type: "input", Data: base64.StdEncoding.EncodeToString([]byte("whoami\n"))})
	writeClientFrameRaw(t, conn, opText, in)
	if !waitFor(func() bool { return string(be.writtenBytes()) == "whoami\n" }, 2*time.Second) {
		t.Fatalf("backend got %q", be.writtenBytes())
	}

	// Backend output -> browser.
	be.out <- []byte("root\n")
	op, payload := readServerFrameRaw(t, conn)
	if op != opBinary || string(payload) != "root\n" {
		t.Fatalf("client frame op=0x%x payload=%q", op, payload)
	}

	// End the session.
	be.Close()
	// Drain remaining frames so the server-side relay completes.
	go func() { _, _ = io.Copy(io.Discard, conn) }()
	if !waitFor(func() bool { return counterVal(t, reg, "talon_access_broker_session_total", "ok") == 1 }, 2*time.Second) {
		t.Fatalf("ok counter = %v", counterVal(t, reg, "talon_access_broker_session_total", "ok"))
	}
}

// --- helpers ---------------------------------------------------------------

// dialWS opens a real client WebSocket handshake against the test server
// and returns the raw connection positioned just after the 101 response.
func dialWS(t *testing.T, srv *httptest.Server, path string) net.Conn {
	t.Helper()
	u := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", u)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	// Wrap so subsequent raw reads include anything buffered in br.
	return &bufferedConn{Conn: conn, r: br}
}

// bufferedConn lets reads after the handshake see bytes the bufio.Reader
// may have already pulled off the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// writeClientFrameRaw writes a masked client frame on a raw conn.
func writeClientFrameRaw(t *testing.T, conn net.Conn, opcode byte, payload []byte) {
	t.Helper()
	if err := clientWriteFrame(conn, true, opcode, payload); err != nil {
		t.Fatalf("client write frame: %v", err)
	}
}

// readServerFrameRaw reads one unmasked server frame from a raw conn.
func readServerFrameRaw(t *testing.T, conn net.Conn) (opcode byte, payload []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read server header: %v", err)
	}
	opcode = hdr[0] & 0x0f
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		_, _ = io.ReadFull(conn, ext[:])
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		_, _ = io.ReadFull(conn, ext[:])
		length = binary.BigEndian.Uint64(ext[:])
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read server payload: %v", err)
	}
	return opcode, payload
}

// counterVal reads a single labeled counter value out of a registry.
func counterVal(t *testing.T, reg *prometheus.Registry, name, outcome string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mtr := range mf.GetMetric() {
			for _, lp := range mtr.GetLabel() {
				if lp.GetName() == "outcome" && lp.GetValue() == outcome {
					return mtr.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
