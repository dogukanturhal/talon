// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/talon/internal/identityjwt"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeRDPDialBackend returns a preset RDPConn (or error) from DialRDP and
// records the RDPDialRequest it saw (mirrors fakeDialBackend).
type fakeRDPDialBackend struct {
	mu   sync.Mutex
	conn RDPConn
	err  error
	seen RDPDialRequest
}

func (f *fakeRDPDialBackend) DialRDP(_ context.Context, req RDPDialRequest) (RDPConn, error) {
	f.mu.Lock()
	f.seen = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func (f *fakeRDPDialBackend) seenReq() RDPDialRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen
}

// --- pre-upgrade gates -----------------------------------------------------

func TestRDPHandler_AuthFailure_401(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, err := NewRDPHandler(RDPHandlerConfig{
		Auth:    fakeAuth{err: identityjwt.ErrNoToken},
		Backend: &fakeRDPDialBackend{},
		Metrics: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/rdp?target=host", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "unauthenticated"); got != 1 {
		t.Fatalf("unauthenticated counter = %v", got)
	}
}

func TestRDPHandler_WrongChannel_403(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	cl := clientlessClaims()
	cl.Channel = "cookie"
	h, _ := NewRDPHandler(RDPHandlerConfig{
		Auth:    fakeAuth{claims: cl},
		Backend: &fakeRDPDialBackend{},
		Metrics: m,
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/rdp?target=host", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "wrong_channel"); got != 1 {
		t.Fatalf("wrong_channel counter = %v", got)
	}
}

func TestRDPHandler_NoTarget_400(t *testing.T) {
	h, _ := NewRDPHandler(RDPHandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeRDPDialBackend{},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/rdp", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestNewRDPHandler_RequiresDeps(t *testing.T) {
	if _, err := NewRDPHandler(RDPHandlerConfig{Backend: &fakeRDPDialBackend{}}); !errors.Is(err, errNilAuth) {
		t.Fatalf("missing auth: err = %v", err)
	}
	if _, err := NewRDPHandler(RDPHandlerConfig{Auth: fakeAuth{}}); !errors.Is(err, errNilRDPBackend) {
		t.Fatalf("missing backend: err = %v", err)
	}
}

// --- post-upgrade: backend dial failure closes with 1011 ------------------

func TestRDPHandler_BackendNotWired_ClosesWith1011(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, _ := NewRDPHandler(RDPHandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeRDPDialBackend{err: ErrRDPBackendNotWired},
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/rdp?target=win-jump")
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

// --- post-upgrade: full happy-path relay with a fake RDP backend ----------

func TestRDPHandler_HappyPath_Relay(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	be := newFakeRDPBackend()
	bd := &fakeRDPDialBackend{conn: be}
	h, _ := NewRDPHandler(RDPHandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: bd,
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/rdp?target=win-jump&user=admin&w=1024&h=768")
	defer func() { _ = conn.Close() }()

	if !waitFor(func() bool { return bd.seenReq().Subject != "" }, 2*time.Second) {
		t.Fatal("handler never dialed the backend")
	}
	seen := bd.seenReq()
	if seen.Subject != clientlessClaims().Subject || seen.Target != "win-jump" || seen.User != "admin" {
		t.Fatalf("dial req = %+v", seen)
	}
	if seen.Width != 1024 || seen.Height != 768 {
		t.Fatalf("geometry not threaded: %+v", seen)
	}
	// The default query resolver supplies a DENY-ALL data policy (fail
	// closed): the handler must not silently enable clipboard/file.
	if seen.Policy.ClipboardToClient || seen.Policy.ClipboardToServer || seen.Policy.FileTransfer {
		t.Fatalf("default policy not deny-all: %+v", seen.Policy)
	}

	// Canvas input (pointer) -> backend.
	in, _ := json.Marshal(rdpClientMsgJSON{Type: "pointer", X: 42, Y: 24, Down: true, Button: 1})
	writeClientFrameRaw(t, conn, opText, in)
	if !waitFor(func() bool {
		ins := be.inputs()
		return len(ins) == 1 && ins[0].Kind == RDPMsgPointer && ins[0].X == 42
	}, 2*time.Second) {
		t.Fatalf("backend got %+v", be.inputs())
	}

	// Backend frame -> canvas (binary wire envelope).
	be.frames <- RDPServerMsg{Kind: RDPMsgFrame, W: 1024, H: 768, Data: []byte("desktop")}
	op, payload := readServerFrameRaw(t, conn)
	if op != opBinary || RDPMsgKind(payload[0]) != RDPMsgFrame || string(payload[rdpHeaderLen:]) != "desktop" {
		t.Fatalf("client frame op=0x%x payload=% x", op, payload)
	}

	be.Close()
	go func() { _, _ = io.Copy(io.Discard, conn) }()
	if !waitFor(func() bool { return counterVal(t, reg, "talon_access_broker_session_total", "ok") == 1 }, 2*time.Second) {
		t.Fatalf("ok counter = %v", counterVal(t, reg, "talon_access_broker_session_total", "ok"))
	}
}
