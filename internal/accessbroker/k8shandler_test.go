// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/base64"
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

	"github.com/prometheus/client_golang/prometheus"
)

// fakeK8sBackend returns a preset BackendConn (or error) from Dial and
// records the K8sDialRequest it saw.
type fakeK8sBackend struct {
	mu   sync.Mutex
	conn BackendConn
	err  error
	seen K8sDialRequest
}

func (f *fakeK8sBackend) Dial(_ context.Context, req K8sDialRequest) (BackendConn, error) {
	f.mu.Lock()
	f.seen = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func (f *fakeK8sBackend) seenReq() K8sDialRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen
}

// --- pre-upgrade gates -----------------------------------------------------

func TestK8sHandler_AuthFailure_401(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, err := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{err: errors.New("no token")}, Backend: &fakeK8sBackend{}, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/k8s?namespace=ns&pod=p", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestK8sHandler_WrongChannel_403(t *testing.T) {
	cl := clientlessClaims()
	cl.Channel = "cookie"
	h, _ := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{claims: cl}, Backend: &fakeK8sBackend{}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/k8s?namespace=ns&pod=p", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestK8sHandler_NoTarget_400(t *testing.T) {
	h, _ := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: &fakeK8sBackend{}})
	// missing pod
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/k8s?namespace=ns", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestK8sHandler_InvalidVerb_400(t *testing.T) {
	h, _ := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: &fakeK8sBackend{}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/k8s?namespace=ns&pod=p&verb=delete", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for unknown verb", rec.Code)
	}
}

func TestNewK8sHandler_RequiresDeps(t *testing.T) {
	if _, err := NewK8sHandler(K8sHandlerConfig{Backend: &fakeK8sBackend{}}); !errors.Is(err, errNilAuth) {
		t.Fatalf("missing auth: err = %v", err)
	}
	if _, err := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{}}); !errors.Is(err, errNilK8sBackend) {
		t.Fatalf("missing backend: err = %v", err)
	}
}

// --- post-upgrade: backend-not-wired closes 1011 (the Phase 4 stub) --------

func TestK8sHandler_BackendNotWired_ClosesWith1011(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, _ := NewK8sHandler(K8sHandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeK8sBackend{err: ErrK8sBackendNotWired},
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/k8s?verb=exec&namespace=prod&pod=api-0")
	defer func() { _ = conn.Close() }()

	op, payload := readServerFrameRaw(t, conn)
	if op != opClose {
		t.Fatalf("expected close frame, got opcode 0x%x", op)
	}
	if len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != closeInternalErr {
		t.Fatalf("close code = %v, want 1011", payload)
	}
	if !strings.Contains(string(payload[2:]), "k8s backend unavailable") {
		t.Fatalf("close reason = %q", payload[2:])
	}
}

// --- post-upgrade: happy path reuses the byte-stream relay -----------------

func TestK8sHandler_HappyPath_ExecRelay(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	be := newFakeBackend()
	bd := &fakeK8sBackend{conn: be}
	h, _ := NewK8sHandler(K8sHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: bd, Metrics: m})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/k8s?verb=exec&cluster=eu-tr-1&namespace=prod&pod=api-0&container=app&command=/bin/sh&cols=100&rows=30")
	defer func() { _ = conn.Close() }()

	if !waitFor(func() bool { return bd.seenReq().Subject != "" }, 2*time.Second) {
		t.Fatal("handler never dialed the k8s backend")
	}
	seen := bd.seenReq()
	if seen.Subject != clientlessClaims().Subject || seen.Verb != VerbExec || seen.Namespace != "prod" || seen.Pod != "api-0" || seen.Container != "app" {
		t.Fatalf("dial req = %+v", seen)
	}
	if len(seen.Command) != 1 || seen.Command[0] != "/bin/sh" {
		t.Fatalf("command not threaded: %+v", seen.Command)
	}
	if seen.Cols != 100 || seen.Rows != 30 {
		t.Fatalf("geometry not threaded: %+v", seen)
	}

	// keystroke -> backend
	in, _ := json.Marshal(clientMsg{Type: "input", Data: base64.StdEncoding.EncodeToString([]byte("ls\n"))})
	writeClientFrameRaw(t, conn, opText, in)
	if !waitFor(func() bool { return string(be.writtenBytes()) == "ls\n" }, 2*time.Second) {
		t.Fatalf("backend got %q", be.writtenBytes())
	}

	// backend output -> browser
	be.out <- []byte("bin etc\n")
	op, payload := readServerFrameRaw(t, conn)
	if op != opBinary || string(payload) != "bin etc\n" {
		t.Fatalf("client frame op=0x%x payload=%q", op, payload)
	}

	be.Close()
	go func() { _, _ = io.Copy(io.Discard, conn) }()
	if !waitFor(func() bool { return counterVal(t, reg, "talon_access_broker_session_total", "ok") == 1 }, 2*time.Second) {
		t.Fatalf("ok counter = %v", counterVal(t, reg, "talon_access_broker_session_total", "ok"))
	}
}

// k8sRecordTarget builds a stable label used by the recording tee.
func TestK8sRecordTarget(t *testing.T) {
	got := k8sRecordTarget(K8sDialRequest{Verb: VerbExec, Cluster: "c", Namespace: "n", Pod: "p", Container: "app"})
	if got != "exec c/n/p/app" {
		t.Fatalf("record target = %q", got)
	}
	got = k8sRecordTarget(K8sDialRequest{Verb: VerbLogs, Cluster: "c", Namespace: "n", Pod: "p"})
	if got != "logs c/n/p" {
		t.Fatalf("record target without container = %q", got)
	}
}
