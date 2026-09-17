// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// fakeDBOpenBackend returns a preset DBSession (or error) from Open and
// records the DBDialRequest it saw.
type fakeDBOpenBackend struct {
	mu   sync.Mutex
	sess DBSession
	err  error
	seen DBDialRequest
}

func (f *fakeDBOpenBackend) Open(_ context.Context, req DBDialRequest) (DBSession, error) {
	f.mu.Lock()
	f.seen = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.sess, nil
}

func (f *fakeDBOpenBackend) seenReq() DBDialRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen
}

// --- pre-upgrade gates -----------------------------------------------------

func TestDBHandler_AuthFailure_401(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, err := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{err: errors.New("no token")}, Backend: &fakeDBOpenBackend{}, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/db?target=db", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "unauthenticated"); got != 1 {
		t.Fatalf("unauthenticated counter = %v", got)
	}
}

func TestDBHandler_WrongChannel_403(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	cl := clientlessClaims()
	cl.Channel = "cookie"
	h, _ := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{claims: cl}, Backend: &fakeDBOpenBackend{}, Metrics: m})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/db?target=db", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestDBHandler_NoTarget_400(t *testing.T) {
	h, _ := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: &fakeDBOpenBackend{}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/db", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestDBHandler_InvalidEngine_400(t *testing.T) {
	h, _ := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: &fakeDBOpenBackend{}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/access/db?target=db&engine=oracle", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for unknown engine", rec.Code)
	}
}

func TestNewDBHandler_RequiresDeps(t *testing.T) {
	if _, err := NewDBHandler(DBHandlerConfig{Backend: &fakeDBOpenBackend{}}); !errors.Is(err, errNilAuth) {
		t.Fatalf("missing auth: err = %v", err)
	}
	if _, err := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{}}); !errors.Is(err, errNilDBBackend) {
		t.Fatalf("missing backend: err = %v", err)
	}
}

// --- post-upgrade: backend-not-wired closes 1011 (the Phase 4 stub) --------

func TestDBHandler_BackendNotWired_ClosesWith1011(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	h, _ := NewDBHandler(DBHandlerConfig{
		Auth:    fakeAuth{claims: clientlessClaims()},
		Backend: &fakeDBOpenBackend{err: ErrDBBackendNotWired},
		Metrics: m,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/db?engine=postgres&target=analytics")
	defer func() { _ = conn.Close() }()

	op, payload := readServerFrameRaw(t, conn)
	if op != opClose {
		t.Fatalf("expected close frame, got opcode 0x%x", op)
	}
	if len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != closeInternalErr {
		t.Fatalf("close code = %v, want 1011", payload)
	}
	if !strings.Contains(string(payload[2:]), "db backend unavailable") {
		t.Fatalf("close reason = %q", payload[2:])
	}
	if got := counterVal(t, reg, "talon_access_broker_session_total", "backend_unavailable"); got != 1 {
		t.Fatalf("backend_unavailable counter = %v", got)
	}
}

// --- post-upgrade: happy path with a fake DBSession ------------------------

func TestDBHandler_HappyPath_QueryRelay(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	sess := &fakeDBSession{results: []*ResultSet{{Columns: []string{"n"}, Rows: [][]*string{{strptr("42")}}, RowsAffected: -1}}}
	bd := &fakeDBOpenBackend{sess: sess}
	h, _ := NewDBHandler(DBHandlerConfig{Auth: fakeAuth{claims: clientlessClaims()}, Backend: bd, Metrics: m})
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn := dialWS(t, srv, "/access/db?engine=postgres&target=analytics&db=metrics")
	defer func() { _ = conn.Close() }()

	// Identity must be projected from the verified claims, never the client.
	if !waitFor(func() bool { return bd.seenReq().Subject != "" }, 2*time.Second) {
		t.Fatal("handler never opened the backend")
	}
	seen := bd.seenReq()
	if seen.Subject != clientlessClaims().Subject || seen.Engine != EnginePostgres || seen.Target != "analytics" || seen.Database != "metrics" {
		t.Fatalf("open req = %+v", seen)
	}

	// ready greeting, then a query/result round trip.
	if mm := readDBServerMsg(t, conn); mm.Type != "ready" {
		t.Fatalf("want ready, got %q", mm.Type)
	}
	q, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select 42"})
	writeClientFrameRaw(t, conn, opText, q)
	mm := readDBServerMsg(t, conn)
	if mm.Type != "result" || mm.Result == nil || mm.Result.Rows[0][0] == nil || *mm.Result.Rows[0][0] != "42" {
		t.Fatalf("result = %+v", mm)
	}

	// End the session.
	writeClientFrameRaw(t, conn, opClose, []byte{0x03, 0xe8})
	drain(conn)
	if !waitFor(func() bool { return counterVal(t, reg, "talon_access_broker_session_total", "ok") == 1 }, 2*time.Second) {
		t.Fatalf("ok counter = %v", counterVal(t, reg, "talon_access_broker_session_total", "ok"))
	}
}
