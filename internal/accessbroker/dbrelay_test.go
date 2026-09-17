// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a goroutine-safe bytes.Buffer for the recording-tee assertions
// (the relay's tee runs on the relay goroutine while the test reads it).
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeDBSession is an in-memory DBSession for relay tests. Exec returns a
// preset result (or error) per call, in order, and records the SQL it saw.
type fakeDBSession struct {
	mu        sync.Mutex
	calls     []string
	results   []*ResultSet
	errs      []error
	idx       int
	closed    bool
	closeOnce sync.Once
	// blockOn, when set, makes the Nth (0-based) Exec block until ctx is
	// cancelled — used to exercise the per-statement QueryTimeout.
	blockOn int
	block   bool
}

func (s *fakeDBSession) Exec(ctx context.Context, sql string) (*ResultSet, error) {
	s.mu.Lock()
	i := s.idx
	s.idx++
	s.calls = append(s.calls, sql)
	block := s.block && i == s.blockOn
	s.mu.Unlock()

	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var rs *ResultSet
	var err error
	if i < len(s.results) {
		rs = s.results[i]
	}
	if i < len(s.errs) {
		err = s.errs[i]
	}
	return rs, err
}

func (s *fakeDBSession) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
	})
	return nil
}

func (s *fakeDBSession) seenCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func strptr(s string) *string { return &s }

// --- decodeDBClientFrame ---------------------------------------------------

func TestDecodeDBClientFrame(t *testing.T) {
	q, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select 1"})
	if sql, ok := decodeDBClientFrame(message{opcode: opText, payload: q}); !ok || sql != "select 1" {
		t.Fatalf("query: sql=%q ok=%v", sql, ok)
	}
	// Binary frame = raw statement.
	if sql, ok := decodeDBClientFrame(message{opcode: opBinary, payload: []byte("select 2")}); !ok || sql != "select 2" {
		t.Fatalf("binary: sql=%q ok=%v", sql, ok)
	}
	// Empty type defaults to query.
	d, _ := json.Marshal(dbClientMsg{SQL: "select 3"})
	if sql, ok := decodeDBClientFrame(message{opcode: opText, payload: d}); !ok || sql != "select 3" {
		t.Fatalf("default type: sql=%q ok=%v", sql, ok)
	}
	// Malformed JSON is not ok.
	if _, ok := decodeDBClientFrame(message{opcode: opText, payload: []byte("{nope")}); ok {
		t.Fatal("malformed json should not be ok")
	}
	// Unknown type is not ok.
	u, _ := json.Marshal(dbClientMsg{Type: "explode"})
	if _, ok := decodeDBClientFrame(message{opcode: opText, payload: u}); ok {
		t.Fatal("unknown type should not be ok")
	}
}

// --- runDBRelay end-to-end with a real wsConn pair -------------------------

// readDBServerMsg reads one server TEXT frame and JSON-decodes it.
func readDBServerMsg(t *testing.T, cli net.Conn) dbServerMsg {
	t.Helper()
	// clientReadFrame (websocket_test.go) reads one unmasked server frame.
	_, payload := clientReadFrame(t, cli)
	var m dbServerMsg
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("decode server msg %q: %v", payload, err)
	}
	return m
}

func TestRunDBRelay_QueryResult(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	sess := &fakeDBSession{
		results: []*ResultSet{{
			Columns:      []string{"id", "name"},
			Rows:         [][]*string{{strptr("1"), strptr("alice")}, {strptr("2"), nil}},
			RowsAffected: -1,
		}},
	}
	done := make(chan relayResult, 1)
	go func() { done <- runDBRelay(context.Background(), ws, sess, DBRelayConfig{}) }()

	// First server frame is the "ready" greeting.
	if m := readDBServerMsg(t, cli); m.Type != "ready" {
		t.Fatalf("first msg type = %q, want ready", m.Type)
	}

	// Send a query.
	q, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select * from t"})
	if err := clientWriteFrame(cli, true, opText, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	m := readDBServerMsg(t, cli)
	if m.Type != "result" || m.Result == nil {
		t.Fatalf("result msg = %+v", m)
	}
	if len(m.Result.Columns) != 2 || len(m.Result.Rows) != 2 {
		t.Fatalf("result shape = %+v", m.Result)
	}
	if m.Result.Rows[1][1] != nil {
		t.Fatalf("expected NULL cell, got %v", *m.Result.Rows[1][1])
	}
	if got := sess.seenCalls(); len(got) != 1 || got[0] != "select * from t" {
		t.Fatalf("session saw %v", got)
	}

	// Close client side -> relay ends client_close.
	body := []byte{0x03, 0xe8} // 1000
	_ = clientWriteFrame(cli, true, opClose, body)
	drain(cli)
	res := <-done
	if res.Reason != "client_close" {
		t.Fatalf("reason = %q", res.Reason)
	}
	if res.BytesToBackend == 0 {
		t.Fatal("BytesToBackend not counted")
	}
}

func TestRunDBRelay_StatementErrorKeepsSessionOpen(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	sess := &fakeDBSession{
		errs:    []error{errors.New("syntax error at or near \"slect\""), nil},
		results: []*ResultSet{nil, {Command: "SELECT 1", RowsAffected: -1}},
	}
	done := make(chan relayResult, 1)
	go func() { done <- runDBRelay(context.Background(), ws, sess, DBRelayConfig{}) }()

	if m := readDBServerMsg(t, cli); m.Type != "ready" {
		t.Fatalf("want ready, got %q", m.Type)
	}

	// First statement errors.
	q1, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "slect 1"})
	_ = clientWriteFrame(cli, true, opText, q1)
	m1 := readDBServerMsg(t, cli)
	if m1.Type != "error" || !strings.Contains(m1.Error, "syntax error") {
		t.Fatalf("error msg = %+v", m1)
	}

	// Session is STILL open — a second statement succeeds.
	q2, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select 1"})
	_ = clientWriteFrame(cli, true, opText, q2)
	m2 := readDBServerMsg(t, cli)
	if m2.Type != "result" || m2.Result == nil || m2.Result.Command != "SELECT 1" {
		t.Fatalf("second result = %+v", m2)
	}

	_ = clientWriteFrame(cli, true, opClose, []byte{0x03, 0xe8})
	drain(cli)
	<-done
}

func TestRunDBRelay_RecordTee(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	sess := &fakeDBSession{results: []*ResultSet{{Columns: []string{"x"}, Rows: [][]*string{{strptr("7")}}, RowsAffected: -1}}}
	var rec syncBuf
	done := make(chan relayResult, 1)
	go func() { done <- runDBRelay(context.Background(), ws, sess, DBRelayConfig{RecordSink: &rec}) }()

	_ = readDBServerMsg(t, cli) // ready
	q, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select 7"})
	_ = clientWriteFrame(cli, true, opText, q)
	_ = readDBServerMsg(t, cli) // result

	if !waitFor(func() bool { return strings.Contains(rec.String(), `"sql":"select 7"`) }, time.Second) {
		t.Fatalf("audit tee = %q", rec.String())
	}
	if !strings.Contains(rec.String(), `"ok":true`) {
		t.Fatalf("audit record missing ok flag: %q", rec.String())
	}

	_ = clientWriteFrame(cli, true, opClose, []byte{0x03, 0xe8})
	drain(cli)
	<-done
}

func TestRunDBRelay_QueryTimeout(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	sess := &fakeDBSession{block: true, blockOn: 0}
	done := make(chan relayResult, 1)
	go func() {
		done <- runDBRelay(context.Background(), ws, sess, DBRelayConfig{QueryTimeout: 40 * time.Millisecond})
	}()

	_ = readDBServerMsg(t, cli) // ready
	q, _ := json.Marshal(dbClientMsg{Type: "query", SQL: "select pg_sleep(99)"})
	_ = clientWriteFrame(cli, true, opText, q)

	// The blocked Exec is cancelled by the per-statement timeout and reported
	// as a statement-level error; the session stays open.
	m := readDBServerMsg(t, cli)
	if m.Type != "error" {
		t.Fatalf("want timeout error, got %+v", m)
	}

	_ = clientWriteFrame(cli, true, opClose, []byte{0x03, 0xe8})
	drain(cli)
	<-done
}

func TestRunDBRelay_MaxDurationDeadline(t *testing.T) {
	ws, cli := wsTestPair(t)
	defer func() { _ = cli.Close() }()
	sess := &fakeDBSession{}
	drain(cli)
	start := time.Now()
	res := runDBRelay(context.Background(), ws, sess, DBRelayConfig{MaxDuration: 60 * time.Millisecond})
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("relay returned before MaxDuration")
	}
	if res.Reason != "deadline" {
		t.Fatalf("reason = %q, want deadline", res.Reason)
	}
}
