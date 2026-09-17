// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

// dbClientMsg is the JSON envelope the browser SQL console sends on TEXT
// frames. One type today:
//
//	{"type":"query","sql":"select 1"}
//
// Unlike the SSH relay (a raw byte stream), the DB console is strictly
// message-oriented: the browser submits a statement, the broker runs it via
// the DBSession, and replies with exactly one dbServerMsg. This keeps the
// recording tee (ADR 0030) a clean per-statement audit record.
type dbClientMsg struct {
	Type string `json:"type"`
	SQL  string `json:"sql,omitempty"`
}

// dbServerMsg is the JSON envelope the broker sends back on TEXT frames.
// Exactly one of Result / Error is set per inbound query (Type mirrors the
// discriminant so the browser can branch without inspecting which field is
// populated).
type dbServerMsg struct {
	Type string `json:"type"` // "result" | "error" | "ready"
	// Result carries the rows/command for a successful statement.
	Result *ResultSet `json:"result,omitempty"`
	// Error carries a statement-level failure message (the session stays
	// open — the user can fix the SQL and retry).
	Error string `json:"error,omitempty"`
}

// DBRelayConfig parameterises a single browser<->DBSession SQL relay.
type DBRelayConfig struct {
	// RecordSink, when non-nil, receives a per-statement JSON audit record
	// (the tee to jess session recording, ADR 0030). jess remains the
	// durable authority; this relay-edge tee is a best-effort secondary
	// copy. nil disables the tee (dev/test).
	RecordSink io.Writer

	// MaxDuration, when > 0, hard-caps the console session lifetime (the
	// clientless absolute TTL from ADR 0044). When it elapses the relay
	// closes both sides with a 1000 normal closure.
	MaxDuration time.Duration

	// QueryTimeout bounds a single statement's execution. Zero -> 30s. A
	// statement that exceeds it is cancelled (ctx) and reported as a
	// statement-level error; the console stays open.
	QueryTimeout time.Duration
}

// dbAuditRecord is the per-statement record teed to the recording sink. It
// is the relay-edge secondary copy of what jess records authoritatively;
// kept deliberately small (no result rows — those can be large and are in
// jess's WORM log).
type dbAuditRecord struct {
	TS           time.Time `json:"ts"`
	SQL          string    `json:"sql"`
	OK           bool      `json:"ok"`
	Err          string    `json:"err,omitempty"`
	RowCount     int       `json:"rowCount"`
	RowsAffected int64     `json:"rowsAffected"`
}

// runDBRelay pumps SQL statements from the browser to the DBSession and
// result sets back, one statement at a time, until the client closes, a
// transport error occurs, or MaxDuration elapses. Unlike runRelay it is a
// single request/response loop (no concurrent output pump) — the DB console
// has no unsolicited backend output — which makes the statement<->result
// pairing, and the per-statement recording tee, exact.
func runDBRelay(parent context.Context, ws *wsConn, sess DBSession, cfg DBRelayConfig) relayResult {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)

	var (
		res   relayResult
		resMu sync.Mutex
	)
	setReason := func(reason string, err error) {
		resMu.Lock()
		defer resMu.Unlock()
		if res.Reason == "" { // first cause wins
			res.Reason = reason
			res.Err = err
		}
	}

	// All WebSocket writes are serialised through wsMu: the main loop writes
	// the ready/result/error frames, while the cancellation goroutine (below)
	// writes the close frame via ws.Close(). Without this they race on the
	// shared bufio.Writer (same discipline as runRelay's wsMu).
	var wsMu sync.Mutex
	writeServer := func(m dbServerMsg) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return writeDBServer(ws, m)
	}

	// Absolute-TTL timer (ADR 0044 clientless cap). Set the reason BEFORE
	// cancelling so the teardown's incidental transport error loses the
	// first-cause race — same discipline as runRelay.
	if cfg.MaxDuration > 0 {
		t := time.AfterFunc(cfg.MaxDuration, func() {
			setReason("deadline", nil)
			cancel()
		})
		defer t.Stop()
	}

	// Unblock the reader on cancellation (deadline) by closing both ends. The
	// ws.Close() writes a close frame, so it must hold wsMu to not race the
	// loop's result writes. Joined via wg before return so it has finished
	// closing before the handler's own deferred ws.Close() runs.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = sess.Close()
		wsMu.Lock()
		_ = ws.Close()
		wsMu.Unlock()
	}()
	defer wg.Wait()
	defer cancel() // ensure the cancel goroutine wakes even on a normal loop exit

	// Greet the console so the UI can flip to "ready" before the first query.
	_ = writeServer(dbServerMsg{Type: "ready"})

	for {
		msg, err := ws.ReadMessage()
		if err != nil {
			if errors.Is(err, ErrConnClosed) {
				setReason("client_close", nil)
			} else {
				setReason(dbReason(parent, ctx, err), err)
			}
			break
		}
		sql, ok := decodeDBClientFrame(msg)
		if !ok || sql == "" {
			// Ignore a malformed/empty control frame rather than dropping the
			// console — a stray frame shouldn't kill a live session.
			continue
		}

		qctx, qcancel := context.WithTimeout(ctx, cfg.QueryTimeout)
		rs, qerr := sess.Exec(qctx, sql)
		qcancel()

		resMu.Lock()
		res.BytesToBackend += int64(len(sql))
		resMu.Unlock()

		if qerr != nil {
			teeDBAudit(cfg.RecordSink, sql, nil, qerr)
			if werr := writeServer(dbServerMsg{Type: "error", Error: qerr.Error()}); werr != nil {
				setReason("error", werr)
				break
			}
			continue
		}
		teeDBAudit(cfg.RecordSink, sql, rs, nil)
		if werr := writeServer(dbServerMsg{Type: "result", Result: rs}); werr != nil {
			setReason("error", werr)
			break
		}
		// BytesToClient tracks the serialised result size for the exfil
		// dashboards (ADR 0044 calls out the relay as the download-volume
		// policy point). Approximate by the JSON length is unnecessary — we
		// already wrote it; count the row payload instead, cheaply.
		resMu.Lock()
		res.BytesToClient += int64(approxResultBytes(rs))
		resMu.Unlock()
	}

	if res.Reason == "" {
		res.Reason = dbReason(parent, ctx, nil)
	}
	return res
}

// decodeDBClientFrame extracts the SQL statement from a client message. A
// TEXT frame is the JSON {"type":"query","sql":...} envelope; a BINARY
// frame is treated as a raw UTF-8 statement (some minimal clients send
// that). Returns (sql, ok); ok is false only for a malformed TEXT/JSON
// frame or an unknown type.
func decodeDBClientFrame(msg message) (sql string, ok bool) {
	if msg.opcode == opBinary {
		return string(msg.payload), true
	}
	var m dbClientMsg
	if err := json.Unmarshal(msg.payload, &m); err != nil {
		return "", false
	}
	switch m.Type {
	case "query", "":
		return m.SQL, true
	default:
		return "", false
	}
}

// writeDBServer serialises a dbServerMsg as a TEXT frame.
func writeDBServer(ws *wsConn, m dbServerMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		// A marshalling failure is a server bug, not a client one; surface a
		// minimal error envelope so the console doesn't hang silently.
		return ws.WriteText(`{"type":"error","error":"internal: result encode failed"}`)
	}
	return ws.WriteText(string(b))
}

// teeDBAudit writes a per-statement audit record to the recording sink.
// Best-effort: a slow/broken recorder must not stall the console, so the
// write error is ignored here (jess is the durable authority).
func teeDBAudit(sink io.Writer, sql string, rs *ResultSet, qerr error) {
	if sink == nil {
		return
	}
	rec := dbAuditRecord{TS: time.Now().UTC(), SQL: sql, OK: qerr == nil, RowsAffected: -1}
	if qerr != nil {
		rec.Err = qerr.Error()
	}
	if rs != nil {
		rec.RowCount = len(rs.Rows)
		rec.RowsAffected = rs.RowsAffected
	}
	if b, err := json.Marshal(rec); err == nil {
		_, _ = sink.Write(append(b, '\n'))
	}
}

// approxResultBytes is a cheap estimate of a result set's payload size for
// the byte-volume metric (exact JSON length isn't worth a second marshal).
func approxResultBytes(rs *ResultSet) int {
	if rs == nil {
		return 0
	}
	n := 0
	for _, c := range rs.Columns {
		n += len(c)
	}
	for _, row := range rs.Rows {
		for _, cell := range row {
			if cell != nil {
				n += len(*cell)
			}
		}
	}
	return n
}

// dbReason classifies how the DB relay ended: parent-cancelled
// ("client_close"), the relay's own MaxDuration timer ("deadline"), a clean
// loop exit ("backend_eof"), or a transport error ("error").
func dbReason(parent, child context.Context, err error) string {
	if parent.Err() != nil {
		return "client_close"
	}
	if child.Err() != nil {
		return "deadline"
	}
	if err != nil {
		return "error"
	}
	return "backend_eof"
}
