// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
)

// DBBackend is the seam between the access-broker's web SQL console and the
// jess Postgres/MySQL protocol brokers (ADR 0049 / ADR 0044 Phase 4). The
// broker authenticates + upgrades the browser WebSocket, opens a DBSession
// to the requested database target via this interface, then pumps query
// envelopes <-> result sets over the socket (see dbrelay.go).
//
// Keeping this an interface — exactly like the SSH-side Backend — lets the
// SQL relay + result-set codec be exercised end-to-end against a fake in
// tests, and lets the real jess DB-broker wiring land behind a clean
// boundary once jess ADR 0049's SQL brokers expose a callable interface
// from talon.
//
// HONEST STATE (Phase 4 scaffold): the production implementation
// (jessDBBackend) is a STUB — the jess-side Postgres/MySQL broker API is
// not yet reachable from talon, so Open returns ErrDBBackendNotWired. The
// in-memory fakeDBBackend used in tests proves the relay + codec are real.
// Everything ABOVE this interface (auth, channel gate, WebSocket framing,
// the query/result pump, the recording tee) is real and tested. See
// README/remaining.
type DBBackend interface {
	// Open establishes a brokered database session for req. jess owns the
	// wire protocol (pgwire / MySQL), connection auth, and the per-statement
	// WORM audit — the broker treats the returned DBSession as an opaque
	// "run this SQL, give me rows back" channel. The caller closes the
	// DBSession when the WebSocket relay ends.
	Open(ctx context.Context, req DBDialRequest) (DBSession, error)
}

// DBEngine identifies the database wire protocol the jess broker should
// speak to the target. The broker passes it through; jess resolves the
// concrete instance + credentials behind it.
type DBEngine string

const (
	// EnginePostgres routes to the jess pgwire broker.
	EnginePostgres DBEngine = "postgres"
	// EngineMySQL routes to the jess MySQL broker.
	EngineMySQL DBEngine = "mysql"
)

// validDBEngine reports whether e is an engine the broker will accept. The
// gate is at the broker edge so an unknown ?engine= can never reach jess.
func validDBEngine(e DBEngine) bool {
	switch e {
	case EnginePostgres, EngineMySQL:
		return true
	default:
		return false
	}
}

// DBDialRequest carries everything the DB backend needs to open + audit a
// brokered SQL session. The identity fields are projected from the verified
// Talon IAP identity token (never trusted from the client), so jess can
// bind the per-statement recording + JIT decision to the real subject —
// mirroring DialRequest on the SSH side.
type DBDialRequest struct {
	// Subject is the Falcon-ID iam_users.id (JWT sub) of the authenticated
	// user. Load-bearing for jess audit + JIT.
	Subject string
	// Email + TenantID are surfaced for the jess recording metadata.
	Email    string
	TenantID string
	// SessionID is the Talon session UUID (JWT sid) — lets jess join its
	// per-statement recording to Talon's audit trail.
	SessionID string
	// SSOChainID spans Talon <-> jess <-> recording logs.
	SSOChainID string

	// Engine selects the jess DB broker (postgres|mysql).
	Engine DBEngine
	// Target is the logical database target the user requested (a jess
	// target handle, e.g. "analytics-ro"). The broker passes it verbatim;
	// jess resolves + authorises it.
	Target string
	// Database is the optional initial database/schema to attach to.
	Database string
}

// DBSession is an opaque brokered SQL session. The broker submits one
// statement at a time and reads back a single ResultSet; jess (behind the
// backend) serialises concurrent statements and owns transaction state.
// Implementations MUST be safe against the relay's single-flight Exec loop
// (one in-flight Exec per session) and a concurrent Close.
type DBSession interface {
	// Exec runs a single SQL statement and returns its result. A query
	// returns rows; a non-query (INSERT/UPDATE/DDL) returns a ResultSet with
	// empty Columns and a populated Command/RowsAffected. A statement-level
	// error (bad SQL, permission denied at jess) is returned as a non-nil
	// error WITHOUT tearing down the session, so the console stays open.
	Exec(ctx context.Context, sql string) (*ResultSet, error)
	// Close ends the brokered session and releases the jess connection.
	Close() error
}

// ResultSet is the broker-neutral shape of a SQL result, rendered as a grid
// in the browser console. It is intentionally string-cell so the broker
// never needs per-engine type marshalling — jess (or the stub) stringifies
// cells; the browser renders text. NULL is represented by a nil *string in
// Rows so the UI can distinguish NULL from the empty string.
type ResultSet struct {
	// Columns are the result column names, in order. Empty for a non-query.
	Columns []string `json:"columns"`
	// Rows are the result rows; each row has len(Columns) cells. A nil cell
	// is SQL NULL; a non-nil cell is the stringified value.
	Rows [][]*string `json:"rows"`
	// Command is the completion tag for a non-query (e.g. "INSERT 0 1",
	// "CREATE TABLE"). Empty for a row-returning query.
	Command string `json:"command,omitempty"`
	// RowsAffected is set for non-query statements; -1 when not applicable.
	RowsAffected int64 `json:"rowsAffected"`
	// Truncated is true when jess capped the row count (the broker advertises
	// a max; jess enforces the authoritative limit). The UI shows a banner.
	Truncated bool `json:"truncated,omitempty"`
}

// ErrDBBackendNotWired is returned by the jess DB backend when it has no
// controller operator address configured — i.e. the deploy has not yet wired
// the path. It signals "the SQL relay + the operator ceremony are real but no
// jess controller address is configured to dial" — surfaced to the browser as
// a clean 1011 close with this reason, never a silent hang or an open
// connection. Mirrors ErrBackendNotWired on the SSH side.
var ErrDBBackendNotWired = errors.New("accessbroker: jess DB backend not wired — no controller operator address configured (set JessDBBackendConfig.ControllerAddr)")

// compile-time guards: the engine wire clients satisfy DBSession.
var (
	_ DBSession = (*pgConn)(nil)
	_ DBSession = (*mysqlConn)(nil)
)

// errNilDBBackend / errNilK8sBackend are returned by the DB / k8s handler
// constructors when their backend dependency is missing — fail closed at
// construction rather than serve an undialable console at runtime.
var (
	errNilDBBackend  = errors.New("accessbroker: DBHandlerConfig.Backend is required")
	errNilK8sBackend = errors.New("accessbroker: K8sHandlerConfig.Backend is required")
)
