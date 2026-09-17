// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// pgwire is a deliberately minimal PostgreSQL wire-protocol (v3) client,
// just enough to drive the jess Postgres broker's OPERATOR side. It is NOT a
// general Postgres driver — it speaks the simple query protocol ('Q' →
// RowDescription/DataRow/CommandComplete) over a connection the jess
// controller has ALREADY bridged to the broker.
//
// Why hand-rolled (no pgx dependency): the broker connection is passwordless
// by design (jess authenticated the operator out of band via the
// wire.OperatorRequest token + JIT grant, then the broker replies
// AuthenticationOk immediately and injects the ephemeral Vault credential to
// the real target — see jess internal/dbproxy/postgres.go). The operator
// side therefore needs only: StartupMessage → wait AuthenticationOk +
// ReadyForQuery → run simple queries. That is a small, well-specified subset,
// and keeping it dependency-free matches this repo's posture (hand-rolled SSH
// relay via x/crypto, hand-rolled WebSocket codec, no gRPC).
//
// Security note: NO statement policy or recording lives here. Every statement
// is enforced + WORM-recorded SERVER-SIDE in the jess broker (postgres.go
// enforce()/qlog); this client is a dumb pipe that hands jess the SQL string
// and renders the rows jess returns.

// pgProtocolVersion3 is the v3.0 startup protocol version (major<<16|minor).
const pgProtocolVersion3 = 196608 // 3 << 16

// pgMaxOutFrame caps the body of any frontend frame we build (StartupMessage,
// Query, Terminate). The Postgres v3 frame length is a signed int32 INCLUDING
// the 4-byte length word, so the body must fit in math.MaxInt32-4. We also use
// it as the safe ceiling for the int->uint32 length conversions below: a body
// at or below this size cannot overflow the int32 length field. Anything bigger
// is rejected rather than silently truncated (DoS / corruption guard). 256 MiB
// is far above any real console statement and well under the int32 cap.
const pgMaxOutFrame = 256 << 20 // 256 MiB

// pgConn is an open simple-query Postgres session over an already-bridged
// connection. Exec is single-flight (the DBSession contract); concurrent Exec
// is the caller's responsibility to serialise — runDBRelay already does (one
// in-flight statement per session).
type pgConn struct {
	rwc io.ReadWriteCloser
	r   *bufio.Reader
	w   *bufio.Writer

	mu     sync.Mutex // serialises Exec vs Close
	closed bool
}

// newPGConn performs the Postgres v3 startup handshake against the
// jess-bridged connection and returns a ready session. user/database are
// cosmetic for the broker (it injects the real ephemeral creds) but are sent
// in the StartupMessage for protocol correctness; a non-empty database lets a
// future direct (non-broker) target attach to a schema.
func newPGConn(ctx context.Context, rwc io.ReadWriteCloser, user, database string) (*pgConn, error) {
	c := &pgConn{
		rwc: rwc,
		r:   bufio.NewReader(rwc),
		w:   bufio.NewWriter(rwc),
	}
	if user == "" {
		user = "operator" // the broker's permissive auth accepts any user; this is for the StartupMessage param list only
	}
	if err := c.startup(user, database); err != nil {
		_ = rwc.Close()
		return nil, err
	}
	if err := c.awaitReady(); err != nil {
		_ = rwc.Close()
		return nil, err
	}
	_ = ctx // startup is bounded by the caller's dial deadline on rwc
	return c, nil
}

// startup writes the v3 StartupMessage (no SSLRequest: the jess broker
// connection is already mTLS-wrapped by the mesh + the controller bridge, and
// the broker's ReceiveStartupMessage path declines SSL negotiation anyway).
func (c *pgConn) startup(user, database string) error {
	params := []string{"user", user}
	if database != "" {
		params = append(params, "database", database)
	}
	// Body = int32 protocolVersion + key\0value\0... + final \0.
	var body []byte
	body = binary.BigEndian.AppendUint32(body, uint32(pgProtocolVersion3))
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)

	// StartupMessage has NO type byte (length-prefixed only). Bound the body so
	// the int->uint32 length conversion cannot overflow the int32 frame length.
	if len(body) > pgMaxOutFrame {
		return fmt.Errorf("pgwire: startup message too large (%d bytes)", len(body))
	}
	var hdr [4]byte
	//nolint:gosec // G115: len(body) is bounded by pgMaxOutFrame (256 MiB) just above, so len(body)+4 cannot overflow uint32 / the int32 frame length.
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)+4))
	if _, err := c.w.Write(hdr[:]); err != nil {
		return fmt.Errorf("pgwire: write startup header: %w", err)
	}
	if _, err := c.w.Write(body); err != nil {
		return fmt.Errorf("pgwire: write startup body: %w", err)
	}
	if err := c.w.Flush(); err != nil {
		return fmt.Errorf("pgwire: flush startup: %w", err)
	}
	return nil
}

// awaitReady reads server messages until the first ReadyForQuery, tolerating
// the parameter-status / backend-key / notice chatter the broker relays from
// the target. An AuthenticationXxx that is not AuthenticationOk (0) is a hard
// error — the broker is expected to inject creds and answer AuthenticationOk,
// so a password challenge means a misconfigured deployment, not something this
// dumb client can satisfy (and must NOT try to — credentials are jess's job).
func (c *pgConn) awaitReady() error {
	for {
		typ, payload, err := c.readMessage()
		if err != nil {
			return err
		}
		switch typ {
		case 'R': // Authentication*
			if len(payload) < 4 {
				return errors.New("pgwire: short Authentication message")
			}
			if code := binary.BigEndian.Uint32(payload[:4]); code != 0 {
				return fmt.Errorf("pgwire: broker requested auth method %d, but the operator path must be passwordless (jess injects target creds) — check the jess Postgres broker wiring", code)
			}
		case 'S', 'K', 'N': // ParameterStatus, BackendKeyData, NoticeResponse — ignore
		case 'E': // ErrorResponse during startup = fatal
			return fmt.Errorf("pgwire: startup error: %s", parsePGError(payload))
		case 'Z': // ReadyForQuery
			return nil
		default:
			// Unexpected but non-fatal pre-ready frame — skip it rather than
			// kill the session on a benign extension message.
		}
	}
}

// Exec runs one SQL statement via the simple query protocol and returns its
// ResultSet. A statement-level ErrorResponse is returned as a non-nil error
// WITHOUT tearing down the session (the console stays open) — matching the
// DBSession contract. A transport error tears the session down.
func (c *pgConn) Exec(ctx context.Context, sql string) (*ResultSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("pgwire: session closed")
	}
	// Honour a cancelled context before writing — the relay's per-query
	// timeout cancels ctx; we surface it as a statement-level error so the
	// console stays open (the underlying conn stays usable).
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := c.writeQuery(sql); err != nil {
		// A write failure is fatal to the session; tear it down. The teardown
		// error is best-effort (the conn is already broken) — the write error is
		// the one worth surfacing.
		_ = c.closeLocked()
		return nil, err
	}
	rs, transportErr := c.readQueryResponse()
	if transportErr != nil {
		// Transport read failure: same — close best-effort, return the transport
		// error that actually describes the failure.
		_ = c.closeLocked()
		return nil, transportErr
	}
	if rs.stmtErr != nil {
		return nil, rs.stmtErr // statement-level: session stays open
	}
	return rs.set, nil
}

// writeQuery sends a 'Q' (simple Query) message.
func (c *pgConn) writeQuery(sql string) error {
	body := make([]byte, 0, len(sql)+1)
	body = append(body, sql...)
	body = append(body, 0) // C-string NUL terminator
	if err := c.writeMessage('Q', body); err != nil {
		return err
	}
	return c.w.Flush()
}

// pgQueryOutcome is the parsed result of one simple-query exchange.
type pgQueryOutcome struct {
	set     *ResultSet
	stmtErr error // statement-level error (ErrorResponse); session survives
}

// readQueryResponse consumes server messages up to and including the
// terminating ReadyForQuery, assembling a ResultSet. The simple query
// protocol may return MULTIPLE result sets (for a multi-statement string);
// the console submits one statement at a time, so we return the LAST
// row-returning set (or the last command tag) — the common, well-defined case.
func (c *pgConn) readQueryResponse() (pgQueryOutcome, error) {
	out := pgQueryOutcome{set: &ResultSet{RowsAffected: -1}}
	var cur *ResultSet
	for {
		typ, payload, err := c.readMessage()
		if err != nil {
			return pgQueryOutcome{}, err
		}
		switch typ {
		case 'T': // RowDescription
			cur = &ResultSet{Columns: parseRowDescription(payload), RowsAffected: -1}
		case 'D': // DataRow
			if cur == nil {
				cur = &ResultSet{RowsAffected: -1}
			}
			cur.Rows = append(cur.Rows, parseDataRow(payload))
		case 'C': // CommandComplete
			tag := cString(payload)
			if cur != nil {
				cur.Command = tag
				cur.RowsAffected = rowsAffectedFromTag(tag)
				out.set = cur
				cur = nil
			} else {
				out.set = &ResultSet{Command: tag, RowsAffected: rowsAffectedFromTag(tag)}
			}
		case 'I': // EmptyQueryResponse
			out.set = &ResultSet{Command: "EMPTY", RowsAffected: -1}
		case 'E': // ErrorResponse — statement-level; session stays open
			out.stmtErr = fmt.Errorf("%s", parsePGError(payload))
		case 'Z': // ReadyForQuery — end of this query's responses
			return out, nil
		case 'S', 'N': // ParameterStatus, NoticeResponse — ignore
		default:
			// Skip frames we don't model (e.g. async NotificationResponse).
		}
	}
}

// readMessage reads one typed backend message: 1 type byte + int32 length
// (length includes itself) + body.
func (c *pgConn) readMessage() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n < 4 {
		return 0, nil, fmt.Errorf("pgwire: invalid message length %d", n)
	}
	bodyLen := int(n) - 4
	const maxMsg = 256 << 20 // 256 MiB guard against a hostile/garbled length
	if bodyLen > maxMsg {
		return 0, nil, fmt.Errorf("pgwire: message too large (%d bytes)", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return 0, nil, err
	}
	return typ, body, nil
}

// writeMessage writes one typed frontend message.
func (c *pgConn) writeMessage(typ byte, body []byte) error {
	// Bound the body so the int->uint32 length conversion cannot overflow the
	// int32 frame length (and guard against an oversized Query string).
	if len(body) > pgMaxOutFrame {
		return fmt.Errorf("pgwire: outbound %c message too large (%d bytes)", typ, len(body))
	}
	var hdr [5]byte
	hdr[0] = typ
	//nolint:gosec // G115: len(body) is bounded by pgMaxOutFrame (256 MiB) just above, so len(body)+4 cannot overflow uint32 / the int32 frame length.
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)+4))
	if _, err := c.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(body); err != nil {
		return err
	}
	return nil
}

// Close tears down the session, sending a Terminate ('X') best-effort first.
func (c *pgConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *pgConn) closeLocked() error {
	if c.closed {
		return nil
	}
	c.closed = true
	_ = c.writeMessage('X', nil) // Terminate — best-effort
	_ = c.w.Flush()
	return c.rwc.Close()
}

// --- payload parsers -------------------------------------------------------

// parseRowDescription extracts the column names from a 'T' message: int16
// fieldCount, then per field a NUL-terminated name + 18 bytes of metadata we
// don't render (table OID, attnum, type OID, type size, type modifier, format).
func parseRowDescription(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(payload[:2]))
	cols := make([]string, 0, count)
	p := payload[2:]
	for i := 0; i < count; i++ {
		name, rest, ok := cutCString(p)
		if !ok {
			break
		}
		cols = append(cols, name)
		if len(rest) < 18 {
			break
		}
		p = rest[18:]
	}
	return cols
}

// parseDataRow extracts the cells from a 'D' message: int16 columnCount, then
// per column an int32 length (-1 = SQL NULL) + that many bytes (text format,
// since we never request binary). A nil *string preserves NULL vs "".
func parseDataRow(payload []byte) []*string {
	if len(payload) < 2 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(payload[:2]))
	row := make([]*string, 0, count)
	p := payload[2:]
	for i := 0; i < count; i++ {
		if len(p) < 4 {
			break
		}
		// The DataRow column length is, by Postgres protocol definition, a SIGNED
		// Int32 where -1 means SQL NULL. Reinterpreting the big-endian uint32 as
		// int32 is the exact protocol decode — EVERY uint32 bit pattern is a
		// legal int32 value, so a "bounds check before conversion" is not
		// meaningful (there is no out-of-range input to reject). The decoded
		// value is validated below: n<0 is NULL, and int(n)>len(p) rejects a
		// length that runs past the buffer. This is the one case where a guard is
		// genuinely impossible, hence the justified suppression below.
		//nolint:gosec // G115: the DataRow column length is a protocol-defined signed Int32 (-1=NULL); every uint32 bit pattern is a valid int32 so there is no out-of-range input to reject, and the decoded value is validated by the n<0 and int(n)>len(p) checks below.
		n := int32(binary.BigEndian.Uint32(p[:4]))
		p = p[4:]
		if n < 0 { // SQL NULL
			row = append(row, nil)
			continue
		}
		if int(n) > len(p) {
			break
		}
		s := string(p[:n])
		row = append(row, &s)
		p = p[n:]
	}
	return row
}

// rowsAffectedFromTag parses the trailing count out of a CommandComplete tag
// ("INSERT 0 5" → 5, "UPDATE 3" → 3, "DELETE 2" → 2, "SELECT 17" → 17). For a
// tag with no numeric suffix it returns -1 (not applicable).
func rowsAffectedFromTag(tag string) int64 {
	fields := splitFields(tag)
	if len(fields) == 0 {
		return -1
	}
	last := fields[len(fields)-1]
	n, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// parsePGError renders an ErrorResponse/'E' message into a human-readable
// string ("ERROR: <message> (SQLSTATE <code>)"), reading the NUL-delimited
// field list (each field is a type byte + NUL-terminated value, list ends on a
// zero type byte).
func parsePGError(payload []byte) string {
	var severity, message, code string
	p := payload
	for len(p) > 0 {
		ft := p[0]
		if ft == 0 {
			break
		}
		val, rest, ok := cutCString(p[1:])
		if !ok {
			break
		}
		switch ft {
		case 'S', 'V':
			if severity == "" {
				severity = val
			}
		case 'M':
			message = val
		case 'C':
			code = val
		}
		p = rest
	}
	if severity == "" {
		severity = "ERROR"
	}
	if message == "" {
		message = "unspecified database error"
	}
	if code != "" {
		return fmt.Sprintf("%s: %s (SQLSTATE %s)", severity, message, code)
	}
	return fmt.Sprintf("%s: %s", severity, message)
}

// --- small byte helpers ----------------------------------------------------

// cString returns the bytes up to (not including) the first NUL as a string.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// cutCString splits a NUL-terminated C string off the front of b, returning
// the string, the remainder AFTER the NUL, and ok=false if no NUL is present.
func cutCString(b []byte) (s string, rest []byte, ok bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", b, false
}

// splitFields splits on ASCII spaces (CommandComplete tags are space-joined).
func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
