// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// mysqlwire is a deliberately minimal MySQL wire-protocol client, just enough
// to drive the jess MySQL broker's OPERATOR side. It is NOT a general MySQL
// driver — it speaks the text-protocol COM_QUERY exchange over a connection
// the jess controller has ALREADY bridged to the broker.
//
// Why hand-rolled (no go-mysql dependency): the broker's operator-facing auth
// is intentionally PERMISSIVE — mysql_native_password with an EMPTY password
// (jess internal/mysqlproxy permissiveAuth: "the operator connects with
// --user=<anything> --password="; the MySQL-level credential is decorative,
// jess already authenticated the operator via the wire.OperatorRequest token +
// grant and injects the real Vault creds to the target). An empty password
// under mysql_native_password means a ZERO-LENGTH auth response — no SHA1
// scramble math — so the handshake the operator must perform is small. Keeping
// it dependency-free matches this repo's posture (hand-rolled SSH/WebSocket,
// no gRPC).
//
// Security note: NO statement policy or recording lives here. Every statement
// is enforced + WORM-recorded SERVER-SIDE in the jess broker; this client is a
// dumb pipe that hands jess the SQL string and renders the rows jess returns.

// MySQL client capability flags (subset we assert in HandshakeResponse41).
const (
	mysqlClientLongPassword     = 0x00000001
	mysqlClientLongFlag         = 0x00000004
	mysqlClientProtocol41       = 0x00000200
	mysqlClientSecureConnection = 0x00008000
	mysqlClientPluginAuth       = 0x00080000
	mysqlClientDeprecateEOF     = 0x01000000
)

const (
	// mysqlMaxColumns caps a result set's column count. MySQL's own hard limit
	// is 4096 columns per table/result; a length-encoded count above this is a
	// garbled or hostile frame and is rejected before any per-column allocation
	// or uint64->int conversion (DoS / overflow guard).
	mysqlMaxColumns = 4096

	// mysqlMaxPacketPayload is the exclusive upper bound for one packet's
	// payload: the wire length field is 24-bit, and a payload of 0xffffff or
	// more triggers the split-packet protocol this minimal client does not
	// implement. Outbound payloads at/above this are rejected rather than
	// silently truncated by the int->byte length-field writes.
	mysqlMaxPacketPayload = 0xffffff // 16 MiB - 1 is the max single-packet payload
)

// mysqlConn is an open text-protocol MySQL session over an already-bridged
// connection. Exec is single-flight (the DBSession contract; runDBRelay runs
// one statement at a time).
type mysqlConn struct {
	rwc io.ReadWriteCloser
	r   *bufio.Reader
	w   *bufio.Writer

	seq          uint8 // packet sequence id (reset to 0 by each command)
	deprecateEOF bool  // server agreed to CLIENT_DEPRECATE_EOF

	mu     sync.Mutex
	closed bool
}

// newMySQLConn performs the MySQL handshake against the jess-bridged
// connection (empty-password mysql_native_password) and returns a ready
// session. user/database are sent in HandshakeResponse41 for protocol
// correctness; the broker injects the real ephemeral creds to the target.
func newMySQLConn(ctx context.Context, rwc io.ReadWriteCloser, user, database string) (*mysqlConn, error) {
	c := &mysqlConn{rwc: rwc, r: bufio.NewReader(rwc), w: bufio.NewWriter(rwc)}
	if user == "" {
		user = "operator" // the broker's permissive auth accepts any user
	}
	if err := c.handshake(user, database); err != nil {
		_ = rwc.Close()
		return nil, err
	}
	_ = ctx // bounded by the caller's dial deadline on rwc
	return c, nil
}

// handshake reads the server's Initial Handshake packet, replies with a
// HandshakeResponse41 carrying an EMPTY auth response (empty-password
// mysql_native_password), and consumes the server's OK/ERR.
func (c *mysqlConn) handshake(user, database string) error {
	greeting, err := c.readPacket()
	if err != nil {
		return fmt.Errorf("mysqlwire: read server greeting: %w", err)
	}
	if len(greeting) == 0 {
		return errors.New("mysqlwire: empty server greeting")
	}
	if greeting[0] == 0xff {
		return fmt.Errorf("mysqlwire: server rejected connection: %s", parseMySQLErr(greeting))
	}
	if greeting[0] != 10 {
		return fmt.Errorf("mysqlwire: unsupported handshake protocol version %d (want 10)", greeting[0])
	}
	srvCaps, err := parseHandshakeCaps(greeting)
	if err != nil {
		return err
	}
	if srvCaps&mysqlClientProtocol41 == 0 {
		return errors.New("mysqlwire: server does not support protocol 4.1")
	}
	// Track whether the server (the broker) speaks DEPRECATE_EOF so the
	// result-set reader knows whether to expect EOF packets between phases.
	c.deprecateEOF = srvCaps&mysqlClientDeprecateEOF != 0

	resp := c.buildHandshakeResponse(user, database, srvCaps)
	if err := c.writePacket(resp); err != nil {
		return fmt.Errorf("mysqlwire: write handshake response: %w", err)
	}
	auth, err := c.readPacket()
	if err != nil {
		return fmt.Errorf("mysqlwire: read auth result: %w", err)
	}
	switch auth[0] {
	case 0x00: // OK
		return nil
	case 0xff: // ERR
		return fmt.Errorf("mysqlwire: auth failed: %s", parseMySQLErr(auth))
	case 0xfe: // AuthSwitchRequest — the broker uses native-password empty-pw, so we shouldn't see this
		return errors.New("mysqlwire: server requested an auth-method switch, but the operator path is empty-password mysql_native_password — check the jess MySQL broker wiring")
	default:
		return fmt.Errorf("mysqlwire: unexpected auth result byte 0x%02x", auth[0])
	}
}

// buildHandshakeResponse assembles a HandshakeResponse41 with an empty auth
// response (the broker's permissive empty-password path).
func (c *mysqlConn) buildHandshakeResponse(user, database string, srvCaps uint32) []byte {
	caps := uint32(mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientLongPassword | mysqlClientLongFlag | mysqlClientPluginAuth)
	if srvCaps&mysqlClientDeprecateEOF != 0 {
		caps |= mysqlClientDeprecateEOF
	}
	const clientConnectWithDB = 0x00000008
	if database != "" {
		caps |= clientConnectWithDB
	}

	var b []byte
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 16<<20) // max packet size 16MiB
	b = append(b, 45)                               // charset utf8mb4_general_ci (cosmetic; broker re-negotiates target)
	b = append(b, make([]byte, 23)...)              // 23 reserved zero bytes
	b = append(b, user...)
	b = append(b, 0) // user NUL terminator

	// auth-response length-prefixed (CLIENT_SECURE_CONNECTION): empty password
	// => 1-byte length 0x00, no bytes.
	b = append(b, 0x00)

	if database != "" {
		b = append(b, database...)
		b = append(b, 0)
	}
	// auth plugin name (CLIENT_PLUGIN_AUTH).
	b = append(b, "mysql_native_password"...)
	b = append(b, 0)
	return b
}

// Exec runs one SQL statement via COM_QUERY and returns its ResultSet. A
// statement-level MySQL ERR is returned as a non-nil error WITHOUT tearing
// down the session; a transport error tears it down.
func (c *mysqlConn) Exec(ctx context.Context, sql string) (*ResultSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("mysqlwire: session closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.seq = 0                           // each command sequence restarts at 0
	cmd := append([]byte{0x03}, sql...) // COM_QUERY = 0x03
	if err := c.writePacket(cmd); err != nil {
		// Write failure is fatal to the session; tear it down. The teardown
		// error is best-effort (the conn is already broken) — surface the write
		// error that actually describes the failure.
		_ = c.closeLocked()
		return nil, err
	}
	rs, stmtErr, transportErr := c.readQueryResult()
	if transportErr != nil {
		// Transport read failure: close best-effort, return the transport error.
		_ = c.closeLocked()
		return nil, transportErr
	}
	if stmtErr != nil {
		return nil, stmtErr // session stays open
	}
	return rs, nil
}

// readQueryResult reads the response to a COM_QUERY: an OK packet (non-query),
// an ERR packet (statement error), or a result set (column-count + column
// defs + [EOF] + rows + EOF/OK).
func (c *mysqlConn) readQueryResult() (rs *ResultSet, stmtErr, transportErr error) {
	first, err := c.readPacket()
	if err != nil {
		return nil, nil, err
	}
	if len(first) == 0 {
		// A zero-length COM_QUERY response is a protocol violation; treat it as a
		// transport-level fault rather than indexing first[0] (panic guard).
		return nil, nil, errors.New("mysqlwire: empty COM_QUERY response packet")
	}
	switch first[0] {
	case 0x00: // OK packet — non-query (INSERT/UPDATE/DDL)
		affected, _ := lenEncInt(first[1:])
		ra, err := safeUint64ToInt64(affected)
		if err != nil {
			return nil, nil, fmt.Errorf("mysqlwire: OK packet affected-rows: %w", err)
		}
		return &ResultSet{RowsAffected: ra, Command: "OK"}, nil, nil
	case 0xff: // ERR packet — statement-level
		return nil, fmt.Errorf("%s", parseMySQLErr(first)), nil
	case 0xfb: // LOCAL INFILE — unsupported in the clientless console
		return nil, errors.New("mysqlwire: LOCAL INFILE is not supported by the clientless console"), nil
	}

	// Otherwise first[0] is a length-encoded column count. Bound it before any
	// uint64->int conversion (and before allocating per-column): MySQL's own
	// hard limit is 4096 columns, so a count above mysqlMaxColumns is a garbled
	// or hostile length — reject it rather than convert/alloc on it.
	colCount, _ := lenEncInt(first)
	if colCount == 0 || colCount > mysqlMaxColumns {
		return nil, nil, fmt.Errorf("mysqlwire: implausible column count %d (max %d)", colCount, mysqlMaxColumns)
	}
	cols := make([]string, 0, colCount)
	for i := uint64(0); i < colCount; i++ {
		def, derr := c.readPacket()
		if derr != nil {
			return nil, nil, derr
		}
		cols = append(cols, parseColumnName(def))
	}
	// Pre-DEPRECATE_EOF servers send an EOF packet after the column defs.
	if !c.deprecateEOF {
		if _, eerr := c.readPacket(); eerr != nil {
			return nil, nil, eerr
		}
	}

	// colCount is bounded by mysqlMaxColumns above, so int(colCount) is safe.
	out := &ResultSet{Columns: cols, RowsAffected: -1}
	for {
		row, rerr := c.readPacket()
		if rerr != nil {
			return nil, nil, rerr
		}
		if len(row) == 0 {
			return nil, nil, errors.New("mysqlwire: empty result-set row packet")
		}
		// End of rows: EOF (0xfe, <9 bytes) in legacy mode, or OK-as-EOF
		// (0xfe) under DEPRECATE_EOF. ERR mid-stream is a statement error.
		if row[0] == 0xff {
			return nil, fmt.Errorf("%s", parseMySQLErr(row)), nil
		}
		if row[0] == 0xfe && len(row) < 9 {
			return out, nil, nil
		}
		out.Rows = append(out.Rows, parseTextRow(row, int(colCount)))
	}
}

// --- packet framing --------------------------------------------------------

// readPacket reads one MySQL packet: 3-byte little-endian length + 1-byte
// sequence + payload. (We do not reassemble 16MiB-spanning split packets here;
// a single console result row exceeding 16MiB-1 is not a realistic case and
// would surface as a short read rather than silent corruption.)
func (c *mysqlConn) readPacket() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	c.seq = hdr[3] + 1
	if n == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writePacket writes one MySQL packet with the current sequence id, then
// flushes.
func (c *mysqlConn) writePacket(payload []byte) error {
	n := len(payload)
	// The MySQL packet length is a 24-bit little-endian field; a payload of
	// 0xffffff or more would require the split-packet protocol this minimal
	// client does not implement (see readPacket). Bound it before the int->byte
	// length-field conversions so we never silently truncate a too-long packet
	// (which would corrupt the framing). A console COM_QUERY this large is not a
	// realistic case.
	if n >= mysqlMaxPacketPayload {
		return fmt.Errorf("mysqlwire: outbound packet too large (%d bytes; max %d)", n, mysqlMaxPacketPayload-1)
	}
	var hdr [4]byte
	hdr[0] = byte(n & 0xff)
	hdr[1] = byte((n >> 8) & 0xff)
	hdr[2] = byte((n >> 16) & 0xff)
	hdr[3] = c.seq
	c.seq++
	if _, err := c.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.w.Write(payload); err != nil {
		return err
	}
	return c.w.Flush()
}

// Close tears down the session, sending COM_QUIT (0x01) best-effort first.
func (c *mysqlConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *mysqlConn) closeLocked() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.seq = 0
	_ = c.writePacket([]byte{0x01}) // COM_QUIT — best-effort
	return c.rwc.Close()
}

// --- payload parsers -------------------------------------------------------

// parseHandshakeCaps extracts the server capability flags from the Initial
// Handshake packet (protocol 10). Layout: 1 protoVer, NUL serverVersion, 4
// connID, 8 auth-data-1, 1 filler, 2 caps-low, [if more] 1 charset, 2 status,
// 2 caps-high, ...
func parseHandshakeCaps(g []byte) (uint32, error) {
	p := g[1:] // skip protocol version
	// server version (NUL-terminated)
	_, rest, ok := cutCStringBytes(p)
	if !ok {
		return 0, errors.New("mysqlwire: malformed greeting (server version)")
	}
	p = rest
	if len(p) < 4+8+1+2 {
		return 0, errors.New("mysqlwire: greeting too short")
	}
	p = p[4:] // connection id
	p = p[8:] // auth-plugin-data part 1
	p = p[1:] // filler
	capsLow := uint32(binary.LittleEndian.Uint16(p[:2]))
	p = p[2:]
	caps := capsLow
	// Extended section (charset + status + caps-high) is present when there's
	// more data — standard for any modern server / the go-mysql broker.
	if len(p) >= 1+2+2 {
		p = p[1:] // charset
		p = p[2:] // status flags
		capsHigh := uint32(binary.LittleEndian.Uint16(p[:2]))
		caps |= capsHigh << 16
	}
	return caps, nil
}

// parseColumnName extracts the column name (the 5th length-encoded string) from
// a Column Definition 41 packet: catalog, schema, table, org_table, NAME, ...
func parseColumnName(def []byte) string {
	p := def
	for i := 0; i < 4; i++ { // skip catalog, schema, table, org_table
		_, rest, ok := skipLenEncStr(p)
		if !ok {
			return ""
		}
		p = rest
	}
	name, _, ok := lenEncStr(p)
	if !ok {
		return ""
	}
	return name
}

// parseTextRow extracts the cells from a text-protocol ResultsetRow: each cell
// is a length-encoded string, or 0xfb for SQL NULL.
func parseTextRow(row []byte, colCount int) []*string {
	cells := make([]*string, 0, colCount)
	p := row
	for i := 0; i < colCount; i++ {
		if len(p) == 0 {
			break
		}
		if p[0] == 0xfb { // NULL
			cells = append(cells, nil)
			p = p[1:]
			continue
		}
		s, rest, ok := lenEncStr(p)
		if !ok {
			break
		}
		v := s
		cells = append(cells, &v)
		p = rest
	}
	return cells
}

// parseMySQLErr renders an ERR packet (0xff) into "ERROR <code>: <message>".
// Layout: 0xff, 2-byte errorCode, ['#' + 5-byte SQL state], message.
func parseMySQLErr(pkt []byte) string {
	if len(pkt) < 3 {
		return "unknown MySQL error"
	}
	code := binary.LittleEndian.Uint16(pkt[1:3])
	msg := pkt[3:]
	state := ""
	if len(msg) > 6 && msg[0] == '#' {
		state = string(msg[1:6])
		msg = msg[6:]
	}
	if state != "" {
		return fmt.Sprintf("ERROR %d (%s): %s", code, state, string(msg))
	}
	return fmt.Sprintf("ERROR %d: %s", code, string(msg))
}

// safeUint64ToInt64 converts a wire-supplied uint64 (e.g. an OK packet's
// affected-rows count) to int64, rejecting a value that would overflow int64's
// positive range rather than wrapping it to a negative count.
func safeUint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("value %d exceeds int64 range", v)
	}
	return int64(v), nil
}

// --- length-encoded helpers ------------------------------------------------

// lenEncInt decodes a MySQL length-encoded integer, returning the value and
// the number of bytes consumed.
func lenEncInt(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] {
	case 0xfb: // NULL sentinel (caller-dependent meaning)
		return 0, 1
	case 0xfc:
		if len(b) < 3 {
			return 0, 1
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3
	case 0xfd:
		if len(b) < 4 {
			return 0, 1
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	case 0xfe:
		if len(b) < 9 {
			return 0, 1
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9
	default:
		return uint64(b[0]), 1
	}
}

// lenEncStr decodes a length-encoded string, returning it, the remainder, and
// ok=false on truncation.
func lenEncStr(b []byte) (s string, rest []byte, ok bool) {
	n, consumed := lenEncInt(b)
	if consumed == 0 {
		return "", b, false
	}
	b = b[consumed:]
	if uint64(len(b)) < n {
		return "", b, false
	}
	return string(b[:n]), b[n:], true
}

// skipLenEncStr advances past a length-encoded string without allocating it.
func skipLenEncStr(b []byte) (skipped int, rest []byte, ok bool) {
	n, consumed := lenEncInt(b)
	if consumed == 0 {
		return 0, b, false
	}
	body := b[consumed:]
	// Bound the declared length against the buffer BEFORE slicing/converting:
	// n must fit in the remaining bytes (which is an int). This both rejects a
	// truncated/hostile length and makes the body-length an in-range int derived
	// from len() (no uint64->int width hazard).
	if uint64(len(body)) < n {
		return 0, b, false
	}
	bodyLen := len(body) - len(body[n:]) // == n, but expressed as an in-range int
	return consumed + bodyLen, body[n:], true
}

// cutCStringBytes splits a NUL-terminated C string off the front of b,
// returning its bytes, the remainder AFTER the NUL, and ok.
func cutCStringBytes(b []byte) (s []byte, rest []byte, ok bool) {
	for i, ch := range b {
		if ch == 0 {
			return b[:i], b[i+1:], true
		}
	}
	return nil, b, false
}
