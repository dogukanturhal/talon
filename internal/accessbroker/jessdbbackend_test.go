// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeAssertion is a test AssertionMinter that returns a fixed token and
// records the request it saw, so we can assert identity binding.
type fakeAssertion struct {
	token string
	err   error
	seen  DBDialRequest
}

func (f *fakeAssertion) Mint(_ context.Context, req DBDialRequest) (string, error) {
	f.seen = req
	return f.token, f.err
}

// fakeGrant returns a fixed grant id.
type fakeGrant struct{ id string }

func (f fakeGrant) GrantID(context.Context, DBDialRequest) (string, error) { return f.id, nil }

// openNoTLSForTest mirrors Open but dials the configured ControllerAddr over
// PLAINTEXT (the fake servers speak plaintext) and runs the same ceremony +
// engine startup. It exercises the production assertion-mint + grant-resolve +
// operator-request + pgwire/MySQL codec path; only the TLS wrap is skipped.
func (b *jessDBBackend) openNoTLSForTest(ctx context.Context, req DBDialRequest) (DBSession, error) {
	token, err := b.cfg.Assertion.Mint(ctx, req)
	if err != nil {
		return nil, err
	}
	var grantID string
	if b.cfg.GrantResolver != nil {
		if grantID, err = b.cfg.GrantResolver.GrantID(ctx, req); err != nil {
			return nil, err
		}
	}
	conn, err := b.dial(ctx, "tcp", b.cfg.ControllerAddr)
	if err != nil {
		return nil, err
	}
	return b.ceremony(ctx, conn, req, token, grantID)
}

// --- fail-closed gates -----------------------------------------------------

func TestJessDBBackend_FailsClosed(t *testing.T) {
	ctx := context.Background()
	req := DBDialRequest{Engine: EnginePostgres, Target: "analytics", Subject: "u-1"}

	t.Run("no controller addr -> ErrDBBackendNotWired", func(t *testing.T) {
		_, err := NewJessDBBackend(JessDBBackendConfig{}).Open(ctx, req)
		if !errors.Is(err, ErrDBBackendNotWired) {
			t.Fatalf("err = %v, want ErrDBBackendNotWired", err)
		}
	})
	t.Run("no TLS -> refuse plaintext", func(t *testing.T) {
		_, err := NewJessDBBackend(JessDBBackendConfig{ControllerAddr: "jess:9100"}).Open(ctx, req)
		if err == nil || !strings.Contains(err.Error(), "mTLS") {
			t.Fatalf("err = %v, want mTLS refusal", err)
		}
	})
	t.Run("no assertion minter -> fail closed", func(t *testing.T) {
		_, err := NewJessDBBackend(JessDBBackendConfig{ControllerAddr: "jess:9100", TLS: &tls.Config{MinVersion: tls.VersionTLS13}}).Open(ctx, req)
		if err == nil || !strings.Contains(err.Error(), "AssertionMinter") {
			t.Fatalf("err = %v, want AssertionMinter requirement", err)
		}
	})
}

// --- wired happy path: pgwire over a fake jess operator bridge -------------

// fakePGServer simulates the jess controller operator port + bridged Postgres
// broker: it reads the OperatorRequest JSON, then speaks the minimal pgwire
// server side (AuthenticationOk, ReadyForQuery, then a canned result for any
// query) so the real pgConn client is exercised end-to-end.
func TestJessDBBackend_Postgres_WiredQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotReq := make(chan operatorRequest, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		// The client writes the OperatorRequest JSON object with NO delimiter,
		// then (for Postgres) the StartupMessage back-to-back on the same conn.
		// json.Decoder reads ahead and can buffer some of those trailing wire
		// bytes into its own buffer; they would be LOST if we read the rest
		// straight from the conn. Carry the decoder's buffered remainder ahead of
		// the live conn so the pgwire stream is byte-complete (this is what the
		// real jess controller does when it bridges the decoded conn).
		dec := json.NewDecoder(conn)
		var or operatorRequest
		_ = dec.Decode(&or)
		gotReq <- or
		servePGFake(conn, io.MultiReader(dec.Buffered(), conn))
	}()

	asrt := &fakeAssertion{token: "tok-abc"}
	be := &jessDBBackend{
		cfg: JessDBBackendConfig{
			ControllerAddr: ln.Addr().String(),
			TLS:            nil, // dial seam below skips TLS
			Assertion:      asrt,
			GrantResolver:  fakeGrant{id: "grant-7"},
			DialTimeout:    5 * time.Second,
		},
		// Override the dial seam to return a plain TCP conn and skip the TLS
		// wrap (the fake server speaks plaintext); the ceremony + pgwire codec
		// are what we're testing here, not the TLS handshake.
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, addr)
		},
	}
	// Bypass the TLS path: set a non-nil TLS so the nil-guard passes, but the
	// overridden dial returns the raw conn and dialOperator would still try to
	// TLS-wrap it. So we test through a dedicated openNoTLS path instead.
	sess, err := be.openNoTLSForTest(context.Background(), DBDialRequest{
		Engine: EnginePostgres, Target: "analytics", Database: "metrics",
		Subject: "u-1", Email: "a@b.co",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	or := <-gotReq
	if or.Token != "tok-abc" || or.TargetID != "analytics" || or.GrantID != "grant-7" {
		t.Fatalf("operator request = %+v", or)
	}
	if asrt.seen.Subject != "u-1" {
		t.Fatalf("assertion saw subject %q, want u-1", asrt.seen.Subject)
	}

	rs, err := sess.Exec(context.Background(), "select 1")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(rs.Columns) != 1 || rs.Columns[0] != "n" {
		t.Fatalf("columns = %v", rs.Columns)
	}
	if len(rs.Rows) != 1 || rs.Rows[0][0] == nil || *rs.Rows[0][0] != "42" {
		t.Fatalf("rows = %v", rs.Rows)
	}
}

// servePGFake is a tiny pgwire SERVER: read StartupMessage, send
// AuthenticationOk + ReadyForQuery, then for any 'Q' reply with one column "n"
// = "42" and CommandComplete + ReadyForQuery. Terminate ('X') ends it.
func servePGFake(conn net.Conn, r io.Reader) {
	// Startup message (no type byte): int32 len + body. Read + discard.
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 4 {
		return
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return
	}
	w := bufio.NewWriter(conn)
	writePG := func(typ byte, payload []byte) {
		var h [5]byte
		h[0] = typ
		binary.BigEndian.PutUint32(h[1:], uint32(len(payload)+4))
		_, _ = w.Write(h[:])
		_, _ = w.Write(payload)
	}
	// AuthenticationOk: int32 0.
	writePG('R', []byte{0, 0, 0, 0})
	// ReadyForQuery: 'I'.
	writePG('Z', []byte{'I'})
	_ = w.Flush()

	for {
		typ, payload, err := readPGFrame(r)
		if err != nil {
			return
		}
		switch typ {
		case 'Q':
			// RowDescription: 1 field "n".
			var rd []byte
			rd = binary.BigEndian.AppendUint16(rd, 1)
			rd = append(rd, "n"...)
			rd = append(rd, 0)
			rd = append(rd, make([]byte, 18)...) // 18 bytes field metadata
			writePG('T', rd)
			// DataRow: 1 column "42".
			var dr []byte
			dr = binary.BigEndian.AppendUint16(dr, 1)
			dr = binary.BigEndian.AppendUint32(dr, 2)
			dr = append(dr, "42"...)
			writePG('D', dr)
			// CommandComplete "SELECT 1".
			writePG('C', append([]byte("SELECT 1"), 0))
			writePG('Z', []byte{'I'})
			_ = w.Flush()
		case 'X':
			return
		default:
		}
		_ = payload
	}
}

func readPGFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n < 4 {
		return 0, nil, errors.New("bad len")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return h[0], body, nil
}

// --- MySQL happy path: minimal handshake + COM_QUERY result ----------------

func TestJessDBBackend_MySQL_WiredQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		// Same json.Decoder read-ahead hazard as the Postgres fake: carry the
		// decoder's buffered remainder ahead of the live conn so no client bytes
		// are stranded. (MySQL's client reads the server greeting before writing
		// its handshake response, so in practice nothing trails the JSON yet —
		// but this keeps the fake correct regardless of timing.)
		dec := json.NewDecoder(conn)
		var or operatorRequest
		_ = dec.Decode(&or)
		serveMySQLFake(conn, io.MultiReader(dec.Buffered(), conn))
	}()

	be := &jessDBBackend{
		cfg: JessDBBackendConfig{
			ControllerAddr: ln.Addr().String(),
			Assertion:      &fakeAssertion{token: "tok"},
			DialTimeout:    5 * time.Second,
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	sess, err := be.openNoTLSForTest(context.Background(), DBDialRequest{
		Engine: EngineMySQL, Target: "orders", Subject: "u-2", Email: "x@y.co",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	rs, err := sess.Exec(context.Background(), "select name from t")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(rs.Columns) != 1 || rs.Columns[0] != "name" {
		t.Fatalf("columns = %v", rs.Columns)
	}
	if len(rs.Rows) != 2 || rs.Rows[0][0] == nil || *rs.Rows[0][0] != "ada" || rs.Rows[1][0] != nil {
		t.Fatalf("rows = %v (want [ada, NULL])", rs.Rows)
	}
}

// serveMySQLFake speaks the minimal MySQL server side: a protocol-10 greeting
// (DEPRECATE_EOF on so we skip the intermediate EOF), an OK after the
// handshake response, then for a COM_QUERY a 1-column result with rows
// ["ada", NULL] terminated by an OK-as-EOF.
func serveMySQLFake(conn net.Conn, r io.Reader) {
	w := bufio.NewWriter(conn)
	seq := byte(0)
	writePkt := func(payload []byte) {
		var h [4]byte
		h[0] = byte(len(payload))
		h[1] = byte(len(payload) >> 8)
		h[2] = byte(len(payload) >> 16)
		h[3] = seq
		seq++
		_, _ = w.Write(h[:])
		_, _ = w.Write(payload)
		_ = w.Flush()
	}
	readPkt := func() ([]byte, error) {
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
		seq = h[3] + 1
		p := make([]byte, n)
		_, err := io.ReadFull(r, p)
		return p, err
	}

	// Greeting: protover 10, "5.7\0", connID(4), authdata1(8), filler(1),
	// capsLow(2), charset(1), status(2), capsHigh(2), reserved(10), authdata2.
	caps := uint32(mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth | mysqlClientDeprecateEOF)
	var g []byte
	g = append(g, 10)
	g = append(g, "5.7.0"...)
	g = append(g, 0)
	g = append(g, 1, 0, 0, 0)             // conn id
	g = append(g, 1, 2, 3, 4, 5, 6, 7, 8) // auth-data part 1
	g = append(g, 0)                      // filler
	g = binary.LittleEndian.AppendUint16(g, uint16(caps&0xffff))
	g = append(g, 45)                          // charset
	g = binary.LittleEndian.AppendUint16(g, 0) // status
	g = binary.LittleEndian.AppendUint16(g, uint16(caps>>16))
	g = append(g, make([]byte, 10)...) // reserved
	writePkt(g)

	// Read HandshakeResponse41.
	if _, err := readPkt(); err != nil {
		return
	}
	// OK packet (header 0x00, affected 0, lastInsert 0, status 2, warnings 2).
	writePkt([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Command loop.
	for {
		pkt, err := readPkt()
		if err != nil || len(pkt) == 0 {
			return
		}
		seq = 0 // response sequence restarts
		switch pkt[0] {
		case 0x03: // COM_QUERY
			writePkt([]byte{0x01})                                     // column count = 1
			writePkt(mysqlColDef("name"))                              // column def
			writePkt(lenEncStrBytes("ada"))                            // row 1 = "ada"
			writePkt([]byte{0xfb})                                     // row 2 = NULL
			writePkt([]byte{0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}) // OK-as-EOF
		case 0x01: // COM_QUIT
			return
		default:
		}
	}
}

// mysqlColDef builds a minimal Column Definition 41 packet with the given
// name (catalog/schema/table/org_table are empty length-enc strings).
func mysqlColDef(name string) []byte {
	var b []byte
	for i := 0; i < 4; i++ {
		b = append(b, 0x00) // empty len-enc string
	}
	b = append(b, lenEncStrBytes(name)...)      // name
	b = append(b, lenEncStrBytes(name)...)      // org_name
	b = append(b, 0x0c)                         // length of fixed fields = 12
	b = binary.LittleEndian.AppendUint16(b, 45) // charset
	b = binary.LittleEndian.AppendUint32(b, 64) // column length
	b = append(b, 0xfd)                         // type = VAR_STRING
	b = binary.LittleEndian.AppendUint16(b, 0)  // flags
	b = append(b, 0x00)                         // decimals
	b = append(b, 0x00, 0x00)                   // filler
	return b
}

func lenEncStrBytes(s string) []byte {
	// length < 251 -> single length byte.
	return append([]byte{byte(len(s))}, s...)
}
