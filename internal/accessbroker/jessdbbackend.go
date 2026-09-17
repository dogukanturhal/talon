// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// JessDBBackendConfig parameterises the jess DB backend — the production
// access-broker → jess Postgres/MySQL brokering path (ADR 0049 / ADR 0044
// Phase 4 / jess ADR 0050 clientless-operator credentials).
//
// The dial mirrors the jess operator ceremony every other client (jessctl,
// the SSH backend) uses: open a net.Conn to the controller's OPERATOR port
// (over Linkerd mTLS), write a single wire.OperatorRequest JSON object
// ({token, target_id, grant_id}), and then the SAME connection is bridged to
// the protocol broker — so the operator side speaks raw pgwire / MySQL to the
// target THROUGH the jess relay. jess (server-side) injects the ephemeral
// Vault credential, enforces the per-statement policy, and WORM-records every
// statement; talon NEVER sees the target credential and NEVER enforces policy
// or records — it is a dumb SQL pipe.
type JessDBBackendConfig struct {
	// ControllerAddr is the jess controller OPERATOR address (host:port). The
	// backend dials it per session over mTLS and writes the OperatorRequest.
	// Empty -> the backend is "not wired" and Open fails closed with
	// ErrDBBackendNotWired (the deploy hasn't supplied the address yet), never
	// a silent open.
	ControllerAddr string

	// TLS is the client mTLS config for the controller operator port. In the
	// mesh the Linkerd sidecar normally provides transport identity, but the
	// jess operator listener is a raw TLS listener (idFn over the peer cert),
	// so a client cert is required. nil with a non-empty ControllerAddr ->
	// Open fails closed (no plaintext operator dial).
	TLS *tls.Config

	// Assertion mints the Talon-vouched clientless-access assertion (jess ADR
	// 0050) that becomes the OperatorRequest.Token, binding the brokered
	// session to the REAL Falcon-ID subject (never a broker identity). REQUIRED
	// when ControllerAddr is set — without it the backend cannot identify the
	// accessor to jess, so Open fails closed.
	Assertion AssertionMinter

	// GrantResolver maps the dial request to an active JIT grant id (jess
	// requires an active grant for the (subject, target)). nil -> the backend
	// sends an empty grant_id, which lets the jess admin-auto-grant /
	// clientless-sensitivity path mint the grant inline (ADR 0050 matrix:
	// low/medium auto-grant; high needs approval; critical denied). A real
	// deployment that pre-requests grants wires a resolver here.
	GrantResolver DBGrantResolver

	// DialTimeout bounds the TCP+TLS handshake AND the operator-request write +
	// protocol startup handshake. Zero -> 10s.
	DialTimeout time.Duration
}

// AssertionMinter mints the short-lived, target-bound Talon clientless-access
// assertion (jess ADR 0050 §"Trust chain") for a brokered session. The
// returned token is presented to jess as wire.OperatorRequest.Token; jess
// verifies it against Talon's IAP JWKS and binds the recording + JIT decision
// to its `sub`. The access-broker's identityjwt.Signer is the production
// implementation (see SignerAssertionMinter); tests inject a fake.
type AssertionMinter interface {
	// Mint returns a signed assertion for req (already stamped with the verified
	// Subject/Email/TenantID/SessionID/SSOChainID + Engine/Target). It MUST
	// scope the assertion to the request's identity + target so a leaked token
	// cannot be replayed against another target/user.
	Mint(ctx context.Context, req DBDialRequest) (token string, err error)
}

// DBGrantResolver resolves the active JIT grant id for a brokered DB session.
// Splitting it out keeps the backend agnostic to how a deployment tracks
// grants (a pre-approval request store, an inline auto-grant, etc.).
type DBGrantResolver interface {
	// GrantID returns the active grant id for req, or "" to let jess decide
	// (inline auto-grant per the clientless sensitivity matrix). A non-nil
	// error fails the session closed.
	GrantID(ctx context.Context, req DBDialRequest) (string, error)
}

// operatorRequest is talon's copy of jess internal/wire.OperatorRequest. It is
// the on-the-wire contract with the jess controller operator port: a single
// JSON object, immediately followed by the raw session (pgwire/MySQL) bytes.
// Subject is intentionally absent — jess derives identity from the verified
// Token, so a client cannot impersonate another user. talon does not import
// the jess module, so this struct is duplicated; the JSON tags are the
// load-bearing contract (keep in sync with jess wire.OperatorRequest).
type operatorRequest struct {
	Token    string `json:"token"`
	TargetID string `json:"target_id"`
	GrantID  string `json:"grant_id"`
}

// jessDBBackend is the production DBBackend: it brokers SQL to jess over the
// operator ceremony. The relay, codec, auth, channel gate, and recording tee
// ABOVE it (dbhandler.go / dbrelay.go) are protocol-agnostic; this backend
// supplies the per-session DBSession that speaks the engine wire protocol to
// the jess-bridged connection.
type jessDBBackend struct {
	cfg JessDBBackendConfig
	// dial is the net dialer seam (overridable in tests). Production dials TCP
	// then wraps in TLS.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewJessDBBackend constructs the jess DB Backend. See JessDBBackendConfig.
func NewJessDBBackend(cfg JessDBBackendConfig) DBBackend {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &jessDBBackend{
		cfg: cfg,
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.DialTimeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// Open implements DBBackend. It performs the jess operator ceremony and
// returns a DBSession that speaks the engine wire protocol to the brokered
// connection. Fail-closed at every gate: an unwired deploy, a missing
// assertion minter, a TLS/dial failure, a grant-resolution failure, or a
// protocol startup failure all return an error (the handler surfaces it as a
// 1011 close) — never a silent or open connection.
func (b *jessDBBackend) Open(ctx context.Context, req DBDialRequest) (DBSession, error) {
	if b.cfg.ControllerAddr == "" {
		// Not wired at deploy time: no controller address. Fail closed with the
		// documented sentinel so the handler closes the socket cleanly.
		return nil, ErrDBBackendNotWired
	}
	if b.cfg.TLS == nil {
		return nil, fmt.Errorf("accessbroker: jess DB backend requires mTLS config for the controller operator port (refusing a plaintext operator dial)")
	}
	if b.cfg.Assertion == nil {
		return nil, fmt.Errorf("accessbroker: jess DB backend requires an AssertionMinter (cannot identify the accessor to jess)")
	}
	if !validDBEngine(req.Engine) {
		return nil, fmt.Errorf("accessbroker: jess DB backend: invalid engine %q", req.Engine)
	}

	// 1) Mint the Talon-vouched clientless-access assertion (binds to the REAL
	//    subject + target; never a broker identity).
	token, err := b.cfg.Assertion.Mint(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("accessbroker: mint clientless assertion: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("accessbroker: clientless assertion minter returned an empty token (fail-closed)")
	}

	// 2) Resolve the JIT grant id (or "" to let jess auto-grant per the
	//    sensitivity matrix).
	var grantID string
	if b.cfg.GrantResolver != nil {
		grantID, err = b.cfg.GrantResolver.GrantID(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("accessbroker: resolve JIT grant: %w", err)
		}
	}

	// 3) Dial the controller operator port over mTLS.
	conn, err := b.dialOperator(ctx)
	if err != nil {
		return nil, err
	}

	// 4-5) Run the operator ceremony + engine startup over the bridged conn.
	return b.ceremony(ctx, conn, req, token, grantID)
}

// ceremony writes the OperatorRequest over an already-established connection
// (the controller bridges it to the broker), then runs the engine-specific
// startup handshake and returns the DBSession. Factored out of Open so the
// post-dial protocol path is exercised in tests over a plaintext pipe.
func (b *jessDBBackend) ceremony(ctx context.Context, conn net.Conn, req DBDialRequest, token, grantID string) (DBSession, error) {
	if err := writeOperatorRequest(conn, operatorRequest{
		Token:    token,
		TargetID: req.Target,
		GrantID:  grantID,
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("accessbroker: send operator request: %w", err)
	}

	if b.cfg.DialTimeout > 0 {
		// Bound the protocol handshake too — a stalled broker must not hang the
		// open (the handler also wraps Open in a 30s timeout).
		_ = conn.SetDeadline(time.Now().Add(b.cfg.DialTimeout))
	}
	sess, err := openEngineSession(ctx, req.Engine, conn, req.Email, req.Database)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("accessbroker: %s startup over jess broker: %w", req.Engine, err)
	}
	// Clear the handshake deadline; the relay enforces its own per-query +
	// idle + absolute-TTL bounds.
	_ = conn.SetDeadline(time.Time{})
	return sess, nil
}

// dialOperator opens the TCP connection and wraps it in the configured client
// mTLS, completing the TLS handshake within the dial timeout.
func (b *jessDBBackend) dialOperator(ctx context.Context) (net.Conn, error) {
	dialCtx := ctx
	if b.cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, b.cfg.DialTimeout)
		defer cancel()
	}
	raw, err := b.dial(dialCtx, "tcp", b.cfg.ControllerAddr)
	if err != nil {
		return nil, fmt.Errorf("accessbroker: dial jess controller %s: %w", b.cfg.ControllerAddr, err)
	}
	tlsConn := tls.Client(raw, b.cfg.TLS)
	if dl, ok := dialCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(dl)
	}
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("accessbroker: mTLS handshake with jess controller: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// writeOperatorRequest writes the request as a single JSON object with NO
// trailing bytes — matching the canonical jess operator client
// (internal/client.Dial: json.Marshal + one conn.Write). The controller reads
// it with json.Decoder.Decode and bridges everything after the object as the
// raw session stream, so the request must be exactly the object and nothing
// more (no encoder newline) to keep the byte stream identical to jessctl.
func writeOperatorRequest(w io.Writer, req operatorRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// openEngineSession runs the engine-specific startup handshake over the
// jess-bridged connection and returns the DBSession. user is the accessor's
// email (cosmetic for the broker — it injects the real ephemeral creds — but
// carried for protocol correctness); database is the optional initial schema.
func openEngineSession(ctx context.Context, engine DBEngine, conn net.Conn, user, database string) (DBSession, error) {
	switch engine {
	case EnginePostgres:
		return newPGConn(ctx, conn, user, database)
	case EngineMySQL:
		return newMySQLConn(ctx, conn, user, database)
	default:
		return nil, fmt.Errorf("unsupported engine %q", engine)
	}
}
