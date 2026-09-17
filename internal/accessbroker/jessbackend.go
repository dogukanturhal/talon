// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// JessBackendConfig parameterises the (currently stub) jess SSH backend.
type JessBackendConfig struct {
	// BrokerAddr is the jess SSH-broker address the production path will
	// dial once ADR 0049 exposes it (host:port over Linkerd mTLS). Empty
	// in the Phase 2 scaffold — the production dial is STUBBED.
	BrokerAddr string

	// DevLoopbackAddr, when non-empty, makes Dial connect to a plain SSH
	// server at this host:port instead of the (unwired) jess broker. This
	// exercises the FULL real relay path — WebSocket <-> x/crypto/ssh
	// session — against any reachable sshd, for local/e2e testing. NEVER
	// set in production; it bypasses jess policy + recording.
	DevLoopbackAddr string
	// DevLoopbackUser/Password authenticate the dev loopback SSH dial.
	DevLoopbackUser     string
	DevLoopbackPassword string

	// DialTimeout bounds the backend TCP+SSH handshake. Zero -> 10s.
	DialTimeout time.Duration
}

// jessSSHBackend is the Backend that (eventually) brokers to jess. In
// the Phase 2 scaffold it has two modes:
//
//   - dev loopback (DevLoopbackAddr set): a REAL SSH dial via
//     x/crypto/ssh, so the whole relay is exercised end-to-end. Used for
//     local testing only; bypasses jess.
//   - production (BrokerAddr only): STUBBED — returns ErrBackendNotWired,
//     because the jess SSH broker (ADR 0049) is not yet callable from
//     talon. This is the single clearly-marked stub seam.
type jessSSHBackend struct {
	cfg JessBackendConfig
}

// NewJessBackend constructs the jess SSH Backend. See JessBackendConfig
// for the dev-loopback vs production-stub behaviour.
func NewJessBackend(cfg JessBackendConfig) Backend {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &jessSSHBackend{cfg: cfg}
}

// Dial implements Backend. With a dev loopback configured it opens a real
// SSH PTY session; otherwise it returns ErrBackendNotWired (the jess
// broker path is the documented stub).
func (b *jessSSHBackend) Dial(ctx context.Context, req DialRequest) (BackendConn, error) {
	if b.cfg.DevLoopbackAddr == "" {
		// PRODUCTION PATH — STUBBED. The jess SSH broker (ADR 0049) is
		// not yet reachable from talon. When it is, replace this branch
		// with the broker dial (mTLS to b.cfg.BrokerAddr, forwarding
		// req's identity for jess JIT + recording).
		return nil, ErrBackendNotWired
	}
	return b.dialLoopback(ctx, req)
}

// dialLoopback performs a real SSH dial to the dev loopback target and
// opens an interactive PTY session. This is the code shape the jess
// broker dial will reuse (request a PTY, wire stdin/stdout, return a
// BackendConn) — only the address + auth + recording-tee differ.
func (b *jessSSHBackend) dialLoopback(ctx context.Context, req DialRequest) (BackendConn, error) {
	user := req.User
	if user == "" {
		user = b.cfg.DevLoopbackUser
	}
	clientCfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(b.cfg.DevLoopbackPassword)},
		// Dev loopback only — accept any host key. The production jess
		// path delegates host-key trust to the jess broker (it owns the
		// known-hosts / CA trust), so this insecure callback never runs
		// in production.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // dev-loopback only; production goes through jess.
		Timeout:         b.cfg.DialTimeout,
	}

	d := net.Dialer{Timeout: b.cfg.DialTimeout}
	netConn, err := d.DialContext(ctx, "tcp", b.cfg.DevLoopbackAddr)
	if err != nil {
		return nil, fmt.Errorf("accessbroker: dial loopback %s: %w", b.cfg.DevLoopbackAddr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, b.cfg.DevLoopbackAddr, clientCfg)
	if err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("accessbroker: ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("accessbroker: new ssh session: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("accessbroker: ssh stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("accessbroker: ssh stdout: %w", err)
	}
	cols, rows := normalizeGeometry(req.Cols, req.Rows)
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", int(rows), int(cols), modes); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("accessbroker: request pty: %w", err)
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, fmt.Errorf("accessbroker: start shell: %w", err)
	}
	return &sshBackendConn{
		client: client,
		sess:   sess,
		stdin:  stdin,
		stdout: stdout,
	}, nil
}

// sshBackendConn adapts an x/crypto/ssh session to BackendConn.
type sshBackendConn struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  interface{ Write([]byte) (int, error) }
	stdout interface{ Read([]byte) (int, error) }
}

func (c *sshBackendConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *sshBackendConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

// Resize sends an SSH window-change request (RFC 4254 §6.7) to the
// remote PTY.
func (c *sshBackendConn) Resize(cols, rows uint16) error {
	cols, rows = normalizeGeometry(cols, rows)
	return c.sess.WindowChange(int(rows), int(cols))
}

// Close tears down the SSH session and the underlying client.
func (c *sshBackendConn) Close() error {
	_ = c.sess.Close()
	return c.client.Close()
}

// normalizeGeometry clamps a terminal geometry to sane bounds so a
// malformed resize from the browser can't request a 0x0 or absurdly
// large PTY.
func normalizeGeometry(cols, rows uint16) (uint16, uint16) {
	if cols == 0 || cols > 1000 {
		cols = 80
	}
	if rows == 0 || rows > 1000 {
		rows = 24
	}
	return cols, rows
}
