// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
	"time"
)

// K8sBackend is the seam between the access-broker's web kubectl terminal
// and the jess Kubernetes broker (ADR 0049 / ADR 0044 Phase 4). It opens a
// streaming session — `kubectl exec` (a PTY byte stream) or `kubectl logs`
// (a follow stream) — to a pod the jess broker authorises, and returns it
// as a BackendConn so the EXISTING byte-stream relay (runRelay) and the
// xterm.js front-end are reused verbatim. jess owns the SPDY/exec protocol,
// RBAC impersonation, and the WORM recording; the broker only relays bytes.
//
// HONEST STATE (Phase 4 scaffold): jessK8sBackend is a STUB — the jess-side
// k8s broker API is not yet reachable from talon, so Dial returns
// ErrK8sBackendNotWired. The relay/auth/channel-gate/framing/recording
// seam above it is the same real, tested code path the SSH console uses.
type K8sBackend interface {
	// Dial opens the requested k8s streaming session (exec or logs) and
	// returns it as a BackendConn. For `logs` the Write side is a no-op
	// (logs are one-directional) and Resize returns nil; for `exec` the
	// BackendConn behaves exactly like the SSH PTY conn.
	Dial(ctx context.Context, req K8sDialRequest) (BackendConn, error)
}

// K8sVerb selects the kubectl-style operation the broker requests of jess.
type K8sVerb string

const (
	// VerbExec is `kubectl exec -it` — an interactive PTY into a container.
	VerbExec K8sVerb = "exec"
	// VerbLogs is `kubectl logs -f` — a one-directional follow stream.
	VerbLogs K8sVerb = "logs"
)

// validK8sVerb gates the verb at the broker edge so an unknown ?verb= can
// never reach jess.
func validK8sVerb(v K8sVerb) bool {
	switch v {
	case VerbExec, VerbLogs:
		return true
	default:
		return false
	}
}

// K8sDialRequest carries everything the k8s backend needs to open + audit a
// brokered exec/logs session. Identity fields are projected from the
// verified Talon IAP token (never trusted from the client) so jess binds
// the recording + RBAC impersonation to the real subject.
type K8sDialRequest struct {
	// Subject / Email / TenantID / SessionID / SSOChainID — see DialRequest.
	Subject    string
	Email      string
	TenantID   string
	SessionID  string
	SSOChainID string

	// Verb selects exec vs logs.
	Verb K8sVerb
	// Cluster is the logical jess cluster-target handle (jess resolves the
	// kube-apiserver + the impersonation policy behind it).
	Cluster string
	// Namespace / Pod / Container address the workload. Container may be
	// empty (jess defaults to the pod's first/only container).
	Namespace string
	Pod       string
	Container string
	// Command is the exec command argv (exec only). Empty -> jess's default
	// (typically /bin/sh). Ignored for logs.
	Command []string

	// Cols / Rows are the initial PTY geometry (exec only).
	Cols uint16
	Rows uint16
}

// JessK8sBackendConfig parameterises the (currently stub) jess k8s backend.
type JessK8sBackendConfig struct {
	// BrokerAddr is the jess k8s-broker address the production path will dial
	// once ADR 0049 exposes it (host:port over Linkerd mTLS). Empty in the
	// Phase 4 scaffold — the production dial is STUBBED.
	BrokerAddr string
	// DialTimeout bounds the backend handshake. Zero -> 10s.
	DialTimeout time.Duration
}

type jessK8sBackend struct {
	cfg JessK8sBackendConfig
}

// NewJessK8sBackend constructs the jess k8s Backend (stubbed in Phase 4).
func NewJessK8sBackend(cfg JessK8sBackendConfig) K8sBackend {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &jessK8sBackend{cfg: cfg}
}

// Dial implements K8sBackend. PRODUCTION PATH — STUBBED. The jess k8s
// broker (ADR 0049) is not yet reachable from talon. When it is, replace
// this with the broker dial (mTLS to b.cfg.BrokerAddr, forwarding req's
// identity for jess RBAC impersonation + recording) returning a BackendConn
// that proxies the SPDY/exec stdin/stdout (exec) or the log stream (logs).
func (b *jessK8sBackend) Dial(_ context.Context, req K8sDialRequest) (BackendConn, error) {
	_ = req // identity + target will be forwarded to jess once wired.
	return nil, ErrK8sBackendNotWired
}

// ErrK8sBackendNotWired is returned by the stub jess k8s backend. Mirrors
// ErrBackendNotWired / ErrDBBackendNotWired — the relay path is real but the
// jess k8s broker is not reachable yet; surfaced as a clean 1011 close.
var ErrK8sBackendNotWired = errors.New("accessbroker: jess k8s backend not wired (Phase 4 stub) — k8s exec/logs broker (ADR 0049) not yet reachable from talon")
