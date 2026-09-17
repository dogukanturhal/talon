// SPDX-License-Identifier: AGPL-3.0-or-later

// Package credexchange resolves a Talon-fronted host to a per-host
// upstream credential (Basic username/password, Bearer token) and
// substitutes that credential on the outbound request to the upstream.
//
// Wire shape (Phase 4.5 — talon-service-tokens credential exchange):
//
//	1. Inbound: Authorization: Basic base64(<anything>:<falcon-jwt>)
//	            or Authorization: Bearer <falcon-jwt>
//	2. Router calls svctoken.Verifier.VerifyRequestBearerOrBasic
//	   and confirms the JWT (signature, iss, aud, exp, scope).
//	3. Router calls Loader.Load(ctx, host) to resolve the per-host
//	   upstream credential.
//	4. Router calls Apply(req, cred) to STRIP the inbound
//	   Authorization header and substitute the upstream-shaped one
//	   (Basic with the upstream's username/password, or Bearer with
//	   the upstream's token).
//	5. Request proxies to upstream; upstream sees only the
//	   substituted credential.
//
// Architecturally this mirrors Envoy ext_authz's
// allowed_upstream_headers override semantics + Ory Oathkeeper's
// verify-then-mutate pipeline. See the talon-service-tokens spec
// §Phase 4.5 + the deep-research synthesis 2026-05-29 for the
// industry-pattern citations.
//
// The Loader is a per-pod singleton wired in cmd/talon. It looks up
// Kubernetes Secrets in the talon namespace by the convention
//
//	talon-upstream-creds-<host-with-dots-as-dashes>
//
// (e.g. github.com → talon-upstream-creds-git-example-com).
// Operators provision these Secrets via ExternalSecret from Vault so
// the actual credential material lives in Vault, never in Git, and
// rotation happens out-of-band of Talon's release cycle.
//
// Cache semantics: positive hits and negative misses are both cached
// with the same TTL (default 30s) so a host without a credential
// doesn't hammer the apiserver on every request. The TTL is short
// enough that an ExternalSecret rotation propagates to the proxy
// within ~30s without operator intervention.
package credexchange

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Format describes the wire shape Apply uses when substituting the
// outbound Authorization header.
type Format string

const (
	// FormatBasicOauth2 — substitute as Authorization: Basic
	// base64("oauth2:" + password). The canonical Git-over-HTTPS shape
	// every Git server accepts (GitLab, Gitea, Bitbucket, GitHub
	// Enterprise). The Secret's username field is IGNORED in this
	// format; the literal "oauth2" is used so the operator doesn't
	// have to remember per-Git-server username conventions.
	FormatBasicOauth2 Format = "basic-oauth2"

	// FormatBasic — substitute as Authorization: Basic
	// base64(username + ":" + password). Use when the upstream
	// authenticates with a specific username (Harbor robot account,
	// JFrog Artifactory API token + username).
	FormatBasic Format = "basic"

	// FormatBearer — substitute as Authorization: Bearer password.
	// Use when the upstream accepts opaque API tokens via the Bearer
	// scheme (some Vault-style APIs, GitLab API path under
	// `Authorization: Bearer <PAT>` ).
	FormatBearer Format = "bearer"

	// FormatPrivateToken — substitute via the `PRIVATE-TOKEN: <password>`
	// header. The Authorization header is stripped (no Basic/Bearer
	// fallback) so the upstream can't pick the lower-privilege auth
	// shape over the explicit PRIVATE-TOKEN one. The Secret's username
	// field is IGNORED.
	//
	// Used for GitLab admin REST endpoints, which silently downgrade
	// permissions when the same PAT arrives via Basic-oauth2 — verified
	// live 2026-05-30 against `GET /api/v4/users`:
	//   PRIVATE-TOKEN: glpat-...    → 200 (admin view)
	//   Basic oauth2:glpat-...      → 403 "Not authorized to access /api/v4/users"
	//   Authorization: Bearer glpat-...   → 401 "unauthorized"
	// Same PAT, three different headers — only PRIVATE-TOKEN unlocks
	// admin authority on the user-admin surface.
	//
	// NOTE: this format is GitLab-specific. Other upstreams that need
	// an X-* header for auth should get their own Format value rather
	// than overloading this one — the field name is meaningful for
	// audit grep.
	FormatPrivateToken Format = "private-token"
)

// IsValid reports whether f is a recognised Format.
func (f Format) IsValid() bool {
	switch f {
	case FormatBasicOauth2, FormatBasic, FormatBearer, FormatPrivateToken:
		return true
	default:
		return false
	}
}

// Credential is the resolved per-host upstream credential. The
// password field is the only mandatory data; Username is consumed by
// FormatBasic, ignored by FormatBasicOauth2 + FormatBearer +
// FormatPrivateToken.
type Credential struct {
	Username string
	Password string
	Format   Format
}

// ErrNoCredential is returned by Loader.Load when no per-host Secret
// is configured for the host. Callers treat this as a graceful "no
// exchange wired" signal (the request falls through to passthrough)
// — NOT a security failure. The negative cache entry uses this
// sentinel so repeated misses don't hammer the apiserver.
var ErrNoCredential = errors.New("credexchange: no per-host upstream credential")

// Loader resolves a host (+ optionally a client_id) to a Credential.
// Implementations must be safe for concurrent use across all router
// goroutines.
//
// The optional clientID parameter enables per-consumer upstream-cred
// differentiation on the same host — required when consumers of one
// Talon-fronted host need DIFFERENT upstream privileges (the canonical
// example: gitlab-bcl-receiver needs admin GitLab REST scope while
// ArgoCD repo-server needs only group-scoped read+write_repository on
// the same github.com host). Pass empty clientID for the
// host-default behaviour (Phase 4.5 back-compat: every caller gets
// the same Secret).
//
// Resolution order in K8sSecretLoader:
//
//	1. talon-upstream-creds-<host-dashed>-<client-id>  (per-client)
//	2. talon-upstream-creds-<host-dashed>              (host-default)
//	3. ErrNoCredential                                  (neither exists)
//
// This mirrors the per-source-identity upstream-creds pattern in
// Envoy ext_authz (allowed_upstream_headers + source-identity), NGINX
// Plus `auth_jwt_claim_set`, and Pomerium per-route `from`/`to`. Was
// the OSS gap caught live in the 2026-05-30 gitlab-bcl-receiver
// Phase 5 migration (see
// [[internal engineering notes]]).
type Loader interface {
	Load(ctx context.Context, host, clientID string) (Credential, error)
}

// Secret-key conventions. Operators put the upstream creds in a
// Kubernetes Secret with these keys; ExternalSecret hydrates them
// from Vault. Choosing standard names lets the same Secret schema
// drive every per-host credential type.
const (
	secretKeyUsername = "username"
	secretKeyPassword = "password"
	secretKeyFormat   = "format" // optional; defaults to basic-oauth2
)

// SecretNameForHost returns the canonical Secret name for the
// host-default upstream credential. Dots become dashes so the
// resulting name is a valid DNS-1123 SUBDOMAIN (max 253 chars).
// github.com → talon-upstream-creds-git-example-com.
//
// The name is deterministic so operators can predict it without
// reading Talon source. Reserved for the K8sSecretLoader; alternative
// Loader implementations may use a different mapping.
//
// Pairs with SecretNameForHostClient for per-consumer differentiation
// — K8sSecretLoader prefers the per-client Secret when present and
// falls back to this host-default name.
func SecretNameForHost(host string) string {
	return "talon-upstream-creds-" + strings.ReplaceAll(host, ".", "-")
}

// SecretNameForHostClient returns the per-client variant of the
// upstream-creds Secret name. Used when a host fronts multiple Talon
// consumers with differentiated upstream privileges. Pattern:
//
//	talon-upstream-creds-<host-with-dots-as-dashes>-<client-id>
//
// e.g. github.com + svc-svc-gitlab-bcl-receiver →
// talon-upstream-creds-git-example-com-svc-svc-gitlab-bcl-receiver.
//
// K8s Secret names follow DNS-1123 SUBDOMAIN (max 253 chars), so this
// scheme fits even pessimistic host + client_id combinations. The
// client_id is consumed verbatim — Falcon-ID's client_ids are already
// DNS-safe (lowercase ascii + dash + dot).
//
// Returns an empty string for empty clientID so callers can use a
// single len-check to skip the per-client lookup.
func SecretNameForHostClient(host, clientID string) string {
	if clientID == "" {
		return ""
	}
	return SecretNameForHost(host) + "-" + clientID
}

// K8sSecretLoader resolves per-host credentials from Kubernetes
// Secrets in a configured namespace. Results (both hits and misses)
// are cached for ttl to keep request latency negligible and to bound
// apiserver QPS even on cold cache.
//
// Per-client differentiation (Phase 5+, 2026-05-30): when Load is
// called with a non-empty clientID, the loader first tries the
// per-client Secret (SecretNameForHostClient(host, clientID)); on
// NotFound or empty clientID, falls back to the host-default Secret
// (SecretNameForHost(host)). Both outcomes (hit + miss) are cached
// with the same TTL under a (host, clientID) cache key so per-
// consumer lookups don't collide.
type K8sSecretLoader struct {
	cs        kubernetes.Interface
	namespace string
	ttl       time.Duration

	mu    sync.RWMutex
	cache map[cacheKey]cacheEntry
}

type cacheKey struct {
	host     string
	clientID string
}

type cacheEntry struct {
	cred Credential
	err  error
	exp  time.Time
}

// NewK8sSecretLoader returns a Loader that reads Secrets from
// `namespace` (typically "talon"). ttl=0 selects the default 30s.
func NewK8sSecretLoader(cs kubernetes.Interface, namespace string, ttl time.Duration) *K8sSecretLoader {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &K8sSecretLoader{
		cs:        cs,
		namespace: namespace,
		ttl:       ttl,
		cache:     make(map[cacheKey]cacheEntry),
	}
}

// Load returns the upstream Credential, preferring the per-client
// variant when clientID is non-empty AND a Secret with the per-client
// name exists. Falls back to the host-default Secret otherwise.
// Returns ErrNoCredential when neither Secret exists. The cache holds
// both outcomes with the same TTL so a host without a credential
// doesn't burn an apiserver round-trip per request.
func (l *K8sSecretLoader) Load(ctx context.Context, host, clientID string) (Credential, error) {
	key := cacheKey{host: host, clientID: clientID}
	l.mu.RLock()
	if entry, ok := l.cache[key]; ok && time.Now().Before(entry.exp) {
		l.mu.RUnlock()
		return entry.cred, entry.err
	}
	l.mu.RUnlock()

	cred, err := l.fetch(ctx, host, clientID)

	l.mu.Lock()
	l.cache[key] = cacheEntry{cred: cred, err: err, exp: time.Now().Add(l.ttl)}
	l.mu.Unlock()

	return cred, err
}

// fetch resolves the upstream Credential through the
// per-client-then-host-default ladder. Per-client miss falls through
// to host-default; host-default miss returns ErrNoCredential.
func (l *K8sSecretLoader) fetch(ctx context.Context, host, clientID string) (Credential, error) {
	// Try per-client first if a clientID was provided.
	if perClientName := SecretNameForHostClient(host, clientID); perClientName != "" {
		cred, err := l.fetchOne(ctx, perClientName)
		if err == nil {
			return cred, nil
		}
		if !errors.Is(err, ErrNoCredential) {
			// Real apiserver / Secret-shape error on the per-client
			// path — surface it so the operator sees the misconfig
			// rather than silently falling back. A per-client Secret
			// with malformed data should NOT silently demote to the
			// host-default (security-relevant scope mismatch).
			return Credential{}, err
		}
		// Per-client NotFound → fall through to host-default. This is
		// the back-compat path: existing host-default Secrets keep
		// working for every consumer until an operator opts a specific
		// client_id into a per-client variant.
	}

	return l.fetchOne(ctx, SecretNameForHost(host))
}

// fetchOne retrieves a single Secret by name + parses it into a
// Credential. Returns ErrNoCredential on NotFound (sentinel — caller
// may fall back); any other error is wrapped and returned as-is.
func (l *K8sSecretLoader) fetchOne(ctx context.Context, name string) (Credential, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sec, err := l.cs.CoreV1().Secrets(l.namespace).Get(fetchCtx, name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return Credential{}, ErrNoCredential
		}
		return Credential{}, fmt.Errorf("credexchange: get secret %s/%s: %w", l.namespace, name, err)
	}

	pass := string(sec.Data[secretKeyPassword])
	if pass == "" {
		// A Secret exists but has no password — operator misconfig.
		// Surface it as a NON-sentinel error so the router can
		// distinguish from no-Secret-at-all and 503 if it wants to.
		return Credential{}, fmt.Errorf("credexchange: secret %s/%s has empty %q",
			l.namespace, name, secretKeyPassword)
	}

	format := Format(strings.TrimSpace(string(sec.Data[secretKeyFormat])))
	if format == "" {
		format = FormatBasicOauth2
	}
	if !format.IsValid() {
		return Credential{}, fmt.Errorf("credexchange: secret %s/%s has invalid %q=%q",
			l.namespace, name, secretKeyFormat, format)
	}

	return Credential{
		Username: string(sec.Data[secretKeyUsername]),
		Password: pass,
		Format:   format,
	}, nil
}

// Apply strips the inbound Authorization header from req and
// substitutes a header constructed from cred. Mutates req in place.
// Always overrides; never appends (Envoy ext_authz override-on-
// conflict semantics).
//
// IMPORTANT: Apply assumes the caller has already verified the
// inbound Bearer/Basic-as-Bearer svctoken. Calling Apply without
// prior verification would let any request swap to the privileged
// upstream credential — caller MUST gate on a successful
// svctoken.Verify outcome first.
func Apply(req *http.Request, cred Credential) {
	if req == nil {
		return
	}
	req.Header.Del("Authorization")
	// PRIVATE-TOKEN can ride along on a stale request; strip it too so
	// the upstream sees ONLY the auth shape we intend.
	req.Header.Del("PRIVATE-TOKEN")
	switch cred.Format {
	case FormatBearer:
		req.Header.Set("Authorization", "Bearer "+cred.Password)
	case FormatBasic:
		req.Header.Set("Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)))
	case FormatPrivateToken:
		// GitLab admin endpoints reject Basic-oauth2 with 403 ("Not
		// authorized") on the SAME PAT that PRIVATE-TOKEN unlocks
		// with 200. No Authorization header set — only PRIVATE-TOKEN.
		req.Header.Set("PRIVATE-TOKEN", cred.Password)
	default: // FormatBasicOauth2 (and unrecognised — defensive)
		req.Header.Set("Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte("oauth2:"+cred.Password)))
	}
}
