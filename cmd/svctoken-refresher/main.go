// SPDX-License-Identifier: AGPL-3.0-or-later

// Command svctoken-refresher is the universal sidecar that keeps a
// Falcon-ID-issued client_credentials JWT fresh in a shared file so
// machine consumers (ArgoCD repo-server, image-updater, Atlantis,
// Renovate, CI) can present it as Authorization: Bearer to Talon
// without learning the OAuth dance.
//
// One binary, one Helm chart, every consumer reuses it. See
// docs/specs/talon-service-tokens.md §"D4 Refresh pattern".
//
// Operational contract:
//
//   - Reads SVCTOKEN_CLIENT_ID + SVCTOKEN_CLIENT_SECRET from env
//     (mounted as Secret keys by ExternalSecret).
//   - Reads SVCTOKEN_TOKEN_URL, SVCTOKEN_SCOPES, SVCTOKEN_RESOURCE,
//     SVCTOKEN_OUTPUT_PATH (the shared file the consumer reads),
//     SVCTOKEN_REFRESH_BEFORE_EXPIRY (Go duration, default 5m).
//   - Calls Falcon-ID's RFC 6749 §4.4 token endpoint, writes the
//     access_token to OUTPUT_PATH atomically (write + rename), then
//     sleeps until (exp - refresh_before_expiry) and repeats.
//   - On startup, refreshes immediately so the consumer never reads
//     a missing or stale file.
//   - On every refresh, fsync the temp file before rename so a node
//     crash mid-write doesn't leave a partial JWT.
//   - On token-endpoint failure: exponential backoff (start 5s, cap
//     5min). NEVER overwrite the existing OUTPUT_PATH on failure —
//     the consumer keeps using the last good token until it actually
//     expires.
//   - Liveness HTTP at :8080/healthz — green iff the last refresh
//     succeeded AND the in-memory token has not yet expired.
//   - Readiness HTTP at :8080/readyz — green iff the OUTPUT_PATH
//     exists and is non-empty.
//   - Prometheus metrics at :8080/metrics:
//     svctoken_refresher_refresh_total{outcome=ok|failed}
//     svctoken_refresher_token_expires_at (unix-epoch gauge)
//     svctoken_refresher_last_refresh_at (unix-epoch gauge)
//     svctoken_refresher_secret_patch_total{outcome=ok|failed}
//
// OPTIONAL Secret-patch mode (Phase 4 consumer wiring):
//
// Some consumers — notably ArgoCD repo-server — read credentials from
// Kubernetes Secrets, not files (go-git used for HTTPS clones ignores
// git's credential.helper, so file-based rotation can't drive ArgoCD).
// Setting SVCTOKEN_SECRET_NAME (+ SVCTOKEN_SECRET_NAMESPACE, default
// the pod's own namespace) flips on Secret-patch mode: after every
// successful token mint the refresher additionally StrategicMerge-
// patches the named Secret's data.SVCTOKEN_SECRET_PASSWORD_KEY field
// (default "password") with the fresh JWT. If SVCTOKEN_SECRET_USERNAME
// is non-empty it is written to data.SVCTOKEN_SECRET_USERNAME_KEY
// (default "username") on the same patch — useful for ArgoCD's
// repo-creds Secrets where the username must accompany the password.
//
// Secret-patch failures are logged + retried at the next refresh tick;
// they do NOT crash the refresher or skip the file write (the file
// remains the primary observability surface). The pod's
// ServiceAccount must have `patch` on the named Secret in the
// configured namespace (and only that one — least privilege).
//
// Lifecycle:
//
//   - The sidecar runs as a NORMAL container (not initContainer) so
//     it survives across the consumer's pod lifecycle.
//   - On SIGTERM (pod deletion), exit cleanly — the consumer's
//     terminationGracePeriodSeconds covers in-flight reads of
//     OUTPUT_PATH.
//   - Use a Restart on Failure pod policy so a transient panic in
//     the refresher doesn't take down the whole pod (the consumer
//     can fall back to the last-known-good token until expiry).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	refreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "svctoken_refresher_refresh_total",
		Help: "Number of Falcon-ID token refresh attempts by outcome.",
	}, []string{"outcome"})
	tokenExpiresAt = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "svctoken_refresher_token_expires_at",
		Help: "Unix-epoch expiry of the currently-loaded token. Zero when no token loaded.",
	})
	lastRefreshAt = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "svctoken_refresher_last_refresh_at",
		Help: "Unix-epoch timestamp of the last successful refresh.",
	})
	secretPatchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "svctoken_refresher_secret_patch_total",
		Help: "Number of Secret patches by outcome. Only emitted when Secret-patch mode is enabled.",
	}, []string{"outcome"})
)

type config struct {
	clientID            string
	clientSecret        string
	tokenURL            string
	scopes              []string
	resource            string
	outputPath          string
	refreshBeforeExpiry time.Duration
	listen              string

	// Optional Secret-patch mode. When secretNames is non-empty, the
	// refresher additionally StrategicMerge-patches each named Secret's
	// data on every successful mint. See the package doc-comment for
	// rationale (ArgoCD repo-server reads creds from Secrets, not
	// files).
	//
	// Multi-Secret support (Phase 5): SVCTOKEN_SECRET_NAMES accepts a
	// comma- or whitespace-separated list. Each entry patches an
	// independent Secret in the SAME namespace with the SAME username
	// / password / format. Failure on one Secret logs + counts (per
	// secret_name label) but does NOT block the others — partial
	// progress is preferred over all-or-nothing because the consumer
	// of each Secret has its own retry loop.
	//
	// SVCTOKEN_SECRET_NAME (singular) is still accepted as an alias
	// for backward compatibility with Phase 4 deployments; the value
	// gets prepended onto the names list at config-load time.
	secretNamespace   string   // SVCTOKEN_SECRET_NAMESPACE; defaults to in-pod namespace
	secretNames       []string // SVCTOKEN_SECRET_NAMES + SVCTOKEN_SECRET_NAME (alias)
	secretPasswordKey string   // SVCTOKEN_SECRET_PASSWORD_KEY, default "password"
	secretUsernameKey string   // SVCTOKEN_SECRET_USERNAME_KEY, default "username"
	secretUsername    string   // SVCTOKEN_SECRET_USERNAME; empty => omit from patch
}

func loadConfig() (*config, error) {
	c := &config{
		clientID:     mustEnv("SVCTOKEN_CLIENT_ID"),
		clientSecret: mustEnv("SVCTOKEN_CLIENT_SECRET"),
		tokenURL:     envOrDefault("SVCTOKEN_TOKEN_URL", "https://id.example.com/oauth/token"),
		resource:     os.Getenv("SVCTOKEN_RESOURCE"),
		outputPath:   mustEnv("SVCTOKEN_OUTPUT_PATH"),
		listen:       envOrDefault("SVCTOKEN_LISTEN", ":8080"),
	}
	if scopesRaw := os.Getenv("SVCTOKEN_SCOPES"); scopesRaw != "" {
		c.scopes = splitFields(scopesRaw)
	}
	c.refreshBeforeExpiry = 5 * time.Minute
	if raw := os.Getenv("SVCTOKEN_REFRESH_BEFORE_EXPIRY"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid SVCTOKEN_REFRESH_BEFORE_EXPIRY: %w", err)
		}
		c.refreshBeforeExpiry = d
	}
	if c.clientID == "" || c.clientSecret == "" || c.tokenURL == "" || c.outputPath == "" {
		return nil, errors.New("SVCTOKEN_{CLIENT_ID,CLIENT_SECRET,TOKEN_URL,OUTPUT_PATH} are all required")
	}
	// Collect target Secret names from EITHER the singular env var
	// (Phase 4 compatibility) or the new plural env var (Phase 5+).
	// Dedup so an operator who sets both with overlap doesn't get
	// duplicate patches.
	if single := strings.TrimSpace(os.Getenv("SVCTOKEN_SECRET_NAME")); single != "" {
		c.secretNames = append(c.secretNames, single)
	}
	if list := os.Getenv("SVCTOKEN_SECRET_NAMES"); list != "" {
		for _, n := range splitFields(list) {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			c.secretNames = appendIfMissing(c.secretNames, n)
		}
	}
	if len(c.secretNames) > 0 {
		c.secretNamespace = envOrDefault("SVCTOKEN_SECRET_NAMESPACE", inPodNamespace())
		if c.secretNamespace == "" {
			return nil, errors.New("SVCTOKEN_SECRET_NAMESPACE required when SVCTOKEN_SECRET_NAME(S) is set " +
				"(could not auto-detect from /var/run/secrets/kubernetes.io/serviceaccount/namespace)")
		}
		c.secretPasswordKey = envOrDefault("SVCTOKEN_SECRET_PASSWORD_KEY", "password")
		c.secretUsernameKey = envOrDefault("SVCTOKEN_SECRET_USERNAME_KEY", "username")
		c.secretUsername = os.Getenv("SVCTOKEN_SECRET_USERNAME")
	}
	return c, nil
}

// appendIfMissing keeps `secretNames` distinct so an operator who
// sets the same name in both SVCTOKEN_SECRET_NAME and
// SVCTOKEN_SECRET_NAMES doesn't trigger duplicate patches per mint.
func appendIfMissing(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

// inPodNamespace returns the namespace this pod runs in, read from
// the standard in-pod ServiceAccount projection. Returns "" if the
// file is missing (e.g. local-dev) so the caller can surface a clear
// error instead of silently patching a default namespace.
func inPodNamespace() string {
	const p = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	return v
}

func envOrDefault(name, dflt string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return dflt
}

func splitFields(s string) []string {
	out := []string{}
	for _, f := range []byte(s) {
		_ = f
	}
	// space- and comma-tolerant split — Falcon-ID accepts either.
	for _, part := range splitOnAny(s, " ,") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitOnAny(s, seps string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		isSep := false
		for _, sep := range seps {
			if r == sep {
				isSep = true
				break
			}
		}
		if isSep {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// state holds the in-memory token + expiry the readiness/liveness
// probes consult. Pointer to time.Time so a nil value is distinguishable
// from "expired" — used by readiness on cold start.
type state struct {
	mu           sync.RWMutex
	currentToken *oauth2.Token
	healthy      atomic.Bool
}

func (s *state) update(tok *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentToken = tok
	s.healthy.Store(tok != nil && time.Until(tok.Expiry) > 0)
	tokenExpiresAt.Set(float64(tok.Expiry.Unix()))
	lastRefreshAt.Set(float64(time.Now().Unix()))
}

func (s *state) hasValidToken() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentToken == nil {
		return false
	}
	return time.Until(s.currentToken.Expiry) > 0
}

// writeTokenAtomic writes the access token to dest with fsync + rename.
// Mode 0640 so the consumer's UID can read but world cannot.
func writeTokenAtomic(dest string, token string) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".svctoken-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if _, err := tmp.WriteString(token); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close: %w", err)
	}
	// 0640 is required (NOT 0600): the sidecar writes the file as its
	// own UID and the consumer container (e.g. argocd-repo-server)
	// reads it as a different UID via the pod's fsGroup. 0600 would
	// EACCES the consumer, breaking the entire credential-sharing
	// substrate. See pb!740 + the chart fsGroup wiring for the full
	// argocd-side story.
	if err := os.Chmod(tmp.Name(), 0o640); err != nil { //nolint:gosec // G302 false positive — group-readable is the contract.
		cleanup()
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		cleanup()
		return fmt.Errorf("rename to %s: %w", dest, err)
	}
	return nil
}

// newClientCredentials builds the clientcredentials.Config bound to
// our endpoint + scopes + RFC 8707 resource. Unlike TokenSource(), we
// call Token(ctx) directly so the request's context plumbs into the
// underlying HTTP call (cancellation cuts the wire mid-request, not
// just after the response).
func newClientCredentials(c *config) *clientcredentials.Config {
	cfg := &clientcredentials.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		TokenURL:     c.tokenURL,
		Scopes:       c.scopes,
	}
	if c.resource != "" {
		cfg.EndpointParams = map[string][]string{
			"resource": {c.resource},
		}
	}
	return cfg
}

// refresh attempts one token mint + atomic file write. Returns the
// new token on success so the caller can schedule the next tick.
// The ctx is plumbed all the way to the HTTP call so a hung
// Falcon-ID endpoint cancels cleanly when the caller's ctx fires
// (no leaked goroutines).
func refresh(ctx context.Context, cc *clientcredentials.Config, outputPath string) (*oauth2.Token, error) {
	// Defense-in-depth: cap the call at 30s independently of the
	// caller's ctx so a forgotten context.Background() can't stall
	// the refresher forever.
	mintCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tok, err := cc.Token(mintCtx)
	if err != nil {
		return nil, fmt.Errorf("mint: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("mint returned empty token")
	}
	if err := writeTokenAtomic(outputPath, tok.AccessToken); err != nil {
		return nil, fmt.Errorf("write atomic: %w", err)
	}
	return tok, nil
}

// secretPatcher abstracts the k8s.CoreV1().Secrets() Patch call so
// tests can exercise the refresh loop without an apiserver.
type secretPatcher interface {
	patch(ctx context.Context, namespace, name, usernameKey, username, passwordKey, token string) error
}

// k8sSecretPatcher is the production implementation backed by an
// in-cluster client-go connection.
type k8sSecretPatcher struct {
	cs kubernetes.Interface
}

func newK8sSecretPatcher() (secretPatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}
	return &k8sSecretPatcher{cs: cs}, nil
}

func (p *k8sSecretPatcher) patch(ctx context.Context, ns, name, usernameKey, username, passwordKey, token string) error {
	// StrategicMerge patch on data.<key> with base64-encoded values.
	// Using the data field (not stringData) avoids a server-side
	// re-encode round-trip and matches what every other consumer of
	// Secrets sees over the wire.
	data := map[string]string{
		passwordKey: encodeB64(token),
	}
	if usernameKey != "" && username != "" {
		data[usernameKey] = encodeB64(username)
	}
	body, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	patchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = p.cs.CoreV1().Secrets(ns).Patch(
		patchCtx, name, types.StrategicMergePatchType, body,
		metav1.PatchOptions{FieldManager: "svctoken-refresher"},
	)
	return err
}

func encodeB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// loop runs the refresh ticker. Backoff on failure: 5s, 10s, 20s, ...
// capped at 5min; resets on success.
//
// `sp` is the optional Secret patcher. When non-nil and the config
// has secretName set, every successful mint also patches the named
// Secret with the new JWT. Patch failures are logged + counted but
// don't fail the refresh (the file write is the primary path and
// already succeeded).
func loop(ctx context.Context, c *config, st *state, ts *clientcredentials.Config, sp secretPatcher) {
	backoff := 5 * time.Second
	const maxBackoff = 5 * time.Minute
	for {
		tok, err := refresh(ctx, ts, c.outputPath)
		if err != nil {
			refreshTotal.WithLabelValues("failed").Inc()
			logErr("refresh", "err", err.Error(), "next_retry", backoff.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		refreshTotal.WithLabelValues("ok").Inc()
		st.update(tok)
		backoff = 5 * time.Second
		if sp != nil && len(c.secretNames) > 0 {
			// Patch each configured Secret. Partial progress is
			// preferred over all-or-nothing — every consumer has its
			// own retry loop, and failing the whole tick over one bad
			// Secret would delay the others' rotation for a whole
			// refresh cycle.
			for _, name := range c.secretNames {
				perr := sp.patch(ctx, c.secretNamespace, name,
					c.secretUsernameKey, c.secretUsername, c.secretPasswordKey, tok.AccessToken)
				if perr != nil {
					secretPatchTotal.WithLabelValues("failed").Inc()
					logErr("secret patch",
						"err", perr.Error(),
						"namespace", c.secretNamespace,
						"name", name)
					continue
				}
				secretPatchTotal.WithLabelValues("ok").Inc()
				logInfo("secret patched",
					"namespace", c.secretNamespace,
					"name", name,
					"password_key", c.secretPasswordKey)
			}
		}
		nextRefresh := time.Until(tok.Expiry) - c.refreshBeforeExpiry
		// Defense-in-depth: never sleep less than 30s — protects against
		// a Falcon-ID config emitting unusually short TTLs that would
		// burn through the rate-limit.
		if nextRefresh < 30*time.Second {
			nextRefresh = 30 * time.Second
		}
		logInfo("refresh ok",
			"expires_at", tok.Expiry.Format(time.RFC3339),
			"next_refresh_in", nextRefresh.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextRefresh):
		}
	}
}

// healthMux serves /healthz, /readyz, /metrics, exposing the lifecycle
// state to kubelet + Prom.
func healthMux(st *state, outputPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if st.healthy.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("no valid token\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		info, err := os.Stat(outputPath)
		if err != nil || info.Size() == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("token file missing or empty\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		logErr("config", "err", err.Error())
		os.Exit(2)
	}
	logInfo("svctoken-refresher starting",
		"token_url", cfg.tokenURL,
		"client_id", cfg.clientID,
		"scopes", fmt.Sprintf("%v", cfg.scopes),
		"resource", cfg.resource,
		"output_path", cfg.outputPath,
		"refresh_before_expiry", cfg.refreshBeforeExpiry.String())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	st := &state{}
	ts := newClientCredentials(cfg)

	// Secret-patch mode is opt-in via SVCTOKEN_SECRET_NAME(S). When
	// at least one target is set we wire an in-cluster k8s client; if
	// that wiring fails we log a clear error and exit (the consumer
	// is depending on the patched Secret — degrading silently to
	// file-only would mask the outage). When unset we skip the wire
	// entirely so file-only consumers (CI runners, Atlantis, image-
	// updater) keep the small resource footprint they had before.
	var sp secretPatcher
	if len(cfg.secretNames) > 0 {
		p, err := newK8sSecretPatcher()
		if err != nil {
			logErr("secret patcher init", "err", err.Error())
			// Explicit cancel() before os.Exit — calling the same
			// closure the `defer cancel()` would invoke, so the
			// signal.NotifyContext's SIGTERM/SIGINT handlers are
			// released cleanly even though os.Exit skips defers.
			// gocritic exitAfterDefer can't see that cancel() IS
			// the deferred call (its analysis is function-scoped,
			// not closure-aware).
			cancel()
			os.Exit(3) //nolint:gocritic // exitAfterDefer false positive; cancel() above already invoked.
		}
		sp = p
		logInfo("secret-patch mode enabled",
			"namespace", cfg.secretNamespace,
			"names", strings.Join(cfg.secretNames, ","),
			"password_key", cfg.secretPasswordKey,
			"username_key", cfg.secretUsernameKey,
			"username_set", strconv.FormatBool(cfg.secretUsername != ""))
	}

	go func() {
		srv := &http.Server{
			Addr:              cfg.listen,
			Handler:           healthMux(st, cfg.outputPath),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			<-ctx.Done()
			shutdownCtx, sc := context.WithTimeout(context.Background(), 5*time.Second)
			defer sc()
			_ = srv.Shutdown(shutdownCtx)
		}()
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logErr("health server", "err", err.Error())
		}
	}()

	loop(ctx, cfg, st, ts, sp)
	logInfo("svctoken-refresher exiting")
}

// logInfo + logErr — minimal structured logging without bringing in a
// full zap dep. Output is JSON so it ships cleanly to Loki.
func logInfo(msg string, kv ...string) { writeLog("info", msg, kv...) }
func logErr(msg string, kv ...string)  { writeLog("error", msg, kv...) }
func writeLog(level, msg string, kv ...string) {
	out := `{"level":"` + level + `","msg":` + strconv.Quote(msg) + `,"time":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"`
	for i := 0; i+1 < len(kv); i += 2 {
		out += `,` + strconv.Quote(kv[i]) + `:` + strconv.Quote(kv[i+1])
	}
	out += "}\n"
	_, _ = os.Stdout.WriteString(out)
}
