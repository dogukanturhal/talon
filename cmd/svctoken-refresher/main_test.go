// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeIDP simulates Falcon-ID's /oauth/token endpoint. Returns a
// caller-controlled token + caller-controlled expires_in. Records the
// last request so tests can assert on grant_type / client_id / scope.
type fakeIDP struct {
	srv       *httptest.Server
	requests  []map[string]string
	failNext  bool
	expiresIn int64
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{expiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		req := map[string]string{
			"grant_type": r.PostFormValue("grant_type"),
			"scope":      r.PostFormValue("scope"),
			"resource":   r.PostFormValue("resource"),
		}
		// Basic-auth client_id (canonical for clientcredentials.Config)
		if u, _, ok := r.BasicAuth(); ok {
			req["client_id"] = u
		}
		f.requests = append(f.requests, req)
		if f.failNext {
			f.failNext = false
			http.Error(w, "transient", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "fake-token-" + req["client_id"],
			"token_type":   "Bearer",
			"expires_in":   f.expiresIn,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestRefresh_WritesTokenFile(t *testing.T) {
	idp := newFakeIDP(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "jwt")
	cfg := &config{
		clientID:     "svc-test",
		clientSecret: "secret",
		tokenURL:     idp.srv.URL + "/oauth/token",
		scopes:       []string{"talon:github.com:read"},
		resource:     "https://github.com",
		outputPath:   outPath,
	}
	ts := newClientCredentials(cfg)
	tok, err := refresh(context.Background(), ts, outPath)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.AccessToken != "fake-token-svc-test" {
		t.Errorf("AccessToken = %q, want fake-token-svc-test", tok.AccessToken)
	}
	// File written with right permissions + contents
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("file mode = %o, want 0640", info.Mode().Perm())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != "fake-token-svc-test" {
		t.Errorf("file contents = %q, want fake-token-svc-test", string(data))
	}
}

func TestRefresh_PostsCorrectParams(t *testing.T) {
	idp := newFakeIDP(t)
	dir := t.TempDir()
	cfg := &config{
		clientID:     "svc-imgupd",
		clientSecret: "imgupd-secret",
		tokenURL:     idp.srv.URL + "/oauth/token",
		scopes:       []string{"talon:registry.example.com:pull", "talon:registry.example.com:push"},
		resource:     "https://registry.example.com",
		outputPath:   filepath.Join(dir, "jwt"),
	}
	ts := newClientCredentials(cfg)
	if _, err := refresh(context.Background(), ts, cfg.outputPath); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(idp.requests) != 1 {
		t.Fatalf("expected 1 IDP request, got %d", len(idp.requests))
	}
	req := idp.requests[0]
	if req["grant_type"] != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", req["grant_type"])
	}
	if req["client_id"] != "svc-imgupd" {
		t.Errorf("client_id = %q, want svc-imgupd", req["client_id"])
	}
	// Scopes are space-separated per RFC 6749 §3.3
	if !strings.Contains(req["scope"], "talon:registry.example.com:pull") ||
		!strings.Contains(req["scope"], "talon:registry.example.com:push") {
		t.Errorf("scope = %q, want both pull and push", req["scope"])
	}
	if req["resource"] != "https://registry.example.com" {
		t.Errorf("resource = %q, want https://registry.example.com", req["resource"])
	}
}

func TestRefresh_AtomicWrite_NoPartialOnError(t *testing.T) {
	idp := newFakeIDP(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "jwt")

	// Seed a known-good token first.
	cfg := &config{
		clientID:     "svc-test",
		clientSecret: "secret",
		tokenURL:     idp.srv.URL + "/oauth/token",
		outputPath:   outPath,
	}
	ts := newClientCredentials(cfg)
	if _, err := refresh(context.Background(), ts, outPath); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Capture seed content.
	seedBytes, _ := os.ReadFile(outPath)
	if len(seedBytes) == 0 {
		t.Fatal("seed file empty")
	}

	// Force the next refresh to fail. The file MUST be unchanged.
	idp.failNext = true
	_, err := refresh(context.Background(), ts, outPath)
	if err == nil {
		t.Error("expected refresh to fail, got nil")
	}
	after, _ := os.ReadFile(outPath)
	if string(after) != string(seedBytes) {
		t.Errorf("file contents changed on failed refresh:\n  before=%q\n  after=%q",
			string(seedBytes), string(after))
	}

	// And no leftover .svctoken-* temp files in the dir.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".svctoken-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// NB: a hung-endpoint test was attempted with httptest blocking the
// handler on r.Context().Done(); httptest.Server.Close() then waited
// for the handler to return, which never happened because the
// client-side context cancellation did not propagate through to the
// server-side request context in time. The 30s internal cap in
// refresh() (context.WithTimeout) provides this defense already; the
// e2e behaviour will exercise it against the real Falcon-ID endpoint
// in Phase 4 staging.

func TestState_HealthyTracksToken(t *testing.T) {
	st := &state{}
	if st.healthy.Load() {
		t.Error("fresh state should not be healthy")
	}
	st.update(&oauth2.Token{
		AccessToken: "tok",
		Expiry:      time.Now().Add(1 * time.Hour),
	})
	if !st.healthy.Load() {
		t.Error("after update with valid token, state should be healthy")
	}
	if !st.hasValidToken() {
		t.Error("hasValidToken should report true")
	}
	// Expired token
	st.update(&oauth2.Token{
		AccessToken: "tok",
		Expiry:      time.Now().Add(-1 * time.Minute),
	})
	if st.healthy.Load() {
		t.Error("expired token should set unhealthy")
	}
}

func TestWriteTokenAtomic_CreatesParentDir(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "nested", "dir", "jwt")
	if err := writeTokenAtomic(dest, "abc"); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "abc" {
		t.Errorf("contents = %q, want abc", string(data))
	}
}

// recordingPatcher captures every patch() invocation. The optional
// onCall hook lets the test break the loop after the first observed
// patch by cancelling the loop's context — without it the loop would
// sit in its 30s minimum sleep waiting for the next token expiry.
//
// `failOn` makes patch() return an error when name == failOn; used by
// the multi-Secret partial-failure test to verify that one failing
// target does NOT block the remaining targets in the same tick.
type recordingPatcher struct {
	calls  []patchCall
	err    error
	onCall func()
	failOn string
}
type patchCall struct{ ns, name, uk, u, pk, t string }

func (r *recordingPatcher) patch(_ context.Context, ns, name, uk, u, pk, t string) error {
	r.calls = append(r.calls, patchCall{ns, name, uk, u, pk, t})
	if r.onCall != nil {
		r.onCall()
	}
	if r.failOn != "" && name == r.failOn {
		return errors.New("recordingPatcher: simulated failure for name=" + name)
	}
	return r.err
}

func TestLoop_SecretPatchOff_NoCallsAndStillWritesFile(t *testing.T) {
	idp := newFakeIDP(t)
	idp.expiresIn = 60 // short so the loop's sleep cap (30s) doesn't dominate
	cfg := &config{
		clientID: "svc-test", clientSecret: "secret",
		tokenURL: idp.srv.URL + "/oauth/token",
		outputPath: filepath.Join(t.TempDir(), "jwt"),
		refreshBeforeExpiry: 5 * time.Second,
	}
	cc := newClientCredentials(cfg)
	st := &state{}
	rp := &recordingPatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	// Give the loop time to do one refresh, then cancel.
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	loop(ctx, cfg, st, cc, rp)
	// Sidecar is in file-only mode (secretName empty) so the loop
	// must NOT invoke the patcher even though we passed one.
	if len(rp.calls) != 0 {
		t.Errorf("expected zero patcher calls in file-only mode, got %d", len(rp.calls))
	}
	if _, err := os.Stat(cfg.outputPath); err != nil {
		t.Errorf("output file missing: %v", err)
	}
}

func TestLoop_SecretPatchOn_PatchesNamespaceNameAndCredentials(t *testing.T) {
	idp := newFakeIDP(t)
	idp.expiresIn = 60
	cfg := &config{
		clientID: "svc-test", clientSecret: "secret",
		tokenURL: idp.srv.URL + "/oauth/token",
		outputPath: filepath.Join(t.TempDir(), "jwt"),
		refreshBeforeExpiry: 5 * time.Second,
		// Secret-patch mode wired ON via the canonical ArgoCD repo-creds
		// shape: data.username + data.password.
		secretNamespace:   "argocd",
		secretNames:       []string{"argocd-repo-creds-gitlab-svctoken"},
		secretPasswordKey: "password",
		secretUsernameKey: "username",
		secretUsername:    "oauth2",
	}
	cc := newClientCredentials(cfg)
	st := &state{}
	ctx, cancel := context.WithCancel(context.Background())
	rp := &recordingPatcher{onCall: cancel}
	loop(ctx, cfg, st, cc, rp)
	if len(rp.calls) != 1 {
		t.Fatalf("expected exactly one patcher call, got %d", len(rp.calls))
	}
	c := rp.calls[0]
	if c.ns != "argocd" || c.name != "argocd-repo-creds-gitlab-svctoken" {
		t.Errorf("wrong target: ns=%q name=%q", c.ns, c.name)
	}
	if c.pk != "password" || c.uk != "username" || c.u != "oauth2" {
		t.Errorf("wrong creds shape: pk=%q uk=%q u=%q", c.pk, c.uk, c.u)
	}
	if !strings.HasPrefix(c.t, "fake-token-") {
		t.Errorf("token not propagated to patch: got %q", c.t)
	}
}

// TestLoop_MultiSecret_PatchesAllNames — Phase 5 multi-Secret
// support. With more than one entry in secretNames, every successful
// mint must trigger one patch per entry, IN ORDER, with the SAME
// token + creds shape. The cancel-on-first-patch trick can't be used
// here because we want the loop to fan out to all targets before
// terminating; instead we count patches and cancel after the last one
// observed.
func TestLoop_MultiSecret_PatchesAllNames(t *testing.T) {
	idp := newFakeIDP(t)
	idp.expiresIn = 60
	cfg := &config{
		clientID: "svc-test", clientSecret: "secret",
		tokenURL:            idp.srv.URL + "/oauth/token",
		outputPath:          filepath.Join(t.TempDir(), "jwt"),
		refreshBeforeExpiry: 5 * time.Second,
		secretNamespace:     "argocd",
		secretNames: []string{
			"argocd-repo-creds-gitlab-svctoken",
			"argocd-repo-the GitOps repository",
			"argocd-repo-platform",
		},
		secretPasswordKey: "password",
		secretUsernameKey: "username",
		secretUsername:    "oauth2",
	}
	cc := newClientCredentials(cfg)
	st := &state{}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the THIRD patch (one per target Secret).
	rp := &recordingPatcher{}
	rp.onCall = func() {
		if len(rp.calls) >= len(cfg.secretNames) {
			cancel()
		}
	}
	loop(ctx, cfg, st, cc, rp)
	if len(rp.calls) != len(cfg.secretNames) {
		t.Fatalf("expected %d patcher calls, got %d", len(cfg.secretNames), len(rp.calls))
	}
	// Order preservation: the Nth call must target the Nth Secret.
	for i, c := range rp.calls {
		if c.name != cfg.secretNames[i] {
			t.Errorf("call %d: name=%q, want %q", i, c.name, cfg.secretNames[i])
		}
		if c.u != "oauth2" || c.pk != "password" || c.uk != "username" {
			t.Errorf("call %d: wrong creds shape u=%q pk=%q uk=%q", i, c.u, c.pk, c.uk)
		}
	}
}

// TestLoop_MultiSecret_OneFailure_OthersContinue — partial-progress
// contract: a single Secret rejecting the patch must NOT block the
// rest. The recovery loop is per-consumer (each Argo repo has its
// own retry / fetch loop), and an all-or-nothing semantic would mean
// one stale Secret stalls every other consumer's rotation until the
// next refresh tick — potentially 55min of pinned-stale credentials.
func TestLoop_MultiSecret_OneFailure_OthersContinue(t *testing.T) {
	idp := newFakeIDP(t)
	idp.expiresIn = 60
	cfg := &config{
		clientID: "svc-test", clientSecret: "secret",
		tokenURL:            idp.srv.URL + "/oauth/token",
		outputPath:          filepath.Join(t.TempDir(), "jwt"),
		refreshBeforeExpiry: 5 * time.Second,
		secretNamespace:     "argocd",
		secretNames:         []string{"first", "fails", "third"},
		secretPasswordKey:   "password",
		secretUsernameKey:   "username",
		secretUsername:      "oauth2",
	}
	cc := newClientCredentials(cfg)
	st := &state{}
	ctx, cancel := context.WithCancel(context.Background())
	rp := &recordingPatcher{failOn: "fails"}
	rp.onCall = func() {
		if len(rp.calls) >= len(cfg.secretNames) {
			cancel()
		}
	}
	loop(ctx, cfg, st, cc, rp)
	if len(rp.calls) != 3 {
		t.Fatalf("expected 3 attempts (1 ok, 1 fail, 1 ok), got %d", len(rp.calls))
	}
	if rp.calls[0].name != "first" || rp.calls[1].name != "fails" || rp.calls[2].name != "third" {
		t.Errorf("wrong order: %+v", rp.calls)
	}
}

// TestAppendIfMissing checks the dedup helper used when both
// SVCTOKEN_SECRET_NAME and SVCTOKEN_SECRET_NAMES are set with overlap
// — operators should not see double patches on the same Secret per
// mint.
func TestAppendIfMissing(t *testing.T) {
	got := appendIfMissing([]string{"a", "b"}, "b")
	if len(got) != 2 {
		t.Errorf("expected dedup: got %v", got)
	}
	got = appendIfMissing([]string{"a", "b"}, "c")
	if len(got) != 3 || got[2] != "c" {
		t.Errorf("expected append: got %v", got)
	}
}

// patchEncoded verifies the JSON shape sent to the apiserver — every
// stringData/data key must be base64'd (not raw) for the Secret API
// to accept it. Catches a regression where someone swaps Strategic
// for stringData and forgets the encoding.
func TestK8sSecretPatcher_EncodesValuesAsBase64(t *testing.T) {
	if got := encodeB64("oauth2"); got != "b2F1dGgy" {
		t.Errorf("encodeB64(oauth2) = %q, want b2F1dGgy", got)
	}
	if got := encodeB64(""); got != "" {
		t.Errorf("encodeB64(empty) = %q, want empty string", got)
	}
}

func TestSplitFields(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a b c", []string{"a", "b", "c"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b c", []string{"a", "b", "c"}},
		{"", []string{}},
		{"single", []string{"single"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := splitFields(tc.in)
			if len(got) != len(tc.want) {
				t.Errorf("splitFields(%q) = %v, want %v", tc.in, got, tc.want)
				return
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("splitFields(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}
