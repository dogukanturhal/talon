// SPDX-License-Identifier: AGPL-3.0-or-later

package credexchange

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretNameForHost(t *testing.T) {
	cases := map[string]string{
		"github.com": "talon-upstream-creds-github-com",
		"registry.example.com": "talon-upstream-creds-registry-example-com",
		"single":              "talon-upstream-creds-single",
		"a.b.c.d.e.f":         "talon-upstream-creds-a-b-c-d-e-f",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			if got := SecretNameForHost(in); got != want {
				t.Errorf("SecretNameForHost(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestFormatIsValid(t *testing.T) {
	for _, ok := range []Format{FormatBasicOauth2, FormatBasic, FormatBearer, FormatPrivateToken} {
		if !ok.IsValid() {
			t.Errorf("Format %q expected valid", ok)
		}
	}
	for _, bad := range []Format{"", "x", "BASIC", "basic_oauth2"} {
		if bad.IsValid() {
			t.Errorf("Format %q expected invalid", bad)
		}
	}
}

func TestApply_BasicOauth2(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://gitlab.example/repo.git", nil)
	req.Header.Set("Authorization", "Basic AAAAAAAA") // inbound (svctoken-shape) must be stripped
	Apply(req, Credential{Password: "glpat-xxx", Format: FormatBasicOauth2})
	got := req.Header.Get("Authorization")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-xxx"))
	if got != want {
		t.Errorf("auth = %q, want %q", got, want)
	}
}

func TestApply_Basic(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://harbor.example/v2/", nil)
	req.Header.Set("Authorization", "Basic prev")
	Apply(req, Credential{Username: "robot$svc", Password: "robot-pwd", Format: FormatBasic})
	got := req.Header.Get("Authorization")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("robot$svc:robot-pwd"))
	if got != want {
		t.Errorf("auth = %q, want %q", got, want)
	}
}

func TestApply_Bearer(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example/v1/x", nil)
	req.Header.Set("Authorization", "Bearer prev-jwt")
	Apply(req, Credential{Password: "opaque-api-token", Format: FormatBearer})
	got := req.Header.Get("Authorization")
	want := "Bearer opaque-api-token"
	if got != want {
		t.Errorf("auth = %q, want %q", got, want)
	}
}

func TestApply_PrivateToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://gitlab.example/api/v4/users", nil)
	req.Header.Set("Authorization", "Bearer prev-jwt") // svctoken-shape — MUST be stripped
	req.Header.Set("PRIVATE-TOKEN", "stale-value")     // any prior PRIVATE-TOKEN MUST be replaced
	Apply(req, Credential{Password: "glpat-admin", Format: FormatPrivateToken})
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty (PRIVATE-TOKEN must be the only auth)", got)
	}
	if got := req.Header.Get("PRIVATE-TOKEN"); got != "glpat-admin" {
		t.Errorf("PRIVATE-TOKEN = %q, want %q", got, "glpat-admin")
	}
}

func TestApply_PrivateToken_IgnoresUsername(t *testing.T) {
	// Username is documented as ignored for FormatPrivateToken. Verify
	// even an explicit username value doesn't leak into any header.
	req, _ := http.NewRequest("GET", "https://gitlab.example/api/v4/users", nil)
	Apply(req, Credential{Username: "ignored-user", Password: "glpat-x", Format: FormatPrivateToken})
	if got := req.Header.Get("PRIVATE-TOKEN"); got != "glpat-x" {
		t.Errorf("PRIVATE-TOKEN = %q, want %q", got, "glpat-x")
	}
	for _, h := range []string{"Authorization", "X-Forwarded-User", "User"} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("Header %q leaked username/password: %q", h, got)
		}
	}
}

func TestApply_StripsPriorPrivateTokenForOtherFormats(t *testing.T) {
	// Defensive cross-format check: a stale PRIVATE-TOKEN header on
	// the inbound request MUST be stripped when Apply uses any other
	// format. Otherwise a forged PRIVATE-TOKEN could ride alongside
	// the Talon-substituted Authorization header.
	for _, f := range []Format{FormatBasicOauth2, FormatBasic, FormatBearer} {
		t.Run(string(f), func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://x", nil)
			req.Header.Set("PRIVATE-TOKEN", "forged-attacker-pat")
			Apply(req, Credential{Username: "u", Password: "p", Format: f})
			if got := req.Header.Get("PRIVATE-TOKEN"); got != "" {
				t.Errorf("format %q leaked PRIVATE-TOKEN: %q", f, got)
			}
		})
	}
}

func TestApply_StripsInboundEvenIfNoMatchingHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://x", nil)
	// No prior Authorization. Apply must still set the new one.
	Apply(req, Credential{Password: "p", Format: FormatBasicOauth2})
	if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("auth = %q, want Basic-prefixed", got)
	}
}

func TestApply_NilRequest_NoPanic(t *testing.T) {
	// Defensive: routers MUST pass a non-nil req but a regression
	// shouldn't crash the whole proxy.
	Apply(nil, Credential{Password: "p", Format: FormatBasicOauth2})
}

func TestK8sSecretLoader_HitMiss(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-github-com",
			Namespace: "talon",
		},
		Data: map[string][]byte{
			"username": []byte("oauth2"),
			"password": []byte("glpat-secret"),
			"format":   []byte("basic-oauth2"),
		},
	})
	l := NewK8sSecretLoader(cs, "talon", 0)

	c, err := l.Load(context.Background(), "github.com", "")
	if err != nil {
		t.Fatalf("hit: err=%v", err)
	}
	if c.Password != "glpat-secret" || c.Format != FormatBasicOauth2 {
		t.Errorf("hit: cred=%+v", c)
	}

	_, err = l.Load(context.Background(), "missing.example.com", "")
	if err != ErrNoCredential {
		t.Errorf("miss: err=%v want ErrNoCredential", err)
	}
}

func TestK8sSecretLoader_DefaultFormatWhenAbsent(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-x",
			Namespace: "talon",
		},
		Data: map[string][]byte{"password": []byte("p")},
	})
	l := NewK8sSecretLoader(cs, "talon", 0)
	c, err := l.Load(context.Background(), "x", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatBasicOauth2 {
		t.Errorf("default format = %q, want basic-oauth2", c.Format)
	}
}

func TestK8sSecretLoader_EmptyPasswordIsError(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-x",
			Namespace: "talon",
		},
		Data: map[string][]byte{"password": []byte("")},
	})
	l := NewK8sSecretLoader(cs, "talon", 0)
	_, err := l.Load(context.Background(), "x", "")
	if err == nil || err == ErrNoCredential {
		t.Errorf("err=%v; expected non-sentinel error for empty password", err)
	}
}

func TestK8sSecretLoader_InvalidFormatIsError(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-x",
			Namespace: "talon",
		},
		Data: map[string][]byte{
			"password": []byte("p"),
			"format":   []byte("bogus-format"),
		},
	})
	l := NewK8sSecretLoader(cs, "talon", 0)
	_, err := l.Load(context.Background(), "x", "")
	if err == nil {
		t.Error("expected error on invalid format")
	}
}

func TestK8sSecretLoader_CachesHits(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-x",
			Namespace: "talon",
		},
		Data: map[string][]byte{"password": []byte("p")},
	})
	l := NewK8sSecretLoader(cs, "talon", 5*time.Second)
	if _, err := l.Load(context.Background(), "x", ""); err != nil {
		t.Fatal(err)
	}
	// Mutate the underlying cache by deleting the Secret; the cached
	// hit must still serve because TTL hasn't expired.
	_ = cs.CoreV1().Secrets("talon").Delete(context.Background(),
		"talon-upstream-creds-x", metav1.DeleteOptions{})
	c, err := l.Load(context.Background(), "x", "")
	if err != nil {
		t.Errorf("cached hit: err=%v", err)
	}
	if c.Password != "p" {
		t.Errorf("cached hit: pass=%q", c.Password)
	}
}

func TestK8sSecretLoader_CachesMisses(t *testing.T) {
	cs := fake.NewClientset()
	l := NewK8sSecretLoader(cs, "talon", 5*time.Second)
	if _, err := l.Load(context.Background(), "x", ""); err != ErrNoCredential {
		t.Fatalf("first miss: %v", err)
	}
	// Creating the Secret after the miss should NOT serve until TTL
	// expires — negative cache holds. Operator who provisioned the
	// Secret on miss waits at most TTL for propagation.
	_, _ = cs.CoreV1().Secrets("talon").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-x",
			Namespace: "talon",
		},
		Data: map[string][]byte{"password": []byte("p")},
	}, metav1.CreateOptions{})
	if _, err := l.Load(context.Background(), "x", ""); err != ErrNoCredential {
		t.Errorf("post-create within TTL: err=%v, expected cached ErrNoCredential", err)
	}
}

// TestK8sSecretLoader_PerClientHit — Phase 5+ per-consumer
// differentiation. A per-client Secret named with
// SecretNameForHostClient takes priority over the host-default Secret
// when a non-empty clientID is passed.
func TestK8sSecretLoader_PerClientHit(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-github-com",
				Namespace: "talon",
			},
			Data: map[string][]byte{
				"password": []byte("default-group-token"),
				"format":   []byte("basic-oauth2"),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-github-com-svc-svc-gitlab-bcl-receiver",
				Namespace: "talon",
			},
			Data: map[string][]byte{
				"password": []byte("admin-pat-secret"),
				"format":   []byte("basic-oauth2"),
			},
		},
	)
	l := NewK8sSecretLoader(cs, "talon", 0)

	// Per-client lookup returns the per-client Secret, NOT the
	// host-default.
	c, err := l.Load(context.Background(), "github.com", "svc-svc-gitlab-bcl-receiver")
	if err != nil {
		t.Fatalf("per-client hit: err=%v", err)
	}
	if c.Password != "admin-pat-secret" {
		t.Errorf("per-client hit returned default creds: pass=%q want admin-pat-secret", c.Password)
	}

	// A DIFFERENT client_id falls back to the host-default (no
	// per-client Secret named for it).
	c, err = l.Load(context.Background(), "github.com", "svc-svc-argocd-repo-server")
	if err != nil {
		t.Fatalf("fallback hit: err=%v", err)
	}
	if c.Password != "default-group-token" {
		t.Errorf("fallback returned per-client creds: pass=%q want default-group-token", c.Password)
	}

	// Empty clientID bypasses per-client lookup entirely — back-compat
	// for Phase 4.5 callers that don't pass an identity.
	c, err = l.Load(context.Background(), "github.com", "")
	if err != nil {
		t.Fatalf("empty clientID: err=%v", err)
	}
	if c.Password != "default-group-token" {
		t.Errorf("empty clientID returned per-client creds: pass=%q want default-group-token", c.Password)
	}
}

// TestK8sSecretLoader_PerClientMissFallsThroughToHostDefault — when
// the per-client Secret doesn't exist BUT the host-default does, the
// loader serves the host-default (the back-compat path: existing
// host-default Secrets keep working for every consumer until an
// operator provisions a per-client variant).
func TestK8sSecretLoader_PerClientMissFallsThroughToHostDefault(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "talon-upstream-creds-github-com",
			Namespace: "talon",
		},
		Data: map[string][]byte{
			"password": []byte("group-token"),
			"format":   []byte("basic-oauth2"),
		},
	})
	l := NewK8sSecretLoader(cs, "talon", 0)

	c, err := l.Load(context.Background(), "github.com", "svc-some-unconfigured-client")
	if err != nil {
		t.Fatalf("fallback path: err=%v", err)
	}
	if c.Password != "group-token" {
		t.Errorf("fallback returned wrong creds: pass=%q", c.Password)
	}
}

// TestK8sSecretLoader_PerClientShapeErrorDoesNotFallThrough —
// security-relevant guard. When a per-client Secret EXISTS but has
// malformed data (empty password, invalid format), the loader MUST
// surface the error to the operator rather than silently demoting to
// the host-default. Silent demotion could mask a scope mismatch
// (per-client creds are typically MORE privileged than host-default;
// falling back hides the misconfig).
func TestK8sSecretLoader_PerClientShapeErrorDoesNotFallThrough(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-github-com",
				Namespace: "talon",
			},
			Data: map[string][]byte{"password": []byte("default-token")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-github-com-svc-broken-client",
				Namespace: "talon",
			},
			Data: map[string][]byte{"password": []byte("")}, // empty — operator misconfig
		},
	)
	l := NewK8sSecretLoader(cs, "talon", 0)

	_, err := l.Load(context.Background(), "github.com", "svc-broken-client")
	if err == nil {
		t.Fatal("per-client shape error: want non-nil error, got nil (silently demoted to host-default)")
	}
	if err == ErrNoCredential {
		t.Errorf("per-client shape error: returned ErrNoCredential (silent fallback), want surface error")
	}
}

// TestSecretNameForHostClient — pin the per-client name format so
// operators can predict it. Empty clientID returns empty string
// (loader uses this to skip per-client lookup).
func TestSecretNameForHostClient(t *testing.T) {
	cases := []struct {
		host, clientID, want string
	}{
		{"github.com", "svc-svc-gitlab-bcl-receiver", "talon-upstream-creds-github-com-svc-svc-gitlab-bcl-receiver"},
		{"registry.example.com", "svc-some-client", "talon-upstream-creds-registry-example-com-svc-some-client"},
		{"github.com", "", ""},
		{"x.y.z", "c", "talon-upstream-creds-x-y-z-c"},
	}
	for _, c := range cases {
		got := SecretNameForHostClient(c.host, c.clientID)
		if got != c.want {
			t.Errorf("SecretNameForHostClient(%q,%q) = %q, want %q", c.host, c.clientID, got, c.want)
		}
	}
}

// TestK8sSecretLoader_PerClientCacheKey — cache keyed by (host,
// clientID), so two clients on the same host don't share a cache slot
// and accidentally swap creds.
func TestK8sSecretLoader_PerClientCacheKey(t *testing.T) {
	cs := fake.NewClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-h-a",
				Namespace: "talon",
			},
			Data: map[string][]byte{"password": []byte("for-A")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "talon-upstream-creds-h-b",
				Namespace: "talon",
			},
			Data: map[string][]byte{"password": []byte("for-B")},
		},
	)
	l := NewK8sSecretLoader(cs, "talon", 5*time.Second)

	cA, _ := l.Load(context.Background(), "h", "a")
	cB, _ := l.Load(context.Background(), "h", "b")
	if cA.Password != "for-A" {
		t.Errorf("client A: pass=%q want for-A", cA.Password)
	}
	if cB.Password != "for-B" {
		t.Errorf("client B: pass=%q want for-B", cB.Password)
	}
	// Re-fetch from cache — must NOT swap.
	cA2, _ := l.Load(context.Background(), "h", "a")
	if cA2.Password != "for-A" {
		t.Errorf("client A cache: pass=%q (cache key collision!)", cA2.Password)
	}
}
