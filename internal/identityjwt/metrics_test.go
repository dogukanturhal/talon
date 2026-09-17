// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dogukanturhal/talon/internal/session"
)

// recordingMetrics captures every Inc call for assertion.
type recordingMetrics struct {
	successes      atomic.Int32
	failures       atomic.Int32
	lastFailReason atomic.Value // string
	lastFailKid    atomic.Value // string
	jwksSuccess    atomic.Int32
	jwksFailure    atomic.Int32
	replayBlocked  atomic.Int32
}

func (m *recordingMetrics) OnVerifySuccess(_, _ string) {
	m.successes.Add(1)
}
func (m *recordingMetrics) OnVerifyFailure(_, kid, reason string) {
	m.failures.Add(1)
	m.lastFailReason.Store(reason)
	m.lastFailKid.Store(kid)
}
func (m *recordingMetrics) OnJWKSFetch(result string) {
	if result == "success" {
		m.jwksSuccess.Add(1)
	} else {
		m.jwksFailure.Add(1)
	}
}
func (m *recordingMetrics) OnReplayBlocked(_ string) {
	m.replayBlocked.Add(1)
}

func TestVerifierMetrics_SuccessIncrementsCounter(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	m := &recordingMetrics{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		Metrics: m,
	})
	tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	if _, err := v.VerifyToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if got := m.successes.Load(); got != 1 {
		t.Errorf("successes = %d, want 1", got)
	}
	if got := m.failures.Load(); got != 0 {
		t.Errorf("failures = %d, want 0", got)
	}
	if got := m.jwksSuccess.Load(); got != 1 {
		t.Errorf("jwks success = %d, want 1 (first verify triggers fetch)", got)
	}
}

func TestVerifierMetrics_FailureCarriesReasonAndKid(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	m := &recordingMetrics{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "registry.example.com",
		Metrics: m,
	})
	// Mint for the WRONG audience → reason=audience_mismatch.
	tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "argocd.ops")
	if _, err := v.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected verify failure")
	}
	if got := m.failures.Load(); got != 1 {
		t.Errorf("failures = %d, want 1", got)
	}
	if r, _ := m.lastFailReason.Load().(string); r != "audience_mismatch" {
		t.Errorf("reason = %q, want audience_mismatch", r)
	}
	if kid, _ := m.lastFailKid.Load().(string); kid != signer.Kid() {
		t.Errorf("kid = %q, want %q (must propagate through failure path)", kid, signer.Kid())
	}
}

func TestVerifierMetrics_ReplayBlockedDistinctFromFailure(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	m := &recordingMetrics{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		ReplayCacheSize: 16,
		Metrics:         m,
	})
	tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	if _, err := v.VerifyToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	// Replay the same token.
	if _, err := v.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected ErrReplay")
	}
	if got := m.successes.Load(); got != 1 {
		t.Errorf("successes = %d, want 1 (only first verify counts)", got)
	}
	if got := m.replayBlocked.Load(); got != 1 {
		t.Errorf("replay blocked = %d, want 1", got)
	}
	// Replay path must NOT increment the generic failure counter —
	// operators dashboard on replay separately from cryptographic
	// failures.
	if got := m.failures.Load(); got != 0 {
		t.Errorf("failures = %d, want 0 (replay has its own counter)", got)
	}
}

func TestVerifierMetrics_JWKSFailureCounted(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no key", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m := &recordingMetrics{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: srv.URL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		Metrics: m,
	})
	_, _ = v.VerifyToken(context.Background(), tok)

	if got := m.jwksFailure.Load(); got != 1 {
		t.Errorf("jwks failure = %d, want 1", got)
	}
}

func TestVerifierMetrics_NilMetricsIsNoOp(t *testing.T) {
	// Default config (no Metrics field) MUST NOT panic and MUST verify normally.
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	if _, err := v.VerifyToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierMetrics_JWKSCachedFetchSkipsCounter(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	m := &recordingMetrics{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: jwksURL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		Metrics: m,
	})
	for i := 0; i < 5; i++ {
		tok, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
		if _, err := v.VerifyToken(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	}
	// 5 verifies, 5 success counter increments.
	if got := m.successes.Load(); got != 5 {
		t.Errorf("successes = %d, want 5", got)
	}
	// But only ONE JWKS fetch — cache served the rest. Critical for
	// operators sizing alert thresholds: jwks_fetch is per-cache-miss,
	// not per-request.
	if got := m.jwksSuccess.Load(); got != 1 {
		t.Errorf("jwks success counter = %d, want 1 (cache must not double-count)", got)
	}
}

// Quick sanity check that the recordingMetrics shape compiles against
// the VerifierMetrics interface; would catch interface-drift at build
// time but is also a useful documentation point.
var _ VerifierMetrics = (*recordingMetrics)(nil)

// awaitNonZero lets time-dependent metric tests poll the counter
// rather than guessing a sleep duration. Currently unused but kept
// as a helper for future metric tests that exercise async paths.
func awaitNonZero(t *testing.T, fn func() int32, timeout time.Duration) int32 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := fn(); got > 0 {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	return fn()
}

var _ = awaitNonZero
