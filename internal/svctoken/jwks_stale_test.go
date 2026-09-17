// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// toggleJWKS is a JWKS endpoint whose availability the test flips at
// will, with a hit counter so DDIL P3.11 load-shed can be asserted.
type toggleJWKS struct {
	url  string
	fail atomic.Bool
	hits atomic.Int32
}

func newToggleJWKS(t *testing.T) *toggleJWKS {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: "stale-key-1", Algorithm: "RS256", Use: "sig"},
	}}
	tj := &toggleJWKS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		tj.hits.Add(1)
		if tj.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	tj.url = srv.URL + "/.well-known/jwks.json"
	return tj
}

// TestJWKSStale_ServedWithinBudget_FailClosedAfter is the core P3.1
// contract: after the cache TTL, a refresh failure serves the last-good
// key set until the stale budget elapses, then fails closed.
func TestJWKSStale_ServedWithinBudget_FailClosedAfter(t *testing.T) {
	tj := newToggleJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	var staleCalls int32
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:            tj.url,
		ExpectedIssuer:     "https://id.test",
		JWKSStaleThreshold: time.Hour,
		Clock:              fc,
		OnJWKSStale:        func(time.Duration) { atomic.AddInt32(&staleCalls, 1) },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()

	// t0: healthy fetch populates the cache.
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}

	// Falcon-ID goes down.
	tj.fail.Store(true)

	// +6min: past the 5-min TTL, within the 1h stale budget → served stale.
	fc.Advance(6 * time.Minute)
	got, err := v.getJWKS(ctx, false, true)
	if err != nil {
		t.Fatalf("within stale budget: expected stale-serve, got err %v", err)
	}
	if got == nil {
		t.Fatal("within stale budget: expected cached keyset, got nil")
	}
	if atomic.LoadInt32(&staleCalls) != 1 {
		t.Fatalf("OnJWKSStale should have fired once, got %d", staleCalls)
	}

	// +61min total: past the stale budget → fail closed.
	fc.Advance(55 * time.Minute)
	if _, err := v.getJWKS(ctx, false, true); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("past stale budget: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_DisabledFailsClosedAtTTL asserts a non-positive threshold
// restores the strict pre-P3.1 behaviour: no stale window at all.
func TestJWKSStale_DisabledFailsClosedAtTTL(t *testing.T) {
	tj := newToggleJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:            tj.url,
		ExpectedIssuer:     "https://id.test",
		JWKSStaleThreshold: -1, // disabled
		Clock:              fc,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	tj.fail.Store(true)
	fc.Advance(6 * time.Minute) // past TTL, would be within a 1h budget
	if _, err := v.getJWKS(ctx, false, true); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("stale window disabled: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_HealthCheckPathBypassesStale asserts allowStale=false (the
// HealthCheck / PrefetchJWKS surface) surfaces the real fetch failure so a
// readiness probe is never masked by a stale-cache success.
func TestJWKSStale_HealthCheckPathBypassesStale(t *testing.T) {
	tj := newToggleJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:            tj.url,
		ExpectedIssuer:     "https://id.test",
		JWKSStaleThreshold: time.Hour,
		Clock:              fc,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	tj.fail.Store(true)
	fc.Advance(6 * time.Minute) // well within the stale budget
	// allowStale=false must NOT serve the stale cache.
	if _, err := v.getJWKS(ctx, true, false); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("HealthCheck path within budget: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_BreakerShedsSustainedOutage is the P3.11 assertion: once
// the JWKS endpoint has failed enough to trip the breaker, further verifies
// are served from stale WITHOUT hammering the dead dependency.
func TestJWKSStale_BreakerShedsSustainedOutage(t *testing.T) {
	tj := newToggleJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:            tj.url,
		ExpectedIssuer:     "https://id.test",
		JWKSStaleThreshold: 24 * time.Hour, // stay comfortably in-budget
		Clock:              fc,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	hitsAfterWarm := tj.hits.Load()

	tj.fail.Store(true)
	fc.Advance(6 * time.Minute) // past TTL so every call attempts a refresh

	// Default breaker trips after 5 consecutive failures. Call many times
	// at the same instant (no cool-down elapses) and assert the endpoint is
	// probed at most FailureThreshold times, while every call still serves
	// stale (nil error) within budget.
	for i := 0; i < 40; i++ {
		if _, err := v.getJWKS(ctx, false, true); err != nil {
			t.Fatalf("call %d: expected stale-serve within budget, got %v", i, err)
		}
	}
	probes := tj.hits.Load() - hitsAfterWarm
	if probes > 5 {
		t.Fatalf("breaker failed to shed: %d live probes during sustained outage (want <= 5)", probes)
	}
}
