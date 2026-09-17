// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

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

// toggleIdentityJWKS is a Talon JWKS endpoint whose availability the test
// flips at will, with a hit counter for the P3.11 load-shed assertion.
type toggleIdentityJWKS struct {
	url  string
	fail atomic.Bool
	hits atomic.Int32
}

func newToggleIdentityJWKS(t *testing.T) *toggleIdentityJWKS {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: "iap-stale-1", Algorithm: "RS256", Use: "sig"},
	}}
	tj := &toggleIdentityJWKS{}
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

func newStaleTestVerifier(t *testing.T, tj *toggleIdentityJWKS, clk resilient.Clock, stale time.Duration, onStale func(time.Duration)) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:            tj.url,
		ExpectedIssuer:     "https://auth.test",
		ExpectedAudience:   "app.test",
		JWKSStaleThreshold: stale,
		Clock:              clk,
		OnJWKSStale:        onStale,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestJWKSStale_ServedWithinBudget_FailClosedAfter is the core P3.1
// contract for the identity-token verifier.
func TestJWKSStale_ServedWithinBudget_FailClosedAfter(t *testing.T) {
	tj := newToggleIdentityJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	var staleCalls int32
	v := newStaleTestVerifier(t, tj, fc, time.Hour, func(time.Duration) { atomic.AddInt32(&staleCalls, 1) })
	ctx := context.Background()

	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	tj.fail.Store(true)

	fc.Advance(6 * time.Minute) // past the 5-min TTL, within the 1h budget
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

	fc.Advance(55 * time.Minute) // +61min total, past budget
	if _, err := v.getJWKS(ctx, false, true); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("past stale budget: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_DisabledFailsClosedAtTTL asserts a non-positive threshold
// restores strict pre-P3.1 fail-closed-at-TTL behaviour.
func TestJWKSStale_DisabledFailsClosedAtTTL(t *testing.T) {
	tj := newToggleIdentityJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v := newStaleTestVerifier(t, tj, fc, -1, nil)
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	tj.fail.Store(true)
	fc.Advance(6 * time.Minute)
	if _, err := v.getJWKS(ctx, false, true); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("stale window disabled: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_HealthCheckPathBypassesStale asserts allowStale=false surfaces
// the real fetch failure (HealthCheck / PrefetchJWKS) even within budget.
func TestJWKSStale_HealthCheckPathBypassesStale(t *testing.T) {
	tj := newToggleIdentityJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v := newStaleTestVerifier(t, tj, fc, time.Hour, nil)
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	tj.fail.Store(true)
	fc.Advance(6 * time.Minute)
	if _, err := v.getJWKS(ctx, true, false); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("HealthCheck path within budget: want ErrJWKSUnavailable, got %v", err)
	}
}

// TestJWKSStale_BreakerShedsSustainedOutage is the P3.11 assertion for the
// identity-token verifier's JWKS fetch.
func TestJWKSStale_BreakerShedsSustainedOutage(t *testing.T) {
	tj := newToggleIdentityJWKS(t)
	fc := resilient.NewFakeClock(time.Now())
	v := newStaleTestVerifier(t, tj, fc, 24*time.Hour, nil)
	ctx := context.Background()
	if _, err := v.getJWKS(ctx, false, true); err != nil {
		t.Fatalf("initial getJWKS: %v", err)
	}
	hitsAfterWarm := tj.hits.Load()

	tj.fail.Store(true)
	fc.Advance(6 * time.Minute)
	for i := 0; i < 40; i++ {
		if _, err := v.getJWKS(ctx, false, true); err != nil {
			t.Fatalf("call %d: expected stale-serve within budget, got %v", i, err)
		}
	}
	if probes := tj.hits.Load() - hitsAfterWarm; probes > 5 {
		t.Fatalf("breaker failed to shed: %d live probes during sustained outage (want <= 5)", probes)
	}
}
