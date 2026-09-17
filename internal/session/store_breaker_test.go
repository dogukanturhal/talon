// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"context"
	"errors"
	"testing"

	"github.com/dogukanturhal/hexx-pep-core/pkg/resilient"
)

// TestRedisDo_BreakerShedsSustainedFailure asserts the DDIL P3.11 wiring:
// once the per-request Redis path has failed enough to trip the breaker,
// further reads are shed (fn not called) with an ErrBreakerOpen-wrapped
// error — which the router classifies as ReasonInternal (fail-closed 503).
func TestRedisDo_BreakerShedsSustainedFailure(t *testing.T) {
	s := &Store{breaker: resilient.NewBreaker(resilient.BreakerConfig{})}
	down := func(context.Context) error { return errors.New("redis down") }

	// Default breaker trips after 5 consecutive failures.
	for i := 0; i < 5; i++ {
		if err := s.redisDo(context.Background(), down); err == nil {
			t.Fatalf("call %d: expected failure", i)
		}
	}

	// Breaker open: fn must not run and the error is a shed.
	called := false
	err := s.redisDo(context.Background(), func(context.Context) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("breaker open: fn should not be invoked")
	}
	if !errors.Is(err, resilient.ErrBreakerOpen) {
		t.Fatalf("want ErrBreakerOpen, got %v", err)
	}
}

// TestRedisDo_MissDoesNotTripBreaker asserts an expected non-error outcome
// (cache miss modelled as fn returning nil) never counts as a breaker
// failure, so a high miss rate cannot open the breaker.
func TestRedisDo_MissDoesNotTripBreaker(t *testing.T) {
	s := &Store{breaker: resilient.NewBreaker(resilient.BreakerConfig{})}
	for i := 0; i < 50; i++ {
		if err := s.redisDo(context.Background(), func(context.Context) error { return nil }); err != nil {
			t.Fatalf("miss %d should pass through, got %v", i, err)
		}
	}
	// The breaker is still closed: a subsequent call runs fn.
	called := false
	_ = s.redisDo(context.Background(), func(context.Context) error { called = true; return nil })
	if !called {
		t.Fatal("breaker should remain closed after only misses")
	}
}

// TestRedisDo_NilBreakerPassthrough asserts the pre-P3.11 behaviour when no
// breaker is wired: fn runs and its error is returned verbatim.
func TestRedisDo_NilBreakerPassthrough(t *testing.T) {
	s := &Store{}
	sentinel := errors.New("boom")
	if err := s.redisDo(context.Background(), func(context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("nil breaker should return fn error verbatim, got %v", err)
	}
}
