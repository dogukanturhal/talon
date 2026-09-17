// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hexxlock/talon/internal/session"
)

func TestSign_StampsUniqueJTI(t *testing.T) {
	s, err := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		raw, err := s.Sign(&session.Blob{Sub: "u"}, "a")
		if err != nil {
			t.Fatal(err)
		}
		// Parse via the verifier path so we test the actual emitted shape.
		v, _ := NewVerifier(VerifierConfig{
			JWKSURL: must(jwksTestServer(t, s)), ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
		})
		claims, err := v.VerifyToken(context.Background(), raw)
		if err != nil {
			t.Fatalf("verify minted token: %v", err)
		}
		if claims.JTI == "" {
			t.Fatal("jti missing on minted JWT — RFC 7519 §4.1.7 noncompliant")
		}
		if _, dup := seen[claims.JTI]; dup {
			t.Fatalf("duplicate jti at iteration %d: %q", i, claims.JTI)
		}
		seen[claims.JTI] = struct{}{}
	}
}

// must collapses the two-return jwksTestServer for the inline NewVerifier above.
func must(url string, _ *atomic.Int32) string { return url }

func TestVerifier_ReplayDetectedWhenCacheEnabled(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)

	v, _ := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://auth.ops",
		ExpectedAudience: "a",
		ReplayCacheSize:  64,
	})
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")

	if _, err := v.VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := v.VerifyToken(context.Background(), token); !errors.Is(err, ErrReplay) {
		t.Fatalf("second verify err = %v, want ErrReplay", err)
	}
}

func TestVerifier_ReplayDisabledByDefault(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://auth.ops",
		ExpectedAudience: "a",
		// ReplayCacheSize zero — replay protection off.
	})
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	if _, err := v.VerifyToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	// Second verify must succeed when replay is off (= legacy behaviour).
	if _, err := v.VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("replay-disabled second verify should succeed, got %v", err)
	}
}

func TestVerifier_CustomReplayCacheHonoured(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	custom := &countingReplayCache{}
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://auth.ops",
		ExpectedAudience: "a",
		ReplayCache:      custom,
		ReplayCacheSize:  9999, // should be ignored when ReplayCache != nil
	})
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")
	if _, err := v.VerifyToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if custom.calls.Load() != 1 {
		t.Errorf("custom cache calls = %d, want 1", custom.calls.Load())
	}
}

func TestReplayLRU_EvictsAtCap(t *testing.T) {
	c := newReplayLRU(3)
	for i := 0; i < 5; i++ {
		if seen := c.SeenOrAdd("jti-"+strconv.Itoa(i), time.Minute); seen {
			t.Errorf("brand-new jti %d reported as seen", i)
		}
	}
	if got := c.Len(); got != 3 {
		t.Errorf("Len = %d, want 3 (cap enforced)", got)
	}
	// The oldest two (jti-0, jti-1) must have been evicted, so a
	// fresh insert of jti-0 should NOT report seen.
	if seen := c.SeenOrAdd("jti-0", time.Minute); seen {
		t.Error("evicted entry should not report as seen on re-insert")
	}
}

func TestReplayLRU_ExpiredEntriesAreNotReplays(t *testing.T) {
	c := newReplayLRU(8)
	_ = c.SeenOrAdd("jti-1", 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if seen := c.SeenOrAdd("jti-1", time.Second); seen {
		t.Error("expired entry must not report as seen")
	}
}

func TestReplayLRU_ConcurrentRaceFree(t *testing.T) {
	c := newReplayLRU(1024)
	var wg sync.WaitGroup
	const goroutines = 50
	const itersPerGoroutine = 50
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < itersPerGoroutine; i++ {
				_ = c.SeenOrAdd("jti-"+strconv.Itoa(gID)+"-"+strconv.Itoa(i), time.Minute)
			}
		}(g)
	}
	wg.Wait()
	// 50 * 50 = 2500 entries, but cap is 1024 — LRU should have
	// pruned us back down to 1024 exactly.
	if got := c.Len(); got != 1024 {
		t.Errorf("Len after concurrent inserts = %d, want 1024", got)
	}
}

func TestVerifier_MissingJTIRejectedWhenReplayEnabled(t *testing.T) {
	// Manually mint a token WITHOUT a jti — simulates an upstream
	// rolled back to a pre-jti Talon while the verifier already
	// enabled replay protection. Verifier MUST reject as malformed.
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	jwksURL, _ := jwksTestServer(t, signer)
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://auth.ops",
		ExpectedAudience: "a",
		ReplayCacheSize:  16,
	})

	// Mint a token directly via jose without going through Sign so we
	// can omit jti. (Sign always sets jti now.)
	noJTI := mintTokenWithoutJTI(t, signer, "a")
	_, err := v.VerifyToken(context.Background(), noJTI)
	if !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("got %v, want ErrTokenMalformed (no-jti rejection)", err)
	}
}

// mintTokenWithoutJTI builds a JWT via jose's claim API directly,
// bypassing Sign() so the jti claim is intentionally absent.
func mintTokenWithoutJTI(t *testing.T, s *Signer, audience string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := IdentityClaims{
		Issuer: "https://auth.ops", Subject: "u", Audience: audience,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		// JTI deliberately omitted.
	}
	tok, err := signClaimsViaJose(s, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// countingReplayCache records SeenOrAdd invocation count for the
// custom-cache test. Always reports NOT seen (so first verify passes).
type countingReplayCache struct {
	calls atomic.Int32
}

func (c *countingReplayCache) SeenOrAdd(_ string, _ time.Duration) bool {
	c.calls.Add(1)
	return false
}

