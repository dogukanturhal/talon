// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNonceCache_FirstSeenAccepted(t *testing.T) {
	c := NewNonceCache()
	defer c.Stop()

	if !c.Accept("nonce-abc") {
		t.Fatal("first presentation of nonce should be accepted")
	}
}

func TestNonceCache_SecondSeenRejected(t *testing.T) {
	c := NewNonceCache()
	defer c.Stop()

	if !c.Accept("replay-nonce") {
		t.Fatal("first presentation should be accepted")
	}
	if c.Accept("replay-nonce") {
		t.Fatal("second presentation of same nonce within TTL should be rejected")
	}
}

func TestNonceCache_ExpiredThenResubmit_Accepted(t *testing.T) {
	// Use an injected clock so we can advance time past nonceTTL without
	// actually sleeping 10 minutes.
	var mu sync.Mutex
	fakeNow := time.Now()
	clockFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return fakeNow
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		fakeNow = fakeNow.Add(d)
	}

	c := newNonceCacheWithClock(clockFn)
	defer c.Stop()

	// Accept nonce initially.
	if !c.Accept("expiry-nonce") {
		t.Fatal("first presentation should be accepted")
	}
	// Still within TTL — must be rejected.
	if c.Accept("expiry-nonce") {
		t.Fatal("second presentation within TTL should be rejected")
	}

	// Advance clock past nonceTTL (10 minutes + 1 second).
	advance(nonceTTL + time.Second)

	// Now the stored entry is expired — Accept should overwrite + return true.
	if !c.Accept("expiry-nonce") {
		t.Fatal("resubmission after TTL expiry should be accepted")
	}
}

func TestNonceCache_Size(t *testing.T) {
	c := NewNonceCache()
	defer c.Stop()

	for i := range 5 {
		c.Accept(fmt.Sprintf("size-nonce-%d", i))
	}
	if s := c.Size(); s != 5 {
		t.Fatalf("expected size 5, got %d", s)
	}
}

func TestNonceCache_Concurrent_RaceDetector(t *testing.T) {
	// This test is intentionally racy in the "many goroutines hammer the
	// same nonce" sense — the race detector must NOT fire because the
	// implementation uses sync.Map. We race 100 goroutines all trying to
	// Accept the same nonce: exactly 1 must get true; 99 must get false.
	c := NewNonceCache()
	defer c.Stop()

	const workers = 100
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			results <- c.Accept("concurrent-nonce")
		}()
	}
	wg.Wait()
	close(results)

	var accepted int
	for r := range results {
		if r {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly 1 acceptance among %d concurrent goroutines, got %d", workers, accepted)
	}
}

func TestNonceCache_DifferentNoncesIndependent(t *testing.T) {
	c := NewNonceCache()
	defer c.Stop()

	// Each unique nonce must be independently accepted.
	for i := range 10 {
		nonce := fmt.Sprintf("independent-nonce-%d", i)
		if !c.Accept(nonce) {
			t.Fatalf("first presentation of nonce %q should be accepted", nonce)
		}
		if c.Accept(nonce) {
			t.Fatalf("second presentation of nonce %q should be rejected", nonce)
		}
	}
}

func TestNonceCache_GCSweep(t *testing.T) {
	var mu sync.Mutex
	fakeNow := time.Now()
	clockFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return fakeNow
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		fakeNow = fakeNow.Add(d)
	}

	c := newNonceCacheWithClock(clockFn)
	defer c.Stop()

	c.Accept("sweep-nonce-1")
	c.Accept("sweep-nonce-2")
	if c.Size() != 2 {
		t.Fatalf("expected 2 entries before GC, got %d", c.Size())
	}

	// Advance clock past TTL and manually trigger sweep.
	advance(nonceTTL + time.Second)
	c.sweep()

	if c.Size() != 0 {
		t.Fatalf("expected 0 entries after GC sweep, got %d", c.Size())
	}
}
