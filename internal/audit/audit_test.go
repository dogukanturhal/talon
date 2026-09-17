// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
)

// TestNewDualEmitsChainStream pins the ADR 0031 dual-emit contract for the
// half that this MR adds: every Emit produces ONE chain.JSONLChain line
// with seq + prev_hash, hash-chained per NIST AU-9. The slog stream lives
// on its own path through tlog.From(ctx) and is asserted by existing
// integration tests; this unit test isolates the chain-side guarantee.
func TestNewDualEmitsChainStream(t *testing.T) {
	var chainBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	e := NewDual(logger, "v0.0.0-test", &chainBuf)

	for i := 0; i < 3; i++ {
		e.Emit(context.Background(), Record{
			Event: EventRequestAllow,
			Sub:   "test-sub",
			Route: "internal.example.com",
		})
	}

	chainLines := bytes.Split(bytes.TrimRight(chainBuf.Bytes(), "\n"), []byte("\n"))
	if len(chainLines) != 3 {
		t.Fatalf("chain stream: want 3 lines, got %d", len(chainLines))
	}

	// Chain integrity: each emitted line must record the SHA-256 of the
	// previous emitted line (matches Jess's algorithm exactly).
	prev := ""
	for i, ln := range chainLines {
		var rec Record
		if err := json.Unmarshal(ln, &rec); err != nil {
			t.Fatalf("chain line %d: %v", i, err)
		}
		if rec.Seq != uint64(i) {
			t.Errorf("chain line %d: seq = %d, want %d", i, rec.Seq, i)
		}
		if rec.PrevHash != prev {
			t.Errorf("chain line %d: prev_hash = %q, want %q (chain broken)", i, rec.PrevHash, prev)
		}
		sum := sha256.Sum256(append(append([]byte{}, ln...), '\n'))
		prev = hex.EncodeToString(sum[:])
	}
}

// TestNewSkipsChainEmission proves the original New constructor stays
// chain-free — no surprises for callers that haven't opted into NewDual.
func TestNewSkipsChainEmission(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	e := New(logger, "v0.0.0-test")
	if e.chain != nil {
		t.Error("plain New must NOT configure a chain sink")
	}
}

// TestChainEmitErrorIsNonFatal proves a broken chain writer cannot crash
// the request path — the audit subsystem must never be the cause of a
// dropped Talon response.
func TestChainEmitErrorIsNonFatal(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	e := NewDual(logger, "v0.0.0-test", brokenWriter{})
	// Must not panic even though the chain sink errors on every write.
	e.Emit(context.Background(), Record{Event: EventRequestAllow, Sub: "test"})
}

type brokenWriter struct{}

func (brokenWriter) Write(_ []byte) (int, error) { return 0, io.ErrClosedPipe }
