// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/dogukanturhal/talon/internal/caep"
)

func TestIsCompliant(t *testing.T) {
	cases := []struct {
		name     string
		compl    map[string]any
		required []string
		want     bool
	}{
		{"no baseline → always compliant", map[string]any{"x": false}, nil, true},
		{"single key true", map[string]any{"disk_encryption": true}, []string{"disk_encryption"}, true},
		{"single key false", map[string]any{"disk_encryption": false}, []string{"disk_encryption"}, false},
		{"key missing", map[string]any{"other": true}, []string{"disk_encryption"}, false},
		{"key non-bool", map[string]any{"disk_encryption": "yes"}, []string{"disk_encryption"}, false},
		{"all of several true", map[string]any{"a": true, "b": true}, []string{"a", "b"}, true},
		{"one of several false", map[string]any{"a": true, "b": false}, []string{"a", "b"}, false},
		{"nil compliance map", nil, []string{"a"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCompliant(tc.compl, tc.required); got != tc.want {
				t.Fatalf("isCompliant(%v, %v) = %v, want %v", tc.compl, tc.required, got, tc.want)
			}
		})
	}
}

func TestComplianceTracker_Observe(t *testing.T) {
	tr := newComplianceTracker()

	// First observation establishes a baseline and never reports a change.
	if tr.observe("dev-1", true) {
		t.Fatal("first observation must not report a change")
	}
	// Same status → no change.
	if tr.observe("dev-1", true) {
		t.Fatal("repeated same status must not report a change")
	}
	// Transition compliant→not → change.
	if !tr.observe("dev-1", false) {
		t.Fatal("compliant→not-compliant must report a change")
	}
	// Stays not-compliant → no change.
	if tr.observe("dev-1", false) {
		t.Fatal("repeated not-compliant must not report a change")
	}
	// Transition back → change.
	if !tr.observe("dev-1", true) {
		t.Fatal("not-compliant→compliant must report a change")
	}
	// A different device tracks independently (its first obs = no change).
	if tr.observe("dev-2", false) {
		t.Fatal("a different device's first observation must not report a change")
	}
}

// fakeSETSigner is a no-Vault caep.Signer for the emit-path test. It does
// not produce a verifiable signature — the capture receiver below only
// records the delivered body, it does not verify it.
type fakeSETSigner struct{}

func (fakeSETSigner) SignSET(_ context.Context, claims caep.SETClaims) (string, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return "h." + base64.RawURLEncoding.EncodeToString(b) + ".sig", nil
}

// serverWithCAEP builds a Server wired to a CAEP transmitter that pushes to
// a capture receiver. Returns the server and a channel that receives each
// delivered SET body. Only the maybeEmitComplianceChange path is exercised,
// so Issuer/Nonces/DeviceVerifier/Metrics are intentionally nil.
func serverWithCAEP(t *testing.T, requiredKeys []string) (*Server, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 8)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		got <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(recv.Close)

	tx, err := caep.NewTransmitter(caep.TransmitterConfig{
		SetIssuer:     "https://posture.example.com",
		SubjectIssuer: "https://id.example.com",
		Audience:      "https://auth.internal.example.com",
		ReceiverURL:   recv.URL,
	}, fakeSETSigner{})
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	s := NewServer(ServerConfig{
		Logger:                 zaptest.NewLogger(t),
		CAEP:                   tx,
		RequiredComplianceKeys: requiredKeys,
	})
	// Drain in-flight CAEP emission goroutines before the test returns.
	// They log through zaptest into t, and testing panics (or races) if
	// that happens after the test function has completed.
	t.Cleanup(s.Close)
	return s, got
}

func TestMaybeEmitComplianceChange_NoCAEP_NoOp(t *testing.T) {
	// CAEP disabled (nil transmitter) → no panic, no emission.
	s := NewServer(ServerConfig{
		Logger:                 zaptest.NewLogger(t),
		RequiredComplianceKeys: []string{"disk_encryption"},
	})
	s.maybeEmitComplianceChange(&HeartbeatRequest{
		DeviceUUID: "dev-1", UserSub: "user-1",
		Compliance: map[string]any{"disk_encryption": false},
	})
	// Nothing to assert beyond "did not panic" — the nil-guard returned early.
}

func TestMaybeEmitComplianceChange_EmitsOnTransitionOnly(t *testing.T) {
	s, got := serverWithCAEP(t, []string{"disk_encryption"})

	mk := func(compliant bool) *HeartbeatRequest {
		return &HeartbeatRequest{
			DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
			UserSub:    "user-1",
			Compliance: map[string]any{"disk_encryption": compliant},
		}
	}

	assertNoEmit := func(label string) {
		select {
		case body := <-got:
			t.Fatalf("%s: unexpected CAEP emission: %s", label, body)
		case <-time.After(150 * time.Millisecond):
		}
	}
	assertEmit := func(label, wantStatus string) {
		select {
		case body := <-got:
			// The receiver gets a compact JWS (header.payload.sig); decode
			// the payload before asserting on its contents.
			parts := strings.Split(string(body), ".")
			if len(parts) < 2 {
				t.Fatalf("%s: malformed SET: %s", label, body)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("%s: payload decode: %v", label, err)
			}
			if !strings.Contains(string(payload), wantStatus) {
				t.Fatalf("%s: emitted SET missing %q: %s", label, wantStatus, payload)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: expected a CAEP emission, got none", label)
		}
	}

	// First observation (compliant) → baseline, no emit.
	s.maybeEmitComplianceChange(mk(true))
	assertNoEmit("first observation")

	// Transition compliant→not → emit not-compliant.
	s.maybeEmitComplianceChange(mk(false))
	assertEmit("compliant→not", `"current_level":"not-compliant"`)

	// Same status again → no emit.
	s.maybeEmitComplianceChange(mk(false))
	assertNoEmit("repeated not-compliant")

	// Transition back → emit compliant.
	s.maybeEmitComplianceChange(mk(true))
	assertEmit("not→compliant", `"current_level":"compliant"`)
}
