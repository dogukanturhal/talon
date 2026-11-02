// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeSigner struct {
	got     SETClaims
	compact string
	err     error
}

func (f *fakeSigner) SignSET(_ context.Context, c SETClaims) (string, error) {
	f.got = c
	if f.err != nil {
		return "", f.err
	}
	if f.compact == "" {
		f.compact = "hdr.payload.sig"
	}
	return f.compact, nil
}

func newTestTx(t *testing.T, s Signer) *Transmitter {
	t.Helper()
	tx, err := NewTransmitter(TransmitterConfig{
		SetIssuer:     "https://posture.example.com",
		SubjectIssuer: "https://id.example.com",
		Audience:      "https://auth.internal.example.com",
		ReceiverURL:   "https://auth.internal.example.com/caep/events",
	}, s)
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic for assertions.
	tx.now = func() time.Time { return time.Unix(1_717_000_000, 0) }
	tx.newJTI = func() string { return "jti-fixed-1" }
	return tx
}

func TestBuildSessionRevoked(t *testing.T) {
	tx := newTestTx(t, &fakeSigner{})
	set := tx.BuildSessionRevoked("user-123", "device de-provisioned")

	if set.Iss != "https://posture.example.com" {
		t.Errorf("iss=%q", set.Iss)
	}
	if !set.Aud.contains("https://auth.internal.example.com") {
		t.Errorf("aud=%v", set.Aud)
	}
	if set.JTI != "jti-fixed-1" || set.IAT != 1_717_000_000 {
		t.Errorf("jti=%q iat=%d", set.JTI, set.IAT)
	}
	ev, ok := set.Events[EventSessionRevoked]
	if !ok {
		t.Fatalf("missing session-revoked event; events=%v", set.Events)
	}
	if ev.Subject.Format != "iss_sub" || ev.Subject.Iss != "https://id.example.com" || ev.Subject.Sub != "user-123" {
		t.Errorf("subject=%+v (want iss_sub / Falcon-ID iss / user-123)", ev.Subject)
	}
	if ev.EventTimestamp != 1_717_000_000 {
		t.Errorf("event_timestamp=%d", ev.EventTimestamp)
	}
	if ev.ReasonAdmin["en"] != "device de-provisioned" {
		t.Errorf("reason=%v", ev.ReasonAdmin)
	}
}

func TestBuildDeviceComplianceChange(t *testing.T) {
	tx := newTestTx(t, &fakeSigner{})
	set := tx.BuildDeviceComplianceChange("user-123", "dev-uuid-9", false)
	ev, ok := set.Events[EventDeviceComplianceChange]
	if !ok {
		t.Fatalf("missing device-compliance-change; events=%v", set.Events)
	}
	if ev.CurrentLevel != "not-compliant" {
		t.Errorf("current_level=%q want not-compliant", ev.CurrentLevel)
	}
	if ev.Subject.Sub != "user-123" {
		t.Errorf("subject.sub=%q", ev.Subject.Sub)
	}
	if got := ev.ReasonAdmin["en"]; got != "device dev-uuid-9 is not-compliant" {
		t.Errorf("reason=%q", got)
	}
	// compliant=true flips the status.
	set2 := tx.BuildDeviceComplianceChange("u", "d", true)
	if set2.Events[EventDeviceComplianceChange].CurrentLevel != "compliant" {
		t.Errorf("compliant status not set")
	}
}

// A built SET must round-trip through the receiver's own SETClaims struct
// unchanged — proves the transmitter emits exactly what the receiver parses
// (single shared type, but this locks the JSON wire shape incl. aud + events).
func TestSET_WireRoundTrip(t *testing.T) {
	tx := newTestTx(t, &fakeSigner{})
	set := tx.BuildSessionRevoked("user-xyz", "test")
	raw, err := marshalSET(set)
	if err != nil {
		t.Fatal(err)
	}
	var back SETClaims
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("receiver-side unmarshal: %v", err)
	}
	if back.Iss != set.Iss || back.JTI != set.JTI {
		t.Errorf("envelope drift: %+v", back)
	}
	ev, ok := back.Events[EventSessionRevoked]
	if !ok || ev.Subject.Sub != "user-xyz" {
		t.Errorf("event drift: %+v", back.Events)
	}
	// aud serializes as a single string (RFC 7519), still parses back.
	if !back.Aud.contains("https://auth.internal.example.com") {
		t.Errorf("aud round-trip lost: %v", back.Aud)
	}
}

func TestEmit_PushDelivery(t *testing.T) {
	fs := &fakeSigner{compact: "aaa.bbb.ccc"}
	var gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted) // 202
	}))
	defer srv.Close()

	tx := newTestTx(t, fs)
	tx.cfg.ReceiverURL = srv.URL

	if err := tx.Emit(context.Background(), tx.BuildSessionRevoked("u", "r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if gotCT != "application/secevent+jwt" {
		t.Errorf("content-type=%q", gotCT)
	}
	if gotBody != "aaa.bbb.ccc" {
		t.Errorf("body=%q want the signed compact JWS", gotBody)
	}
}

func TestEmit_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	tx := newTestTx(t, &fakeSigner{compact: "x.y.z"})
	tx.cfg.ReceiverURL = srv.URL
	if err := tx.Emit(context.Background(), tx.BuildSessionRevoked("u", "")); err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestNewTransmitter_Validation(t *testing.T) {
	if _, err := NewTransmitter(TransmitterConfig{SetIssuer: "a", Audience: "b", ReceiverURL: "c"}, nil); err == nil {
		t.Error("nil signer should error")
	}
	if _, err := NewTransmitter(TransmitterConfig{}, &fakeSigner{}); err == nil {
		t.Error("missing config should error")
	}
}
