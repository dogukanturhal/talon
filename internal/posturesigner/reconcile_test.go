// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// ------------------------------------------------------------------
// Reconcile test helpers (reuse the server_test.go serverFixture/PKI)
// ------------------------------------------------------------------

// historicalReport builds a HeartbeatRequest whose iat is 2h in the PAST —
// stale enough that the live /v1/sign-posture clock-skew gate would reject it.
// Accepting it on the reconcile path is the whole point of the endpoint.
func historicalReport(deviceUUID string) HeartbeatRequest {
	return HeartbeatRequest{
		DeviceUUID: deviceUUID,
		Tier:       TierCorp,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IAT:        time.Now().Add(-2 * time.Hour).Unix(),
		Compliance: map[string]any{"disk_encrypted": true},
	}
}

// staleCapturedAt is an RFC3339 timestamp 2h in the past (real offline
// observation time).
func staleCapturedAt() string {
	return time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
}

// reconcileBody marshals a ReconcileRecord to the exact wire shape the agent
// POSTs ({seq, captured_at, report}).
func reconcileBody(t *testing.T, seq uint64, capturedAt string, report HeartbeatRequest) []byte {
	t.Helper()
	b, err := json.Marshal(ReconcileRecord{Seq: seq, CapturedAt: capturedAt, Report: report})
	if err != nil {
		t.Fatalf("marshal ReconcileRecord: %v", err)
	}
	return b
}

// doReconcile POSTs body to /v1/reconcile-posture. certUUID selects the device
// SPIFFE SAN the presented client cert encodes ("" = present no client cert);
// it is independent of the body so the SAN-mismatch case can be exercised.
func (f *serverFixture) doReconcile(t *testing.T, body []byte, certUUID string) *http.Response {
	t.Helper()
	var cl *http.Client
	if certUUID != "" {
		cl = f.clientWithCert(f.pki.tlsCertFor(t, certUUID))
	} else {
		cl = f.clientWithoutCert()
	}
	req, _ := http.NewRequest(http.MethodPost, f.httpSrv.URL+"/v1/reconcile-posture", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("doReconcile: %v", err)
	}
	return resp
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

// Accepts a valid historical record (stale iat + stale captured_at) → 202,
// and does NOT issue a JWS (no freshness/access granted; audit only).
func TestReconcile_AcceptsHistoricalRecord_NoJWS(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	body := reconcileBody(t, 1, staleCapturedAt(), historicalReport(uuid))
	resp := f.doReconcile(t, body, uuid)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("historical record: expected 202, got %d", resp.StatusCode)
	}

	var ack map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	// No JWS: the reconcile path records past state, it does not mint access.
	if _, ok := ack["jws"]; ok {
		t.Errorf("reconcile must NOT issue a JWS, body had jws: %v", ack)
	}
	if _, ok := ack["expires_at"]; ok {
		t.Errorf("reconcile must NOT issue an expiry, body had expires_at: %v", ack)
	}
	if ack["status"] != "accepted" {
		t.Errorf("expected status=accepted, got %v", ack["status"])
	}
}

// Rejects a record whose body device_uuid does not match the presented device
// cert's SPIFFE SAN → 403 (same fail-closed binding as the live path).
func TestReconcile_RejectsDeviceSANMismatch(t *testing.T) {
	f := newServerFixture(t)
	bodyUUID := "550e8400-e29b-41d4-a716-446655440000"
	certUUID := "660e8400-e29b-41d4-a716-446655440001"

	body := reconcileBody(t, 1, staleCapturedAt(), historicalReport(bodyUUID))
	// Present a cert for a DIFFERENT device than the record claims.
	resp := f.doReconcile(t, body, certUUID)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("device SAN mismatch: expected 403, got %d", resp.StatusCode)
	}
}

// No client certificate → 401 (fail closed on any auth doubt).
func TestReconcile_MissingDeviceCert_Unauthorized(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	body := reconcileBody(t, 1, staleCapturedAt(), historicalReport(uuid))
	resp := f.doReconcile(t, body, "" /* no cert */)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing device cert: expected 401, got %d", resp.StatusCode)
	}
}

// A retried flush of the same (device, seq) is idempotent: first lands 202
// (recorded), the replay returns 409 (accepted, NOT re-recorded).
func TestReconcile_IdempotentReplay(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	body := reconcileBody(t, 42, staleCapturedAt(), historicalReport(uuid))

	resp1 := f.doReconcile(t, body, uuid)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first flush: expected 202, got %d", resp1.StatusCode)
	}

	resp2 := f.doReconcile(t, body, uuid)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("replayed flush: expected 409, got %d", resp2.StatusCode)
	}
	var ack map[string]any
	json.NewDecoder(resp2.Body).Decode(&ack) //nolint:errcheck
	if ack["status"] != "duplicate" {
		t.Errorf("expected status=duplicate on replay, got %v", ack["status"])
	}
}

// A different seq for the same device is NOT a duplicate — each distinct
// spooled report is recorded once.
func TestReconcile_DistinctSeqNotDeduped(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	resp1 := f.doReconcile(t, reconcileBody(t, 1, staleCapturedAt(), historicalReport(uuid)), uuid)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("seq=1: expected 202, got %d", resp1.StatusCode)
	}
	resp2 := f.doReconcile(t, reconcileBody(t, 2, staleCapturedAt(), historicalReport(uuid)), uuid)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("seq=2: expected 202 (distinct seq), got %d", resp2.StatusCode)
	}
}

// Malformed JSON → 400.
func TestReconcile_MalformedJSON(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	resp := f.doReconcile(t, []byte(`{not json`), uuid)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: expected 400, got %d", resp.StatusCode)
	}
}

// An unknown wire field → 400 (DisallowUnknownFields keeps the agent contract
// tight, mirroring the live path).
func TestReconcile_UnknownField_Rejected(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	// Start from a valid record, then inject an unknown top-level field.
	valid := reconcileBody(t, 1, staleCapturedAt(), historicalReport(uuid))
	var m map[string]any
	if err := json.Unmarshal(valid, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["surprise"] = "reject me"
	body, _ := json.Marshal(m)

	resp := f.doReconcile(t, body, uuid)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field: expected 400, got %d", resp.StatusCode)
	}
}

// A non-RFC3339 captured_at → 400 (the observation time must be usable).
func TestReconcile_MalformedCapturedAt(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	body := reconcileBody(t, 1, "not-a-timestamp", historicalReport(uuid))
	resp := f.doReconcile(t, body, uuid)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed captured_at: expected 400, got %d", resp.StatusCode)
	}
}

// ValidateHistorical accepts a stale iat that Validate rejects, yet still
// enforces every other field-level check.
func TestValidateHistorical_SkipsFreshnessKeepsFieldChecks(t *testing.T) {
	stale := historicalReport("550e8400-e29b-41d4-a716-446655440000")

	// The live path rejects the 2h-old iat...
	if err := stale.Validate(time.Now()); err == nil {
		t.Fatal("Validate: expected stale-iat clock-skew rejection, got nil")
	}
	// ...but the historical path accepts it.
	if err := stale.ValidateHistorical(); err != nil {
		t.Fatalf("ValidateHistorical: expected stale iat accepted, got %v", err)
	}

	// Field checks still apply: bad UUID is rejected.
	bad := stale
	bad.DeviceUUID = "not-a-uuid"
	if err := bad.ValidateHistorical(); err == nil {
		t.Error("ValidateHistorical: expected device_uuid rejection")
	}

	// iat presence still required.
	noIAT := stale
	noIAT.IAT = 0
	if err := noIAT.ValidateHistorical(); err == nil {
		t.Error("ValidateHistorical: expected iat-required rejection")
	}
}

// GET is not allowed.
func TestReconcile_MethodNotAllowed(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	resp, err := cl.Get(f.httpSrv.URL + "/v1/reconcile-posture")
	if err != nil {
		t.Fatalf("GET /v1/reconcile-posture: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET reconcile: expected 405, got %d", resp.StatusCode)
	}
}
