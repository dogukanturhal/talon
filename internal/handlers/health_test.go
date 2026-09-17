// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// markReadyAndSkipRedis primes a Health for the IAP-probe paths under
// test: OIDC discovery flag set + lastReady within the 30s cache so
// the redis ping is skipped (we don't carry a redis mock in this
// package). The IAP probe is what we're exercising.
func markReadyAndSkipRedis(h *Health) {
	h.MarkReady()
	h.lastReady.Store(time.Now().Unix())
}

func TestReadiness_NoIAPProbe_RemainsReady(t *testing.T) {
	h := &Health{}
	markReadyAndSkipRedis(h)
	rr := httptest.NewRecorder()
	h.Readiness(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no IAP probe wired, unrelated to readiness)", rr.Code)
	}
}

func TestReadiness_IAPProbeOK_ReportsReady(t *testing.T) {
	h := &Health{}
	markReadyAndSkipRedis(h)
	h.SetIAPHealthCheck(func() error { return nil })
	rr := httptest.NewRecorder()
	h.Readiness(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "ready") {
		t.Errorf("body = %q, want 'ready'", rr.Body.String())
	}
}

func TestReadiness_IAPProbeFails_503WithReason(t *testing.T) {
	h := &Health{}
	markReadyAndSkipRedis(h)
	h.SetIAPHealthCheck(func() error {
		return errors.New("synthetic verify failed: signature_invalid")
	})
	rr := httptest.NewRecorder()
	h.Readiness(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (IAP probe failure must pull pod out of rotation)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "iap signer unhealthy") {
		t.Errorf("503 body should mention 'iap signer unhealthy', got %q", rr.Body.String())
	}
	// The actual error message must reach the body so ops can see it.
	if !strings.Contains(rr.Body.String(), "signature_invalid") {
		t.Errorf("503 body should carry the underlying error, got %q", rr.Body.String())
	}
}

func TestReadiness_IAPProbeClearedToNil(t *testing.T) {
	h := &Health{}
	markReadyAndSkipRedis(h)
	h.SetIAPHealthCheck(func() error { return errors.New("transient") })
	// Operator opts out (e.g. an emergency Phase A fallback) by clearing.
	h.SetIAPHealthCheck(nil)
	rr := httptest.NewRecorder()
	h.Readiness(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("clearing the probe should restore the previous 200 path, got %d", rr.Code)
	}
}

func TestLiveness_AlwaysOK(t *testing.T) {
	// Liveness is decoupled from readiness — IAP signer state must not
	// affect /healthz (we never want kubelet to RESTART the pod on
	// IAP misconfig; readiness pulls it out of rotation, that's enough).
	h := &Health{}
	h.SetIAPHealthCheck(func() error { return errors.New("broken") })
	rr := httptest.NewRecorder()
	h.Liveness(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("Liveness should always be 200 even when IAP probe fails, got %d", rr.Code)
	}
}
