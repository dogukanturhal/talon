// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
	"testing"
)

// The k8s Phase 4 production backend is deliberately STUBBED: until the jess
// k8s broker (ADR 0049) is reachable from talon, Dial returns the documented
// "not wired" sentinel so a live session closes cleanly (1011) instead of
// hanging. The DB backend is now WIRED (jessdbbackend.go) — it fails closed
// with ErrDBBackendNotWired ONLY when the deploy has not supplied a controller
// operator address; see jessdbbackend_test.go for the wired-path contract.

func TestJessDBBackend_NotWiredWithoutControllerAddr(t *testing.T) {
	be := NewJessDBBackend(JessDBBackendConfig{}) // no ControllerAddr -> not wired at deploy
	_, err := be.Open(context.Background(), DBDialRequest{Engine: EnginePostgres, Target: "analytics"})
	if !errors.Is(err, ErrDBBackendNotWired) {
		t.Fatalf("Open err = %v, want ErrDBBackendNotWired", err)
	}
}

func TestJessK8sBackend_StubbedUntilWired(t *testing.T) {
	be := NewJessK8sBackend(JessK8sBackendConfig{BrokerAddr: "jess-k8s:443"})
	_, err := be.Dial(context.Background(), K8sDialRequest{Verb: VerbExec, Namespace: "prod", Pod: "api-0"})
	if !errors.Is(err, ErrK8sBackendNotWired) {
		t.Fatalf("Dial err = %v, want ErrK8sBackendNotWired", err)
	}
}

func TestValidDBEngine(t *testing.T) {
	for _, e := range []DBEngine{EnginePostgres, EngineMySQL} {
		if !validDBEngine(e) {
			t.Fatalf("engine %q should be valid", e)
		}
	}
	for _, e := range []DBEngine{"", "oracle", "mssql"} {
		if validDBEngine(e) {
			t.Fatalf("engine %q should be invalid", e)
		}
	}
}

func TestValidK8sVerb(t *testing.T) {
	for _, v := range []K8sVerb{VerbExec, VerbLogs} {
		if !validK8sVerb(v) {
			t.Fatalf("verb %q should be valid", v)
		}
	}
	for _, v := range []K8sVerb{"", "delete", "apply"} {
		if validK8sVerb(v) {
			t.Fatalf("verb %q should be invalid", v)
		}
	}
}
