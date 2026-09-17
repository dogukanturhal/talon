// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"testing"

	gatewayv1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// --- fixtures --------------------------------------------------------

func sampleRoute() *gatewayv1alpha1.TalonRoute {
	return &gatewayv1alpha1.TalonRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "talon",
			Name:      "mearax-prod",
		},
		Spec: gatewayv1alpha1.TalonRouteSpec{
			Host: "mearax.hexxlock.com",
			Upstream: gatewayv1alpha1.Upstream{
				Service: "mearax.example-platform",
				Port:    80,
			},
		},
	}
}

func sampleCfg() SecurityPolicyTranslatorConfig {
	return SecurityPolicyTranslatorConfig{
		Enabled:                  true,
		Namespace:                "envoy-gateway-system",
		ExtAuthzServiceName:      "talon-talon",
		ExtAuthzServiceNamespace: "talon",
		ExtAuthzPort:             9001,
		HTTPRouteNamespace:       "envoy-gateway-system",
	}
}

// --- DesiredSecurityPolicy tests ------------------------------------

func TestDesiredSecurityPolicy_BasicShape(t *testing.T) {
	sp := DesiredSecurityPolicy(sampleRoute(), sampleCfg())

	if got, want := sp.GetKind(), "SecurityPolicy"; got != want {
		t.Errorf("kind: got %q, want %q", got, want)
	}
	if got, want := sp.GetAPIVersion(), "gateway.envoyproxy.io/v1alpha1"; got != want {
		t.Errorf("apiVersion: got %q, want %q", got, want)
	}
	if got, want := sp.GetNamespace(), "envoy-gateway-system"; got != want {
		t.Errorf("namespace: got %q, want %q", got, want)
	}
	if got, want := sp.GetName(), "talon-talon-mearax-prod-securitypolicy"; got != want {
		t.Errorf("name: got %q, want %q", got, want)
	}
}

func TestDesiredSecurityPolicy_Labels(t *testing.T) {
	sp := DesiredSecurityPolicy(sampleRoute(), sampleCfg())
	labels := sp.GetLabels()
	checks := map[string]string{
		LabelManagedBy:      ManagedByValue,
		LabelOwnerNamespace: "talon",
		LabelOwnerName:      "mearax-prod",
		LabelOwnerHost:      "mearax.hexxlock.com",
	}
	for k, want := range checks {
		if got := labels[k]; got != want {
			t.Errorf("label %s: got %q, want %q", k, got, want)
		}
	}
}

func TestDesiredSecurityPolicy_TargetRefShape(t *testing.T) {
	sp := DesiredSecurityPolicy(sampleRoute(), sampleCfg())
	refs, found, err := unstructured.NestedSlice(sp.Object, "spec", "targetRefs")
	if err != nil || !found {
		t.Fatalf("targetRefs not found: err=%v found=%v", err, found)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 targetRef, got %d", len(refs))
	}
	ref := refs[0].(map[string]interface{})
	if ref["group"] != "gateway.networking.k8s.io" {
		t.Errorf("targetRef.group: %v", ref["group"])
	}
	if ref["kind"] != "HTTPRoute" {
		t.Errorf("targetRef.kind: %v", ref["kind"])
	}
	if ref["name"] != "mearax-hexxlock-com-prod" {
		t.Errorf("targetRef.name: %v (expected mearax-hexxlock-com-prod)", ref["name"])
	}
}

func TestDesiredSecurityPolicy_ExtAuthShape(t *testing.T) {
	sp := DesiredSecurityPolicy(sampleRoute(), sampleCfg())

	// failOpen: false (ADR 0010 invariant)
	failOpen, found, err := unstructured.NestedBool(sp.Object, "spec", "extAuth", "failOpen")
	if err != nil || !found {
		t.Fatalf("failOpen not found: err=%v found=%v", err, found)
	}
	if failOpen {
		t.Errorf("failOpen MUST be false per ADR 0010, got true")
	}

	// recomputeRoute: false
	recompute, found, err := unstructured.NestedBool(sp.Object, "spec", "extAuth", "recomputeRoute")
	if err != nil || !found {
		t.Fatalf("recomputeRoute not found")
	}
	if recompute {
		t.Errorf("recomputeRoute should be false (ext_authz shouldn't reshape routing), got true")
	}

	// grpc.backendRefs[0]
	backends, found, err := unstructured.NestedSlice(sp.Object, "spec", "extAuth", "grpc", "backendRefs")
	if err != nil || !found {
		t.Fatalf("grpc.backendRefs not found")
	}
	if len(backends) != 1 {
		t.Fatalf("expected 1 backendRef, got %d", len(backends))
	}
	be := backends[0].(map[string]interface{})
	if be["name"] != "talon-talon" {
		t.Errorf("backendRef.name: %v", be["name"])
	}
	if be["namespace"] != "talon" {
		t.Errorf("backendRef.namespace: %v", be["namespace"])
	}
	if be["port"] != int64(9001) {
		t.Errorf("backendRef.port: %v", be["port"])
	}
}

func TestSecurityPolicyName_NamespaceDisambiguation(t *testing.T) {
	// Two TalonRoutes in different namespaces but same name produce
	// different SecurityPolicy names — the owner-ns is part of the
	// SecurityPolicy name so collisions don't cross-bind.
	r1 := &gatewayv1alpha1.TalonRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "talon", Name: "foo"},
	}
	r2 := &gatewayv1alpha1.TalonRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "foo"},
	}
	if SecurityPolicyName(r1) == SecurityPolicyName(r2) {
		t.Errorf("two namespaces same name should disambiguate; both got %q", SecurityPolicyName(r1))
	}
}

func TestHTTPRouteNameForHost(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"mearax.hexxlock.com", "mearax-hexxlock-com-prod"},
		{"id.hexxlock.com", "id-hexxlock-com-prod"},
		{"webhooks.hexxlock.com", "webhooks-hexxlock-com-prod"},
		{"api.example.app", "api-example-app-prod"},
	}
	for _, c := range cases {
		if got := HTTPRouteNameForHost(c.host); got != c.want {
			t.Errorf("HTTPRouteNameForHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// --- EnsureSecurityPolicy / DeleteSecurityPolicy tests --------------

func TestEnsureSecurityPolicy_Disabled_NoOp(t *testing.T) {
	cfg := sampleCfg()
	cfg.Enabled = false
	// EnsureSecurityPolicy is no-op when disabled; passing a nil
	// client should not panic.
	if err := EnsureSecurityPolicy(t.Context(), nil, sampleRoute(), cfg); err != nil {
		t.Errorf("Enable=false should be a no-op, got %v", err)
	}
}

func TestEnsureSecurityPolicy_MissingConfig(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*SecurityPolicyTranslatorConfig)
	}{
		{"no-namespace", func(c *SecurityPolicyTranslatorConfig) { c.Namespace = "" }},
		{"no-extauthz-service", func(c *SecurityPolicyTranslatorConfig) { c.ExtAuthzServiceName = "" }},
		{"no-extauthz-ns", func(c *SecurityPolicyTranslatorConfig) { c.ExtAuthzServiceNamespace = "" }},
		{"no-port", func(c *SecurityPolicyTranslatorConfig) { c.ExtAuthzPort = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := sampleCfg()
			c.mut(&cfg)
			err := EnsureSecurityPolicy(t.Context(), nil, sampleRoute(), cfg)
			if err == nil {
				t.Errorf("expected config error for %s, got nil", c.name)
			}
		})
	}
}

func TestDeleteSecurityPolicy_Disabled_NoOp(t *testing.T) {
	cfg := sampleCfg()
	cfg.Enabled = false
	if err := DeleteSecurityPolicy(t.Context(), nil, sampleRoute(), cfg); err != nil {
		t.Errorf("Enable=false should be a no-op, got %v", err)
	}
}

// --- AcceptedConditionFromSecurityPolicy tests -----------------------

func spWithConditions(conds []map[string]interface{}) *unstructured.Unstructured {
	sp := &unstructured.Unstructured{}
	sp.Object = map[string]interface{}{
		"status": map[string]interface{}{
			"conditions": func() []interface{} {
				out := make([]interface{}, 0, len(conds))
				for _, c := range conds {
					out = append(out, c)
				}
				return out
			}(),
		},
	}
	return sp
}

func TestAcceptedCondition_NilSP(t *testing.T) {
	_, _, _, ok := AcceptedConditionFromSecurityPolicy(nil)
	if ok {
		t.Fatal("nil SP must report not-found")
	}
}

func TestAcceptedCondition_NoStatus(t *testing.T) {
	sp := &unstructured.Unstructured{Object: map[string]interface{}{}}
	_, _, _, ok := AcceptedConditionFromSecurityPolicy(sp)
	if ok {
		t.Fatal("SP without status.conditions must report not-found")
	}
}

func TestAcceptedCondition_OtherConditionsOnly(t *testing.T) {
	sp := spWithConditions([]map[string]interface{}{
		{"type": "Programmed", "status": "True", "reason": "Done"},
		{"type": "Synced", "status": "True", "reason": "Synced"},
	})
	_, _, _, ok := AcceptedConditionFromSecurityPolicy(sp)
	if ok {
		t.Fatal("SP without Accepted condition must report not-found")
	}
}

func TestAcceptedCondition_AcceptedTrue(t *testing.T) {
	sp := spWithConditions([]map[string]interface{}{
		{"type": "Accepted", "status": "True", "reason": "Accepted", "message": "policy translated"},
	})
	st, reason, msg, ok := AcceptedConditionFromSecurityPolicy(sp)
	if !ok {
		t.Fatal("Accepted condition must be found")
	}
	if st != "True" || reason != "Accepted" || msg != "policy translated" {
		t.Errorf("got %q/%q/%q", st, reason, msg)
	}
}

func TestAcceptedCondition_AcceptedFalseWithReason(t *testing.T) {
	sp := spWithConditions([]map[string]interface{}{
		{"type": "Accepted", "status": "False", "reason": "Invalid", "message": "extauth port missing"},
	})
	st, reason, msg, ok := AcceptedConditionFromSecurityPolicy(sp)
	if !ok {
		t.Fatal("expected found")
	}
	if st != "False" || reason != "Invalid" || msg != "extauth port missing" {
		t.Errorf("got %q/%q/%q", st, reason, msg)
	}
}

func TestAcceptedCondition_MalformedEntrySkipped(t *testing.T) {
	sp := &unstructured.Unstructured{}
	sp.Object = map[string]interface{}{
		"status": map[string]interface{}{
			"conditions": []interface{}{
				"not-a-map", // malformed
				map[string]interface{}{"type": "Accepted", "status": "True"},
			},
		},
	}
	st, _, _, ok := AcceptedConditionFromSecurityPolicy(sp)
	if !ok || st != "True" {
		t.Fatalf("malformed entry must be skipped; got found=%v st=%q", ok, st)
	}
}

// --- truncateMessage --------------------------------------------------

func TestTruncateMessage_Short(t *testing.T) {
	got := truncateMessage("short")
	if got != "short" {
		t.Fatalf("got %q", got)
	}
}

func TestTruncateMessage_Long(t *testing.T) {
	in := make([]byte, 2048)
	for i := range in {
		in[i] = 'a'
	}
	got := truncateMessage(string(in))
	if len(got) != 1024 {
		t.Fatalf("expected 1024, got %d", len(got))
	}
	if got[len(got)-3:] != "..." {
		t.Fatalf("expected trailing ellipsis, got %q", got[len(got)-3:])
	}
}
