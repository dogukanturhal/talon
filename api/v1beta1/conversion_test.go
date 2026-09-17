// SPDX-License-Identifier: AGPL-3.0-or-later

package v1beta1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
)

// TestRoundTrip_V1alpha1_to_V1beta1_to_V1alpha1 locks the
// "v1alpha1 → v1beta1 → v1alpha1 = identity" property required by
// the Phase 6a acceptance criteria. Every v1alpha1 policy field
// must round-trip through v1beta1's nested DefaultPolicy without
// loss. PathRules cannot be reached from v1alpha1, so the empty
// PathRules slice on the v1beta1 intermediate is the canonical
// non-state.
func TestRoundTrip_V1alpha1_to_V1beta1_to_V1alpha1(t *testing.T) {
	original := v1alpha1.TalonRouteSpec{
		Host: "internal.example.com",
		Upstream: v1alpha1.Upstream{
			Service: "kube-prometheus-stack-prometheus",
			Port:    9090,
			Scheme:  "http",
		},
		Permission:                v1alpha1.PermissionViewer,
		AllowedGroups:             []string{"platform_admin", "platform_sre"},
		AllowedSubjects:           []string{"00000000-0000-0000-0000-000000000001"},
		SessionTTLOverride:        14400,
		SessionIdleSeconds:        1800,
		ReauthOnNetworkChange:     true,
		RequireDeviceClaims: []v1alpha1.DeviceClaimRequirement{
			{Claim: "device_compliant", Equals: "true"},
			{Claim: "device_managed_by_mdm", Equals: "true"},
		},
		PublicPaths: []v1alpha1.PublicRoute{
			{Method: "POST", Path: "/device-cert/attest"},
			{Method: "GET", Path: "/healthz"},
		},
		AuditOnly:                  false,
		ContinuousVerifyMinutes:    30,
		MfaRequired:                true,
		PolicyRego:                 "package talon.route\ndefault allow := true",
		InjectAuthorizationBearer:  true,
		RequireSignedIdentityToken: true,
		AuthMode:                   "bearer_or_basic_with_credential_exchange",
	}

	up := FromV1alpha1Spec(original)
	down := ToV1alpha1Spec(up)

	if !reflect.DeepEqual(original, down) {
		t.Fatalf("v1alpha1 → v1beta1 → v1alpha1 NOT identity\nwant=%#v\ngot =%#v", original, down)
	}
}

// TestRoundTrip_V1beta1_NoPathRules_to_V1alpha1_to_V1beta1 locks the
// inverse property for the subset of v1beta1 that v1alpha1 can
// represent (everything except PathRules + AcrValues). When pathRules
// is empty + acrValues is nil, the round-trip is identity.
func TestRoundTrip_V1beta1_NoPathRules_to_V1alpha1_to_V1beta1(t *testing.T) {
	original := TalonRouteSpec{
		Host: "github.com",
		Upstream: Upstream{Service: "gitlab", Port: 80, Scheme: "http"},
		DefaultPolicy: Policy{
			AuthMode:              "bearer_or_basic_with_credential_exchange",
			Permission:            PermissionViewer,
			AllowedGroups:         []string{"hexxlock_employees"},
			SessionTTLOverride:    14400,
			SessionIdleSeconds:    1800,
			ReauthOnNetworkChange: true,
			MfaRequired:           false,
		},
		PublicPaths: []PublicRoute{
			{Method: "POST", Path: "/device-cert/attest"},
		},
		// PathRules intentionally empty
	}

	down := ToV1alpha1Spec(original)
	up := FromV1alpha1Spec(down)

	if !reflect.DeepEqual(original, up) {
		t.Fatalf("v1beta1 (no pathRules) → v1alpha1 → v1beta1 NOT identity\nwant=%#v\ngot =%#v", original, up)
	}
}

// TestDownConvert_DropsPathRules locks the documented data-loss
// behaviour: a v1beta1 with non-empty pathRules down-converts to
// v1alpha1 with no pathRules (v1alpha1 has no such field). The
// pathRules + acrValues drops are by design — see ToV1alpha1Spec
// doc comment for the rationale.
func TestDownConvert_DropsPathRules(t *testing.T) {
	in := TalonRouteSpec{
		Host:     "github.com",
		Upstream: Upstream{Service: "gitlab", Port: 80},
		DefaultPolicy: Policy{
			AuthMode:   "cookie",
			Permission: PermissionViewer,
			AcrValues:  []string{"urn:hexxlock:acr:mfa"},
		},
		PathRules: []PathRule{
			{
				Name: "admin-mfa",
				Match: PathRuleMatch{
					PathPrefix: []string{"/admin/"},
				},
				Policy: Policy{
					MfaRequired: true,
					AcrValues:   []string{"urn:hexxlock:acr:mfa-yubikey"},
				},
			},
		},
	}

	down := ToV1alpha1Spec(in)

	// Spec fields v1alpha1 CAN represent should be preserved.
	if down.Host != in.Host {
		t.Errorf("Host: want %q, got %q", in.Host, down.Host)
	}
	if string(down.Permission) != string(in.DefaultPolicy.Permission) {
		t.Errorf("Permission: want %q, got %q", in.DefaultPolicy.Permission, down.Permission)
	}
	if down.AuthMode != in.DefaultPolicy.AuthMode {
		t.Errorf("AuthMode: want %q, got %q", in.DefaultPolicy.AuthMode, down.AuthMode)
	}
	// Re-up-converting the v1alpha1 spec should produce NO pathRules
	// + NO acrValues (the canonical CRD-versioning loss).
	reup := FromV1alpha1Spec(down)
	if len(reup.PathRules) != 0 {
		t.Errorf("PathRules should drop on v1beta1→v1alpha1→v1beta1; got %d", len(reup.PathRules))
	}
	if reup.DefaultPolicy.AcrValues != nil {
		t.Errorf("DefaultPolicy.AcrValues should drop on v1beta1→v1alpha1→v1beta1; got %v", reup.DefaultPolicy.AcrValues)
	}
}

// TestFromV1alpha1_FullCR locks the full-object conversion path —
// metadata + status both copy verbatim; only Spec is reshaped.
func TestFromV1alpha1_FullCR(t *testing.T) {
	in := &v1alpha1.TalonRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "TalonRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-ops",
			Namespace: "monitoring",
			Labels:    map[string]string{"app.kubernetes.io/part-of": "hexxlock-platform"},
		},
		Spec: v1alpha1.TalonRouteSpec{
			Host:       "internal.example.com",
			Upstream:   v1alpha1.Upstream{Service: "kube-prometheus-stack-prometheus", Port: 9090},
			Permission: v1alpha1.PermissionViewer,
		},
		Status: v1alpha1.TalonRouteStatus{
			ObservedGeneration: 7,
			UpstreamReachable:  true,
			Conditions: []metav1.Condition{
				{
					Type:    v1alpha1.ConditionRegistered,
					Status:  metav1.ConditionTrue,
					Reason:  v1alpha1.ReasonProxyHandlerInstalled,
					Message: "handler installed",
				},
			},
		},
	}

	out := FromV1alpha1(in)

	if out.APIVersion != GroupVersion.String() {
		t.Errorf("APIVersion: want %q, got %q", GroupVersion.String(), out.APIVersion)
	}
	if out.Kind != "TalonRoute" {
		t.Errorf("Kind: want TalonRoute, got %q", out.Kind)
	}
	if out.Name != in.Name {
		t.Errorf("Name: want %q, got %q", in.Name, out.Name)
	}
	if out.Namespace != in.Namespace {
		t.Errorf("Namespace: want %q, got %q", in.Namespace, out.Namespace)
	}
	if out.Status.ObservedGeneration != 7 {
		t.Errorf("ObservedGeneration: want 7, got %d", out.Status.ObservedGeneration)
	}
	if len(out.Status.Conditions) != 1 {
		t.Errorf("Conditions: want 1, got %d", len(out.Status.Conditions))
	}
	if out.Spec.Host != "internal.example.com" {
		t.Errorf("Spec.Host did not survive conversion: %q", out.Spec.Host)
	}
}

// TestDeepCopy_PathRulesIndependent verifies that DeepCopy on a
// v1beta1 TalonRoute produces an independent PathRules slice that
// can be mutated without affecting the original. Catches the
// classic "shared backing array" bug that the auto-generated
// DeepCopy would catch but hand-written code can miss.
func TestDeepCopy_PathRulesIndependent(t *testing.T) {
	in := &TalonRoute{
		Spec: TalonRouteSpec{
			Host: "x.hexxlock.com",
			PathRules: []PathRule{
				{Name: "r1", Match: PathRuleMatch{Path: "/a"}},
				{Name: "r2", Match: PathRuleMatch{PathPrefix: []string{"/b/"}}},
			},
		},
	}
	out := in.DeepCopy()

	// Mutate the original; expect the copy untouched.
	in.Spec.PathRules[0].Name = "MUTATED"
	in.Spec.PathRules[1].Match.PathPrefix[0] = "MUTATED"

	if out.Spec.PathRules[0].Name != "r1" {
		t.Errorf("DeepCopy did not isolate PathRules[0].Name: %q", out.Spec.PathRules[0].Name)
	}
	if out.Spec.PathRules[1].Match.PathPrefix[0] != "/b/" {
		t.Errorf("DeepCopy did not isolate PathRules[1].Match.PathPrefix: %q", out.Spec.PathRules[1].Match.PathPrefix[0])
	}
}
