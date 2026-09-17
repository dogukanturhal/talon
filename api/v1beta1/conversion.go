// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1beta1 — conversion between v1alpha1 and v1beta1 TalonRoute.
//
// The conversion preserves the operator's authoring shape across both
// served versions: a v1alpha1 CR up-converted to v1beta1 round-trips
// identically when down-converted again. A v1beta1 CR with non-empty
// pathRules down-converts to v1alpha1 by DROPPING the pathRules (the
// canonical CRD-versioning rule — fields absent from a target schema
// can't be preserved). Operators authoring v1beta1 features MUST
// expect the down-convert to lose pathRules; the runbook flag is
// documented in docs/operations/migrate-host.md when the migration
// lands.
//
// Hand-written (no kubebuilder/conversion-gen) per the project's
// avoid-codegen convention. The conversion is small + stable.
//
// Wire shape:
//   v1alpha1.TalonRouteSpec (flat) ⇄ v1beta1.TalonRouteSpec
//                                    { Host, Upstream, DefaultPolicy{...}, PathRules[] }
//
// Every v1alpha1 policy field maps to a v1beta1.DefaultPolicy.<same-name>
// field; the up-convert is a 1:1 copy into the nested struct.
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
)

// FromV1alpha1Spec builds a v1beta1.TalonRouteSpec from a v1alpha1
// spec. The mapping is mechanical: Host + Upstream + the device-claim
// allow-list move verbatim; every policy field nests under
// DefaultPolicy; PathRules is left empty (v1alpha1 has no per-path
// concept).
func FromV1alpha1Spec(in v1alpha1.TalonRouteSpec) TalonRouteSpec {
	return TalonRouteSpec{
		Host: in.Host,
		Upstream: Upstream{
			Service: in.Upstream.Service,
			Port:    in.Upstream.Port,
			Scheme:  in.Upstream.Scheme,
		},
		DefaultPolicy: Policy{
			AuthMode:                   in.AuthMode,
			Permission:                 PermissionLevel(in.Permission),
			AllowedGroups:              cloneStringSlice(in.AllowedGroups),
			AllowedSubjects:            cloneStringSlice(in.AllowedSubjects),
			MfaRequired:                in.MfaRequired,
			AcrValues:                  nil, // v1alpha1 has no acrValues — defaults to nil
			SessionTTLOverride:         in.SessionTTLOverride,
			SessionIdleSeconds:         in.SessionIdleSeconds,
			ReauthOnNetworkChange:      in.ReauthOnNetworkChange,
			RequireDeviceClaims:        cloneDeviceClaims(in.RequireDeviceClaims),
			AuditOnly:                  in.AuditOnly,
			ContinuousVerifyMinutes:    in.ContinuousVerifyMinutes,
			PolicyRego:                 in.PolicyRego,
			InjectAuthorizationBearer:  in.InjectAuthorizationBearer,
			RequireSignedIdentityToken: in.RequireSignedIdentityToken,
		},
		// PublicPaths is a top-level field in both versions (not nested
		// in DefaultPolicy) — carry it verbatim so the carve-out
		// survives a round-trip.
		PublicPaths: clonePublicRoutes(in.PublicPaths),
		// PathRules intentionally empty — v1alpha1 cannot express them.
	}
}

// ToV1alpha1Spec flattens a v1beta1 spec back to v1alpha1 shape. The
// pathRules slice is DISCARDED (v1alpha1 has no such field); callers
// that need to preserve it must store v1beta1 directly. The discard
// is by design — every CRD-versioning model (Kubernetes built-ins,
// kubebuilder docs, Argo CD's CRD conversion guide) treats this as
// the load-bearing rule: target schema dictates what's preserved.
//
// When the active downstream consumer is v1alpha1-only (the existing
// reconciler in this MR), down-converting a v1beta1 CR with non-empty
// pathRules loses the per-path policy — the reconciler treats the
// route as host-wide-only. That's the safe degradation: nothing
// silently grants access; missing pathRules just means
// DefaultPolicy applies to every request.
func ToV1alpha1Spec(in TalonRouteSpec) v1alpha1.TalonRouteSpec {
	return v1alpha1.TalonRouteSpec{
		Host: in.Host,
		Upstream: v1alpha1.Upstream{
			Service: in.Upstream.Service,
			Port:    in.Upstream.Port,
			Scheme:  in.Upstream.Scheme,
		},
		AuthMode:        in.DefaultPolicy.AuthMode,
		Permission:      v1alpha1.PermissionLevel(in.DefaultPolicy.Permission),
		AllowedGroups:   cloneStringSlice(in.DefaultPolicy.AllowedGroups),
		AllowedSubjects: cloneStringSlice(in.DefaultPolicy.AllowedSubjects),
		MfaRequired:     in.DefaultPolicy.MfaRequired,
		// AcrValues silently dropped — v1alpha1 has no such field. The
		// step-up behaviour falls back to the v1alpha1 default (require
		// amr=mfa, redirect-to-/auth/start).
		SessionTTLOverride:         in.DefaultPolicy.SessionTTLOverride,
		SessionIdleSeconds:         in.DefaultPolicy.SessionIdleSeconds,
		ReauthOnNetworkChange:      in.DefaultPolicy.ReauthOnNetworkChange,
		RequireDeviceClaims:        fromV1beta1DeviceClaims(in.DefaultPolicy.RequireDeviceClaims),
		AuditOnly:                  in.DefaultPolicy.AuditOnly,
		ContinuousVerifyMinutes:    in.DefaultPolicy.ContinuousVerifyMinutes,
		PolicyRego:                 in.DefaultPolicy.PolicyRego,
		InjectAuthorizationBearer:  in.DefaultPolicy.InjectAuthorizationBearer,
		RequireSignedIdentityToken: in.DefaultPolicy.RequireSignedIdentityToken,
		// PublicPaths is a top-level field in both versions — flatten it
		// back verbatim so the carve-out survives a round-trip.
		PublicPaths: fromV1beta1PublicRoutes(in.PublicPaths),
	}
}

// FromV1alpha1 builds a complete v1beta1.TalonRoute from a v1alpha1
// CR. ObjectMeta + TypeMeta + Status all copy verbatim; only Spec is
// shape-transformed.
func FromV1alpha1(in *v1alpha1.TalonRoute) *TalonRoute {
	out := &TalonRoute{
		TypeMeta:   in.TypeMeta,
		ObjectMeta: *in.ObjectMeta.DeepCopy(),
		Spec:       FromV1alpha1Spec(in.Spec),
		Status: TalonRouteStatus{
			ObservedGeneration: in.Status.ObservedGeneration,
			UpstreamReachable:  in.Status.UpstreamReachable,
		},
	}
	if in.Status.Conditions != nil {
		out.Status.Conditions = append(make([]metav1.Condition, 0, len(in.Status.Conditions)), in.Status.Conditions...)
	}
	// Stamp the version-pivot in TypeMeta so consumers (and the
	// API server's status round-trip) reflect the post-conversion
	// version. Group is unchanged across versions.
	out.APIVersion = GroupVersion.String()
	out.Kind = "TalonRoute"
	return out
}

// ToV1alpha1 flattens a v1beta1 CR back to v1alpha1. ObjectMeta +
// Status copy verbatim. PathRules are dropped per the comment on
// ToV1alpha1Spec.
func ToV1alpha1(in *TalonRoute) *v1alpha1.TalonRoute {
	out := &v1alpha1.TalonRoute{
		TypeMeta:   in.TypeMeta,
		ObjectMeta: *in.ObjectMeta.DeepCopy(),
		Spec:       ToV1alpha1Spec(in.Spec),
		Status: v1alpha1.TalonRouteStatus{
			ObservedGeneration: in.Status.ObservedGeneration,
			UpstreamReachable:  in.Status.UpstreamReachable,
		},
	}
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]metav1.Condition(nil), in.Status.Conditions...)
	}
	out.APIVersion = v1alpha1.GroupVersion.String()
	out.Kind = "TalonRoute"
	return out
}

// --- helpers --------------------------------------------------------

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

func cloneDeviceClaims(in []v1alpha1.DeviceClaimRequirement) []DeviceClaimRequirement {
	if in == nil {
		return nil
	}
	out := make([]DeviceClaimRequirement, 0, len(in))
	for _, c := range in {
		out = append(out, DeviceClaimRequirement{Claim: c.Claim, Equals: c.Equals})
	}
	return out
}

func fromV1beta1DeviceClaims(in []DeviceClaimRequirement) []v1alpha1.DeviceClaimRequirement {
	if in == nil {
		return nil
	}
	out := make([]v1alpha1.DeviceClaimRequirement, 0, len(in))
	for _, c := range in {
		out = append(out, v1alpha1.DeviceClaimRequirement{Claim: c.Claim, Equals: c.Equals})
	}
	return out
}

func clonePublicRoutes(in []v1alpha1.PublicRoute) []PublicRoute {
	if in == nil {
		return nil
	}
	out := make([]PublicRoute, 0, len(in))
	for _, p := range in {
		out = append(out, PublicRoute{Method: p.Method, Path: p.Path})
	}
	return out
}

func fromV1beta1PublicRoutes(in []PublicRoute) []v1alpha1.PublicRoute {
	if in == nil {
		return nil
	}
	out := make([]v1alpha1.PublicRoute, 0, len(in))
	for _, p := range in {
		out = append(out, v1alpha1.PublicRoute{Method: p.Method, Path: p.Path})
	}
	return out
}
