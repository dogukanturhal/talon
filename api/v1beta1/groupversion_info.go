// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1beta1 — scheme registration for the second TalonRoute API
// version. v1beta1 adds per-path policy (pathRules) on top of the
// v1alpha1 per-host shape, and groups the existing per-host policy
// fields into a nested defaultPolicy struct for readability.
//
// Schema lifecycle follows ADR 0003: v1alpha1 stays SERVED + UNTOUCHED
// (no field deletion). v1beta1 is the new active-development surface;
// once it stabilises a future MR flips storage version and eventually
// retires v1alpha1 after the documented soak.
//
// Conversion between versions is hand-written in conversion.go (the
// project deliberately avoids the kubebuilder/controller-tools build
// dep — types are small and the round-trip is straightforward).
//
// +groupName=gateway.talon.hexxlock.com
package v1beta1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is group version used to register these objects.
var GroupVersion = schema.GroupVersion{Group: "gateway.talon.hexxlock.com", Version: "v1beta1"}

// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the types in this group-version to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&TalonRoute{}, &TalonRouteList{})
}
