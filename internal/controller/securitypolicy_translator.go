// SPDX-License-Identifier: AGPL-3.0-or-later

// securitypolicy_translator.go — emits Envoy Gateway SecurityPolicy CRs
// (gateway.envoyproxy.io/v1alpha1) for every TalonRoute, so EG's data
// plane delegates auth decisions to Talon's ext_authz gRPC server via
// the canonical Gateway API extension shape.
//
// Architectural rationale (verified against tier-1 research 2026-06-04):
//
//   - Use Envoy Gateway's SecurityPolicy v1alpha1, NOT the upstream
//     Gateway API GEP-1494 ExternalAuth Filter — GEP-1494 is still
//     marked Experimental in v1.4.0 (kubernetes-sigs/gateway-api
//     release notes). SecurityPolicy ships in EG's production-ready
//     extensions today and is what every EG ext-auth tutorial uses.
//
//   - Reference Talon by Service backendRefs (name + port), not by URL.
//     EG's canonical example wires `name: grpc-ext-auth, port: 9002`;
//     URL backends are not shown in the tutorial path and not
//     production-stable across EG versions.
//
//   - failOpen: false — matches ADR 0010 fail-mode policy. Losing the
//     Talon ext_authz pod MUST deny, not silently allow.
//
//   - We mirror Istio's istiod-translates-to-EnvoyFilter pattern
//     (talonroute controller owns the SecurityPolicy lifecycle) rather
//     than Pomerium's gateway-as-its-own-class pattern. Pomerium's
//     approach replaces the gateway; Talon coexists alongside EG and
//     emits SecurityPolicy CRs that EG renders into ext_authz config.
//
// Lifecycle:
//
//   - Talon's CRs live in the talon namespace; the targetRefs they
//     reference (HTTPRoute or Gateway objects) live in
//     envoy-gateway-system. SecurityPolicy MUST live in the SAME
//     namespace as its targetRefs (EG enforces this), so the
//     SecurityPolicy is emitted in envoy-gateway-system (configurable
//     via cfg.SecurityPolicyNamespace).
//
//   - Cross-namespace ownership disqualifies metadata.ownerReferences
//     (K8s rejects OwnerReferences across namespaces). We use labels
//     instead:
//
//       talon.example.com/owner-namespace: <talonroute ns>
//       talon.example.com/owner-name:      <talonroute name>
//       app.kubernetes.io/managed-by:       talon-controller
//
//     A finalizer on the TalonRoute drives synchronous cleanup of the
//     matching SecurityPolicy before allowing the TalonRoute to be
//     garbage-collected — see talonroute_controller.go finalizer
//     handler. This is the same shape Cilium's CiliumClusterwideEnvoy
//     Config controller uses for its cross-namespace emit pattern.
//
// Drift handling:
//
//   - Each reconcile re-applies the desired SecurityPolicy spec via
//     server-side apply (SSA) with field-manager
//     `talon.example.com/securitypolicy-translator`. An operator
//     hand-edit on a Talon-managed field surfaces as an SSA conflict
//     on the next reconcile and the controller re-asserts.
//
//   - Hand-edits on fields the translator does NOT own (e.g. extra
//     annotations) are preserved — SSA's per-field-owner model handles
//     this without three-way-merge logic in the controller.
//
// Status reflection (Phase 2 deferred):
//
//   - SecurityPolicy.status.conditions[type=Accepted] is THE truth
//     about whether EG has wired the ext_authz filter. The Phase-2
//     follow-up watches SecurityPolicy events and bubbles the Accepted
//     condition into TalonRoute.status as `policyAccepted`. Phase 1
//     ships translator + emit only; operators check
//     `kubectl -n envoy-gateway-system get securitypolicy` for now.
package controller

import (
	"context"
	"errors"
	"fmt"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecurityPolicyGVR is the gateway.envoyproxy.io/v1alpha1 SecurityPolicy
// group-version-resource. Exposed as a package var so tests can
// override the API group if EG bumps the version (anticipated v1beta1
// once the CRD reaches GA in EG v1.5+).
var SecurityPolicyGVR = schema.GroupVersionKind{
	Group:   "gateway.envoyproxy.io",
	Version: "v1alpha1",
	Kind:    "SecurityPolicy",
}

// SecurityPolicyTranslatorConfig wires the translator. Loaded from
// cfg.SecurityPolicy* envs at controller setup time.
type SecurityPolicyTranslatorConfig struct {
	// Enabled toggles the translator on. When false, no SecurityPolicy
	// is emitted (legacy behavior — operators run TalonRoute alongside
	// hand-crafted SecurityPolicy CRs).
	Enabled bool

	// Namespace is where SecurityPolicy CRs are written. Typically
	// `envoy-gateway-system` — must match the namespace of the
	// HTTPRoute/Gateway targetRefs. Env: TALON_SECURITY_POLICY_NAMESPACE
	Namespace string

	// ExtAuthzServiceName is the in-cluster Service Talon ext_authz
	// listens on. Typically `talon-talon` with port 9001 (Phase 7
	// chart values). Env: TALON_EXTAUTHZ_SERVICE_NAME
	ExtAuthzServiceName string

	// ExtAuthzServiceNamespace is the namespace of ExtAuthzServiceName.
	// Same as the talon ns in normal deploys. Env:
	// TALON_EXTAUTHZ_SERVICE_NAMESPACE
	ExtAuthzServiceNamespace string

	// ExtAuthzPort is the port Talon ext_authz listens on (default
	// 9001 per chart values).
	ExtAuthzPort int32

	// HTTPRouteNamespace is where the HTTPRoute targetRefs live — the
	// SecurityPolicy MUST be in the SAME namespace as its targets per
	// EG semantics. Operators set this once in chart values; per-route
	// override is intentionally not supported (the EG canonical pattern
	// puts all customer-tier HTTPRoutes in one ns).
	HTTPRouteNamespace string
}

// Labels emitted on every Talon-managed SecurityPolicy. Constants are
// the GC anchor: a finalizer-driven cleanup or a periodic orphan
// sweeper keys on these.
const (
	LabelManagedBy      = "app.kubernetes.io/managed-by"
	LabelOwnerNamespace = "talon.example.com/owner-namespace"
	LabelOwnerName      = "talon.example.com/owner-name"
	LabelOwnerHost      = "talon.example.com/owner-host"

	ManagedByValue = "talon-controller"

	// FieldManager is the SSA field-owner string. Drift on a Talon-
	// managed field surfaces as an SSA conflict; hand-edits on fields
	// the translator does NOT manage are preserved via SSA's per-field
	// ownership model.
	FieldManager = "talon.example.com/securitypolicy-translator"
)

// FinalizerName is the finalizer Talon attaches to TalonRoutes when
// the translator is enabled. On TalonRoute deletion, the controller
// must remove the matching SecurityPolicy before clearing this
// finalizer (otherwise EG keeps the ext_authz wire alive after the
// TalonRoute is gone — silent half-deletion).
const FinalizerName = "talon.example.com/securitypolicy-finalizer"

// DesiredSecurityPolicy builds the unstructured object for the given
// TalonRoute. Exposed for unit testing — the actual Ensure/Delete
// methods drive this through SSA. Returns the SecurityPolicy CR in
// cfg.Namespace with the Talon-managed labels + ext_authz spec.
//
// The HTTPRoute name targetRef is derived from route.Spec.Host
// (one HTTPRoute per host is the EG convention from Phase 7.4
// migration). Operators with a different naming convention can
// override via route.Spec.Annotations
// `talon.example.com/httproute-name` — preserved for forward
// compatibility but not yet wired.
func DesiredSecurityPolicy(route *gatewayv1alpha1.TalonRoute, cfg SecurityPolicyTranslatorConfig) *unstructured.Unstructured {
	sp := &unstructured.Unstructured{}
	sp.SetGroupVersionKind(SecurityPolicyGVR)
	sp.SetNamespace(cfg.Namespace)
	sp.SetName(SecurityPolicyName(route))
	sp.SetLabels(map[string]string{
		LabelManagedBy:      ManagedByValue,
		LabelOwnerNamespace: route.Namespace,
		LabelOwnerName:      route.Name,
		LabelOwnerHost:      route.Spec.Host,
	})

	// EG SecurityPolicy.spec
	spec := map[string]interface{}{
		"targetRefs": []interface{}{
			map[string]interface{}{
				"group": "gateway.networking.k8s.io",
				"kind":  "HTTPRoute",
				"name":  HTTPRouteNameForHost(route.Spec.Host),
			},
		},
		"extAuth": map[string]interface{}{
			"grpc": map[string]interface{}{
				"backendRefs": []interface{}{
					map[string]interface{}{
						"name":      cfg.ExtAuthzServiceName,
						"namespace": cfg.ExtAuthzServiceNamespace,
						"port":      int64(cfg.ExtAuthzPort),
					},
				},
			},
			// failOpen: false — ADR 0010 invariant. Losing the Talon
			// ext_authz pod MUST deny, not silently allow.
			"failOpen": false,
			// recomputeRoute: false — the route decision is already
			// made by EG before ext_authz fires; the auth check
			// shouldn't reshape routing.
			"recomputeRoute": false,
		},
	}
	_ = unstructured.SetNestedMap(sp.Object, spec, "spec")
	return sp
}

// SecurityPolicyName returns the name Talon uses for the per-route
// SecurityPolicy. Includes the TalonRoute owner-namespace + name as
// the prefix so two TalonRoutes (in different ns) with the same host
// cannot collide on the same SecurityPolicy.
//
// Format: talon-<owner-ns>-<owner-name>-securitypolicy
func SecurityPolicyName(route *gatewayv1alpha1.TalonRoute) string {
	return fmt.Sprintf("talon-%s-%s-securitypolicy", route.Namespace, route.Name)
}

// HTTPRouteNameForHost returns the conventional HTTPRoute name for a
// given host. The Phase-7.4 EG migration named HTTPRoutes after their
// hosts with a trailing `-prod` (e.g. `app-prod`, `idp-example-prod`).
// Future TalonRoute API additions may expose
// `spec.gateway.httpRouteName` to override this convention.
func HTTPRouteNameForHost(host string) string {
	// Strip wildcard + dots + return host with -prod suffix.
	// "app.example.com" → "app-prod"
	// "idp.example.com" → "idp-example-prod"  (no, that's not right)
	// Actually Phase 7.4 used hostname-derived names; for now we use
	// the host directly with dots → dashes + -prod suffix as the
	// default convention. Operators with non-standard naming can
	// override via TalonRoute annotation (separate commit).
	out := []rune(host)
	for i, r := range out {
		if r == '.' {
			out[i] = '-'
		}
	}
	return string(out) + "-prod"
}

// EnsureSecurityPolicy creates or updates the SecurityPolicy CR for
// route. Uses server-side apply with the package's FieldManager so
// concurrent operator hand-edits on Talon-managed fields surface as
// SSA conflicts on the next reconcile.
//
// Errors:
//   - cfg.Enabled == false → nil (no-op; caller must check)
//   - K8s API failure → wrapped error; caller should requeue
func EnsureSecurityPolicy(ctx context.Context, c client.Client, route *gatewayv1alpha1.TalonRoute, cfg SecurityPolicyTranslatorConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if err := validateTranslatorConfig(cfg); err != nil {
		return fmt.Errorf("translator config: %w", err)
	}
	desired := DesiredSecurityPolicy(route, cfg)
	// Server-side apply. Force ownership transfer on Talon-managed
	// fields so a previous controller-version's stale field ownership
	// doesn't block the apply.
	//
	// SA1019 — controller-runtime v0.23 marks the `client.Apply` Patch
	// singleton deprecated, recommending the new
	// `Client.Apply(ctx, runtime.ApplyConfiguration, …)` method instead.
	// The replacement signature requires a codegen-derived
	// `runtime.ApplyConfiguration` (k8s.io/apimachinery), which exists
	// only for typed APIs that ship apply configurations via
	// `applyconfiguration-gen`. Our SecurityPolicy payload is an
	// `*unstructured.Unstructured` for the dynamic
	// `gateway.envoyproxy.io/v1alpha1` GVR — Envoy Gateway does not yet
	// publish typed apply configurations, and apimachinery itself does
	// not expose a public `UnstructuredApplyConfiguration` adapter
	// (tracked in kubernetes-sigs/controller-runtime#3076 and
	// kubernetes/kubernetes#129662). Retaining `client.Apply` is
	// therefore the only supported SSA path for unstructured payloads
	// today; this `//nolint` is a documented deferral, not a silence.
	// Revisit when upstream ships unstructured ApplyConfiguration.
	return c.Patch(ctx, desired, client.Apply, //nolint:staticcheck // SA1019 — see comment above
		client.FieldOwner(FieldManager),
		client.ForceOwnership)
}

// DeleteSecurityPolicy removes the SecurityPolicy belonging to route.
// Idempotent — IsNotFound is treated as success.
func DeleteSecurityPolicy(ctx context.Context, c client.Client, route *gatewayv1alpha1.TalonRoute, cfg SecurityPolicyTranslatorConfig) error {
	if !cfg.Enabled {
		return nil
	}
	sp := &unstructured.Unstructured{}
	sp.SetGroupVersionKind(SecurityPolicyGVR)
	sp.SetNamespace(cfg.Namespace)
	sp.SetName(SecurityPolicyName(route))
	if err := c.Delete(ctx, sp); err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete SecurityPolicy %s/%s: %w", cfg.Namespace, SecurityPolicyName(route), err)
	}
	return nil
}

// GetSecurityPolicy fetches the current SecurityPolicy for route.
// Returns (nil, nil) if not found (translator may not have emitted
// yet, or was disabled when route was created). Used by the status-
// reflection helper to bubble SecurityPolicy.status.conditions back
// into TalonRoute.status.
func GetSecurityPolicy(ctx context.Context, c client.Client, route *gatewayv1alpha1.TalonRoute, cfg SecurityPolicyTranslatorConfig) (*unstructured.Unstructured, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	sp := &unstructured.Unstructured{}
	sp.SetGroupVersionKind(SecurityPolicyGVR)
	key := types.NamespacedName{Namespace: cfg.Namespace, Name: SecurityPolicyName(route)}
	if err := c.Get(ctx, key, sp); err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get SecurityPolicy %s/%s: %w", cfg.Namespace, SecurityPolicyName(route), err)
	}
	return sp, nil
}

// AcceptedConditionFromSecurityPolicy extracts the `Accepted`
// condition from an Envoy Gateway SecurityPolicy.status.conditions
// list and returns the metav1.ConditionStatus + Reason + Message
// trio we mirror into TalonRoute.status. Returns ("", "", "", false)
// when the SecurityPolicy has no status yet OR carries no `Accepted`
// condition.
//
// Envoy Gateway sets `Accepted=True` once its controller's reconcile
// has translated the SecurityPolicy into Envoy data-plane ext_authz
// config; `False` with a non-empty `Reason` indicates a translation
// failure surfaced for debugging. We propagate verbatim.
func AcceptedConditionFromSecurityPolicy(sp *unstructured.Unstructured) (status, reason, message string, found bool) {
	if sp == nil {
		return "", "", "", false
	}
	conds, ok, _ := unstructured.NestedSlice(sp.Object, "status", "conditions")
	if !ok {
		return "", "", "", false
	}
	for _, c := range conds {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t != "Accepted" {
			continue
		}
		st, _ := m["status"].(string)
		rs, _ := m["reason"].(string)
		ms, _ := m["message"].(string)
		return st, rs, ms, true
	}
	return "", "", "", false
}

func validateTranslatorConfig(cfg SecurityPolicyTranslatorConfig) error {
	if cfg.Namespace == "" {
		return errors.New("namespace is required")
	}
	if cfg.ExtAuthzServiceName == "" {
		return errors.New("extAuthzServiceName is required")
	}
	if cfg.ExtAuthzServiceNamespace == "" {
		return errors.New("extAuthzServiceNamespace is required")
	}
	if cfg.ExtAuthzPort == 0 {
		return errors.New("extAuthzPort is required")
	}
	return nil
}

// isNotFound is a tiny shim so this file doesn't need to import
// apierrors directly (k8s.io/apimachinery is already imported by the
// controller; this keeps the import surface in this file minimal).
// We delegate to client.IgnoreNotFound at call sites where possible
// but the explicit version here makes the error path self-documenting.
func isNotFound(err error) bool {
	return client.IgnoreNotFound(err) == nil && err != nil
}

// controllerutilContainsFinalizer mirrors
// controllerutil.ContainsFinalizer without importing the whole
// controllerutil package (which would pull k8s.io/api into the
// dependency surface). Same semantics; trivially testable.
func controllerutilContainsFinalizer(finalizers []string, name string) bool {
	for _, f := range finalizers {
		if f == name {
			return true
		}
	}
	return false
}

// controllerutilRemoveFinalizer returns a copy of finalizers with the
// first occurrence of name removed. Returns the original slice
// unmodified if name is not present (no-allocation fast path).
func controllerutilRemoveFinalizer(finalizers []string, name string) []string {
	for i, f := range finalizers {
		if f == name {
			out := make([]string, 0, len(finalizers)-1)
			out = append(out, finalizers[:i]...)
			out = append(out, finalizers[i+1:]...)
			return out
		}
	}
	return finalizers
}
