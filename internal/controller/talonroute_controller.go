// SPDX-License-Identifier: AGPL-3.0-or-later

// Package controller is Talon's TalonRoute reconciler. Per ADR 0003 §4
// it watches TalonRoute cluster-wide and atomically registers/deregisters
// upstream handlers in the in-process router. Phase 2 ships this stub
// next to the static env-var path; Phase 3 makes the env-var an opt-in
// fallback only.
package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
	gatewayv1beta1 "github.com/dogukanturhal/talon/api/v1beta1"
	"github.com/dogukanturhal/talon/internal/config"
	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/observability"
	"github.com/dogukanturhal/talon/internal/policy"
	"github.com/dogukanturhal/talon/internal/proxy"
	"github.com/dogukanturhal/talon/internal/router"
	"github.com/dogukanturhal/talon/internal/spicedb"
	"github.com/dogukanturhal/talon/internal/svctoken"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// boolPtr returns a pointer to the boolean (no `ptr` pkg dep just for this).
func boolPtr(b bool) *bool { return &b }

// protectedHostSuffixes is the list of admin-tier DNS zones a TalonRoute's
// spec.host may live in. Sourced from TALON_PROTECTED_HOST_SUFFIXES env
// var (comma-separated, e.g. ".internal.example.com,.apps.example.com").
// Defaults to ".internal.example.com" when unset — preserves the original
// single-zone behavior. Multi-zone support added 2026-05-03 to enable
// Track 2 Phase 7 migration onto the apps.example.com subzone.
var protectedHostSuffixes = parseSuffixEnv("TALON_PROTECTED_HOST_SUFFIXES", []string{".internal.example.com"})

// clientlessHostSuffixes is the access-zone DNS suffix list for the
// agentless clientless tier (ADR 0044). Sourced from
// TALON_CLIENTLESS_HOST_SUFFIXES (comma-separated, e.g.
// ".access.example.com"). Unset = clientless tier disabled (no access-zone
// hosts admitted), preserving existing deployments unchanged on upgrade.
// A TalonRoute whose spec.host ends with one of these suffixes is admitted
// (see allowedHostSuffixes) so the access zone is a first-class route class
// — the router separately tags its requests channel=clientless and applies
// the AAL cap + clientlessMaxTTL.
var clientlessHostSuffixes = parseSuffixEnv("TALON_CLIENTLESS_HOST_SUFFIXES", nil)

// parseSuffixEnv reads a comma-separated DNS-suffix env var, trimming
// blanks. Returns def when the var is unset or yields no entries.
func parseSuffixEnv(name string, def []string) []string {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// allowedHostSuffixes returns the union of the admin-tier protected zones
// and the clientless access zones — the full set a TalonRoute's spec.host
// may live in. The access zone (ADR 0044) is admitted on equal footing so
// an operator can declare a TalonRoute on `<app>.access.example.com`
// exactly as they would on `<app>.internal.example.com`; the router decides
// the channel from the same suffix list at request time.
func allowedHostSuffixes() []string {
	out := make([]string, 0, len(protectedHostSuffixes)+len(clientlessHostSuffixes))
	out = append(out, protectedHostSuffixes...)
	out = append(out, clientlessHostSuffixes...)
	return out
}

// TalonRouteReconciler reconciles TalonRoute CRs into Router upstream
// handler entries + SpiceDB relationships per ADR 0003 §5.
type TalonRouteReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Router  *router.Router
	Metrics *observability.Metrics
	// SpiceDB is optional — when nil, only the Router registration
	// happens (Phase-2 base behaviour). Phase-2.1 wires it.
	SpiceDB *spicedb.Client
	// SecurityPolicyTranslator is optional — when enabled, emits an
	// Envoy Gateway SecurityPolicy CR per TalonRoute so EG's data
	// plane delegates auth to Talon's ext_authz gRPC via the canonical
	// Gateway API extension shape. See securitypolicy_translator.go.
	SecurityPolicyTranslator SecurityPolicyTranslatorConfig
}

// +kubebuilder:rbac:groups=gateway.talon.example.com,resources=talonroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.talon.example.com,resources=talonroutes/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=gateway.talon.example.com,resources=talonroutes/finalizers,verbs=update

// Reconcile is the per-event entrypoint.
func (r *TalonRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := tlog.From(ctx).With("talonroute", req.NamespacedName)

	var route gatewayv1alpha1.TalonRoute
	if err := r.Get(ctx, req.NamespacedName, &route); err != nil {
		if apierrors.IsNotFound(err) {
			// Deletion event. We don't have spec to know the host →
			// finalizer-driven cleanup is Phase 2.2; for Phase-2.1 we
			// log and return. The router entry is left until pod
			// restart — acceptable: a deleted TalonRoute sees its
			// IngressRoute deleted by the chart's pruning, so traffic
			// stops at Traefik before reaching Talon.
			logger.Info("talonroute deleted", "name", req.String())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get talonroute: %w", err)
	}

	// SecurityPolicy translator finalizer handling. When the
	// translator is enabled, we attach a finalizer so we can clean up
	// the corresponding SecurityPolicy CR (which lives in a different
	// namespace and can't be tied via OwnerReferences) before allowing
	// TalonRoute deletion. Without this, deleting a TalonRoute leaves
	// a stale SecurityPolicy bound to the (now-gone) HTTPRoute name —
	// EG keeps ext_authz wired but no Talon route registration exists,
	// which surfaces as 503 on every request to that host.
	if r.SecurityPolicyTranslator.Enabled {
		if route.DeletionTimestamp != nil {
			// Mid-delete: clean up the SecurityPolicy then drop the
			// finalizer so the API server can complete GC.
			if err := DeleteSecurityPolicy(ctx, r.Client, &route, r.SecurityPolicyTranslator); err != nil {
				logger.Error("delete SecurityPolicy on TalonRoute delete failed; requeuing",
					"err", err)
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
			if controllerutilContainsFinalizer(route.Finalizers, FinalizerName) {
				route.Finalizers = controllerutilRemoveFinalizer(route.Finalizers, FinalizerName)
				if err := r.Update(ctx, &route); err != nil {
					logger.Warn("remove finalizer failed", "err", err)
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}
			}
			return ctrl.Result{}, nil
		}
		// Live: ensure finalizer is present so a future deletion
		// triggers the cleanup branch above.
		if !controllerutilContainsFinalizer(route.Finalizers, FinalizerName) {
			route.Finalizers = append(route.Finalizers, FinalizerName)
			if err := r.Update(ctx, &route); err != nil {
				logger.Warn("add finalizer failed", "err", err)
				return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}
	}

	// Validate (runtime checks the OpenAPIv3 schema can't express).
	if err := validateRoute(&route); err != nil {
		setCondition(&route, metav1.Condition{
			Type:               gatewayv1alpha1.ConditionRegistered,
			Status:             metav1.ConditionFalse,
			Reason:             gatewayv1alpha1.ReasonValidationFailed,
			Message:            err.Error(),
			ObservedGeneration: route.Generation,
			LastTransitionTime: metav1.Now(),
		})
		if patchErr := r.Status().Update(ctx, &route); patchErr != nil {
			logger.Warn("status update failed", "err", patchErr)
		}
		// Don't requeue — the spec is invalid; user must edit.
		return ctrl.Result{}, nil
	}

	// Compile per-route Rego escape hatch BEFORE
	// registering the upstream — a malformed module fails the route
	// reconcile here rather than every in-flight request once the
	// route is live. Empty PolicyRego returns (nil, nil); Router
	// treats nil as no-narrowing.
	rego, err := policy.CompileRego(ctx, route.Spec.PolicyRego)
	if err != nil {
		setCondition(&route, metav1.Condition{
			Type:               gatewayv1alpha1.ConditionRegistered,
			Status:             metav1.ConditionFalse,
			Reason:             gatewayv1alpha1.ReasonValidationFailed,
			Message:            "rego compile failed: " + err.Error(),
			ObservedGeneration: route.Generation,
			LastTransitionTime: metav1.Now(),
		})
		if patchErr := r.Status().Update(ctx, &route); patchErr != nil {
			logger.Warn("status update failed", "err", patchErr)
		}
		return ctrl.Result{}, nil
	}

	// Register upstream in the in-process router.
	upstream := proxy.Upstream{
		Service: fmt.Sprintf("%s:%d", qualifyService(route.Spec.Upstream.Service, route.Namespace), route.Spec.Upstream.Port),
		Scheme:  route.Spec.Upstream.Scheme,
	}
	permission := string(route.Spec.Permission)
	if permission == "" {
		permission = "viewer"
	}
	r.Router.RegisterUpstream(route.Spec.Host, router.RegisterUpstreamParams{
		Handler:                 proxy.NewHandler(route.Spec.Host, upstream, r.Metrics),
		Permission:              permission,
		MfaRequired:             route.Spec.MfaRequired,
		ContinuousVerifyMinutes: route.Spec.ContinuousVerifyMinutes,
		Rego:                    rego,
		// Per-host session-control fields (Phase 4 batch).
		SessionAbsoluteSec:    route.Spec.SessionTTLOverride,
		SessionIdleSec:        route.Spec.SessionIdleSeconds,
		ReauthOnNetworkChange: route.Spec.ReauthOnNetworkChange,
		RequireDeviceClaims:   route.Spec.RequireDeviceClaims,
		AuditOnly:             route.Spec.AuditOnly,
		// Phase C opt-in: stamp Authorization: Bearer <iap-jwt> for
		// upstreams that consume stock OAuth2 / OIDC middleware. See
		// docs/architecture/0005-iap-identity-token.md.
		InjectAuthorizationBearer: route.Spec.InjectAuthorizationBearer,
		// ASVS 5.0 V9 — fail-closed identity-token minting. OR'd with the
		// fleet-wide TALON_REQUIRE_SIGNED_IDENTITY_TOKEN floor in
		// RegisterUpstream. Opt-in per route as each downstream adopts the
		// signed-token SDK verifier.
		RequireSignedIdentityToken: route.Spec.RequireSignedIdentityToken,
		// talon-service-tokens — per-host auth-channel selector. Empty
		// or unrecognised strings defensively coerce to AuthModeCookie
		// at RegisterUpstream — see internal/router/router.go.
		AuthMode: svctoken.AuthMode(route.Spec.AuthMode),
		// Phase 7.3.b — v1beta1 per-path policy. Fetched from the
		// same TalonRoute as a v1beta1 CR through the conversion
		// webhook (Phase 6a.2). When the webhook is disabled OR the
		// operator hasn't authored pathRules, this is empty and
		// router behaviour is v1alpha1-identical.
		//
		// Compile failures surface as Registered=False / Validation
		// Failed below — same posture as the Rego compile gate.
		PathRules: compilePathRules(ctx, r.Client, req.NamespacedName, logger),
		// ZTNA Phase 5.b — operator-declared route sensitivity, projected
		// into RegoInputPosture.Compliance["route_sensitivity"] at
		// request time so the ZTNA Rego baseline matrix can apply
		// without operators having to encode the class in posture.
		// Empty defers to Rego's "medium" fallback. Validated against
		// the enum {"low","medium","high","critical"} below.
		Sensitivity: route.Spec.Sensitivity,
		// ADR 0044 — agentless clientless tier. AllowClientless lifts the
		// clientless-on-critical hard deny; ClientlessMaxTTL caps the
		// agentless session lifetime on this route.
		AllowClientless:  route.Spec.AllowClientless,
		ClientlessMaxTTL: route.Spec.ClientlessMaxTTL,
		// ZTNA enrollment-bootstrap carve-out — method+exact-path routes
		// on this host that bypass the Talon session gate. The upstream
		// MUST self-authenticate these requests (e.g. jess verifies a
		// WebAuthn witness JWS on /device-cert/attest). Empty = fully
		// gated. Method is upper-cased for case-stable matching.
		PublicPaths: toConfigPublicRoutes(route.Spec.PublicPaths),
	})

	// Emit Envoy Gateway SecurityPolicy CR. Same posture as SpiceDB:
	// failure is logged but doesn't fail the reconcile because the
	// router registration is the critical path. The translator
	// re-emits on each reconcile via SSA so a transient failure
	// auto-heals on the next watch event.
	//
	// After ensure, bubble the upstream
	// SecurityPolicy.status.conditions[type=Accepted] back into
	// TalonRoute.status as `SecurityPolicyAccepted`. Operators get a
	// single watch surface for "is my route fully programmed?" without
	// having to cross-namespace into envoy-gateway-system. The bubble
	// is best-effort — a transient Get failure falls back to "pending"
	// posture and the next reconcile recovers.
	if r.SecurityPolicyTranslator.Enabled {
		if err := EnsureSecurityPolicy(ctx, r.Client, &route, r.SecurityPolicyTranslator); err != nil {
			logger.Warn("ensure SecurityPolicy failed; route registered but EG ext_authz wire pending",
				"host", route.Spec.Host, "err", err)
			setCondition(&route, metav1.Condition{
				Type:               gatewayv1alpha1.ConditionSecurityPolicyAccepted,
				Status:             metav1.ConditionFalse,
				Reason:             gatewayv1alpha1.ReasonSecurityPolicyEnsureError,
				Message:            truncateMessage(err.Error()),
				ObservedGeneration: route.Generation,
				LastTransitionTime: metav1.Now(),
			})
		} else {
			sp, gErr := GetSecurityPolicy(ctx, r.Client, &route, r.SecurityPolicyTranslator)
			switch {
			case gErr != nil:
				logger.Warn("get SecurityPolicy failed; deferring status bubble",
					"host", route.Spec.Host, "err", gErr)
			case sp == nil:
				setCondition(&route, metav1.Condition{
					Type:               gatewayv1alpha1.ConditionSecurityPolicyAccepted,
					Status:             metav1.ConditionFalse,
					Reason:             gatewayv1alpha1.ReasonSecurityPolicyNotFound,
					Message:            "SecurityPolicy not visible yet — EG controller has not surfaced status",
					ObservedGeneration: route.Generation,
					LastTransitionTime: metav1.Now(),
				})
			default:
				st, reason, msg, found := AcceptedConditionFromSecurityPolicy(sp)
				if !found {
					setCondition(&route, metav1.Condition{
						Type:               gatewayv1alpha1.ConditionSecurityPolicyAccepted,
						Status:             metav1.ConditionFalse,
						Reason:             gatewayv1alpha1.ReasonSecurityPolicyNotFound,
						Message:            "SecurityPolicy has no Accepted condition yet",
						ObservedGeneration: route.Generation,
						LastTransitionTime: metav1.Now(),
					})
				} else {
					mirrored := metav1.ConditionFalse
					mirroredReason := gatewayv1alpha1.ReasonSecurityPolicyRejected
					switch metav1.ConditionStatus(st) {
					case metav1.ConditionTrue:
						mirrored = metav1.ConditionTrue
						mirroredReason = gatewayv1alpha1.ReasonSecurityPolicyAccepted
					case metav1.ConditionUnknown:
						mirrored = metav1.ConditionUnknown
						mirroredReason = gatewayv1alpha1.ReasonSecurityPolicyNotFound
					}
					if reason != "" {
						mirroredReason = reason
					}
					setCondition(&route, metav1.Condition{
						Type:               gatewayv1alpha1.ConditionSecurityPolicyAccepted,
						Status:             mirrored,
						Reason:             mirroredReason,
						Message:            truncateMessage(msg),
						ObservedGeneration: route.Generation,
						LastTransitionTime: metav1.Now(),
					})
				}
			}
		}
	}

	// Write SpiceDB relationships for this route (ADR 0003 §5.1).
	// Failure here is logged but doesn't fail the reconcile — the
	// router registration is what matters for the data plane; SpiceDB
	// CheckPermission runtime errors fail-closed independently.
	if r.SpiceDB != nil && (len(route.Spec.AllowedGroups) > 0 || len(route.Spec.AllowedSubjects) > 0) {
		if err := r.SpiceDB.WriteRouteRelationships(ctx, route.Spec.Host,
			route.Spec.AllowedGroups, route.Spec.AllowedSubjects, permission); err != nil {
			logger.Warn("spicedb WriteRouteRelationships failed; route registered without authz bindings",
				"host", route.Spec.Host, "err", err)
		}
	}

	logger.Info("registered route",
		"host", route.Spec.Host,
		"upstream", upstream.Service,
		"permission", permission,
		"allowedGroups", route.Spec.AllowedGroups,
		"allowedSubjects", route.Spec.AllowedSubjects,
	)

	setCondition(&route, metav1.Condition{
		Type:               gatewayv1alpha1.ConditionRegistered,
		Status:             metav1.ConditionTrue,
		Reason:             gatewayv1alpha1.ReasonProxyHandlerInstalled,
		ObservedGeneration: route.Generation,
		LastTransitionTime: metav1.Now(),
	})
	route.Status.ObservedGeneration = route.Generation
	if err := r.Status().Update(ctx, &route); err != nil {
		logger.Warn("status update failed", "err", err)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler to the controller-runtime manager.
//
// `NeedLeaderElection: boolPtr(false)` overrides the manager-level
// LeaderElection=true and forces this reconciler to run on EVERY
// replica. Required because the reconciler's only side effect is
// populating the in-process `router.upstreams` map; if only the
// leader pod runs it, the non-leader pod has empty upstreams and
// returns HTTP 404 for every request the Service load-balances to
// it. Confirmed live 2026-05-12: 2-replica deploy split 50/50 across
// {1211 routes, 0 routes} pods → intermittent erp.example.com 404s
// + every browser tab that hit the empty replica got a broken page.
//
// `cv.Runner` (continuous verification) DOES need leader election
// because it makes external API calls and must not duplicate work
// across pods; that runnable stays leader-elected via mgr.Add().
//
// References:
//   - https://github.com/kubernetes-sigs/controller-runtime/blob/main/pkg/controller/controller.go#L34
//     (Options.NeedLeaderElection)
//   - feedback memo: talon-replica-route-divergence-2026-05-12 (filed)
func (r *TalonRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		Named("talonroute").
		WithOptions(controller.Options{
			NeedLeaderElection: boolPtr(false),
		}).
		For(&gatewayv1alpha1.TalonRoute{})

	// When the SecurityPolicy translator is enabled, watch the EG
	// SecurityPolicy CR and enqueue the owning TalonRoute on every
	// status update. This is the path that makes status bubble
	// converge in seconds instead of waiting for the next periodic
	// resync. Mapping: SecurityPolicy.metadata.labels[
	// "gateway.talon.io/route-name"] + ["...route-namespace"] →
	// reconcile.Request. The translator stamps these labels in
	// DesiredSecurityPolicy so this lookup is O(1).
	//
	// We do NOT use OwnerReferences here because the SecurityPolicy
	// lives in envoy-gateway-system (a different namespace from the
	// TalonRoute) and OwnerReferences must be same-namespace per the
	// K8s API contract. The label-based map is the
	// cross-namespace-safe equivalent (same pattern Envoy Gateway,
	// Gateway API, and Istio use for parent watches).
	if r.SecurityPolicyTranslator.Enabled {
		sp := &unstructured.Unstructured{}
		sp.SetGroupVersionKind(SecurityPolicyGVR)
		b = b.Watches(sp, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				labels := obj.GetLabels()
				name := labels[LabelOwnerName]
				ns := labels[LabelOwnerNamespace]
				if name == "" || ns == "" {
					return nil
				}
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: ns,
					Name:      name,
				}}}
			}))
	}

	return b.Complete(r)
}

// validateRoute runs the runtime-side checks the OpenAPIv3 schema can't
// express (host suffix, upstream form, cross-field invariants, device-
// claim allow-list). Returns nil on valid spec.
func validateRoute(route *gatewayv1alpha1.TalonRoute) error {
	if route.Spec.Host == "" {
		return fmt.Errorf("spec.host is required")
	}
	suffixes := allowedHostSuffixes()
	matched := false
	for _, suffix := range suffixes {
		if strings.HasSuffix(route.Spec.Host, suffix) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("spec.host %q must end with one of %v (configured via TALON_PROTECTED_HOST_SUFFIXES / TALON_CLIENTLESS_HOST_SUFFIXES)",
			route.Spec.Host, suffixes)
	}
	if route.Spec.Upstream.Service == "" {
		return fmt.Errorf("spec.upstream.service is required")
	}
	if route.Spec.Upstream.Port < 1 || route.Spec.Upstream.Port > 65535 {
		return fmt.Errorf("spec.upstream.port out of range")
	}
	// Idle must be <= absolute when both > 0 (an idle window longer than
	// the absolute cap can never fire — operator typo). When absolute=0
	// (cluster default), defer the check to runtime against the config-
	// time cluster TTL — the router never compares idle past the absolute
	// cap because absolute is checked first.
	if route.Spec.SessionIdleSeconds > 0 && route.Spec.SessionTTLOverride > 0 &&
		route.Spec.SessionIdleSeconds > route.Spec.SessionTTLOverride {
		return fmt.Errorf("spec.sessionIdleSeconds (%d) must be <= spec.sessionTtlOverride (%d)",
			route.Spec.SessionIdleSeconds, route.Spec.SessionTTLOverride)
	}
	// ZTNA Phase 5.b — Sensitivity enum check. Defense-in-depth
	// alongside the CRD enum tag (+kubebuilder:validation:Enum=...);
	// catches values that bypassed the OpenAPIv3 schema (cross-version
	// drift, etcd-direct writes) and gives operators a deterministic
	// per-route failure mode rather than the Rego policy silently
	// behaving as if sensitivity were "medium".
	switch route.Spec.Sensitivity {
	case "", "low", "medium", "high", "critical":
		// ok
	default:
		return fmt.Errorf("spec.sensitivity %q must be one of low|medium|high|critical (or empty for default)",
			route.Spec.Sensitivity)
	}
	// Device-claim allow-list — defense in depth alongside the CRD enum.
	// Catches values that bypassed the OpenAPIv3 schema (cross-version
	// drift, etcd-direct writes) and gives a deterministic per-route
	// failure mode rather than a silent fail-closed at request time.
	for i, dc := range route.Spec.RequireDeviceClaims {
		if dc.Claim == "" {
			return fmt.Errorf("spec.requireDeviceClaims[%d].claim is required", i)
		}
		if !isAllowedDeviceClaim(dc.Claim) {
			return fmt.Errorf("spec.requireDeviceClaims[%d].claim %q not in allow-list (%s)",
				i, dc.Claim, strings.Join(gatewayv1alpha1.AllowedDeviceClaimNames, ","))
		}
		if dc.Equals == "" {
			return fmt.Errorf("spec.requireDeviceClaims[%d].equals must be non-empty (omit the requirement entirely instead of empty equals)", i)
		}
	}
	// PublicPaths carve-out — defense in depth alongside the CRD schema.
	// Each entry must name a non-empty method and an exact path that
	// starts with "/". Catches values that bypassed the OpenAPIv3 schema
	// (cross-version drift, etcd-direct writes) before they punch an
	// unintended hole in the IAP.
	for i, pr := range route.Spec.PublicPaths {
		if strings.TrimSpace(pr.Method) == "" {
			return fmt.Errorf("spec.publicPaths[%d].method is required", i)
		}
		if !strings.HasPrefix(pr.Path, "/") {
			return fmt.Errorf("spec.publicPaths[%d].path %q must start with %q", i, pr.Path, "/")
		}
	}
	return nil
}

// toConfigPublicRoutes converts CRD PublicRoute entries to the router/config
// type consumed by RegisterUpstream. Method is upper-cased for case-stable
// matching (the router also compares case-insensitively).
func toConfigPublicRoutes(in []gatewayv1alpha1.PublicRoute) []config.PublicRoute {
	if len(in) == 0 {
		return nil
	}
	out := make([]config.PublicRoute, 0, len(in))
	for _, pr := range in {
		out = append(out, config.PublicRoute{
			Method: strings.ToUpper(strings.TrimSpace(pr.Method)),
			Path:   pr.Path,
		})
	}
	return out
}

// isAllowedDeviceClaim returns true if name is in the v1alpha1 allow-
// list. Linear scan — the list is fixed at six entries by design.
func isAllowedDeviceClaim(name string) bool {
	for _, n := range gatewayv1alpha1.AllowedDeviceClaimNames {
		if n == name {
			return true
		}
	}
	return false
}

// compilePathRules fetches the v1beta1 representation of the
// TalonRoute (through the API server's conversion webhook) and
// precompiles its pathRules into the matcher form. Returns nil
// (= no per-path policy, v1alpha1-equivalent behaviour) when:
//
//   - the v1beta1 GET returns an error (webhook disabled, CRD
//     v1beta1 not served, etc.)
//   - the operator hasn't authored any pathRules
//   - precompile fails (returns nil + a Warn log; the v1alpha1
//     reconcile continues unaffected, so the route still serves
//     host-default policy even when pathRules are malformed)
//
// Phase 7.3.b — the reconciler's v1alpha1 watch is unchanged;
// this is an in-reconcile additive fetch that surfaces the
// pathRules ONCE per reconcile cycle for the matcher to consume.
//
// The compile-failure-doesn't-fail-the-reconcile posture is a
// deliberate Phase 7.3.b trade-off: when pathRules are broken,
// route serves with host-defaults rather than going dark. A
// future Phase 7.3.c can tighten this to fail-closed (set
// Registered=False on compile error) once operators have a
// healthy reconcile-status dashboard to detect drift.
func compilePathRules(ctx context.Context, c client.Client, key client.ObjectKey, logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}) []router.CompiledRule {
	var v1bRoute gatewayv1beta1.TalonRoute
	if err := c.Get(ctx, key, &v1bRoute); err != nil {
		// Common causes: conversion webhook disabled (Phase 6a.2
		// opt-in flag still false), CRD doesn't yet serve v1beta1,
		// or webhook unreachable. All three boil down to "no path
		// rules visible" — degrade gracefully.
		logger.Info("v1beta1 fetch skipped (conversion webhook disabled or unavailable)",
			"key", key.String(), "err", err)
		return nil
	}
	if len(v1bRoute.Spec.PathRules) == 0 {
		return nil
	}
	compiled, err := router.CompileRules(v1bRoute.Spec.PathRules)
	if err != nil {
		logger.Warn("pathRules compile failed — route will serve with host-default policy",
			"key", key.String(), "err", err)
		return nil
	}
	logger.Info("compiled pathRules",
		"key", key.String(), "rules", len(compiled))
	return compiled
}

// qualifyService converts a bare Service name to a fully-qualified DNS
// name. Already-qualified strings pass through.
func qualifyService(svc, ns string) string {
	if strings.Contains(svc, ".") {
		return svc
	}
	return fmt.Sprintf("%s.%s.svc.cluster.local", svc, ns)
}

// truncateMessage trims a condition.Message to the K8s API server's
// 32 KiB total status budget per condition. metav1.Condition messages
// have no hard length, but the parent Conditions[] list IS bounded by
// the standard status size limit; truncating early at 1 KiB per
// condition keeps the slice under ~32 KiB even with many conditions
// and prevents pathological upstream errors from blocking the status
// Update with `request entity too large`.
func truncateMessage(msg string) string {
	const max = 1024
	if len(msg) <= max {
		return msg
	}
	return msg[:max-3] + "..."
}

// setCondition adds or replaces a condition by Type.
func setCondition(route *gatewayv1alpha1.TalonRoute, c metav1.Condition) {
	for i, existing := range route.Status.Conditions {
		if existing.Type == c.Type {
			if existing.Status != c.Status {
				route.Status.Conditions[i] = c
			} else {
				// Keep LastTransitionTime if status hasn't changed.
				c.LastTransitionTime = existing.LastTransitionTime
				route.Status.Conditions[i] = c
			}
			return
		}
	}
	route.Status.Conditions = append(route.Status.Conditions, c)
}
