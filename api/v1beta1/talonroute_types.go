// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1beta1 — TalonRoute CR types with per-path policy.
//
// Schema additions over v1alpha1:
//
//   - defaultPolicy{} — the existing per-host policy fields
//     (authMode, permission, allowedGroups, mfaRequired, etc.)
//     moved into a nested struct for readability + symmetry with
//     pathRules[].
//   - pathRules[] — ordered, first-match-wins list of per-path
//     policy overrides. Each entry has a match{} clause + the
//     same overlay-able policy fields as defaultPolicy. Modelled
//     on Authelia + Pomerium + Envoy RBAC + K8s Gateway API HTTP
//     routing (the four canonical first-match-wins ordered-rule
//     IAP shapes); see ADR 0003 §4.x for the comparison matrix.
//   - acrValues / action — RFC 9470 step-up support + explicit
//     deny semantics per the Istio + Cloudflare hybrid.
//
// Schema lifecycle follows ADR 0003: v1alpha1 stays SERVED +
// UNTOUCHED (no field deletion at v1alpha1; the up-convert builds
// defaultPolicy from v1alpha1 flat fields; the down-convert
// flattens defaultPolicy back). pathRules don't exist in v1alpha1
// so they're silently dropped on down-convert — that's the
// canonical CRD-versioning rule (operators authoring v1beta1
// shouldn't expect data preservation through v1alpha1).
//
// +groupName=gateway.talon.example.com
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PermissionLevel matches the SpiceDB schema in ADR 0001 §5.b.
// Kept as a distinct type (rather than aliased from v1alpha1) so
// the v1beta1 schema is self-contained and a future v1alpha1
// removal doesn't ripple through the new types.
type PermissionLevel string

const (
	PermissionViewer PermissionLevel = "viewer"
	PermissionEditor PermissionLevel = "editor"
	PermissionAdmin  PermissionLevel = "admin"
)

// PathRuleAction is the allow/deny outcome when a pathRule matches.
// Default is "allow" (matches existing TalonRoute semantics). "deny"
// short-circuits the request with 403 + audit "explicit_deny" — used
// to carve carve out exceptions inside a broader allow (e.g.,
// allow /admin/* AND deny /admin/debug/* for the same role).
//
// Mirrors Istio's explicit `action: DENY` + Cloudflare app paths
// `action: block` semantics — see ADR 0003 §4.x.
type PathRuleAction string

const (
	PathRuleAllow PathRuleAction = "allow"
	PathRuleDeny  PathRuleAction = "deny"
)

// Upstream is the cluster-internal target Talon proxies to.
// Identical schema shape to v1alpha1.Upstream — preserved verbatim
// because the upstream targeting is a stable property; only policy
// authoring evolved between versions.
type Upstream struct {
	// Service is the k8s Service name. Either bare (resolves in this
	// CR's namespace) or fully qualified `<svc>.<ns>.svc(.cluster.local)?`.
	Service string `json:"service"`
	// Port is the upstream Service port.
	Port int32 `json:"port"`
	// Scheme is the upstream URL scheme (`http` or `https`). Defaults
	// to `http` when omitted. See v1alpha1 for the rationale.
	// +kubebuilder:validation:Enum=http;https
	// +optional
	Scheme string `json:"scheme,omitempty"`
}

// DeviceClaimRequirement is a single AND-clause on the id_token's
// device claims. Same shape as v1alpha1.DeviceClaimRequirement —
// preserved verbatim.
type DeviceClaimRequirement struct {
	Claim  string `json:"claim"`
	Equals string `json:"equals"`
}

// PublicRoute is a method + exact-path route on this TalonRoute that bypasses
// the Talon session gate (ZTNA enrollment-bootstrap carve-out). The upstream
// MUST self-authenticate these requests (e.g. jess verifies a WebAuthn witness
// JWS on /device-cert/attest). Match is case-insensitive method + exact path
// (after the router's hardened NormalizePath). Same shape as
// v1alpha1.PublicRoute — preserved verbatim.
type PublicRoute struct {
	// Method is the HTTP method (e.g. "POST"). Case-insensitive.
	// +kubebuilder:validation:Required
	Method string `json:"method"`
	// Path is the exact request path (e.g. "/device-cert/attest").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^/`
	Path string `json:"path"`
}

// AllowedDeviceClaimNames mirrors v1alpha1.AllowedDeviceClaimNames.
// Kept in both packages so each version's reconciler can validate
// independently without crossing the conversion boundary.
var AllowedDeviceClaimNames = []string{
	"device_id",
	"device_compliant",
	"device_managed_by_mdm",
	"device_tpm_attested",
	"device_os_version",
	"device_attestation_chain",
}

// Policy holds the per-host or per-path policy knobs that apply to
// matched requests. Used in two places:
//
//   - TalonRouteSpec.DefaultPolicy — applies when no pathRule matches.
//   - PathRule.Policy             — overlays DefaultPolicy when the
//     pathRule matches.
//
// Every field is optional + zero-valued = "inherit from above" (for
// pathRule overlays) or "use cluster default" (for DefaultPolicy).
// This is the shape that gives the operator the choice between
// flat per-host config (no pathRules; DefaultPolicy carries
// everything) AND fine-grained per-path overlay (DefaultPolicy is
// the deny-baseline, pathRules carve out allow-paths).
type Policy struct {
	// AuthMode controls which authentication channels this policy
	// accepts. Mirrors v1alpha1.TalonRouteSpec.AuthMode — see that
	// type's comment for the full enum description.
	// +kubebuilder:validation:Enum=cookie;bearer;both;bearer_or_passthrough;bearer_or_basic_with_credential_exchange;bearer_or_federated_passthrough;cookie_or_bearer_or_passthrough;anonymous
	// +optional
	AuthMode string `json:"authMode,omitempty"`

	// Permission is the SpiceDB permission name to check against the
	// talon_route resource.
	// +optional
	Permission PermissionLevel `json:"permission,omitempty"`

	// AllowedGroups grants access to members of any of these groups
	// (AND-combined with Permission).
	// +optional
	AllowedGroups []string `json:"allowedGroups,omitempty"`

	// AllowedSubjects grants access to specific Falcon-ID subject
	// UUIDs (break-glass).
	// +optional
	AllowedSubjects []string `json:"allowedSubjects,omitempty"`

	// MfaRequired forces re-auth with id_token amr=mfa.
	// +optional
	MfaRequired bool `json:"mfaRequired,omitempty"`

	// AcrValues lists the OIDC `acr` claim values that satisfy this
	// policy's step-up requirement (RFC 9470 §4). When MfaRequired
	// is true AND the cookie session's acr is not in this list, the
	// router emits an RFC 9470 401 challenge:
	//   WWW-Authenticate: Bearer error="insufficient_user_authentication" acr_values="…"
	// rather than redirecting — so both browser SDKs AND API clients
	// can re-authenticate per the spec. Empty + MfaRequired=true
	// falls back to the v1alpha1 behaviour (require amr=mfa, redirect
	// to /auth/start). Modelled on the RFC 9470 examples in Okta /
	// Keycloak / Duende / Auth0 / PingOne; see ADR 0003 §4.x.
	// +optional
	AcrValues []string `json:"acrValues,omitempty"`

	// SessionTTLOverride is the per-route ABSOLUTE session lifetime
	// in seconds — wall-clock cap, regardless of activity.
	// +optional
	SessionTTLOverride int32 `json:"sessionTtlOverride,omitempty"`

	// SessionIdleSeconds is the per-route INACTIVITY timeout.
	// +optional
	SessionIdleSeconds int32 `json:"sessionIdleSeconds,omitempty"`

	// ReauthOnNetworkChange forces a fresh OIDC handshake when the
	// request's source IP /24 differs from the CIDR bound on the
	// session at issuance time.
	// +optional
	ReauthOnNetworkChange bool `json:"reauthOnNetworkChange,omitempty"`

	// RequireDeviceClaims gates access on claims about the client
	// device emitted by Falcon-ID into the id_token.
	// +optional
	RequireDeviceClaims []DeviceClaimRequirement `json:"requireDeviceClaims,omitempty"`

	// AuditOnly downgrades EVERY enforcement check introduced by the
	// per-host session/device-claim batch from deny to audit-emit
	// only — the request still serves through.
	// +optional
	AuditOnly bool `json:"auditOnly,omitempty"`

	// ContinuousVerifyMinutes overrides the cluster default
	// continuous-verification cadence (0 = use cluster default,
	// 15m per ADR 0001 §6).
	// +optional
	ContinuousVerifyMinutes int32 `json:"continuousVerifyMinutes,omitempty"`

	// PolicyRego is an opt-in OPA Rego module that runs AFTER the
	// role filter + SpiceDB CheckPermission both ALLOW. Can only
	// NARROW access — never broaden. This is the per-route Rego escape hatch.
	// See v1alpha1.TalonRouteSpec.PolicyRego for the contract.
	// +optional
	PolicyRego string `json:"policyRego,omitempty"`

	// InjectAuthorizationBearer additionally stamps the per-request
	// X-Talon-Identity-Token JWT into the canonical Authorization
	// header. See v1alpha1.TalonRouteSpec.InjectAuthorizationBearer.
	// +optional
	InjectAuthorizationBearer bool `json:"injectAuthorizationBearer,omitempty"`

	// RequireSignedIdentityToken fails the route CLOSED (deny 5xx) when the
	// signed X-Talon-Identity-Token cannot be minted, instead of the default
	// fail-open unsigned-header fallback (ASVS 5.0 V9). OR'd with the
	// fleet-wide TALON_REQUIRE_SIGNED_IDENTITY_TOKEN floor. See
	// v1alpha1.TalonRouteSpec.RequireSignedIdentityToken.
	// +optional
	RequireSignedIdentityToken bool `json:"requireSignedIdentityToken,omitempty"`
}

// PathRuleMatch declares WHICH requests this rule applies to.
// Exactly one of Path / PathPrefix / PathRegex must be set; multiple
// set is rejected at admission time (the conversion webhook + the
// CRD's OpenAPI x-kubernetes-validations both check this).
//
// Matching happens against the NORMALIZED request path:
//   - percent-decoded (except reserved chars)
//   - double slashes (//) collapsed
//   - dot-segments (. / ..) resolved
//   - path parameters (;jsessionid=…) stripped
//
// Mirroring Envoy's `normalize_path: true` + `merge_slashes: true`
// + `path_with_escaped_slashes_action: REJECT_REQUEST` defaults.
// Percent-encoded slashes (%2F, %5C) are REJECTED by default; the
// future per-route opt-in for allow-percent-slash is out-of-scope
// for v1beta1.
type PathRuleMatch struct {
	// Path is an EXACT match (after normalization).
	// +optional
	Path string `json:"path,omitempty"`

	// PathPrefix matches if the normalized path starts with ANY of
	// these strings. Ordering inside the slice is irrelevant
	// (prefix-OR); ordering between PathRules entries IS the policy.
	// +optional
	PathPrefix []string `json:"pathPrefix,omitempty"`

	// PathRegex is an RE2 regex matched against the normalized path.
	// Compiled at admission; backreferences and lookaround are
	// rejected at admission (RE2 doesn't support them, but the CRD
	// validator catches PCRE-style patterns before they reach the
	// router).
	// +optional
	PathRegex string `json:"pathRegex,omitempty"`

	// Methods restricts the rule to specific HTTP methods. Empty =
	// all methods. Case-sensitive per RFC 7230 §3.1.1.
	// +optional
	Methods []string `json:"methods,omitempty"`
}

// PathRule is a single first-match-wins entry in PathRules.
// Evaluated in the order declared in the YAML; first match wins.
// The rule's Policy fields OVERLAY the route's DefaultPolicy —
// fields set on the rule override the default; fields unset on
// the rule inherit from the default. Action is checked first;
// "deny" short-circuits before Policy evaluation.
type PathRule struct {
	// Name uniquely identifies the rule within a TalonRoute. Used as
	// the {rule="…"} label on talon_authz_decision_total so each
	// rule's hit/miss/deny rate is independently observable. Must
	// be unique across a route's PathRules; admission rejects dupes.
	Name string `json:"name"`

	// Match declares the request-path filter.
	Match PathRuleMatch `json:"match"`

	// Action is "allow" (default) or "deny". Deny short-circuits to
	// 403 + audit "explicit_deny" before the Policy fields are
	// consulted; use it to carve out exceptions inside a broader
	// allow.
	// +kubebuilder:validation:Enum=allow;deny
	// +optional
	Action PathRuleAction `json:"action,omitempty"`

	// Policy overlays the route's DefaultPolicy for matched
	// requests. Fields set here override the default; fields unset
	// inherit from the default.
	// +optional
	Policy Policy `json:"policy,omitempty"`
}

// TalonRouteSpec is the operator-authored desired state.
type TalonRouteSpec struct {
	// Host is the public host the IngressRoute matches on
	// (e.g. prometheus.internal.example.com).
	Host string `json:"host"`

	// Upstream is the in-cluster target.
	Upstream Upstream `json:"upstream"`

	// DefaultPolicy applies when no PathRule matches. When PathRules
	// is empty, this is the host-wide policy (same semantics as
	// v1alpha1's flat fields).
	// +optional
	DefaultPolicy Policy `json:"defaultPolicy,omitempty"`

	// PathRules is the ordered, first-match-wins list of per-path
	// policy overlays. Empty = host-wide DefaultPolicy applies to
	// every request (v1alpha1-compatible behaviour). When non-empty,
	// the matcher walks the list in declared order; first match
	// wins; non-matching requests fall through to DefaultPolicy.
	// +optional
	PathRules []PathRule `json:"pathRules,omitempty"`

	// PublicPaths are method+exact-path routes on this host that bypass the
	// Talon session gate (enrollment-bootstrap carve-out). The upstream MUST
	// self-authenticate. Empty = fully gated. KEEP THIS MINIMAL — it punches a
	// hole in the IAP for exactly these method+path pairs.
	// +optional
	PublicPaths []PublicRoute `json:"publicPaths,omitempty"`
}

// TalonRouteStatus is the reconciler-authored observed state.
// Same shape as v1alpha1 — Conditions vocabulary is shared.
type TalonRouteStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	UpstreamReachable  bool               `json:"upstreamReachable,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// Standard condition types (reused from v1alpha1's vocabulary).
const (
	ConditionRegistered = "Registered"
)

// Standard reasons for ConditionRegistered.
const (
	ReasonProxyHandlerInstalled = "ProxyHandlerInstalled"
	ReasonHostAlreadyClaimed    = "HostAlreadyClaimed"
	ReasonValidationFailed      = "ValidationFailed"
	ReasonReconcileError        = "ReconcileError"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TalonRoute is one routing entry per protected admin host.
type TalonRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TalonRouteSpec   `json:"spec,omitempty"`
	Status TalonRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TalonRouteList is a list of TalonRoute.
type TalonRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TalonRoute `json:"items"`
}

// DeepCopyInto copies the receiver into out (hand-written; mirrors
// the v1alpha1 approach — no kubebuilder/controller-tools build dep).
func (in *TalonRoute) DeepCopyInto(out *TalonRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep clone of the receiver.
func (in *TalonRoute) DeepCopy() *TalonRoute {
	if in == nil {
		return nil
	}
	out := new(TalonRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *TalonRoute) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto for TalonRouteList.
func (in *TalonRouteList) DeepCopyInto(out *TalonRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]TalonRoute, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep clone of the receiver.
func (in *TalonRouteList) DeepCopy() *TalonRouteList {
	if in == nil {
		return nil
	}
	out := new(TalonRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object.
func (in *TalonRouteList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto for TalonRouteSpec.
func (in *TalonRouteSpec) DeepCopyInto(out *TalonRouteSpec) {
	*out = *in
	out.Upstream = in.Upstream
	in.DefaultPolicy.DeepCopyInto(&out.DefaultPolicy)
	if in.PathRules != nil {
		out.PathRules = make([]PathRule, len(in.PathRules))
		for i := range in.PathRules {
			in.PathRules[i].DeepCopyInto(&out.PathRules[i])
		}
	}
	if in.PublicPaths != nil {
		out.PublicPaths = append([]PublicRoute(nil), in.PublicPaths...)
	}
}

// DeepCopyInto for TalonRouteStatus.
func (in *TalonRouteStatus) DeepCopyInto(out *TalonRouteStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyInto for Policy.
func (in *Policy) DeepCopyInto(out *Policy) {
	*out = *in
	if in.AllowedGroups != nil {
		out.AllowedGroups = append([]string(nil), in.AllowedGroups...)
	}
	if in.AllowedSubjects != nil {
		out.AllowedSubjects = append([]string(nil), in.AllowedSubjects...)
	}
	if in.AcrValues != nil {
		out.AcrValues = append([]string(nil), in.AcrValues...)
	}
	if in.RequireDeviceClaims != nil {
		out.RequireDeviceClaims = append([]DeviceClaimRequirement(nil), in.RequireDeviceClaims...)
	}
}

// DeepCopyInto for PathRule.
func (in *PathRule) DeepCopyInto(out *PathRule) {
	*out = *in
	in.Match.DeepCopyInto(&out.Match)
	in.Policy.DeepCopyInto(&out.Policy)
}

// DeepCopyInto for PathRuleMatch.
func (in *PathRuleMatch) DeepCopyInto(out *PathRuleMatch) {
	*out = *in
	if in.PathPrefix != nil {
		out.PathPrefix = append([]string(nil), in.PathPrefix...)
	}
	if in.Methods != nil {
		out.Methods = append([]string(nil), in.Methods...)
	}
}
