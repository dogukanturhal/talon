// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1alpha1 holds the TalonRoute CR types. Schema lifecycle
// follows ADR 0003: never delete fields at v1alpha1; rename / shape
// changes ship as v1beta1 with a conversion webhook.
//
// +groupName=gateway.talon.example.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PermissionLevel matches the SpiceDB schema in ADR 0001 §5.b.
type PermissionLevel string

const (
	PermissionViewer PermissionLevel = "viewer"
	PermissionEditor PermissionLevel = "editor"
	PermissionAdmin  PermissionLevel = "admin"
)

// Upstream is the cluster-internal target Talon proxies to.
type Upstream struct {
	// Service is the k8s Service name. Either bare (resolves in this CR's
	// namespace) or fully qualified `<svc>.<ns>.svc(.cluster.local)?`.
	Service string `json:"service"`
	// Port is the upstream Service port.
	Port int32 `json:"port"`
	// Scheme is the upstream URL scheme (`http` or `https`). Defaults to
	// `http` when omitted. Use `https` for upstreams that terminate TLS
	// at the application layer (e.g. SafeLine mgt nginx on :1443 which
	// returns a JS-redirect on plain HTTP and only serves the SPA over
	// HTTPS). Talon dials the upstream with the declared scheme;
	// in-cluster cert verification follows the existing transport defaults
	// — Linkerd mTLS is the security boundary for in-cluster traffic, not
	// the upstream's self-signed cert.
	// +kubebuilder:validation:Enum=http;https
	// +optional
	Scheme string `json:"scheme,omitempty"`
}

// TalonRouteSpec is the operator-authored desired state.
type TalonRouteSpec struct {
	// Host is the public host the IngressRoute matches on (e.g. prometheus.internal.example.com).
	Host string `json:"host"`
	// Upstream is the in-cluster target.
	Upstream Upstream `json:"upstream"`
	// Permission is the SpiceDB permission name to check against the talon_route resource.
	// +optional
	Permission PermissionLevel `json:"permission,omitempty"`
	// AllowedGroups grants access to members of any of these groups (AND-combined with Permission).
	// +optional
	AllowedGroups []string `json:"allowedGroups,omitempty"`
	// AllowedSubjects grants access to specific Falcon-ID subject UUIDs (break-glass).
	// +optional
	AllowedSubjects []string `json:"allowedSubjects,omitempty"`
	// SessionTTLOverride is the per-route ABSOLUTE session lifetime in
	// seconds — wall-clock cap, regardless of activity. Enforced at
	// request time in the router (see internal/router): when
	// now - session.IAT > SessionTTLOverride, the user is bounced to
	// /auth/start. 0 = use cluster default. Capped at 28800 (8h) per
	// ADR 0002 §3.1. Per-host control modelled on Pomerium per-route
	// `timeout` and Cloudflare Zero Trust application session duration.
	// +optional
	SessionTTLOverride int32 `json:"sessionTtlOverride,omitempty"`
	// SessionIdleSeconds is the per-route INACTIVITY timeout. Enforced at
	// request time: when now - session.LastSeen > SessionIdleSeconds, the
	// user is bounced to /auth/start. 0 = no idle limit (cluster default).
	// Must be <= SessionTTLOverride (or cluster default if zero) — the
	// reconciler rejects values that exceed the absolute cap. Modelled on
	// Pomerium `idle_timeout` and Microsoft Entra Conditional Access
	// "sign-in frequency" idle policy.
	// +optional
	SessionIdleSeconds int32 `json:"sessionIdleSeconds,omitempty"`
	// ReauthOnNetworkChange forces a fresh OIDC handshake when the
	// request's source IP /24 differs from the CIDR bound on the
	// session at issuance time. Defense-in-depth for admin-tier routes —
	// catches stolen-cookie replay from a different network without
	// breaking legitimate IP rotation within the same /24 (NAT, mobile
	// hand-off). Off by default; opt-in per route. Modelled on
	// Pomerium `force_reauth_on_address_change`.
	// +optional
	ReauthOnNetworkChange bool `json:"reauthOnNetworkChange,omitempty"`
	// PublicPaths are method+exact-path routes on this host that bypass the
	// Talon session gate (enrollment-bootstrap carve-out). The upstream MUST
	// self-authenticate. Empty = fully gated. KEEP THIS MINIMAL — it punches a
	// hole in the IAP for exactly these method+path pairs.
	// +optional
	PublicPaths []PublicRoute `json:"publicPaths,omitempty"`
	// RequireDeviceClaims gates access on claims about the client device
	// emitted by Falcon-ID into the id_token (e.g. device_compliant,
	// device_managed_by_mdm). Each requirement must match (AND-combined).
	// Claim names are validated against an allow-list at reconcile time
	// — unknown names cause Registered=False so typos surface immediately
	// instead of silently never matching. Missing claim at request time
	// FAILS CLOSED (deny + audit "device_claim_missing"); never falls
	// open with a warning. Schema landed ahead of MDM onboarding so
	// policies can be authored now and become live the day the IdP starts
	// emitting the claims. Modelled on Microsoft Entra Conditional Access
	// device-compliance grant control + Cloudflare Zero Trust device
	// posture.
	// +optional
	RequireDeviceClaims []DeviceClaimRequirement `json:"requireDeviceClaims,omitempty"`
	// AuditOnly downgrades EVERY new per-route enforcement check
	// introduced by the per-host session/device-claim batch (TTL expiry,
	// idle expiry, IP rebind, device-claim missing/mismatch) from deny
	// to audit-emit only — the request still serves through. Existing
	// checks (group/role, SpiceDB, Rego, MFA, sliding session, CV) are
	// UNAFFECTED and continue to enforce. Used for the one-week soak
	// before flipping a route to enforce; remove after audit confirms
	// no legitimate traffic would have been denied. Defaults to false.
	// +optional
	AuditOnly bool `json:"auditOnly,omitempty"`
	// ContinuousVerifyMinutes overrides the cluster default continuous-verification cadence.
	// 0 = use cluster default (15m, ADR 0001 §6).
	// +optional
	ContinuousVerifyMinutes int32 `json:"continuousVerifyMinutes,omitempty"`
	// MfaRequired (Phase 4) forces re-auth with id_token amr=mfa to access this route.
	// +optional
	MfaRequired bool `json:"mfaRequired,omitempty"`
	// Sensitivity declares the route's sensitivity class for ZTNA
	// Rego policy gating. Projected into `RegoInputPosture.Compliance.
	// route_sensitivity` by the reconciler so the ZTNA baseline bundle
	// (`docs/policy/ztna/ztna_baseline.rego`) can apply the tier × AAL
	// × sensitivity matrix without operators having to encode the
	// value in every TalonRoute's posture stub.
	//
	// Valid values per ADR 0040 Phase 5 contract:
	//   - "low"      — public-ish admin tools (Grafana dashboards, etc.)
	//   - "medium"   — operator surfaces (default if unset)
	//   - "high"     — security-sensitive routes (Wazuh, Falco)
	//   - "critical" — vault, kube-apiserver, ArgoCD admin
	//
	// Empty string defaults to "medium". Unknown values FAIL the route
	// reconcile (Registered=False reason=ValidationFailed) so typos
	// surface immediately. Default of medium matches the Rego baseline's
	// route_sensitivity fallback so a route that omits this field
	// behaves identically before and after the field lands.
	// +optional
	// +kubebuilder:validation:Enum=low;medium;high;critical
	Sensitivity string `json:"sensitivity,omitempty"`
	// AllowClientless opts this route into agentless/clientless browser
	// access (ADR 0044). A clientless session has NO device cert and asserts
	// only browser-attestable signals (Falcon-ID WebAuthn, IP/geo/UA), so it
	// is projected into Rego as `input.session.channel = "clientless"`.
	//
	// Fail-closed default: when this is false (the default), Talon HARD-DENIES
	// any clientless-channel request to this route whose Sensitivity is
	// "critical" — agentless devices cannot reach critical routes unless the
	// operator explicitly opts in here. Non-critical routes still serve
	// clientless traffic subject to the Rego policy + AAL cap. Setting this
	// true lifts the critical-route hard deny so the Rego baseline alone
	// governs (operators SHOULD still gate such routes on WebAuthn + JIT).
	// +optional
	AllowClientless bool `json:"allowClientless,omitempty"`
	// ClientlessMaxTTL is the ABSOLUTE session lifetime (seconds) Talon
	// enforces for clientless-channel sessions on this route, independent of
	// (and capped below) SessionTTLOverride. Agentless sessions are time-boxed
	// tighter than agent sessions since they carry no device posture. 0 = use
	// the cluster clientless default. Ignored for non-clientless sessions.
	// +optional
	ClientlessMaxTTL int32 `json:"clientlessMaxTtl,omitempty"`
	// PolicyRego is an opt-in OPA Rego module that runs AFTER the role
	// filter + SpiceDB CheckPermission both ALLOW. Rego can only NARROW
	// access — never broaden — so the upper layer must already allow
	// before the module evaluates. This is the per-route Rego escape hatch.
	//
	// The module must declare `package talon.route` and expose
	// `allow: bool`. Default semantics: `default allow := true` so an
	// empty rule set is a no-op; rules add conditions that flip allow
	// to false on tenant mismatch, time-of-day, source IP CIDR, AMR
	// requirements, etc.
	//
	// Compile failures fail the route reconcile (Status condition
	// Registered=False reason=ValidationFailed) so a malformed module
	// doesn't ship to production.
	// +optional
	PolicyRego string `json:"policyRego,omitempty"`
	// InjectAuthorizationBearer additionally stamps the per-request
	// X-Talon-Identity-Token JWT into the canonical
	//   Authorization: Bearer <jwt>
	// header. Opt-in per route because Authorization is a hop-by-hop
	// semantic many upstreams already consume for their own purposes —
	// blindly overwriting it can break apps that ship their own OAuth /
	// service-account / API-key flow. Pomerium ships a similar
	// `pass_identity_headers` knob; Cloudflare Access keeps Authorization
	// reserved by default and exposes the JWT only on the dedicated
	// Cf-Access-Jwt-Assertion header. We model on Pomerium's posture: do
	// not touch Authorization unless the operator explicitly opts in.
	//
	// Use cases (opt-in true):
	//   - Grafana (auth.proxy + jwt_auth mode) — consumes Authorization
	//     as the trust assertion.
	//   - Argo CD with `accounts.<name>.enabled: apiKey` — expects
	//     Authorization Bearer.
	//   - Generic Go services using github.com/coreos/go-oidc.
	//
	// Use cases (opt-in false — the default):
	//   - Any upstream that already auths to a backend (Authorization is
	//     theirs).
	//   - Next.js SDK consumers (they read X-Talon-Identity-Token
	//     directly via @hexxlock/falcon-id-client).
	//
	// Per-route placement is intentional: it's a service-specific
	// contract, not a cluster-wide policy. Strip-then-inject ordering
	// in proxy.go ensures a client-supplied Authorization can never
	// reach the upstream when this is enabled.
	// +optional
	InjectAuthorizationBearer bool `json:"injectAuthorizationBearer,omitempty"`
	// RequireSignedIdentityToken makes a signed-identity-token mint failure
	// FAIL CLOSED for this route (deny 5xx) instead of the default fail-open
	// unsigned-header fallback (ASVS 5.0 V9). Opt-in per route: enable it as
	// each downstream finishes verifying the signed X-Talon-Identity-Token,
	// so an unmigrated service is never suddenly starved of the unsigned
	// X-Talon-* headers it still relies on. The effective value is OR'd with
	// the fleet-wide TALON_REQUIRE_SIGNED_IDENTITY_TOKEN floor — a route can
	// tighten but never fall below it. Default false preserves the Phase A/B
	// transitional posture. See docs/architecture/0005-iap-identity-token.md.
	// +optional
	RequireSignedIdentityToken bool `json:"requireSignedIdentityToken,omitempty"`
	// AuthMode controls which authentication channels this route accepts.
	// Mirrors the svctoken AuthMode enum (see
	// internal/svctoken/middleware.go) and the static
	// TALON_PROTECTED_HOSTS_JSON authMode field for parity between the
	// env-var pilot path and the GitOps CRD path. Recognised values:
	//
	//   "" or "cookie"          — browser-only (default; back-compat).
	//                             Bearer headers ignored; cookie/OIDC
	//                             dance every request.
	//   "bearer"                — machine-only. Missing/invalid Bearer →
	//                             401, no OIDC dance.
	//   "both"                  — Bearer-first, cookie fallback for hosts
	//                             that want IAP for browsers AND Bearer
	//                             for machines on the same hostname.
	//   "bearer_or_passthrough" — Bearer-first; when no Bearer header
	//                             present, proxy DIRECTLY to upstream
	//                             with original Authorization header
	//                             intact (no OIDC dance). Enterprise
	//                             BeyondCorp pattern for hosts where
	//                             machine consumers use legacy native
	//                             auth (Basic PAT etc.) and we want to
	//                             add Bearer additively without breaking
	//                             those consumers. See
	//                             docs/specs/talon-service-tokens.md.
	//   "bearer_or_basic_with_credential_exchange" —
	//                             Phase 4.5 credential-exchange mode.
	//                             Bearer OR Basic(*:<jwt>) verified
	//                             against Falcon-ID, then inbound
	//                             Authorization is stripped and
	//                             substituted with a per-host upstream
	//                             credential (PAT / robot) sourced
	//                             from a Secret in the talon ns.
	//   "bearer_or_federated_passthrough" —
	//                             Phase 5+ federated-trust mode. Like
	//                             bearer_or_passthrough but ALSO
	//                             accepts JWTs signed by configured
	//                             SECONDARY trusted issuers
	//                             (svctoken.federatedIssuers in
	//                             Helm values) — sig + exp verified,
	//                             Bearer preserved on the outgoing
	//                             request, upstream re-validates its
	//                             own claim shape. Required for
	//                             fronting Docker Registry v2 upstreams
	//                             (Harbor) that issue their own
	//                             Bearer JWTs via /service/token.
	//                             Envoy CVE-2021-21378 invariant
	//                             preserved: unknown iss → 401.
	//   "cookie_or_bearer_or_passthrough" —
	//                             Path B unified mode. Combines cookie
	//                             SSO (browser path), Bearer-or-Basic
	//                             credential exchange (svctoken
	//                             machine path), legacy Basic
	//                             passthrough (PAT path), and federated
	//                             Bearer trust on a SINGLE hostname.
	//                             Dispatch is wire-shape-driven:
	//                               · no Authorization header →
	//                                 OutcomeNotAttempted (cookie/OIDC
	//                                 dance runs; defense-in-depth
	//                                 device-posture enforcement before
	//                                 the request reaches upstream).
	//                               · Bearer<svctoken> valid →
	//                                 OutcomeAuthorised (credential-
	//                                 exchange substitutes upstream
	//                                 credential downstream).
	//                               · Basic<*:svctoken> valid → same.
	//                               · Basic<*:legacy-PAT> (non-JWT
	//                                 password) → OutcomePassthrough
	//                                 (upstream's native PAT auth).
	//                               · Bearer<federated-iss> valid →
	//                                 OutcomePassthrough (Bearer header
	//                                 preserved; upstream re-validates).
	//                               · Bearer present but broken → 401
	//                                 (Envoy CVE-2021-21378 invariant —
	//                                 never silently downgrade a
	//                                 present-but-broken identity
	//                                 assertion).
	//                             Use for tier-1 unified surfaces such
	//                             as github.com where
	//                             browser SSO (with posture), machine
	//                             svctoken consumers (ArgoCD), and
	//                             legacy PAT callers (Atlantis) all
	//                             share the same hostname. NOT suitable
	//                             for Docker Registry v2 surfaces
	//                             (Harbor) — Docker clients begin every
	//                             pull with no-auth GET /v2/ expecting
	//                             a 401 + WWW-Authenticate challenge;
	//                             routing that to the cookie/OIDC path
	//                             would break the dance. Harbor uses
	//                             bearer_or_federated_passthrough.
	//
	// Cluster-side svctoken feature flag (TALON_SVCTOKEN_ENABLED) must
	// be true for any non-cookie mode to actually consult Bearer headers;
	// otherwise the upstream is registered with authMode=cookie (the
	// safe default that matches today's behaviour).
	// +kubebuilder:validation:Enum=cookie;bearer;both;bearer_or_passthrough;bearer_or_basic_with_credential_exchange;bearer_or_federated_passthrough;cookie_or_bearer_or_passthrough
	// +optional
	AuthMode string `json:"authMode,omitempty"`
}

// PublicRoute is a method + exact-path route on this TalonRoute that bypasses
// the Talon session gate (ZTNA enrollment-bootstrap carve-out). The upstream
// MUST self-authenticate these requests (e.g. jess verifies a WebAuthn witness
// JWS on /device-cert/attest). Match is case-insensitive method + exact path
// (after the router's hardened NormalizePath).
type PublicRoute struct {
	// Method is the HTTP method (e.g. "POST"). Case-insensitive.
	// +kubebuilder:validation:Required
	Method string `json:"method"`
	// Path is the exact request path (e.g. "/device-cert/attest").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^/`
	Path string `json:"path"`
}

// DeviceClaimRequirement is a single AND-clause on the id_token's device
// claims. Wildcards are forbidden on purpose: the operator must enumerate
// the exact claim+value to require. Lets policy diffs read like English.
type DeviceClaimRequirement struct {
	// Claim is the id_token claim name. Validated against the allow-list
	// in AllowedDeviceClaimNames at reconcile time — unknown names cause
	// the route's Registered condition to flip False with reason
	// ValidationFailed. The allow-list is intentionally short to prevent
	// drift via typo + to keep the IdP-side claim contract auditable.
	Claim string `json:"claim"`
	// Equals is the exact-string value the claim must hold. Booleans are
	// compared as their stringified form ("true"/"false") so the schema
	// stays simple. Numbers are compared as decimal strings. Empty string
	// is rejected at reconcile time (use the absence of a requirement
	// instead of an empty equals).
	Equals string `json:"equals"`
}

// AllowedDeviceClaimNames is the validation allow-list for
// DeviceClaimRequirement.Claim. Keep this list short — every entry
// requires the IdP (Falcon-ID) to emit the corresponding id_token claim,
// so adding a name here without IdP support produces a fail-closed deny
// for any route that uses it. Update in coordination with the Falcon-ID
// claim-mapping rules.
var AllowedDeviceClaimNames = []string{
	"device_id",
	"device_compliant",
	"device_managed_by_mdm",
	"device_tpm_attested",
	"device_os_version",
	"device_attestation_chain",
}

// TalonRouteStatus is the reconciler-authored observed state.
type TalonRouteStatus struct {
	// ObservedGeneration is the .metadata.generation the latest reconcile observed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// UpstreamReachable is set true when a recent probe to the upstream succeeded.
	UpstreamReachable bool `json:"upstreamReachable,omitempty"`
	// Conditions report the reconcile outcome.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Standard condition types.
const (
	// ConditionRegistered means the route handler is installed in the in-process router.
	ConditionRegistered = "Registered"

	// ConditionSecurityPolicyAccepted reflects the upstream Envoy Gateway
	// SecurityPolicy.status.conditions[type=Accepted] back into the
	// TalonRoute. Operators can `kubectl wait --for=condition=
	// SecurityPolicyAccepted talonroute/foo` instead of cross-namespace
	// inspecting envoy-gateway-system. Only set when the SecurityPolicy
	// translator is enabled (cfg.SecurityPolicyEnabled); absent when
	// disabled so existing automations don't see "missing condition"
	// false-positives.
	ConditionSecurityPolicyAccepted = "SecurityPolicyAccepted"
)

// Standard reasons for ConditionRegistered.
const (
	ReasonProxyHandlerInstalled = "ProxyHandlerInstalled"
	ReasonHostAlreadyClaimed    = "HostAlreadyClaimed"
	ReasonValidationFailed      = "ValidationFailed"
	ReasonReconcileError        = "ReconcileError"
)

// Standard reasons for ConditionSecurityPolicyAccepted.
const (
	ReasonSecurityPolicyAccepted    = "Accepted"
	ReasonSecurityPolicyNotFound    = "NotFound"
	ReasonSecurityPolicyRejected    = "Rejected"
	ReasonSecurityPolicyDisabled    = "Disabled"
	ReasonSecurityPolicyEnsureError = "EnsureError"
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

// DeepCopyInto copies the receiver into out (hand-written; avoids the
// kubebuilder/controller-tools build dep — types are small and stable).
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

// DeepCopyInto copies the receiver into out.
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
	if in.AllowedGroups != nil {
		out.AllowedGroups = append([]string(nil), in.AllowedGroups...)
	}
	if in.AllowedSubjects != nil {
		out.AllowedSubjects = append([]string(nil), in.AllowedSubjects...)
	}
	if in.RequireDeviceClaims != nil {
		out.RequireDeviceClaims = append([]DeviceClaimRequirement(nil), in.RequireDeviceClaims...)
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
