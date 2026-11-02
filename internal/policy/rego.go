// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy — rego.go is the Tier-1 Gap 5 escape hatch. After the
// role filter + SpiceDB CheckPermission both ALLOW, an operator can opt
// a route into a Rego policy that NARROWS access further. Rego can only
// narrow, never broaden — the upper layer must already allow before
// rego runs at all.
//
// Module contract: the operator's Rego must declare
//
//	package talon.route
//
// and expose an `allow` boolean. Default semantics: `default allow :=
// true` so an empty rule set is a no-op; the operator's rules then add
// conditions that flip allow to false (e.g. time-of-day, source IP CIDR,
// User-Agent fingerprint).
//
// Why a Rego escape hatch and not arbitrary Go: the operator-authored
// path goes through OPA's safety / type analysis, can be unit-tested
// against the same evaluator (talon test policy — separate MR), and is
// portable to Cedar for the equivalence CI gate (separate MR).
//
// Pomerium ships PPL→Rego at the Enterprise tier; OSS Linkerd has no
// equivalent. Talon shipping Rego at the OSS tier is the
// boot-prompt-§4-Gap-5 differentiator.
package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// RegoInput is the canonical document Talon hands to the operator's
// Rego module as `input`. Field names mirror the audit log shape so
// policies stay write-once / read-many.
type RegoInput struct {
	User    RegoInputUser    `json:"user"`
	Route   RegoInputRoute   `json:"route"`
	Request RegoInputRequest `json:"request"`
	// Session carries non-credential session attributes. `channel`
	// distinguishes agent device-cert sessions ("cookie"/"bearer") from
	// agentless browser sessions ("clientless", ADR 0044) so policy can apply
	// a stricter posture/MFA/JIT bar to the latter.
	Session RegoInputSession `json:"session"`
	// Posture is the decoded device-posture assertion from the
	// X-Talon-Posture header (ADR 0011). Nil when the request did not
	// carry a posture header OR the posture verifier is not wired.
	// Operators write Rego rules like:
	//
	//   default allow := true
	//   allow if {
	//     input.posture.compliance.disk_encrypted == true
	//     input.posture.compliance.os == "macos"
	//   }
	//
	// to layer device-trust on top of the route's basic posture
	// requirement (declared via TalonRoute.spec.requirePosture).
	Posture *RegoInputPosture `json:"posture,omitempty"`
	// DeviceMTLS is the device identity from the public-edge client cert
	// (Envoy XFCC, trusted only from the Envoy service account). Nil when the
	// device-mTLS edge is not configured; otherwise always set, with
	// present=false when no trusted cert accompanied the request.
	DeviceMTLS *RegoInputDeviceMTLS `json:"device_mtls,omitempty"`
}

// RegoInputDeviceMTLS mirrors devicemtls.Identity for Rego.
type RegoInputDeviceMTLS struct {
	Present  bool   `json:"present"`
	Valid    bool   `json:"valid"`
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"` // "browser" | "device"
	Channel  string `json:"channel"`
}

// RegoInputUser is the subset of session.Blob the policy can read.
// Refresh-token / id-token-jti / csrf-token are deliberately excluded —
// the policy has no business with credential material.
type RegoInputUser struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	Roles    []string `json:"roles"`
	TenantID string   `json:"tenant_id,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// AMRRecencySeconds is the number of seconds since the user's
	// strongest factor was last asserted. Populated by Talon's session
	// blob projection (last_webauthn_at delta). Used by the ZTNA Rego
	// baseline (docs/policy/ztna/ztna_baseline.rego) to gate critical
	// routes on a 1h step-up window per NIST SP 800-63B-4 §4.3.2.
	// Conservative default: 0 when unknown (Rego policy treats 0 + the
	// `or` recency_seconds default as fresh).
	AMRRecencySeconds int64 `json:"amr_recency_seconds,omitempty"`
}

// RegoInputRoute carries the per-route metadata the operator's policy
// most often keys on (host + the SpiceDB permission level the request
// is being checked against).
type RegoInputRoute struct {
	Host       string `json:"host"`
	Permission string `json:"permission"`
	// Sensitivity is the operator-declared route class
	// ("low"|"medium"|"high"|"critical"); empty when unset. Lives here (not
	// in posture.compliance) so a missing posture is not masked by a
	// synthetic posture object created only to carry it.
	Sensitivity string `json:"sensitivity,omitempty"`
}

// RegoInputRequest is the per-request envelope. Talon populates these
// from the in-flight HTTP request before evaluating.
type RegoInputRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	SrcIP  string `json:"src_ip,omitempty"`
}

// RegoInputSession is the non-credential session metadata the policy may
// read. Channel ∈ {"cookie","bearer","clientless"} (ADR 0044): "clientless"
// marks an agentless browser session (no device cert) reaching Talon via the
// access zone. Policy keys on it to cap AAL / require JIT / deny critical
// routes for agentless sessions.
type RegoInputSession struct {
	Channel string `json:"channel"`
}

// Session channel constants (ADR 0044).
const (
	ChannelCookie     = "cookie"
	ChannelBearer     = "bearer"
	ChannelClientless = "clientless"
)

// RegoInputPosture is the device-posture assertion projected for
// Rego consumption. Fields mirror internal/posture.Claims but
// flattened so operators write `input.posture.compliance.<key>`
// instead of `input.posture.compliance["key"]` for the common case.
//
// The internal/posture package owns the structural verification +
// trust-chain check; this struct is the policy-facing projection.
// Empty Compliance map = posture verifier ran but the assertion
// carried no claims (operator policy can deny on that).
type RegoInputPosture struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	UserSub   string `json:"user_sub,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`

	// Degraded is true when the posture verified structurally AND by signature
	// but is past its hard exp/MaxAge and is being served within Talon's
	// governed grace budget (DDIL P3.10). Policy MUST treat a degraded posture
	// as admissible only for low/medium routes; the Go PEP enforces the same
	// critical/high deny as defense-in-depth (see internal/router), so a
	// custom Rego that ignores this field cannot widen access past the gate.
	Degraded bool `json:"degraded,omitempty"`

	// GraceUntil is the unix-seconds instant the degraded posture will fail
	// closed. Zero when not degraded.
	GraceUntil int64 `json:"grace_until,omitempty"`

	Compliance map[string]any `json:"compliance"`
}

// RegoEvaluator wraps a compiled, prepared Rego query for one route's
// policy module. Construct via CompileRego at reconcile time so a
// malformed module fails the TalonRoute reconcile rather than every
// in-flight request.
type RegoEvaluator struct {
	query rego.PreparedEvalQuery
}

// CompileRego parses + compiles + prepares the operator-supplied Rego
// module string. Returns (nil, nil) for an empty module — the caller
// treats nil as "no narrowing" and skips evaluation entirely.
//
// The module is registered under filename "talon_route.rego" so OPA's
// error messages reference the right source.
func CompileRego(ctx context.Context, module string) (*RegoEvaluator, error) {
	if module == "" {
		return nil, nil
	}
	// Query the whole `data.talon.route` document (not just `.allow`) so we
	// can also surface `deny_reason` — the concrete, audit-log-friendly
	// cause the ZTNA baseline computes (e.g. "ztna: AAL3 required"). Without
	// it operators only ever see the generic `rego_denied` and cannot tell
	// AAL from posture-staleness from tier during a rollout.
	q, err := rego.New(
		rego.Query("data.talon.route"),
		rego.Module("talon_route.rego", module),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego compile: %w", err)
	}
	return &RegoEvaluator{query: q}, nil
}

// Evaluate runs the prepared query against input. Returns true (allow)
// or false (deny). A nil receiver returns true — the "no policy
// configured" path collapses to a no-op so callers don't have to nil-
// check around every call site.
//
// Returning a bool keeps the contract minimal: callers compose this AS
// the narrow step, treating any false as a final deny. Errors are
// surfaced (fail-closed at the caller's policy layer), not swallowed.
func (r *RegoEvaluator) Evaluate(ctx context.Context, in *RegoInput) (bool, error) {
	allow, _, err := r.EvaluateWithReason(ctx, in)
	return allow, err
}

// EvaluateWithReason runs the prepared query and returns (allow,
// denyReason, error). denyReason is the module's
// `data.talon.route.deny_reason` string — the concrete, operator-authored
// cause surfaced to the audit log + 403 body on a deny (empty on allow, or
// when the module defines no deny_reason). A nil receiver returns
// (true, "", nil) — the "no policy configured" no-op.
func (r *RegoEvaluator) EvaluateWithReason(ctx context.Context, in *RegoInput) (bool, string, error) {
	if r == nil {
		return true, "", nil
	}
	rs, err := r.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return false, "", fmt.Errorf("rego eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		// `data.talon.route` was undefined — treat as no-narrowing.
		return true, "", nil
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return false, "", fmt.Errorf("rego 'data.talon.route' must be an object, got %T", rs[0].Expressions[0].Value)
	}
	// `allow` absent = the module defines no allow rule → no-narrowing.
	// Operators who want hard-deny write `default allow := false`.
	av, present := doc["allow"]
	if !present {
		return true, "", nil
	}
	allow, ok := av.(bool)
	if !ok {
		return false, "", fmt.Errorf("rego module 'allow' must be bool, got %T", av)
	}
	// deny_reason is best-effort (a module may omit it) and only meaningful
	// on a deny.
	reason, _ := doc["deny_reason"].(string)
	if allow {
		reason = ""
	}
	return allow, reason, nil
}
