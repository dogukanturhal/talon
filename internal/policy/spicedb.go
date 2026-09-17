// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy — spicedb.go composes the Phase-1 role filter with
// the Phase-2.1 SpiceDB CheckPermission. PE evaluates in this order:
//
//  1. Role filter (cluster-wide RequiredRole gate; cheap)
//  2. SpiceDB CheckPermission (per-route relation; cached 30s)
//
// SpiceDB outage = fail-closed (deny + audit), per ADR 0001 §7.b §10.a.
package policy

import (
	"context"

	tlog "github.com/dogukanturhal/talon/internal/log"
	"github.com/dogukanturhal/talon/internal/session"
	"github.com/dogukanturhal/talon/internal/spicedb"
)

// RoleGateMode controls the Phase-1 cluster-wide RoleFilter.
//
// WHY THIS IS CONFIGURABLE AT ALL
// ===============================
// The RoleFilter requires ONE role (TALON_REQUIRED_ROLE, in practice
// platform_admin) across EVERY Talon-fronted host. That is a global gate
// with no way to say "reading an npm package is not the same act as
// administering Vault" — so granting a developer package access means
// making them a cluster admin.
//
// This is a recognised anti-pattern rather than a local quirk: Azure
// Container Registry hit exactly it (RBAC scoped only at registry level,
// forcing all-or-nothing permissions) and answered with per-repository
// ABAC conditions. Identity-aware proxies converge on the same shape —
// in Google's IAP the role IS bound per-resource, so the role gate and
// the resource binding are one mechanism rather than two layers.
//
// Talon already has the per-resource half: every TalonRoute's
// allowedGroups is projected into SpiceDB by the controller, and
// policy/group.go's own comment says "SpiceDB Phase 2.1 supersedes this
// with relation-based CheckPermission". The Phase-1 filter simply never
// got retired, and it still runs first and denies.
//
// Retiring it is safe by inspection of the current data — every route
// carries allowedGroups: [platform_admin], so platform_admin passes via
// its per-route relation regardless — but "safe by inspection" is not
// something to take on faith for the gate in front of Vault and ArgoCD.
// Hence a mode with a shadow step, which is the standard migration for
// this exact move: run both, let the legacy check decide, and log where
// the new model would have disagreed.
type RoleGateMode string

const (
	// RoleGateEnforce is the legacy behaviour and the default: a session
	// lacking the cluster-wide role is denied before SpiceDB is consulted.
	RoleGateEnforce RoleGateMode = "enforce"

	// RoleGateShadow evaluates the RoleFilter but does NOT act on it —
	// SpiceDB decides. Disagreements are logged so the per-route model can
	// be validated against real traffic before cutover.
	RoleGateShadow RoleGateMode = "shadow"

	// RoleGateOff skips the RoleFilter entirely. SpiceDB's per-route
	// relations are the sole authority.
	RoleGateOff RoleGateMode = "off"
)

// ParseRoleGateMode maps config text to a mode, defaulting to the safe
// legacy behaviour for anything unrecognised — a typo in an env var must
// not silently remove an authorisation gate.
func ParseRoleGateMode(s string) RoleGateMode {
	switch RoleGateMode(s) {
	case RoleGateShadow:
		return RoleGateShadow
	case RoleGateOff:
		return RoleGateOff
	default:
		return RoleGateEnforce
	}
}

// CompositePolicy is the Phase-2.1 PE: role gate + SpiceDB authz.
// SpiceDB is optional (nil = Phase-1 behaviour, role-only).
type CompositePolicy struct {
	role     *RoleFilter
	spicedb  *spicedb.CachedClient
	gateMode RoleGateMode
}

// NewCompositePolicy returns a PE that runs the role filter first, then
// (if spicedbClient is non-nil) checks SpiceDB CheckPermission.
//
// gateMode governs the role filter; the zero value ("") resolves to
// enforce, so an un-migrated caller keeps today's behaviour.
func NewCompositePolicy(role *RoleFilter, spicedbClient *spicedb.CachedClient, gateMode RoleGateMode) *CompositePolicy {
	if gateMode == "" {
		gateMode = RoleGateEnforce
	}
	return &CompositePolicy{role: role, spicedb: spicedbClient, gateMode: gateMode}
}

// Evaluate runs both checks in order.
//
// host + permission must be set for SpiceDB. If either is empty the
// behaviour now depends on gateMode: under `enforce` the RoleFilter's
// verdict stands (legacy behaviour, still useful for the auth host's own
// /auth/* endpoints which need no per-route gating), while under
// `shadow`/`off` there is no gate left to inherit from and the request is
// DENIED rather than allowed.
//
// sensitivity is the route's ZTNA sensitivity class ("critical" | "high"
// | "medium" | "low" | ""). It selects the shorter DDIL offline-decision
// budget for the more-sensitive classes (privileged tier, 5m vs 15m) so a
// SpiceDB partition degrades sensitive routes more conservatively.
func (p *CompositePolicy) Evaluate(ctx context.Context, b *session.Blob, host, permission, sensitivity string) Verdict {
	// Role gate first — subject to gateMode.
	v := p.role.Evaluate(ctx, b)
	switch p.gateMode {
	case RoleGateEnforce:
		if v.Decision != Allow {
			return v
		}
	case RoleGateShadow:
		// Do not act on it; record where the per-route model diverges so
		// the cutover is driven by observed traffic rather than optimism.
		// Logged at WARN because a divergence is precisely the thing an
		// operator running a shadow needs surfaced, not buried at debug.
		if v.Decision != Allow {
			tlog.From(ctx).Warn("policy: role gate SHADOW — legacy filter would have denied, SpiceDB now decides",
				"host", host, "sub", b.Sub, "perm", permission, "reason", v.Reason)
		}
	case RoleGateOff:
		// Not consulted.
	}

	// FAIL CLOSED when SpiceDB cannot be consulted.
	//
	// The legacy code returned the RoleFilter's Allow here, which was
	// defensible only because that filter had just gated the request. With
	// the gate in shadow/off there is NOTHING behind this branch, so
	// returning Allow would turn a missing route permission — or a
	// SpiceDB-less deployment — into open access on every host at once.
	// That is the single most dangerous way for this change to be wrong,
	// so the branch denies instead of inheriting a verdict it no longer
	// earned.
	//
	// No live route hits this today (all 24 carry a permission), but a
	// TalonRoute created without one must not be a bypass.
	if p.spicedb == nil || host == "" || permission == "" {
		if p.gateMode != RoleGateEnforce {
			tlog.From(ctx).Error("policy: no authority to consult (spicedb nil or route permission unset) — denying",
				"host", host, "sub", b.Sub, "perm", permission, "gate_mode", string(p.gateMode))
			return Verdict{Decision: Deny, Reason: ReasonNoPermission}
		}
		return v
	}
	allowed, err := p.spicedb.Check(ctx, spicedb.CheckRequest{
		Host:       host,
		Subject:    b.Sub,
		Permission: permission,
		Privileged: isPrivilegedSensitivity(sensitivity),
	})
	if err != nil {
		// Fail closed per ADR 0001 §7.b: SpiceDB unreachable = deny.
		// Audit log so operators see the SpiceDB outage signal.
		tlog.From(ctx).Error("policy: SpiceDB CheckPermission failed (fail-closed)",
			"host", host, "sub", b.Sub, "perm", permission, "err", err)
		return Verdict{Decision: Error, Reason: ReasonInternal}
	}
	if !allowed {
		return Verdict{Decision: Deny, Reason: ReasonNoPermission}
	}
	return Verdict{Decision: Allow, Reason: ReasonOK}
}

// isPrivilegedSensitivity reports whether a ZTNA sensitivity class gets
// the shorter (privileged) DDIL offline-decision budget. The two most
// sensitive classes — critical and high — degrade more conservatively;
// medium/low/unset take the standard budget.
func isPrivilegedSensitivity(sensitivity string) bool {
	switch sensitivity {
	case "critical", "high":
		return true
	default:
		return false
	}
}
