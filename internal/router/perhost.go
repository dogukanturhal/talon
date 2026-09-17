// SPDX-License-Identifier: AGPL-3.0-or-later

// perhost.go — per-host session controls (Phase 4 per-host TTL/idle/
// IP-rebind/device-claim batch). Industry parity references on each rule:
//
//   - sessionAbsoluteSec → Pomerium per-route `timeout`, Cloudflare Zero
//     Trust application session duration, Google IAP session policy.
//   - sessionIdleSec → Pomerium per-route `idle_timeout`, Microsoft Entra
//     Conditional Access "sign-in frequency" idle policy.
//   - reauthOnIP → Pomerium `force_reauth_on_address_change`.
//   - requireDeviceClaims → Microsoft Entra Conditional Access device-
//     compliance grant control, Cloudflare Zero Trust device posture.
//
// All checks fail-closed by default; the route's `auditOnly` flag is the
// soak-mode escape hatch — see emitWouldHaveDenied below.
package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	gatewayv1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/policy"
	"github.com/dogukanturhal/talon/internal/session"
)

// perHostVerdict is the outcome of evaluatePerHost. Only emitted when
// at least one per-host check is configured; the absent/zero-value case
// returns ok=true with no reason so the caller skips the audit emit.
type perHostVerdict struct {
	ok     bool
	reason policy.Reason
}

// evaluatePerHost runs the per-route session-control checks added by
// the Phase 4 per-host batch in this order:
//
//  1. Absolute TTL (sessionTtlOverride): now - blob.IAT vs the cap.
//     For clientless-channel requests (ADR 0044) the route's
//     clientlessMaxTTL — when set and tighter than the per-host
//     absolute cap — supersedes it, so agentless sessions are
//     time-boxed harder than the same route's agent sessions.
//  2. Idle TTL (sessionIdleSeconds): now - max(lastSeen, blob.IAT) vs
//     the cap. blob.IAT is the floor so a brand-new session isn't
//     judged idle on its very first hit.
//  3. Network change (reauthOnNetworkChange): /24 of current client
//     vs /24 bound on session at issuance.
//  4. Device claims (requireDeviceClaims): every requirement must
//     match against blob.DeviceClaims; missing keys fail-closed.
//
// Returns the FIRST failing check so the audit log carries a single
// canonical reason per request. The caller decides whether to enforce
// (deny + redirect) or audit-only (emit "would_have_denied_X" and
// continue) based on entry.auditOnly.
//
// `currentClientIP` is the X-Forwarded-For-aware client IP for this
// request (router.clientIP). lastSeen is the value pulled from the
// session store ahead of this call so the function stays
// pure-deterministic given its inputs (for unit tests). `channel` is
// the request's access channel (policy.ChannelCookie / ChannelClientless),
// classified by router.sessionChannel — it selects the absolute-TTL cap.
func evaluatePerHost(
	entry upstreamEntry,
	blob *session.Blob,
	now time.Time,
	currentClientIP string,
	lastSeen time.Time,
	channel string,
) perHostVerdict {
	// 1. Absolute TTL. The effective cap is the per-host absolute TTL,
	//    except clientless sessions (ADR 0044) are time-boxed by the
	//    route's clientlessMaxTTL when it is set and STRICTER. We pick the
	//    smaller of the two non-zero caps so neither knob can loosen the
	//    other: an operator who sets a tight per-host cap keeps it even on
	//    clientless, and clientlessMaxTTL only ever tightens. The deny
	//    reason distinguishes which cap fired so the audit log is precise.
	absCap := entry.sessionAbsoluteSec
	absReason := policy.ReasonPerHostExpired
	if channel == policy.ChannelClientless && entry.clientlessMaxTTL > 0 {
		if absCap == 0 || entry.clientlessMaxTTL < absCap {
			absCap = entry.clientlessMaxTTL
			absReason = policy.ReasonClientlessExpired
		}
	}
	if absCap > 0 && blob.IAT > 0 {
		ageSec := now.Unix() - blob.IAT
		if ageSec > int64(absCap) {
			return perHostVerdict{ok: false, reason: absReason}
		}
	}

	// 2. Idle TTL — floor at IAT so a brand-new session with no
	//    TouchLastSeen calls yet isn't immediately judged idle.
	if entry.sessionIdleSec > 0 {
		floor := blob.IAT
		if !lastSeen.IsZero() && lastSeen.Unix() > floor {
			floor = lastSeen.Unix()
		}
		idleSec := now.Unix() - floor
		if idleSec > int64(entry.sessionIdleSec) {
			return perHostVerdict{ok: false, reason: policy.ReasonPerHostIdleTimeout}
		}
	}

	// 3. Source-IP /24 binding. Empty SrcIP on the blob (legacy session
	//    pre-MR1, or test fixture) is permissive — the router has nothing
	//    to compare against; sessions created post-MR1 always populate it.
	if entry.reauthOnIP && blob.SrcIP != "" && currentClientIP != "" {
		if srcCIDR24(blob.SrcIP) != srcCIDR24(currentClientIP) {
			return perHostVerdict{ok: false, reason: policy.ReasonNetworkChange}
		}
	}

	// 4. Device claims. Each requirement must match an entry on
	//    blob.DeviceClaims; missing or mismatched fails closed. The CRD
	//    validation webhook + reconciler enforce the claim-name allow-
	//    list so unknown names never reach this code.
	for _, req := range entry.deviceClaims {
		got, present := blob.DeviceClaims[req.Claim]
		if !present {
			return perHostVerdict{ok: false, reason: policy.ReasonDeviceClaimMissing}
		}
		if got != req.Equals {
			return perHostVerdict{ok: false, reason: policy.ReasonDeviceClaimMismatch}
		}
	}

	return perHostVerdict{ok: true}
}

// srcCIDR24 returns the /24 prefix of an IPv4 address as a dotted-string
// key suitable for equality comparison ("10.0.50.5" → "10.0.50"). For
// IPv6 the function returns the full address — IP-rebind on IPv6 demands
// the same address (stricter than v4 by design; the admin tier today is
// v4-only). Malformed input returns the input unchanged so a comparison
// with a same-malformed value still works (the IP-rebind check is
// permissive when both sides are equal regardless of validity).
func srcCIDR24(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		// net.IP.String() only renders correctly on 4- or 16-byte
		// slices; for the /24 prefix key we format the three octets
		// directly. The result is a comparison key, not a formal CIDR.
		return fmt.Sprintf("%d.%d.%d", v4[0], v4[1], v4[2])
	}
	return parsed.String()
}

// auditDecisionLabel maps a would-have-denied/errored outcome to its
// talon_auth_decision_total `decision` label. During an audit-only soak
// the gate falls through to ALLOW, so the outcome is recorded as
// "would_deny"/"would_error" and deliberately kept OUT of the real
// deny/error rate TalonAuthFailureRate sums — otherwise a soak on a
// low-traffic route (e.g. vault.ops seal-status polling) pegs the
// failure-rate at the would-deny share and trips the critical alert even
// though every request is allowed. Enforce mode (auditOnly=false) records
// the real label. `enforced` is the enforce-mode label ("deny" or "error").
func auditDecisionLabel(auditOnly bool, enforced string) string {
	if auditOnly {
		return "would_" + enforced
	}
	return enforced
}

// emitWouldHaveDenied logs a request.deny event tagged with the
// audit-only prefix on the reason field. The request is then allowed to
// continue — operators read the audit stream during the one-week soak
// to confirm the new policy isn't denying legitimate traffic before
// flipping the route's `auditOnly` flag off. Reused by both the
// protected-host catch-all and /auth/verify.
func emitWouldHaveDenied(
	ctx context.Context,
	em *audit.Emitter,
	blob *session.Blob,
	host, method, path, sessionID, permission string,
	reason policy.Reason,
	detail ...string,
) {
	// Optional granular cause (e.g. the ZTNA Rego deny_reason). Kept
	// separate from Reason so the coarse "would_have_denied_<category>"
	// label stays dashboard-stable while the audit line still carries the
	// precise why.
	denyReason := ""
	if len(detail) > 0 {
		denyReason = detail[0]
	}
	em.Deny(ctx, audit.Record{
		Sub:        blob.Sub,
		Email:      blob.Email,
		TenantID:   blob.TenantID,
		Route:      host,
		Method:     method,
		Path:       path,
		Reason:     "would_have_denied_" + string(reason),
		DenyReason: denyReason,
		SessionID:  sessionID,
		Permission: permission,
		Issuer:     blob.Iss,
		SrcIP:      blob.SrcIP,
	})
}

// upstreamEntry's per-host fields are declared on the entry type itself
// in router.go (so RegisterUpstream's signature can carry them). The
// helpers in this file consume them via the shared package-internal
// type. Keeping device-claim conversion in one place:

// deviceClaimsFromSpec normalizes the CR's []DeviceClaimRequirement into
// the internal slice held on upstreamEntry. Allocates a fresh slice so
// the entry can outlive the CR struct returned from the watch.
func deviceClaimsFromSpec(in []gatewayv1alpha1.DeviceClaimRequirement) []gatewayv1alpha1.DeviceClaimRequirement {
	if len(in) == 0 {
		return nil
	}
	out := make([]gatewayv1alpha1.DeviceClaimRequirement, len(in))
	copy(out, in)
	return out
}
