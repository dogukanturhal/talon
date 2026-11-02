# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Talon ZTNA baseline Rego policy.
#
# ADR cross-refs:
#   Talon 0040 — ZTNA Platform (master)
#   Talon 0011 — CAEP + device posture
#   Talon 0004 — Continuous verification
#
# This module is the operator-authored `regoPolicy` field of every
# TalonRoute that opts into ZTNA. Drop the entire file verbatim into
# the TalonRoute spec; downstream tightening is done by overriding
# defaults at the route level (see "Per-route overrides" comments
# below).
#
# Decision contract: returns `data.talon.route.allow := bool`. Talon's
# PEP treats `false` as a final deny; the deny reason is surfaced via
# `data.talon.route.deny_reason` for the audit log + 403 body.
#
# Input shape: `input` matches `internal/policy/rego.RegoInput`.
# Fields used here:
#   input.user.{sub, email, groups, roles, tenant_id, amr}
#   input.route.{host, permission}
#   input.request.{method, path, src_ip}
#   input.posture.{issuer, subject, iat, exp, degraded, grace_until, compliance.*}
#   input.device_mtls.{present, valid, device_id, kind, channel}  (informational,
#     NOT consulted by this baseline: set only when TALON_DEVICE_MTLS_TRUSTED_CLIENT_ID
#     is configured; kind is "browser"|"device", channel "device-mtls". The cert <->
#     posture `sub` device binding is enforced in Go per TALON_DEVICE_MTLS_MODE
#     (audit default = log would_deny only), so decisions here are unchanged.)
#
# The posture object is populated by Talon's posture verifier when the
# request carried a valid X-Talon-Posture JWT (ADR 0011). `null` posture
# means the request had no posture header OR verification failed; the
# baseline policy denies these by default — operators MUST opt out
# per-route if they want to admit no-posture requests (e.g. the public
# webhook surface).
#
# DDIL P3.10 governed posture-grace (ADR 0010): `input.posture.degraded`
# is true when the posture verified by signature/attestation but is past
# its hard exp/MaxAge and is being served within Talon's governed grace
# budget; `input.posture.grace_until` is the unix-seconds fail-closed
# instant. Talon's Go PEP is AUTHORITATIVE — it already denies a degraded
# posture on critical/high (privileged) routes and serves it on low/medium
# — so these fields are surfaced only so a custom policy MAY reason about
# them; a policy that ignores them cannot widen access past the Go gate.

package talon.route

import rego.v1

# Default deny — fail-closed, per ADR 0010 §3.
default allow := false

# Default deny reason. Concrete reasons override via deny_reason rules
# below.
default deny_reason := "ztna: no rule allowed the request"

# ------------------------------------------------------------------ #
# Trust tiers
#
# Per ADR 0040 Phase 0 decision D-006 there are three explicit tiers.
# Tier is determined by the device-cert SAN claim projected into
# posture.compliance.tier by the posture verifier (jess-issued device
# certs encode `tier=TIER_CORP|TIER_BYOD` in the cert subject).
# TIER_BREAKGLASS is an explicit override — see below.
# ------------------------------------------------------------------ #

tier_corp := "TIER_CORP"
tier_byod := "TIER_BYOD"
tier_breakglass := "TIER_BREAKGLASS"

# Effective tier of the request. Defaults to TIER_BYOD if the device
# did not assert one (most defensive bucket).
effective_tier := tier if {
	tier := input.posture.compliance.tier
} else := tier_byod

# ------------------------------------------------------------------ #
# AAL — authentication assurance level
#
# Per NIST SP 800-63B-4:
#   AAL1 — single-factor (password only)
#   AAL2 — single-factor cryptographic OR multi-factor
#   AAL3 — multi-factor with hardware authenticator
#
# Mapped to amr claim:
#   AAL1 if amr ⊆ {pwd}
#   AAL2 if amr ⊇ {pwd, otp}    or amr ⊇ {pwd, email}
#   AAL3 if amr ⊇ {pwd, hwk}    or amr ⊆ {hwk}
#               where hwk = WebAuthn-with-user-verification, FIDO2,
#               or PIV.
# ------------------------------------------------------------------ #

amr_set := {a | a := input.user.amr[_]}

aal := "aal3" if {
	"hwk" in amr_set
}

aal := "aal2" if {
	not "hwk" in amr_set
	"otp" in amr_set
}

aal := "aal2" if {
	not "hwk" in amr_set
	"email" in amr_set
}

aal := "aal1" if {
	not "hwk" in amr_set
	not "otp" in amr_set
	not "email" in amr_set
}

# ------------------------------------------------------------------ #
# WebAuthn recency
#
# Per ADR 0040 + NIST SP 800-63B-4 §4.3.2, AAL3 requires
# re-authentication within 12 hours for high-sensitivity routes.
# Talon embeds the last WebAuthn assertion's iat into amr_recency_seconds
# via the session.Blob → RegoInputUser projection.
#
# Recency check is conservative: when the input doesn't expose recency
# we treat as "stale" (deny).
# ------------------------------------------------------------------ #

amr_recency_seconds := s if {
	s := input.user.amr_recency_seconds
} else := 86400

webauthn_fresh_12h if amr_recency_seconds <= 43200  # 12h

webauthn_fresh_1h if amr_recency_seconds <= 3600   # 1h step-up window

# ------------------------------------------------------------------ #
# Device posture freshness
#
# Posture JWTs are signed every 5 min (TIER_CORP) / 15 min (TIER_BYOD).
# Allow up to 2x the cadence as freshness budget — anything older
# indicates the posture agent stopped reporting and the device-trust
# claim has decayed.
# ------------------------------------------------------------------ #

now_seconds := time.now_ns() / 1000000000

posture_age_seconds := age if {
	age := now_seconds - input.posture.iat
} else := 1000000  # large = stale

posture_fresh if {
	effective_tier == tier_corp
	posture_age_seconds <= 600
}

posture_fresh if {
	effective_tier == tier_byod
	posture_age_seconds <= 1800
}

posture_fresh if {
	effective_tier == tier_breakglass
	# Breakglass posture cadence handled out-of-band; trust the
	# manager-approval-token instead.
	true
}

# ------------------------------------------------------------------ #
# Device-cert validity
#
# The posture verifier projects device-cert validation into
# posture.compliance.device_cert_valid (boolean).
# ------------------------------------------------------------------ #

device_cert_valid if input.posture.compliance.device_cert_valid == true

# ------------------------------------------------------------------ #
# Network class
#
# Per ADR 0040 Phase 5 contract:
#   "corp"      — request IP in CORP CIDR (10.0.20.0/24)
#   "vpn"       — request IP in VPN CIDR (10.0.50.0/24)
#   "trusted"   — corp or vpn
#   "internet"  — everything else
# Source: Talon's network-class evaluator populates
# posture.compliance.network_class. Falls back to "internet" when
# unknown (most defensive).
# ------------------------------------------------------------------ #

network_class := nc if {
	nc := input.posture.compliance.network_class
} else := "internet"

# ------------------------------------------------------------------ #
# Sensitive route classification
#
# Routes the operator manually flags as sensitive in the TalonRoute
# spec are surfaced via posture.compliance.route_sensitivity (string:
# "low"|"medium"|"high"|"critical"). Defaults to medium.
# ------------------------------------------------------------------ #

route_sensitivity := s if {
	s := input.posture.compliance.route_sensitivity
} else := "medium"

# ------------------------------------------------------------------ #
# Allow rules — tier × sensitivity matrix
#
# The baseline allows the following combinations. Routes that don't
# match are denied with a concrete deny_reason.
#
#                          low   medium  high  critical
#  TIER_CORP + AAL3        ✓     ✓       ✓     ✓ (1h step-up)
#  TIER_CORP + AAL2        ✓     ✓       step-up to AAL3 required
#  TIER_BYOD + AAL3        ✓     ✓       step-up to 1h required  -
#  TIER_BYOD + AAL2        ✓     -       -                       -
#  TIER_BREAKGLASS         -     -       -     manager-approval-token
# ------------------------------------------------------------------ #

# TIER_CORP allows
allow if {
	effective_tier == tier_corp
	aal == "aal3"
	device_cert_valid
	posture_fresh
	webauthn_fresh_12h
	route_sensitivity != "critical"
}

# TIER_CORP critical-route — require 1h webauthn step-up
allow if {
	effective_tier == tier_corp
	aal == "aal3"
	device_cert_valid
	posture_fresh
	webauthn_fresh_1h
	route_sensitivity == "critical"
}

# TIER_CORP AAL2 — low + medium sensitivity only
allow if {
	effective_tier == tier_corp
	aal == "aal2"
	device_cert_valid
	posture_fresh
	webauthn_fresh_12h
	route_sensitivity in {"low", "medium"}
}

# TIER_BYOD AAL3 — low + medium + high sensitivity, no critical
allow if {
	effective_tier == tier_byod
	aal == "aal3"
	posture_fresh  # BYOD has no device-cert claim; relax that gate
	webauthn_fresh_1h
	route_sensitivity != "critical"
}

# TIER_BYOD AAL2 — low only
allow if {
	effective_tier == tier_byod
	aal == "aal2"
	posture_fresh
	webauthn_fresh_12h
	route_sensitivity == "low"
}

# TIER_BREAKGLASS — manager-approval-token + AAL3 + critical only
allow if {
	effective_tier == tier_breakglass
	aal == "aal3"
	input.user.amr[_] == "approval"  # operator-approved breakglass token
	route_sensitivity == "critical"
}

# ------------------------------------------------------------------ #
# Deny reasons — concrete, audit-log friendly
#
# These short-circuit `deny_reason` to a specific cause so the 403
# body + audit log carry useful diagnostics. One else-chain (complete rules
# that can match together raise eval_conflict_error); order = precedence, most
# specific first.
# ------------------------------------------------------------------ #

deny_reason := "ztna: missing posture (no X-Talon-Posture header or verification failed)" if {
	not input.posture
} else := "ztna: posture stale (iat too old for tier)" if {
	input.posture
	not posture_fresh
} else := "ztna: device cert required for TIER_CORP" if {
	effective_tier == tier_corp
	not device_cert_valid
} else := "ztna: AAL3 required (hardware authenticator)" if {
	route_sensitivity in {"high", "critical"}
	aal != "aal3"
} else := "ztna: WebAuthn re-auth required (>1h since last assertion)" if {
	route_sensitivity == "critical"
	aal == "aal3"
	not webauthn_fresh_1h
} else := "ztna: BYOD cannot access critical routes" if {
	effective_tier == tier_byod
	route_sensitivity == "critical"
} else := "ztna: BREAKGLASS requires manager-approval-token" if {
	effective_tier == tier_breakglass
	not "approval" in amr_set
}

# ------------------------------------------------------------------ #
# Per-route overrides — examples
#
# Operators tailor per-route by REPLACING this module in TalonRoute.spec.
# Common tailoring patterns:
#
#   1. Public webhook (no posture, no auth): override `default allow := true`
#      and add specific deny rules for known-bad cases.
#
#   2. Internal-only route (no internet exposure):
#        allow if { network_class == "trusted"; ... }
#
#   3. Tighter recency on sensitive route:
#        allow if { ...; amr_recency_seconds <= 1800 }  # 30 min
#
#   4. Allow-list users:
#        allow if {
#          ...
#          input.user.sub in {"00000000-...-aaaa", "00000000-...-bbbb"}
#        }
#
#   5. ReBAC permission gate (Talon already evaluates SpiceDB before
#      calling Rego, but operators can additionally check the
#      permission level here):
#        allow if {
#          ...
#          input.route.permission in {"viewer", "editor"}
#        }
#
# Shadow mode: during rollout, ALSO compute `allow` and surface as
# `data.talon.route.would_allow` while leaving the live policy
# permissive. Talon's audit log records both — operators see what would
# have been denied without taking the cluster down.
# ------------------------------------------------------------------ #
