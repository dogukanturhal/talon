# ADR 0011 — CAEP 1.0 receiver + device-posture signal pipeline

- **Status:** Accepted
- **Date:** 2026-06-02
- **Cross-refs:** ADR 0009 (shared PDP ext_authz), ADR 0010 (fail-mode)

## Context

The tier-1 IAP gap analysis (research log under
docs/research/2026-06-02-talon-tier1-iap-gap-analysis.md to follow)
identified two real-time security signals Talon does not yet consume:

1. **Cross-IdP / multi-vendor session revocation.** When an IdP
   revokes a user session, marks credentials changed, or disables an
   account, the IdP MUST broadcast that fact to every Relying Party
   so the stolen-cookie window collapses from "until TTL" to
   "within seconds". The OpenID Foundation's **Continuous Access
   Evaluation Profile (CAEP) 1.0** went FINAL on 2025-08-29 and is
   the canonical wire format for these events. Google, Apple, IBM,
   Okta, JAMF, and SailPoint have adopted it.

2. **Device-trust / posture signal.** Without an authenticated
   statement of device compliance (disk encryption on, EDR running,
   patched within the last N days, not jailbroken), Talon admits
   any client with a valid OIDC cookie regardless of the device.
   Cloudflare WARP, Google IAP/BeyondCorp, and Teleport device-trust
   all gate access on a posture signal in addition to identity.

Both signals close gaps that no current Talon feature addresses.

## Decision

### Part A — CAEP 1.0 SET receiver (`internal/caep`)

Talon exposes `POST /caep/events` accepting `application/secevent+jwt`
SETs signed by Falcon-ID (or any future federated transmitter listed
in `cfg.CAEP.TrustedTransmitters`). The receiver:

1. Parses + signature-verifies the SET against the transmitter's JWKS
   (the same JWKSManager used by svctoken — single source of truth
   for transmitter trust).
2. Validates envelope (iss + aud + iat within ±5min + jti not in
   replay cache).
3. Dispatches by event-type URN:

   | Event URN | Action |
   |---|---|
   | `…/caep/event-type/session-revoked` | `RevokeBySubject` |
   | `…/caep/event-type/credential-change` | `RevokeBySubject` |
   | `…/risc/event-type/account-disabled` | `RevokeBySubject` |
   | `…/risc/event-type/account-purged` | `RevokeBySubject` |
   | `…/risc/event-type/account-credential-change-required` | `RevokeBySubject` |
   | `…/caep/event-type/risk-level-change` | Audit only |
   | `…/caep/event-type/device-compliance-change` | Audit only |
   | `…/caep/event-type/assurance-level-change` | Audit only |
   | Unknown URN | Audit + emit `caep.unknown_event` |

4. Returns 202 on success, 401 on sig/iss/aud failure, 400 on parse,
   429 on replay (per RFC 8935 Push Delivery).

The session store gains `Store.RevokeBySubject(ctx, iss, sub, reason)`
that walks the existing `talon:revoke-by-sub:<sub>` ZSet (built by
Create), tombstones each cookie under `talon:revoked:<id>`, deletes
the session record, drops the sub index, and fans out subject-level
decision-cache invalidation once. Idempotent — a sub with no active
sessions returns (0, nil).

**Threat model addressed:** stolen-cookie-lives-until-TTL.
**Threat model NOT addressed by this ADR:** signing-key compromise of
the transmitter (covered separately by JWKS-rotation runbook).

### Part B — Device-posture signal verifier (`internal/posture`)

Talon reads `X-Talon-Posture: <JWS>` on every request. The JWS is
signed by a separately-trusted posture issuer (NOT Falcon-ID — the
trust chains are intentionally distinct so a Falcon-ID compromise
cannot fabricate device-compliant assertions, and a posture-issuer
compromise cannot mint user identity tokens).

Verifier checks:

1. Signature against `cfg.Posture.TrustedIssuers` JWKS set.
2. `iss` in the trusted set.
3. `aud` includes Talon's audience.
4. `exp` not expired, `iat` within `MaxAge` (default 1h) + skew.
   Under the DDIL P3.10 governed posture-grace (ADR 0010), a posture past
   this deadline but within a configured per-tier grace budget (corp 10m /
   byod 30m, default OFF) is returned `Degraded=true` rather than rejected;
   the consumer serves it on low/medium routes and denies it on
   critical/high. Grace never bypasses steps 1–3 (attestation is always
   required) and fails closed past budget.
5. If `user_sub` is present, MUST match session.Blob.Sub.

On success, returns a `Claims` struct with a structured `Compliance`
map. Route policy declares `requirePosture: {key: value}` rules;
`posture.Evaluate(claims, req)` returns (ok, failedKey). Common keys:

| Key | Type | Semantics |
|---|---|---|
| `disk_encrypted` | bool | true required |
| `edr_running` | bool | true required |
| `screen_lock_min` | int | ≥ N minutes |
| `os` | string | exact match |
| `os_version` | string | exact match (operator does range checks via Rego) |
| `patch_level` | string | ISO date; Rego does comparison |
| `managed` | bool | true required |
| `jailbroken` | bool | MUST be false |

Route-level outcomes:
- No `X-Talon-Posture` header AND route declares `requirePosture` → 401 `posture_missing`
- Posture present but signature/issuer/audience invalid → 401 `posture_invalid`
- Posture valid but Compliance map fails policy → 403 `posture_noncompliant`

For nuanced rules (e.g. "macOS ≥ 14.4 OR Windows ≥ 11 22H2"), the
operator stacks `requirePosture` (basic facts) + a Rego policy
(complex predicate) — the existing `internal/policy/rego.go`
already receives posture facts in its input shape (extension to
RegoInputUser.Posture pending — separate commit).

## Consequences

### Positive

- Real-time session revocation across the federation; closes the
  stolen-cookie-until-TTL hole identified as the #1 tier-1 gap.
- Device-trust enforcement at the IAP layer; HexxLock no longer
  trusts "valid OIDC cookie" as the sole admission control on
  admin-tier hosts.
- Posture and CAEP trust chains are deliberately separated; defense
  in depth against a single-issuer compromise.
- Unknown CAEP event types are tolerated (forward-compat); no breaking
  changes when the OpenID Foundation adds new URNs.

### Negative

- Posture-issuer infrastructure is new — HexxLock needs to either
  (a) extend Falcon-ID with a posture-issuer keypair (separate from
  the OIDC signing keypair), or (b) deploy a standalone posture
  daemon. Phase 1 ships option (a) with a chart-level toggle.
- CAEP transmitter must be implemented in Falcon-ID — see
  falcon-id MR (to follow).
- Operators authoring `requirePosture` route policies need a posture-
  fact reference doc (under docs/onboarding/ — to follow).

### Risks named

| Risk | Mitigation |
|---|---|
| Stolen posture JWT replayed across users | `user_sub` binding when present + `exp` ≤ 1h |
| Posture issuer key compromise | Separate trust chain from OIDC keys; key in HSM; CAEP risk-level event from Falcon-ID can revoke retroactively |
| CAEP SET replayed by transmitter | jti replay cache 24h; SETs are idempotent so duplicate processing is harmless apart from audit noise |
| CAEP transmitter unreachable | Talon is fail-closed on session-store unavailable (ADR 0010); CAEP outage degrades to TTL-based revocation only — strictly weaker than pre-CAEP behavior |
| Posture facts changed without re-mint | `exp` ≤ 1h forces re-issuance; combined with CAEP `device-compliance-change` event, stale posture can be invalidated proactively |

## Alternatives considered

### CIBA / push-auth for revocation

Rejected. CIBA (Client-Initiated Backchannel Auth) is a flow for
human approval of OOB requests, not a session-revocation transport.
Standards-misalignment.

### Custom HexxLock revocation protocol

Rejected. CAEP 1.0 final + Google/Apple/Okta adoption means HexxLock
should consume the standard, not a bespoke wire. Future Falcon-ID
can become a CAEP transmitter for any future SaaS Relying Party.

### Encode posture into the id_token

Rejected. Posture changes frequently (every disk-unlock, every patch
install); rebinding the id_token would force re-auth every minute.
A separate short-lived posture-JWS issued every ≤1h with explicit
`exp` is the standard approach (Cloudflare WARP, Google BeyondCorp).

## References

- OpenID CAEP 1.0 (Final, 2025-08-29) —
  https://openid.net/specs/openid-caep-1_0-final.html
- RFC 8417 — Security Event Token
- RFC 8935 — Push-Based Security Event Token (SET) Delivery Using HTTP
- RFC 9449 — DPoP (referenced for thumbprint-binding pattern)
- Google BeyondCorp posture verification — Cloud IAP docs
- Cloudflare WARP posture checks — https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/
- Teleport device trust — https://goteleport.com/docs/identity-governance/device-trust/
- ADR 0010 — fail-mode policy (CAEP outage degrades to TTL-only,
  not to fail-open)
