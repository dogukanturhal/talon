# ADR 0008 — Tier-1 scoring baseline (post-Phase 5 + Phase 4 marathon)

- **Status:** Accepted (locked 2026-04-27 at start of Tier-1 gap-closure session)
- **Date:** 2026-04-27
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Related:** ADRs 0001 §3, 0001 §6, 0002, 0003; `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md`
- **Refines:** N/A (snapshot ADR — calibrates the 17-dimension matrix used by the gap-closure plan)

---

## 1. Status

Accepted. This ADR captures the **honest** scoring baseline against which the
eight Tier-1 gaps in `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` are measured.
The boot-prompt §3 baseline numbers were calibrated before the Phase 4
marathon (2026-04-26/27); some baselines have shifted enough that this ADR
exists to record the corrected starting point. Gap-closure work that follows
references this ADR for the *real* delta to target, not the prompt's stale
numbers.

## 2. Context

The boot prompt prescribed gap-closure targets against a 17-dimension
competitor matrix (Cloudflare Access, AWS Verified Access, Microsoft Entra
Private Access, Pomerium OSS, Google BeyondCorp, Authentik proxy provider,
APISIX `openid-connect`, Authelia). The matrix dimensions were defined
implicitly by the gaps Tier-1 calls out. To re-score, we enumerate all 17
dimensions explicitly, score Talon today, and identify the delta-to-Tier-1.

Phase 4 marathon shipped (`d7b7846`, `df99418`, `4861d08`, `c1fcb8f`,
`9ba7eff`, `ab6447e`, `815d667`, plus Playwright e2e refactor) more than the
prompt's scoring assumed. Re-scoring before starting work avoids
double-counting deliverables that already landed.

## 3. The 17 dimensions

Dimensions 1-9 are "table stakes" — Tier-1 IAPs all do these well; Talon
must too. Dimensions 10-17 are the eight gaps the boot prompt calls out.

| # | Dimension | Talon today | Tier-1 target | Δ | Anchor |
|---|-----------|-------------|---------------|---|--------|
| 1 | Identity flow (OIDC RP correctness) | 9 | 9 | 0 | Auth0 / Pomerium reference |
| 2 | Session/cookie discipline (RFC 6265 §5.3.6) | 9 | 9 | 0 | Cloudflare Access |
| 3 | iOS Safari/Chrome cross-origin redirect shape | 10 | 10 | 0 | The original bug we fixed (ADR 0001 §5.d) |
| 4 | SpiceDB Zanzibar authz model | 9 | 9 | 0 | Google Zanzibar paper |
| 5 | In-cluster mTLS (Linkerd) | 9 | 9 | 0 | BeyondCorp east-west |
| 6 | Header injection/smuggling defence | 9 | 9 | 0 | OWASP, Pomerium PEP |
| 7 | CSRF/replay defence | 9 | 9 | 0 | RFC 6265bis, RFC 7636 |
| 8 | RP-Initiated logout chain | 8 | 9 | +1 | OIDC RP-Initiated Logout 1.0 |
| 9 | Per-route blast radius (CRD) | 9 | 9 | 0 | k8s gateway-api conventions |
| 10 | Documentation / onboarding | **5** | 8 | +3 | Cloudflare reference architecture |
| 11 | Continuous verification | **7.5** | 9 | +1.5 | Cloudflare 5-min poll cadence |
| 12 | WebAuthn / passkeys | 3 | 8 | +5 | Microsoft Entra passkey |
| 13 | Audit / compliance evidence | **6.5** | 9 | +2.5 | AWS CloudTrail, SOC 2 CC6.x |
| 14 | Policy expressiveness | 7 | 9 | +2 | AWS Cedar, Pomerium PPL |
| 15 | Performance / latency | 8 | 10 | +2 | Pomerium JWT cache pattern |
| 16 | Forward-auth composability | 9 | 10 | +1 | Authentik forward-auth |
| 17 | Falcon-ID SDK SLO race fix (cross-app logout reliability) | 5 | 9 | +4 | OIDC Session Management 1.0 |

**Bold cells differ from boot-prompt §3.** Justifications in §4. Other
dimensions match prompt baseline.

## 4. Re-score deltas vs boot prompt

### 4.a Dimension 10 — Documentation / onboarding (4 → **5**)

Prompt baseline: 4. Re-score: 5.

What landed since calibration:
- ADRs 0001 (architecture+threat model), 0002 (cookie/session), 0003 (CRD)
  are full-depth Tier-1 documents (40-200 sections each).
- Operations runbooks: `migrate-host.md` (Phase 3 host migration),
  `per-app-oidc-integration.md`, `vault-oidc-setup.md` (Phase 4.x).
- e2e/playwright suite covers all 17 admin hosts with per-host screenshot +
  state-trace artefacts; e2e/ios/README is the iOS verification rig.

Still missing for Tier-1:
- ADRs 0004 (continuous-verification cadence), 0005 (forward-auth),
  0006 (Falcon-ID integration quirks), 0007 (SDK contract). 0008 (this).
- Operations: `incident-response.md`, `observability.md`, `break-glass.md`.
- `onboarding/new-engineer.md`, `integration/sdk-clients.md`,
  `compliance/control-mapping.md`.

Delta to Tier-1: +3 (5 → 8). Gap 1 owns this work.

### 4.b Dimension 11 — Continuous verification (7 → **7.5**)

Prompt baseline: 7. Re-score: 7.5.

What landed since calibration:
- Phase 4 base (`d7b7846`) shipped `internal/cv/runner.go` with
  controller-runtime leader-elected ticking — already production-grade
  framework.
- Phase 4.1 (`df99418`) replaced the no-op verifyOne with proper
  RFC 6749 §6 refresh-token grant + RFC 6750 Bearer to /oauth/userinfo
  + sub-mismatch / disabled / role-loss invalidation.
- Phase 4.1 hotfix (`4861d08`) removed the false-positive role-loss
  invalidation: /oauth/userinfo doesn't carry `roles` per OIDC core §5.3,
  so the role check is gated on `len(claims.Roles) > 0` and Phase 4.2
  is queued to decode the access_token JWT directly (memory:
  internal engineering notes).
- `DELETE /admin/sessions/{sub}` exists at `internal/handlers/admin.go`
  for operator-driven kick-all (cookie+role auth, fail-closed).

Still missing for Tier-1:
- Default cadence is 15 min; Tier-1 anchor (Cloudflare) is 5 min.
- No streaming revocation: Falcon-ID `user.disabled` /
  `user.groups.changed` / `oauth.token.revoked` events don't push to
  Talon; Talon discovers them on next tick.
- No per-route override: `TalonRoute.spec.continuousVerifyMinutes`
  exists in the CRD schema but is not wired into `cv.Runner`.
- No per-request token re-verify against cached JWKS for Bearer-token
  API requests (only cookie sessions are CV'd today).
- Phase 4.2 access_token JWT decoding for role-loss check is queued
  but not landed.

Delta to Tier-1: +1.5 (7.5 → 9). Gap 2 owns this.

### 4.c Dimension 13 — Audit / compliance evidence (6 → **6.5**)

Prompt baseline: 6. Re-score: 6.5.

What landed since calibration:
- Phase 4 audit pipeline (`d7b7846`) — `internal/audit/audit.go` emits
  structured audit records for OIDC start/callback, session
  create/refresh/revoke, CV invalidate, admin revoke, policy decisions.
- Audit destination: stdout JSON → Loki → Wazuh per ADR 0001 §9 plan.

Still missing for Tier-1:
- No SOC 2 CC6.x / ISO 27001:2022 control mapping doc.
- No evidence-export CLI (`talon evidence export --since=…
  --controls=CC6.6`).
- No HMAC-per-row + cosign-signed manifest.
- No WORM archive (object-locked MinIO bucket; coordinate with
  Platform Security Stack Gap 7).
- No `decision_id` (ULID) on every audit event for end-to-end
  correlation.
- No `sso_chain_id` propagation across Talon ↔ Falcon-ID ↔ upstream.
- No quarterly compliance dashboard.
- No GDPR redaction tool.

Delta to Tier-1: +2.5 (6.5 → 9). Gap 4 owns this.

### 4.d Dimension 17 — Falcon-ID SDK SLO race fix (NEW since prompt v1)

This dimension was added in boot prompt v2 after root-cause analysis on
2026-04-27. Prompt baseline: 5. Re-score: 5 (matches prompt).

The SDK at `frontend/packages/falcon-id-client/src/nextjs/provider.tsx`
lines 374-404 has the race the prompt diagnoses. Confirmed by inspection:
`setStatus('unauthenticated')` on line 381 commits React state before
`await fetch(authBasePath/logout)` on line 385 yields, AuthGuard's
useEffect fires `router.replace('/login')` before
`window.location.href = sloUrl` on line 403.

Delta to Tier-1: +4 (5 → 9). Gap 8 owns this; the SDK fix sequences
first in week 1 because it's a one-day change with 5+ apps' SLO chain
hanging off it.

## 5. Score weighting and aggregate

Equal-weighted sum of all 17 dimensions (each 0-10):

```
Today  = 9 + 9 + 10 + 9 + 9 + 9 + 9 + 8 + 9
       + 5 + 7.5 + 3 + 6.5 + 7 + 8 + 9 + 5
       = 132 / 170
       ≈ 77.6 %        (boot prompt §1 said 71 %)

Tier-1 = 9 + 9 + 10 + 9 + 9 + 9 + 9 + 9 + 9
       + 8 + 9 + 8 + 9 + 9 + 10 + 10 + 9
       = 152 / 170
       ≈ 89.4 %        (boot prompt §1 said 84 %)
```

Both deltas (today and target) sit ~6 pp higher than the prompt because:
- Phase 4 marathon delivered more than the prompt assumed (+1.5 pp on
  dim 11, +0.5 on dim 13, +1 on dim 10 over prompt baselines).
- The per-dimension Tier-1 ceilings are also higher than the prompt's
  implied ceiling on dims 14, 15, 16 (Pomerium-Enterprise-Rego match for
  dim 14; we cite Pomerium OSS as the comparison and beat them by
  shipping Rego at the OSS tier).

The +12 pp jump from gap-closure remains the same (132 → 152 = +20 score
points = +12 pp). The eight gaps' work is unchanged in scope; only the
*starting point* moved.

## 6. Acceptance test for this baseline

Each gap-closure ADR / runbook / implementation MR closes its own delta
in §3 with quantitative evidence:

| Dimension | Gap | Evidence required to claim "done" |
|-----------|-----|-----------------------------------|
| 8 — RP logout | Gap 8 (partial) + existing | E2E test: logout from accounts → Falcon-ID `/oauth/logout` → `falcon_idp_session` cookie gone → re-visit grafana.ops → Falcon-ID login prompt (not silent SSO). Memory: internal engineering notes. |
| 10 — Docs | Gap 1 | Onboarding test: an engineer reaches "I can deploy a TalonRoute" in ≤ 1 day using only `docs/`. |
| 11 — CV | Gap 2 | E2E: disable user in Falcon-ID; existing browser session at any admin host invalidates within 30 s (streaming) or 1-5 min (poll). Bearer-token API call gets 401 within 60 s. |
| 12 — WebAuthn | Gap 3 | E2E: enroll passkey in accounts; `vault.ops` (passkeyRequired=true) forces step-up; `grafana.ops` (passkeyRequired=false) allows pwd+otp; `amr=["webauthn"]` claim in successful Vault session. |
| 13 — Audit | Gap 4 | `talon evidence export --controls=CC6.6 --since=… --until=…` produces auditor-ready CSV; cosign verifies manifest; SOC analyst reconstructs sso_chain via `sso_chain_id` grep. |
| 14 — Policy | Gap 5 | Cedar-equivalence CI gate green on all routes; per-route `policyRego` example (time-of-day + IP CIDR) running in production with `talon test policy` cases passing. |
| 15 — Perf | Gap 6 | k6 ramp 0→1000 RPS; sustained 1000 RPS for 10 min; p99 ≤ 50 ms across allow+deny mix; 0 5xx at 500 RPS sustained; HPA scales 2→6→2 cleanly. |
| 16 — Forward-auth | Gap 7 | Customer-tier route `accounts.hexxlock.com/admin` gated by APISIX → Talon `/auth/verify`; identity headers present on 200; 503+Retry-After on Talon outage; cookie scope isolation verified between admin/customer tiers. |
| 17 — SDK SLO | Gap 8 | E2E `cross-app-logout.spec.ts`: logout from accounts → `falcon_idp_session` gone → re-visit any admin host → re-login required. Soak 2 weeks on accounts before flipping default in v2.x. |

## 7. References

- `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` — this baseline calibrates
  against the prompt's gap targets.
- ADR 0001 §6 (continuous verification cadence — 15 min default Phase 4).
- ADR 0002 §5.5 (admin revoke).
- `internal/cv/runner.go` — Phase 4.1 implementation.
- `internal/handlers/admin.go` — operator break-glass `DELETE
  /admin/sessions/{sub}`.
- `frontend/packages/falcon-id-client/src/nextjs/provider.tsx:374-404`
  — Gap 8 race-condition codepath.
- Memory: internal engineering notes,
  internal engineering notes,
  internal engineering notes,
  internal engineering notes,
  internal engineering notes,
  internal engineering notes,
  internal engineering notes.

---

*This ADR is a snapshot. Re-score at the end of each week of gap-closure
work; update §3 in place rather than superseding (the snapshot itself is
the deliverable). Aggregate-percentage line in §5 is the headline metric
in any status report against the boot prompt's 71→84% target.*
