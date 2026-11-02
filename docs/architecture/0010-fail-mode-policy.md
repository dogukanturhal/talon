# ADR 0010 — Fail-mode policy (fail-closed by default)

- **Status:** Accepted
- **Date:** 2026-06-02
- **Supersedes:** —
- **Cross-refs:** ADR 0001 (overview), ADR 0009 (shared PDP ext_authz)

## Context

Talon is the sole IAP for `*.internal.example.com` (17 admin-tier hosts)
and the customer-tier ext_authz PDP for Envoy Gateway. Every `Verify`
call ultimately depends on at least one of:

1. The Falcon-ID JWKS endpoint (verifying inbound id_tokens + service
   JWTs)
2. The federated-issuer JWKS endpoints (Harbor, future Vault token,
   future Keycloak — for upstream-issued Bearer leg per
   `internal/svctoken/federated.go`)
3. The session store (`internal/session/store.go` — currently
   in-memory + Redis backing)
4. The SpiceDB ReBAC service (when a route enforces a permission
   beyond simple role membership)
5. The OPA evaluator embedded in `internal/policy/rego.go` (when a
   route has a Rego module attached)

Any of these dependencies can become unhealthy: Falcon-ID pods
restart, Redis primary fails over, SpiceDB DB blip, JWKS-fetch
times out behind a firewall blip. Talon must have a stated,
deterministic policy for how `Verify` behaves under each failure
mode. Without this codification:

- Operators cannot predict whether an outage will cascade into a
  full-cluster lockout or a silent fail-open
- Chaos testing has no oracle
- Regression tests for "what happens when X fails" cannot be
  written because the expected behavior is not declared
- Compliance audits (SOC 2 CC6.1, NIST 800-207 §3.4.1 monitor) need
  a single source of truth on continuous-trust degradation

Industry references the position takes after:

- Envoy `ext_authz` documents both `failure_mode_allow: false`
  (default, fail-closed) and `failure_mode_allow: true` (fail-open)
  knobs — Talon's choice maps to the Envoy default.
- NIST SP 800-207 §3.4.1: "The system should maintain a posture of
  least privilege when continuous trust evaluation cannot be
  completed."
- Cloudflare Access publishes its break-glass + emergency-bypass
  semantics explicitly; we mirror that documentation pattern here.

## Decision

**Talon is fail-closed for every authoritative dependency.** The
only fail-open surfaces are:

1. The dedicated `/healthz` liveness probe path (always 200 OK
   without inspecting auth state — pure transport check)
2. The dedicated `/ready` readiness probe path (200 once
   dependencies are healthy enough to serve traffic; otherwise 503
   — never silently allows)
3. A labeled break-glass route declared on a TalonRoute with
   `breakGlass: true` (must include a 6-digit out-of-band-rotated
   pre-shared header, see Break-glass below)

For every other request path, the failure-mode matrix is:

| Failure | Effect on `Verify` | Status emitted | Audit event |
|---|---|---|---|
| Falcon-ID JWKS fetch timeout / 5xx | Reject with `verify-failure` | 401 | `request.deny` with reason=`jwks_unavailable` |
| Federated issuer JWKS fetch timeout / 5xx | Reject with `verify-failure` | 401 | `request.deny` with reason=`federated_jwks_unavailable` |
| JWT signature verification error (any cause) | Reject | 401 | `request.deny` with reason=`signature_invalid` |
| Unknown `iss` claim (not Falcon-ID, not in federated list) | Reject — CVE-2021-21378 invariant | 401 | `request.deny` with reason=`issuer_mismatch` |
| Session store unavailable | Within the DDIL P3.1 offline budget (15m standard / 5m privileged): serve the signed last-known-good session; past budget, no recorded session, or feature off: Reject | 503 (fail-closed path only) | fail-closed: `request.error` reason=`session_store_unavailable`; within-budget serve: `ddil_degraded_total{dependency=session_store,outcome=offline_served}` (no deny event) |
| Session store returns a session blob that fails to unmarshal | Reject + clear cookie + redirect to `/auth/start` | 302 | `session.revoke` with reason=`corrupt_session` |
| Device posture (`X-Talon-Posture`) past its hard `exp`/MaxAge | Within the DDIL P3.10 governed grace budget (per tier: corp 10m / byod 30m, default OFF): serve the TPM-attested posture DEGRADED — admissible for low/medium routes, DENIED on critical/high; past budget: Reject. Grace NEVER bypasses the signature/attestation check | 403 on the critical/high deny + past-grace path (posture-degraded routes are still subject to the route's own policy) | low/medium serve: `ddil_degraded_total{dependency=posture,outcome=stale_served}` + `WARN`; critical/high deny: `request.deny` reason=`posture_degraded` + `ddil_degraded_total{dependency=posture,outcome=offline_denied}`; past grace: `request.deny` reason=`posture_invalid` + `ddil_degraded_total{dependency=posture,outcome=fail_closed}` |
| SpiceDB unavailable (route requires SpiceDB permission) | Reject | 503 | `request.error` with reason=`spicedb_unavailable` |
| Rego policy evaluator panics | Reject | 503 | `request.error` with reason=`rego_panic` (panic recovered + logged) |
| Rego policy returns non-bool | Reject | 503 | `request.error` with reason=`rego_type_error` |
| Continuous-verification check fails | Revoke session + redirect to `/auth/start` | 302 | `cv.invalidate` |
| ext_authz call from Envoy to Talon times out | Envoy treats per its own `failure_mode_allow` knob (HexxLock defaults to `false`) | 403 from Envoy | n/a (Talon never sees the request) |

### Fail-OPEN surfaces

Two surfaces intentionally bypass auth checks:

#### `/healthz` and `/ready`

- `/healthz` always returns 200. Used by Kubernetes liveness probe.
  No claims, no session, no JWKS — pure "this process is up".
- `/ready` returns 200 only when:
  - Falcon-ID JWKS has been successfully loaded at least once
  - Session store has answered a PING successfully within the last
    `cfg.ReadyProbeStaleThreshold` (default 30s)
  - The talon-route controller has converged a route table at least
    once

Both paths emit NO audit event. They are not auth surfaces; emitting
them would pollute the SIEM with kubelet-poll noise (the existing
probeCIDRs NetworkAuthentication scopes them at the Linkerd layer —
see deploy/helm/falcon-id/values.yaml linkerd.policy.probeCIDRs for
the upstream pattern).

#### Break-glass route

Operators can declare a TalonRoute with `spec.breakGlass: true` AND
`spec.breakGlassSecretRef: <Secret with key 'header_value'>`. When
both are present, Talon admits requests carrying
`X-Talon-BreakGlass: <secret>` without OIDC / SpiceDB / Rego
evaluation.

Constraints to keep break-glass tier-1:

- The pre-shared header value MUST be ≥ 32 random URL-safe
  characters. The webhook in the controller validates this on
  TalonRoute admission.
- Every break-glass admission emits `event=auth.breakglass_admit`
  at slog level `WARN` (not `INFO`). Wazuh rule MUST page on this
  event type — this is an emergency-only path and a non-incident
  use is a SOC-investigable anomaly.
- The pre-shared header rotates per `cfg.BreakGlassRotationCron`
  (default daily, 03:00 UTC) — coordinated with operators via the
  break-glass-rotator CronJob. A token leaked yesterday is dead
  today.
- Break-glass admission DOES NOT bypass network-layer
  Linkerd MeshTLSAuthentication or NetworkPolicy. It only bypasses
  Talon's PEP check; the upstream still requires an mTLS-meshed
  caller from a permitted ServiceAccount.

### Circuit breaker + governed stale window on Falcon-ID JWKS (DDIL P3.1/P3.11)

A 503 cascade on a single JWKS-fetch timeout would cause every
in-flight request to fail simultaneously. Talon mitigates with a
short-window cache + a signed-key **governed stale window** + a
circuit breaker:

1. JWKS is fetched on startup and refreshed lazily on a 5-minute TTL.
2. On a refresh failure AFTER the TTL, the previously-cached JWKS keys
   are RETAINED and continue to be used for signature verification
   until `JWKSStaleThreshold` (default **1h**) past the last successful
   fetch. Each verify served from a stale key set emits a `WARN` and
   increments `talon_ddil_degraded_total{dependency="jwks_svctoken",
   outcome="stale_served"}`.
3. After the stale threshold expires, JWT verification fails closed
   with `reason=jwks_unavailable` (per the matrix above).
4. A shared per-verifier circuit breaker (DDIL P3.11) sheds JWKS
   fetches once Falcon-ID is sustained-unreachable, so the verifier
   serves from the stale window without retry-storming a dead endpoint.
5. The `/readyz` `HealthCheck` deliberately **bypasses** the stale
   window (it forces a live fetch and does not accept a stale-serve
   success) so the readiness probe still reflects the true JWKS state
   during an outage.

**Status: implemented (DDIL Phase-3, P3.1).** This is the real
implementation of the previously-planned `JWKSStaleThreshold`. It lives
in `internal/svctoken/verifier.go` and `internal/identityjwt/verifier.go`
(`getJWKS` / `fetchJWKSResilient` / `fetchJWKS`), builds on the shared
`hexx-pep-core/pkg/resilient` clock + breaker, and is configured via
`TALON_JWKS_STALE_THRESHOLD_SECONDS` (unset = 1h; an explicit `0`
disables the window for strict fail-closed-at-TTL; `>0` = seconds). The
1h default is safe because Falcon-ID signing keys rotate on a 90-day
cadence, so a 1h window can never outlive a key generation. The window
is measured from the last **successful** fetch, so repeated failures do
not extend it.

### Circuit breaker + governed offline session-grace on the session store (DDIL P3.1/P3.11)

Symmetrically to JWKS, a Redis session-store outage would 503 every
already-authenticated request the instant Redis blips — and would make
the SpiceDB **privileged** offline PDP budget (5m) unreachable, because
the session read happens *before* the policy check. Talon closes this
with the same signed-decision primitive:

1. On every **successful** live session `Read`, the router records a
   signed, time-boxed last-known-good "session-valid" decision that
   carries the whole session blob, keyed by cookie
   (`internal/session/offline_session.go`, built on
   `hexx-pep-core/pkg/govdecision`). Re-signing is throttled to at most
   once per 60s per cookie.
2. On a session-read **infrastructure unavailability** (Redis transport
   error / open breaker — NOT a genuine not-found / revoked / expired /
   auth-fail, which stay fail-closed), the router serves the cached
   session **within budget**: 15m on a standard route, **5m on a
   privileged/step-up (critical|high) route** (the tier is applied at
   serve time from the signed `IssuedAt`). Each serve emits
   `ddil_degraded_total{dependency="session_store",outcome="offline_served"}`
   and a `WARN`; a miss/expiry emits `outcome="offline_denied"`.
3. Past the budget, with no recorded session, or with the feature
   disabled, the read fails closed exactly as before
   (`reason=session_store_unavailable`).
4. **Revocation is honoured offline.** Every revoke path
   (`Revoke` / `RevokeBySubject` / CAEP kick) bumps the subject's
   monotonic epoch via the `SubjectInvalidator` fan-out
   (`session.MultiInvalidator` → SpiceDB cache **and** the offline
   session cache); a session decision issued under an older epoch is
   denied even offline. Inherent DDIL limit: a revoke that arrives
   *during* a full Redis outage cannot be written to Redis at all, so
   the short budget (≤15m) is the exposure bound.
5. The session's own hard expiry (`Blob.Exp`, 8h) is re-checked on the
   offline path — grace never resurrects a session past its natural
   lifetime. The issuer keypair is ephemeral and per-process (a restart
   voids the cache); nothing durable is served from a dead key.

**Status: implemented (DDIL Phase-3, P3.1).** Configured via
`TALON_DDIL_OFFLINE_SESSION` (unset/`true` = enabled; `false` = strict
fail-closed-at-t=0), reusing the operating-spec budgets
`TALON_DDIL_OFFLINE_PDP_STANDARD_BUDGET_SECONDS` /
`..._PRIVILEGED_BUDGET_SECONDS` so the session and authz windows agree.
Without it, the privileged authz offline budget is dead code during a
Redis outage.

### Governed grace + graceful-downgrade on device posture (DDIL P3.10)

A TPM-attested device-posture assertion (`X-Talon-Posture`) carries a
hard `exp` and an `iat`/MaxAge freshness window. Historically a posture
one second past either deadline was a hard cliff — the verifier returned
`ErrExpired` and the route's Rego fell through to its no-posture deny.
That is correct for a compromised or long-abandoned device, but it is
brittle under DDIL conditions: a device on an intermittent/limited link
that cannot reach the posture-signer to re-attest loses ALL access the
instant its last good posture expires, even for a low-sensitivity route.

Talon closes that gap with the same governed-degrade primitive the
session/PDP budgets use, applied to the posture freshness gate:

1. The signature/attestation check runs FIRST and is unchanged — a
   forged or wrong-key posture is rejected outright (`ErrSignature`).
   **Grace never bypasses attestation**: the device key signature is
   always required.
2. Past `exp+Skew` (or `iat+MaxAge+Skew`) but WITHIN a tier grace budget,
   `Verify` returns the claims with `Degraded=true` + `GraceUntil` set
   instead of erroring. The budget is per device tier — **corp 10m /
   byod 30m** (≈2× the tier's re-attest cadence, aligned to the LOCKED
   PACE staleness spec and the `ztna_baseline.rego` freshness rules).
3. The grace is **CONSUMER-governed**: Talon (the PEP) is the sole
   authority on the budget length and the degraded SCOPE. A device
   cannot self-grant grace — the verifier reads no device-supplied grace
   field. At the consumer (`internal/router` ServeHTTP), a `Degraded`
   posture is **admissible for low/medium routes** (served within grace,
   `ddil_degraded_total{dependency=posture,outcome=stale_served}` + a
   `WARN`) and **denied on critical/high (privileged) routes**
   (reason=`posture_degraded`,
   `ddil_degraded_total{dependency=posture,outcome=offline_denied}`),
   using the SAME `privilegedSensitivity` classifier the offline session/
   PDP budgets use so all three degraded windows agree on "privileged".
4. Past the grace deadline the posture fails closed exactly as before
   (`ErrExpired` → reason=`posture_invalid`,
   `ddil_degraded_total{dependency=posture,outcome=fail_closed}`).
5. `Degraded`/`GraceUntil` are also surfaced into the Rego input
   (`input.posture.degraded` / `.grace_until`) so an operator policy can
   reason about them; the Go gate in step 3 is authoritative and
   defense-in-depth, so a custom Rego that ignores the fields can never
   widen access past the critical/high deny.

**Status: implemented (DDIL Phase-3, P3.10).** Configured via
`TALON_POSTURE_GRACE_CORP_SECONDS` / `TALON_POSTURE_GRACE_BYOD_SECONDS`
(both default **0 = grace OFF** = the pre-P3.10 hard fail-closed-at-exp
behaviour — backward compatible and the fail-closed-biased default). The
reviewed PACE-aligned opt-in values are 10m / 30m
(`posture.RecommendedGraceCorp`/`Byod`). As with the JWKS/session windows
this trades a bounded staleness window for availability under partial
connectivity — a deliberate governed-degrade posture (short, signed by
the device, tiered, auditable, denied on privileged routes, fail-closed
past budget), NOT fail-open. **Grace-window-drift caveat:** keep the
budget an explicit reviewed config — a quietly-stretched posture grace
lengthens the window in which a compromised/decommissioned device that
stops re-attesting can still ride its last good posture onto low/medium
routes. Review it like a credential-lifetime knob.

### Operational verification

Two chaos drills (run quarterly, tracked in
the fail-mode drill runbook (planned)):

**Drill 1 — Falcon-ID outage.** Scale Falcon-ID Deployment to 0. Run
`curl https://argocd.internal.example.com/`. Expected:

- During the JWKS stale-cache window (≤1h): existing sessions
  continue to work (cookies verified against cached JWKS), new
  logins fail at `/auth/start` (no IdP to redirect to)
- After the stale window: existing sessions also fail with 401
  (`reason=jwks_unavailable`)

**Drill 2 — Session store partition (DDIL P3.1 governed offline
session-grace).** Warm the cache with a request while Redis is healthy,
then kill Talon's session-store Redis primary. Run
`curl ... -b talon_session=<valid cookie>`.
Expected on a **standard** route: served from the offline cache for up
to 15m (200/allow), `ddil_degraded_total{dependency=session_store,
outcome=offline_served}` incrementing and a `WARN` per request; past 15m
→ 503 `reason=session_store_unavailable`. On a **critical/high** route:
served for at most 5m, then 503. A cookie never seen while Redis was
healthy (no recorded decision), a genuinely revoked/expired cookie, or
`TALON_DDIL_OFFLINE_SESSION=false` → 503 immediately with
`reason=session_store_unavailable`, no fail-open. Revocation check: bump
the subject's epoch (kick the user via the admin path or a CAEP event)
*before* killing Redis, then confirm the offline serve denies (503) —
proving revoke-online-AND-offline.

## Consequences

### Positive

- Predictable behavior under partial outage. Operators know exactly
  what 401 vs 503 means.
- SIEM rules can alert deterministically on `reason=` field shapes.
- Chaos drills have a clear pass/fail oracle.
- SOC 2 CC6.1 evidence is straightforward: point to this ADR + the
  drill outcomes.
- NIST 800-207 §3.4.1 maps directly: "least privilege when continuous
  trust evaluation cannot complete" = fail-closed everywhere except
  the documented exceptions.

### Negative

- A misconfigured federated-issuer JWKS URL can cause a full Docker
  pull outage cluster-wide if Harbor is the upstream — operators
  must add federated-issuer JWKS URLs to the same monitoring as
  Falcon-ID.
- The DDIL P3.1 offline session-grace trades a bounded staleness window
  for availability: within budget (≤15m standard / ≤5m privileged) a
  session revoked *during a full Redis outage* keeps working, because
  the revoke can't be written to Redis to bump the epoch. This is the
  deliberate governed-degrade posture (short, signed, auditable, and
  fail-closed past budget), not fail-open — and it is the same
  staleness the SpiceDB offline PDP already accepts. The
  grace-window-drift risk (operators quietly stretching the budget to
  dodge friction) is mitigated by keeping the budget an explicit,
  reviewed config that defaults to the operating-spec values; do not
  raise it without a documented decision.
- Break-glass requires CronJob + Secret rotator + Wazuh rule + ADR
  awareness — heavier than a "always allow this header" knob, but
  intentionally so. Tier-1 break-glass design rejects bypass tokens
  that live longer than 24h.
- During the JWKS stale-cache window, a leaked-and-revoked Falcon-ID
  signing key would still verify successfully on existing sessions.
  Acceptable per current threat model (key rotation is operator-
  initiated; CAEP 1.0 SET-receiver — see ADR 0011 to follow —
  closes this for session-level revocation, not signing-key
  rotation specifically).

## Alternatives considered

### Fail-open on JWKS unavailable

Rejected. Cloudflare-Access-style "if we can't reach the IdP, allow
authenticated cookies through" is tempting but conflicts with the
CVE-2021-21378 family: a JWKS-bypass-on-error becomes the attack
surface itself. We retain the cached-JWKS stale window (1h) as the
relaxation, after which fail-closed kicks in.

### Per-route fail-mode override

Rejected for now. A "this specific route is OK to fail-open" knob
on TalonRoute would solve some availability concerns but creates
inconsistent audit semantics. Break-glass route handles the rare
emergency case explicitly.

### Envoy `failure_mode_allow: true` on the ext_authz call

Rejected. Envoy upstream documentation explicitly warns against
this for security-bearing PEPs. We pair the Envoy default
(`failure_mode_allow: false`) with explicit timeout tuning (`grpc.
ext_authz.timeout` ≤ p99 budget + 50ms) so Talon timeouts don't
masquerade as Envoy-side failures.

## References

- Envoy `ext_authz` configuration — `failure_mode_allow` (default
  false): https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto
- NIST SP 800-207 — Zero Trust Architecture, §3.4 (Continuous
  Trust Evaluation)
- CVE-2021-21378 / GHSA-4996-m8hf-hj27 — Envoy unknown-issuer JWT
  bypass; codifies "unknown iss MUST be verify-failure, not
  missing-token"
- Cloudflare Access break-glass policies —
  https://developers.cloudflare.com/cloudflare-one/policies/access/
- ADR 0001 §10 — audit emission pipeline
- ADR 0009 — shared PDP ext_authz wire shape
