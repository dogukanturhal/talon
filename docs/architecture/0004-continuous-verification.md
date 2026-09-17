# ADR 0004 — Continuous verification: cadence, streaming revocation, JWKS cache

- **Status:** Stub (filling during Gap 2 — week 2 of Tier-1 gap-closure)
- **Date:** 2026-04-27 (stub)
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Refines:** ADR 0001 §6, ADR 0002 §5.6
- **Related:** `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` Gap 2;
  ADR 0007 (SDK contract), ADR 0005 (forward-auth)

---

## 1. Status

Stub. The §4-§7 implementation details land as Gap 2 implementation
proceeds in week 2 of the Tier-1 gap-closure plan. ADR 0001 §6 locked
the high-level cadence (poll-based, 15 min default); this ADR refines
to (a) drop default to 5 min, (b) per-route override, (c) streaming
revocation as the primary signal, (d) per-request JWKS-based re-verify
for Bearer-token API requests.

## 2. Context

ADR 0001 §6 sized continuous verification at "15 min default,
per-route configurable." Phase 4.1 shipped the framework
(`internal/cv/runner.go` — refresh-token + userinfo flow, leader
election, audit emit). The Tier-1 competitive matrix (boot prompt §3
dim 11) flagged this at 7→9 because:

- 15 min poll lags Cloudflare Access's 5 min default cadence.
- No streaming revocation: a disabled user keeps an active session
  until the next tick.
- Bearer-token API requests aren't re-verified against Falcon-ID's
  JWKS per request — only cookie sessions are CV'd via the runner.
- TalonRoute.spec.continuousVerifyMinutes exists in the CRD schema
  (`api/v1alpha1/talonroute_types.go:53`) but is not wired into
  `cv.Runner.Interval`.

## 3. Decision

> **TODO during Gap 2 implementation. Outline of locked decisions:**

1. **Default cadence: 5 min** (matches Cloudflare). Tunable via
   `TALON_CONTINUOUS_VERIFY_MINUTES` env var.
2. **Per-route override**: `TalonRoute.spec.continuousVerifyMinutes`
   wired through `cv.Runner` per-session (the runner reads each
   blob's most-recent route binding to decide its tick interval).
   Routes with no override inherit the default.
3. **1-min override list (locked)**: `vault.ops`, `argocd.ops` get
   1 min — highest-privilege admin tier. Decision per boot prompt §7
   recommendation, confirmed 2026-04-27.
4. **Streaming revocation as primary signal**: Falcon-ID server-side
   hooks on `user.disabled`, `user.groups.changed`,
   `oauth.token.revoked` POST to Talon's new
   `POST /admin/revoke` mTLS-only endpoint. Talon scans Redis for
   matching `talon:session:*` and invalidates within 30 s.
5. **Webhook auth: mTLS-only via Linkerd
   `MeshTLSAuthentication`** with a single SPIFFE identity allow-list
   (`falcon-id.falcon-id.serviceaccount.identity.linkerd.cluster.local`).
   Memory: internal engineering notes. JWT-based path
   deferred to multi-cluster Phase 7+.
6. **JWKS-based per-request re-verify** for Bearer-token API
   requests (no cookie). Cache JWKS for 10 min; refresh on `kid`
   miss; deduplicate concurrent fetches via `singleflight.Group`.
7. **Phase 4.2 access_token JWT decoding** for the role-loss check
   (currently gated on userinfo's empty `roles`). Memory:
   internal engineering notes —
   access_token JWT carries `roles`.
8. **Rate limit on `/admin/revoke`**: 100 events/sec per allowed
   identity. Burst 200. Drops with 429 over budget.
9. **Falco-Talon hook** (cross-system, optional): if Falco detects
   compromised pod with identity claim, calls `/admin/revoke`. Owner
   sits in Platform Security Stack Gap 2 — Talon implements the
   webhook, Falco wiring is a separate prompt's deliverable.

## 4. Implementation

> **TODO during Gap 2 implementation.** Will detail:
>
> - `internal/handlers/revoke.go` — POST /admin/revoke (mTLS+SPIFFE,
>   not cookie-auth like /admin/sessions/{sub}).
> - `cv.Runner.Interval` per-session wiring (or split per-route runners).
> - JWKS cache layer in `internal/oidc/jwks.go` with singleflight.
> - `internal/policy/bearer.go` — Bearer-token verifier path.
> - Metrics: `talon_continuous_verification_total{result=…}`,
>   `talon_session_revoked_total{reason=…}`.
> - Falcon-ID side hook (`falcon-id` repo MR) — `internal/events/talon.go`
>   POSTing on user-state changes, with retry budget + dead-letter.

## 5. Failure modes

> **TODO during Gap 2 implementation.** Will cover:
>
> - Falcon-ID `/admin/revoke` POST fails (5xx, network) — retry budget,
>   dead-letter, eventual consistency relies on next poll tick.
> - JWKS rotation race — `kid` miss triggers immediate refresh.
> - Webhook flood (rate-limit hit) — 429 + Falcon-ID retry with
>   exponential backoff.
> - Cache poisoning (forged JWKS in cache) — JWKS source is HTTPS
>   inside Linkerd mesh; cache bypasses external network. Identity
>   pinned to issuer URL.

## 6. Test surface (asserted in CI)

> **TODO during Gap 2 implementation.** Asserted:
>
> - Unit: revoke webhook accepts only allowed SPIFFE identity.
> - Unit: JWKS cache singleflight dedups concurrent fetches.
> - Integration: disable user in Falcon-ID → revoke webhook fires →
>   Talon's session invalidated within 30 s.
> - Load: 100 webhooks/sec sustained, no DoS.

## 7. References

> **TODO** — see `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` Gap 2 §9
> reading list for Cloudflare 5-min cadence, BeyondCorp continuous
> enforcement, Linkerd MeshTLSAuthentication, OIDC RP-Initiated Logout
> for streaming revocation precedent.

---

*Stub. Subsections fill during Gap 2 implementation week 2.*
