# ADR 0005 — Forward-auth endpoint contract for APISIX integration

- **Status:** Stub (filling during Gap 7 — week 1)
- **Date:** 2026-04-27 (stub)
- **Deciders:** dogukanturhal
- **Refines:** ADR 0001 §11 ("Forward-auth endpoint shape for APISIX
  integration (Phase 4) — deferred to ADR 0004"; renumbered to 0005)
- **Related:** `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` Gap 7;
  ADR 0001 §6 (continuous verification — same identity-headers contract);
  ADR 0007 (SDK contract — SDK-fronted apps don't use forward-auth)

---

## 1. Status

Stub. Implementation lands in Gap 7, week 1. Pilot host:
`accounts.example.com/admin` (locked 2026-04-27 per boot-prompt
recommendation — low-traffic existing OIDC RP).

## 2. Context

ADR 0001 §3 defined Talon as an IAP for the admin tier
(`*.internal.example.com`). Customer-tier APIs sit behind APISIX (memory:
internal engineering notes — APISIX is the strategic API gateway). To
extend Talon as the platform's single IAP-style PEP for customer-tier
routes that opt in, we need a forward-auth endpoint APISIX can call
per-request: 200 + identity headers if session valid, 401 otherwise.

This is the Authentik forward-auth pattern, the Pomerium
`/.pomerium/verify` pattern, and (in the OSS world) the oauth2-proxy
`/oauth2/auth` pattern — all the same shape. Talon's contract is
documented here to lock the headers, error semantics, and cookie scope.

## 3. Decision

> **TODO during Gap 7 implementation. Outline of locked decisions:**

1. **Endpoint**: `GET /auth/verify` on `auth.internal.example.com`
   (admin tier) AND `auth.example.com` (customer tier — separate
   cookie scope). Endpoint behaviour identical; cookie domain differs.
2. **Request shape**: APISIX forwards the original request's
   `Cookie:` header verbatim. `X-Forwarded-Host` carries the host the
   client originally requested; Talon uses this to scope the SpiceDB
   `talon_route:<host>#access` check.
3. **Response shape on success (200 OK)**:
   - `X-Talon-User: <Falcon-ID sub UUID>`
   - `X-Talon-Email: <email>`
   - `X-Talon-Groups: <comma-separated list>`
   - `X-Talon-Subject: <preferred_username or sub>`
   - `X-Talon-Tenant-Id: <tenant_id>` (from id_token claim — memory:
     internal engineering notes)
   - `X-Talon-Decision-Id: <ULID>` (Gap 4 — sso_chain_id correlation)
   - Empty body. APISIX strips X-Talon-* from incoming requests
     before adding them on its forward pass (PEP discipline — ADR
     0001 §7.a).
4. **Response on auth failure (401 Unauthorized)**:
   - Empty body. No identity headers.
   - `X-Talon-Reason: <unauthenticated|policy-deny|cv-revoked|…>`
     header — for APISIX to log; never echoed to the client.
5. **Failure mode (Talon down)**: APISIX returns **503 Service
   Unavailable** with `Retry-After: 30` and a static error page.
   **Do not fail-open.** Coupling: APISIX's `forward-auth` plugin
   has a configurable `request_method=GET` and `keepalive=true`; pin
   timeout at 1 s.
6. **Cookie scope isolation**:
   - Admin tier cookie: `talon_session_admin` on `Domain=.internal.example.com`
   - Customer tier cookie: `talon_session_customer` on `Domain=.example.com`
   - Customer-tier cookie **cannot** read admin-tier hosts (browser
     cookie-jar isolation). Test asserted in
     an unpublished e2e test.
7. **Pilot host**: `accounts.example.com/admin` — existing customer-tier
   OIDC RP, low-traffic admin section. If regression, blast radius
   contained. Migration to broader customer tier follows pilot soak.
8. **Authentication of APISIX → Talon link**: Linkerd mTLS.
   AuthorizationPolicy on Talon's `/auth/verify` Server allows only
   `apisix.<ns>.serviceaccount.identity.linkerd.cluster.local` callers.
9. **Rate limit**: 1000 RPS per-IP at APISIX, not at Talon (Talon's
   own rate limit kicks in on auth-deny burst patterns).

## 4. Implementation

> **TODO during Gap 7 implementation.** Will detail:
>
> - `internal/handlers/verify.go` — GET /auth/verify handler.
> - APISIX route config in the GitOps repository with forward-auth plugin.
> - Customer-tier cookie scope wiring (separate cookie name + domain
>   based on the issuing host).
> - Unit tests for header injection / stripping discipline.
> - E2E test for cookie-scope isolation.

## 5. Failure modes

> **TODO during Gap 7 implementation.** Will cover:
>
> - Talon returns 5xx / times out — APISIX 503 + Retry-After. Tested
>   via chaos test.
> - Cookie-scope leak (customer cookie reaching admin host) — assert
>   via Playwright.
> - APISIX caching the 200 response — Talon emits `Cache-Control:
>   no-store` on every /auth/verify response.

## 6. Test surface (asserted in CI)

> **TODO during Gap 7 implementation.**

## 7. References

> **TODO** — boot prompt Gap 7 §9 reading list:
>
> - [Authentik forward auth](https://docs.goauthentik.io/add-secure-apps/providers/proxy/forward_auth/)
> - [APISIX forward-auth plugin](https://apisix.apache.org/docs/apisix/plugins/forward-auth/)
> - [oauth2-proxy /oauth2/auth pattern](https://oauth2-proxy.github.io/oauth2-proxy/configuration/integration/#configuring-for-use-with-the-traefik-v2-forwardauth-middleware)
> - Memory: internal engineering notes (APISIX as strategic API gateway).

---

*Stub. Subsections fill during Gap 7 implementation week 1.*
