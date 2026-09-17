# ADR 0007 — Falcon-ID SDK contract: SLO race, ownership boundary, soak

- **Status:** Stub (filling during Gap 8 — week 1, day-1 fix)
- **Date:** 2026-04-27 (stub)
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Refines:** ADR 0001 §6 (RP-Initiated Logout chain — landed `c1fcb8f`)
- **Related:** `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` Gap 8;
  ADR 0006 §3.4 (Falcon-ID logout chain), ADR 0006 §3.5 (idp_session
  invariant); `docs/integration/sdk-clients.md`

---

## 1. Status

Stub. Day-1 fix in week 1: SDK MR in `frontend` repo against
`packages/falcon-id-client`. v1.x adds `skipSelfHop?: boolean` opt-in.
v2.x flips default true. 2-week soak on `accounts.hexxlock.com` between.

## 2. Context

The 17 admin hosts behind Talon do not use the falcon-id-client SDK —
they are direct OIDC RPs via Talon. The SDK matters for the
**customer-tier** apps (`accounts.hexxlock.com`, ExampleSuite, etc.) where
React-rendered SPAs need a session client. Those apps' SLO chain
crosses Talon's boundary only via Gap 7's forward-auth path; the SDK
owns the cookie chain end-to-end up to and including
`window.location.replace(idp_logout_url)`.

Boot prompt Gap 8 root-caused the race in
`packages/falcon-id-client/src/nextjs/provider.tsx` lines 374-404:

```tsx
const logout = useCallback(async () => {
  // … client-side state cleared first …
  setStatus('unauthenticated')                  // line 381 — React state change
  try {
    await fetch(`${authBasePath}/logout`, …)    // line 385 — yields event loop
  } catch { … }
  // … BroadcastChannel post …
  window.location.href = sloUrl                 // line 403 — loses the race
}, [authBasePath, accountsLogoutUrl])
```

While `fetch` is awaited, React commits the `unauthenticated` state,
AuthGuard's `useEffect` fires `router.replace('/login')`, and the
eventual `window.location.href` never wins. User believes they logged
out, `falcon_idp_session` survives, next visit silently re-issues a
token via SSO.

## 3. Decision

> **TODO during Gap 8 implementation. Outline of locked decisions:**

1. **v1.x adds `skipSelfHop?: boolean` config option** (default false
   = current behaviour). When true:
   - Read `logout_url` from BFF response on `/api/v1/auth/me` or
     a new `/api/v1/auth/logout` POST that returns the IdP
     end_session_endpoint as JSON.
   - Call `window.location.replace(logout_url)` **synchronously
     before** any React state mutation. React commit happens after
     the navigation queue is filled, eliminating the race.
   - Do NOT `await fetch(authBasePath/logout)` on the primary path
     — the IdP `/oauth/logout` will cascade-clear the session by
     design (memory: internal engineering notes).
2. **v2.x flips default to true.** v1.x stays in npm for a 2-week
   soak window after first opt-in adoption.
3. **Pilot rollout**: `accounts.hexxlock.com` opts in v1.x with
   `skipSelfHop: true`. Soak 2 weeks (Playwright e2e
   `cross-app-logout.spec.ts` runs nightly).
4. **`accountsLogoutUrl` config option deprecated** when SDK reads
   `logout_url` from BFF directly. Removed in v2.x.
5. **Backchannel logout (memory:
   internal engineering notes)** unchanged.
   Backchannel handles SLO from external RPs that aren't SDK-fronted.
6. **No Talon-side change required for this gap.** The SDK owns the
   cookie chain for SDK-fronted apps; Talon shadow-clears its own
   cookie via the next-request 401 (no session in Redis →
   redirect to Falcon-ID login).
7. **e2e test**: `e2e/playwright/tests/cross-app-logout.spec.ts` —
   login to accounts → click "Sign out" → verify
   `falcon_idp_session` cookie absent → re-visit
   `internal.example.com` → assert Falcon-ID login prompt
   (NOT silent SSO).

## 4. Implementation

> **TODO during Gap 8 implementation.** Will detail:
>
> - Frontend MR: `frontend/packages/falcon-id-client/src/nextjs/provider.tsx`
>   reorder + `skipSelfHop` flag.
> - BFF MR (consumer apps): `app.config.ts` opt-in in `accounts.hexxlock.com`
>   first.
> - Talon docs MR: `docs/integration/sdk-clients.md` (this repo) —
>   guidance for SDK-fronted apps fronted by Talon.
> - Playwright e2e: cross-app-logout.spec.ts in this repo's e2e suite.

## 5. Failure modes

> **TODO during Gap 8 implementation.** Will cover:
>
> - SDK reads stale `logout_url` (BFF cached) — BFF response
>   includes `Cache-Control: no-store`.
> - User has `skipSelfHop: true` but Falcon-ID `/oauth/logout` is
>   down — browser stays on origin, user sees a transient error.
>   Recovery: page reload triggers AuthGuard → `/login`.
> - v1.x consumers don't opt in within soak window — v2.x release
>   notes flag the breaking change; semver minor → major.

## 6. Boundary contract

> **TODO** — explicit "what the SDK owns vs what Talon owns":
>
> - SDK owns: client-side session, cookie chain TO Falcon-ID, RP
>   discovery, refresh-token rotation, BroadcastChannel cross-tab sync.
> - Talon owns: server-side session for the 17 admin hosts (no SDK
>   involvement), forward-auth `/auth/verify` for SDK-fronted hosts
>   on customer tier, identity-header injection, SpiceDB CheckPermission.
> - Falcon-ID owns: IdP session (`falcon_idp_session` cookie),
>   `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`,
>   `end_session_endpoint`, JWKS publication.

## 7. References

> **TODO** — full reading list:
>
> - [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
> - [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
> - [Auth0 SLO documentation](https://auth0.com/docs/authenticate/login/logout)
> - Memory: internal engineering notes,
>   internal engineering notes (cascading-bug pattern).

---

*Stub. Subsections fill during Gap 8 implementation week 1.*
