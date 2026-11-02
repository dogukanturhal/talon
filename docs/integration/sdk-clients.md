# SDK-fronted apps behind Talon — integration guide

> **Status:** Stub (filling during Gap 8 — week 1)
> **Audience:** developers integrating a customer-tier SPA (using
> `@hexxlock/falcon-id-client`) with Talon's forward-auth path.

The 17 admin hosts behind Talon (`*.internal.example.com`) are direct OIDC
RPs — they don't use the SDK. This document covers the **other**
case: customer-tier apps (`accounts.example.com`, ExampleSuite, etc.)
that use the falcon-id-client SDK and may opt into Talon's
forward-auth gateway (Gap 7) for an admin sub-route.

## 1. Decision flow — do you need this guide?

```
Are you building an admin tier *.internal.example.com host?
├── Yes → use the standard TalonRoute CRD pattern. See ADR 0003.
│         SDK not involved.
│
└── No, customer tier (*.example.com)
    │
    ├── Customer-tier with SDK (accounts, ExampleSuite) — single OIDC RP
    │   per app, BFF-managed cookies → continue this doc.
    │
    └── Customer-tier API edge (no SDK) → APISIX +
        openid-connect plugin (no Talon). See
        internal engineering notes.
```

## 2. Cookie chain ownership

> **TODO** — explicit boundary between SDK ownership and
> Talon ownership for SDK-fronted apps:
>
> - **SDK owns**: client-side session marker cookie
>   (`app_access_token`), client-side state, BroadcastChannel
>   cross-tab sync, refresh-token rotation through the BFF.
> - **BFF (per-app) owns**: httpOnly OIDC cookies
>   (`app_access_token`, `app_refresh_token`,
>   `hexxlock_id_token`), `/api/v1/auth/login`, `/api/v1/auth/logout`,
>   `/api/v1/auth/refresh`, `/api/v1/auth/me`.
> - **Talon owns** (only when the app is fronted by Talon's forward-auth
>   gateway, e.g. `accounts.example.com/admin`):
>   `talon_session_customer` cookie on `Domain=.example.com`,
>   `/auth/verify`, identity-header injection.
> - **Falcon-ID owns**: `falcon_idp_session` cookie on
>   `Domain=.example.com` (memory:
>   internal engineering notes).

## 3. Logout chain (Gap 8 fix)

> **TODO** — exact sequence for SDK-fronted-app logout (post-fix):
>
> ```
> 1. User clicks "Sign out" in the SPA.
> 2. SDK reads logout_url from BFF response (was: read accountsLogoutUrl).
> 3. SDK calls window.location.replace(logout_url) FIRST,
>    BEFORE setStatus('unauthenticated').
> 4. Browser navigates to id.example.com/oauth/logout?…
> 5. Falcon-ID clears falcon_idp_session cookie.
> 6. Falcon-ID redirects to post_logout_redirect_uri
>    (=accounts.example.com/).
> 7. Talon's session cookie (if any) shadow-clears via
>    next-request 401 path (no session in Redis →
>    OIDC handshake → since falcon_idp_session is gone,
>    user sees Falcon-ID login prompt, not silent SSO).
> 8. User visits any other Talon-fronted host → same outcome.
> ```
>
> See ADR 0007 for the SDK-side rollout plan (skipSelfHop opt-in v1.x,
> default v2.x). See internal engineering notes
> for why Talon doesn't try to clear `falcon_idp_session` itself.

## 4. SDK config for Talon-fronted SDK apps

> **TODO** — exact `FalconIDProvider` props for SDK apps fronted by Talon:
>
> ```tsx
> <FalconIDProvider
>   bffBasePath="/api/v1/auth"
>   skipSelfHop={true}                         // Gap 8 v1.x opt-in
>   // accountsLogoutUrl removed in v2.x; v1.x leaves it as fallback
> >
>   {children}
> </FalconIDProvider>
> ```
>
> When fronted by Talon's forward-auth, the SPA also receives
> `X-Talon-User`, `X-Talon-Email`, `X-Talon-Tenant-Id` headers
> from APISIX → Talon → app. The SDK can use these for SSR
> hydration without re-fetching the session.

## 5. Forward-auth pilot host: accounts.example.com/admin

> **TODO** — the pilot configuration:
>
> - APISIX route: matches `Host: accounts.example.com` + `Path:
>   /admin/*`.
> - APISIX `forward-auth` plugin: `uri:
>   https://auth.example.com/auth/verify`,
>   `request_method: GET`, `keepalive: true`, `timeout: 1000`.
> - On 200: APISIX adds `X-Talon-*` headers per ADR 0005.
> - On 401: APISIX redirects to Falcon-ID login (or returns 401 to the
>   SPA which triggers SDK re-login flow).
> - On 503: APISIX returns 503 + `Retry-After: 30` (no fail-open).

## 6. Test surface for SDK consumers

> **TODO** — Playwright e2e templates:
>
> - `cross-app-logout.spec.ts` — Gap 8 acceptance test.
> - `forward-auth-cookie-isolation.spec.ts` — verify customer-tier
>   cookie can't read admin-tier host.
> - `tenant-header-propagation.spec.ts` — verify
>   `X-Talon-Tenant-Id` reaches the SPA.

## 7. Failure modes

> **TODO** — what goes wrong:
>
> - SDK opts into `skipSelfHop` but BFF doesn't yet return
>   `logout_url` — SDK falls back to v1.x behaviour (the
>   self-hop) with a console.warn().
> - APISIX `forward-auth` cache hits stale 200 — Talon emits
>   `Cache-Control: no-store`; verify in APISIX logs.
> - Customer-tier session leaks to admin tier — Playwright
>   cookie-isolation test catches this.

## 8. References

- ADR 0005 (forward-auth contract).
- ADR 0007 (SDK contract).
- ADR 0006 §3.5 (`falcon_idp_session` invariant).
- Memory: internal engineering notes,
  internal engineering notes,
  internal engineering notes (cascading-bug pattern).

---

*Stub. Sections fill during Gap 7 + Gap 8 implementation week 1.*
