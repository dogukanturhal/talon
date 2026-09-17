# ADR 0006 — Falcon-ID integration: claims, PKCE, schema, logout chain

- **Status:** Stub (filling alongside Gap 1 — week 1, ongoing)
- **Date:** 2026-04-27 (stub)
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Related:** `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` Gap 1;
  ADR 0001 §5.a (request flow), ADR 0001 §6 (continuous verification),
  ADR 0002 §4.1 (session blob shape — claim sources), ADR 0003 §5
  (SpiceDB binding from claims)

---

## 1. Status

Stub. Documents Falcon-ID-side quirks Talon depends on, codifies the
working integration after the 2026-04 marathon. Refresh as Falcon-ID
ships changes that touch the integration boundary.

## 2. Context

Talon trusts Falcon-ID for identity (ADR 0001 §7.d — compromise of
Falcon-ID compromises Talon entirely). Five Falcon-ID-side details
have direct correctness consequences for Talon and need to be
documented in one place so SDK consumers, Talon reviewers, and the
on-call engineer share a model:

1. PKCE per-client setting (Falcon-ID `d4d3e62`, 2026-04-24).
2. iam_oauth_tokens schema (Falcon-ID `migrations/212`+, 2026-04-24).
3. OIDC claims delivered: `groups`, `roles`, `amr`, `tenant_id`
   (Falcon-ID `d0f29ad`, 2026-04-21).
4. RP-Initiated Logout chain (`fix/oidc-rp-initiated-logout`,
   `c1fcb8f`).
5. The `falcon_idp_session` two-write-site invariant.

## 3. Decision (recorded — not changing)

> **TODO fill body. Outline of locked decisions:**

### 3.1 PKCE per-client (memory: internal engineering notes)

- Falcon-ID enforces PKCE per-OAuthClient.PKCERequired column
  (default true).
- Talon's OAuthClient (`svc-talon`) registered with PKCERequired=true.
- Pomerium client (`svc-pomerium`) was registered with
  PKCERequired=false during the IAP-decommission soak — has been
  cleaned up post-Phase 5.
- ArgoCD client has PKCE disabled (`c9997a6`) — Argo's CLI flow can't
  do PKCE. SDK-fronted OIDC RPs (BFF-only) must keep PKCE enabled.

### 3.2 iam_oauth_tokens schema (memory: internal engineering notes)

- Schema landed at migration 212 (token_type / token / is_revoked
  layout, replacing the deprecated hash-col layout).
- Talon depends on this schema only indirectly via the token endpoint —
  no direct table reads.

### 3.3 OIDC claims delivered (memory: internal engineering notes)

- id_token claims: `sub`, `email`, `groups`, `roles`, `amr`,
  `tenant_id`, `iss`, `iat`, `exp`, `nonce`, `jti`.
- /oauth/userinfo claims: SCIM-standard set —
  `sub`, `email`, `email_verified`, `given_name`, `family_name`,
  `preferred_username`, `updated_at`. **No `roles`** even with
  scope=roles.
- Talon's CV runner (`internal/cv/runner.go:206-232`) gates the
  role-loss check on `len(claims.Roles) > 0` because of this.
- Phase 4.2 candidate: decode access_token JWT for roles in CV.

### 3.4 RP-Initiated Logout chain (`c1fcb8f`)

- Talon's `/auth/logout` chains to Falcon-ID's `end_session_endpoint`
  via the OIDC discovery doc. Falcon-ID clears `falcon_idp_session`
  cookie (memory: internal engineering notes —
  the codepath that needs the dual-write).
- post_logout_redirect_uri returns the user to
  `internal.example.com/auth/logged-out` (the branded
  redirect-completion page from `d69ec71`).

### 3.5 The `falcon_idp_session` two-write-site invariant

- Memory: internal engineering notes. /api/v1/auth/login
  AND /oauth/authorize MUST both write the SSO cookie or
  `/oauth/authorize` loops back to `/login`. Critical for SDK-fronted
  app flows (ExampleSuite, accounts) — if the SDK's BFF /api/v1/auth/login
  forgets to set the cookie, every Falcon-ID redirect-back loops.

## 4. Implementation observations

> **TODO** — captured runtime behaviours that didn't fit elsewhere:
>
> - Falcon-ID `/oauth/authorize` returns 302 with full HTML body
>   (the `writeOAuthHTMLRedirect` pattern from
>   `internal/handlers/oauth_provider_handler.go`) — same shape Talon
>   adopts in `internal/oidc/redirect.go` (ADR 0001 §5.d).
> - JWKS endpoint at
>   `https://id.hexxlock.com/.well-known/jwks.json`; cache TTL 10 min
>   in Talon (Gap 6).
> - Falcon-ID rotates refresh tokens per OAuth 2.0 BCP §4.14; Talon CV
>   persists rotated tokens (`internal/cv/runner.go:235-245`).

## 5. Failure modes Talon defends against

> **TODO** — list of Falcon-ID-side bugs Talon has guards for:
>
> - PKCE setting drift between code and OAuthClient row.
> - JWKS rotation without `kid` change (Talon refreshes on auth-tag
>   failure regardless).
> - /oauth/userinfo missing `roles` (already gated; see 3.3).
> - `falcon_idp_session` write-site split (covered by Falcon-ID's own
>   tests post-resolution).
> - iam_oauth_tokens schema drift (covered by Falcon-ID migration
>   tests post-212).

## 6. References

> **TODO** — full reading list:
>
> - Falcon-ID repo: `internal/handlers/oauth_provider_handler.go`
>   (writeOAuthHTMLRedirect — Talon's redirect-shape ancestor).
> - Falcon-ID repo: `internal/handlers/oauth_provider_service_tokens.go`
>   (claim emission — `emitSubjectClaims`).
> - Memory: internal engineering notes,
>   internal engineering notes,
>   internal engineering notes,
>   internal engineering notes,
>   internal engineering notes (cascading-bug pattern).

---

*Stub. Sections 3.1-3.5 are factual records, not decisions; updates
land via PR amendment, not superseding ADR.*
