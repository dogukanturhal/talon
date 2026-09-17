# Vault OIDC SSO via Falcon-ID — setup runbook

Provisioned 2026-04-26. End-user flow:

```
arrive at internal.example.com
  → (silent) Talon perimeter authn (Falcon-ID OIDC + step-up MFA per
    talonroute-vault-ops.yaml mfaRequired:true)
  → land on Vault UI auth-method picker
  → select OIDC + click "Sign in with OIDC Provider"
  → Vault redirects to Falcon-ID /oauth/authorize (with PKCE)
  → Falcon-ID auto-consents (existing falcon_idp_session)
  → callback to vault.ops/ui/vault/auth/oidc/oidc/callback?code&state
  → Vault exchanges code, mints token bound to `admin` policy, lands
    on dashboard
```

## Provisioning steps (one-shot, idempotent)

### 1. Falcon-ID OAuth client

```sql
INSERT INTO iam_oauth_clients
  (id, tenant_id, client_id, client_secret_hash, client_name,
   redirect_uris, grant_types, response_types, scopes,
   require_pkce, require_consent, is_active, is_public)
VALUES (
  gen_random_uuid(),
  '00000000-0000-0000-0000-000000000002',  -- example-tenant tenant
  'vault',
  '<SHA256-base64url(client_secret)>',
  'HashiCorp Vault OIDC',
  ARRAY[
    'https://internal.example.com/ui/vault/auth/oidc/oidc/callback',
    'https://internal.example.com/oidc/callback'
  ],
  ARRAY['authorization_code','refresh_token'],
  ARRAY['code'],
  ARRAY['openid','profile','email','groups'],
  true,   -- require_pkce — Vault's OIDC RP sends code_challenge by
          -- default; verified live via `vault write
          -- auth/oidc/oidc/auth_url ...`
  false,  -- require_consent — operator step-up MFA already enforced by
          -- Talon (mfaRequired:true on talonroute-vault-ops.yaml)
  true,   -- is_active
  false   -- is_public — confidential client with secret
);
```

### 2. Vault KV with the client_secret

```bash
vault kv put example/platform/vault/oidc-client \
  clientID=vault \
  clientSecret="<the same secret hashed above>"
```

### 3. Enable Vault's OIDC auth method

```bash
vault auth enable oidc
```

### 4. Configure the OIDC backend

```bash
vault write auth/oidc/config \
  oidc_discovery_url=https://id.hexxlock.com \
  oidc_client_id=vault \
  oidc_client_secret=<secret> \
  default_role=platform-admin
```

### 5. Create the platform-admin role

```bash
vault write auth/oidc/role/platform-admin \
  bound_audiences=vault \
  user_claim=email \
  allowed_redirect_uris=https://internal.example.com/ui/vault/auth/oidc/oidc/callback,https://internal.example.com/oidc/callback \
  policies=admin \
  ttl=8h \
  max_ttl=24h \
  oidc_scopes=openid,profile,email,groups
```

## Verification

```bash
# 1. Auth method present
vault auth list | grep oidc/

# 2. Config readable
vault read auth/oidc/config

# 3. Role readable
vault read auth/oidc/role/platform-admin

# 4. Auth URL generation works
vault write auth/oidc/oidc/auth_url \
  role=platform-admin \
  redirect_uri=https://internal.example.com/ui/vault/auth/oidc/oidc/callback
# Expected: returns auth_url with client_id=vault, code_challenge,
# scope=openid+profile+email+groups, redirect_uri matching the role.
```

End-to-end via browser: see `talon/e2e/playwright/tests/vault-deep-login.spec.ts`.

## Tighten / follow-up

- The OAuth client + Vault auth-method config are NOT yet
  GitOps-tracked. Crossplane vault-provider exposes only
  `providerconfigs` + `storeconfigs` today — no `authbackend` /
  `authbackendrole` CRDs. Track this as a Phase D follow-up: bump the
  vault-provider to a version that surfaces the auth-method APIs and
  port the imperative `vault auth enable oidc` + writes into
  declarative CRs.
- `policies=admin` is broad. Once Vault's policy authoring matures,
  swap to a tier-stratified set (e.g. `platform-viewer`,
  `platform-secrets-rw`, `platform-root`) gated by the user's
  Falcon-ID `roles` claim via `groups_claim` mapping.
