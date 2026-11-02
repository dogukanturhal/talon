# Per-app OIDC integration after Talon migration

Talon authenticates users at the perimeter (`*.internal.example.com`) but
several upstream apps ship their own login pages. From an end-user
perspective that's a SECOND login screen they can't get past
("Falcon-ID login gives error" / "ArgoCD login not working").

This runbook is the per-app to-do list to make every dashboard
visible after a single Falcon-ID login.

Live state captured 2026-04-26 by an unpublished e2e test.

---

## Status matrix

| Host | Status | Final URL post-Talon | Action needed |
|------|--------|----------------------|---------------|
| `prometheus.ops` | ❌ 502 | `/` | **Linkerd Server CR fix** — `prometheus-http` `proxyProtocol: HTTP/1` rejects Talon SA mTLS handshake. Direct curl from another meshed pod also 502s. Either flip the Server CR to `proxyProtocol: opaque`, or correct the actual protocol. See internal engineering notes. |
| `alertmanager.ops` | ✅ | `/#/alerts` | none — pure proxy works |
| `grafana.ops` | ⚠️ | `/login` | **Grafana OAuth flow broken** — OAuth client `grafana` exists in Falcon-ID with the correct `redirect_uris`, and `grafana.ini` has full `auth.generic_oauth` config. Clicking the "Falcon-ID" button stays on `/login`. Likely causes: (a) Grafana's `envFromSecret: grafana-oidc-client-secret` is empty/wrong; (b) Falcon-ID `oauth_clients.client_secret_hash` doesn't match. Check `kubectl -n monitoring get secret grafana-oidc-client-secret -o yaml` and Grafana pod logs. |
| `jaeger.ops` | ✅ | `/search` | none |
| `sonar.ops` | ❌ | `/sessions/new` | **OAuth client missing for ops URL** — Falcon-ID has a `sonarqube` client but with `redirect_uris: ['https://sonar.example.com/oauth2/callback/oidc']` (NOT `sonar.internal.example.com`). Add the ops redirect URI: `UPDATE iam_oauth_clients SET redirect_uris = redirect_uris \|\| '{https://sonar.internal.example.com/oauth2/callback/oidc}' WHERE client_id = 'sonarqube';`. Then enable the SAML/OIDC plugin in SonarQube via its admin UI or chart values. |
| `dojo.ops` | ❌ 500 | `/login` | **Talon → defectdojo returns 500** despite direct mesh-pod curls returning 302. Likely `X-Forwarded-*` handling in DefectDojo's nginx — investigate request shape with `kubectl -n monitoring logs deploy/defectdojo` while running the e2e. |
| `argocd.ops` | ❌ | `/login` | **OAuth client not provisioned**. ArgoCD's `/login` shows a "Falcon-ID" button (its `dex` config or own OIDC) and clicks land on `https://id.example.com/oauth/authorize?client_id=argocd&...` but Falcon-ID rejects (no client). Provision via `ServiceClientClaim`: see template in `the OAuth client claim manifest in your GitOps repository`. Mirror it for `argocd` with redirect URI `https://argocd.internal.example.com/auth/callback`. Then update `argocd-cm` ConfigMap with `oidc.config` block referencing Falcon-ID. |
| `atlantis.ops` | ✅ | `/` | none — Atlantis serves its main page without auth (admin actions still require GitHub OAuth on its API, but the dashboard is reachable). |
| `awx.ops` | ❌ | `/#/login` | **AWX has its own auth + no Falcon-ID OAuth client**. Provision OAuth client via ServiceClientClaim. Configure AWX `SOCIAL_AUTH_OIDC_*` settings via the AWX `extra_settings` Helm values. |
| `rollouts.ops` | ✅ | `/rollouts/` | none |
| `longhorn.ops` | ✅ | `/#/dashboard` | none |
| `netbox.ops` | ❌ | `/login/?next=/` | **NetBox needs OAuth client + python-social-auth config** (`SOCIAL_AUTH_PIPELINE` + `OIDC_KEY/SECRET`). Or simpler: enable `REMOTE_USER_AUTH` and trust `X-Talon-Email` header. |
| `wazuh.ops` | ✅ | `/app/home` | none — verified the dashboard renders after Talon session replay (some lazy SPA loading; assert via `/app/home` URL). |
| `vault.ops` | ⚠️ | `/ui/vault/auth` | **Vault has no SSO** — its UI auth-method picker comes up. Configure an OIDC auth method against Falcon-ID via `vault auth enable oidc` + `vault write auth/oidc/config oidc_discovery_url=https://id.example.com ...`. With `mfaRequired:true` on the TalonRoute, Talon also enforces step-up MFA before reaching this URL. |
| `admin.ops` | ❌ | `/login` | **ExampleSuite admin frontend has its own login** — needs to either consume Talon `X-Talon-Email` header to auto-create a session OR run its own OIDC flow against Falcon-ID. Owned by example-frontend; this repo can't fix unilaterally. |
| `falcon.ops` | ❌ 404 | `/` | **No admin UI exists in Falcon-ID** at `/`. Either drop the `talonroute-falcon-ops.yaml` or wait for Falcon-ID to ship its admin UI. |

---

## Common patterns

### Pattern A — Provision a Falcon-ID OAuth client

Used by every internal-OIDC app (ArgoCD, AWX, NetBox, etc.). Falcon-ID
provisions OAuth clients via the `ServiceClientClaim` Crossplane CR;
the canonical example is at:

```
the OAuth client claim manifest in your GitOps repository
```

For each app, copy + adjust:
- `metadata.name` → app slug (e.g. `argocd-oauth-client`)
- `spec.parameters.clientId` → `argocd`
- `spec.parameters.redirectUris` → `["https://argocd.internal.example.com/auth/callback"]`
- `spec.parameters.scopes` → `["openid","profile","email","groups","roles"]`
- `spec.writeConnectionSecretToRef.name` → where to write `client_id` + `client_secret`

The provisioner Job inserts the row into `iam_oauth_clients` and writes
the secret to the target Kubernetes Secret + Vault path.

### Pattern B — Wire the app's OIDC config

App-specific. Examples:

#### ArgoCD (`argocd-cm` ConfigMap)
```yaml
data:
  oidc.config: |
    name: Falcon-ID
    issuer: https://id.example.com
    clientID: argocd
    clientSecret: $argocd-oauth-creds:client_secret
    requestedScopes: ["openid","profile","email","groups","roles"]
    requestedIDTokenClaims: {groups: {essential: true}}
```

#### Vault (one-shot via `vault` CLI from a meshed pod)
```bash
vault auth enable -path=oidc oidc
vault write auth/oidc/config \
  oidc_discovery_url=https://id.example.com \
  oidc_client_id=vault \
  oidc_client_secret=$(cat /tmp/secret) \
  default_role=platform-admin
vault write auth/oidc/role/platform-admin \
  bound_audiences=vault \
  user_claim=preferred_username \
  allowed_redirect_uris=https://vault.internal.example.com/ui/vault/auth/oidc/oidc/callback \
  policies=admin
```

### Pattern C — Header-trust auth-proxy mode

For apps that don't natively support OIDC but DO support a "trust this
upstream proxy's authenticated user header" mode (Grafana, NetBox,
some custom apps). Talon already injects:
- `X-Talon-User` / `X-Talon-Email` (the email)
- `X-Talon-Subject` (Falcon-ID user UUID)
- `X-Talon-Groups` (comma-separated)
- `X-Talon-Tenant` (tenant UUID)

#### Grafana (`grafana.ini`)
```ini
[auth.proxy]
enabled = true
header_name = X-Talon-Email
header_property = email
auto_sign_up = true
sync_ttl = 60
whitelist = 10.42.0.0/16
```

(Co-existing with `auth.generic_oauth` is supported — auth-proxy
fires first when the header is present.)

---

## Prioritisation suggestion

If you have time for two MRs, the highest user value is:
1. **`argocd.ops` OIDC** — the most frequently visited admin host.
2. **`grafana.ops` OAuth-secret debug** — already 90% configured; the
   remaining gap is the `grafana-oidc-client-secret` Secret content.

If you have time for a third:
3. **`prometheus.ops` Linkerd fix** — restore the Phase 1 pilot host
   to actually working state. This is a one-line change to the
   `server-prometheus.yaml` Server CR's `proxyProtocol`.
