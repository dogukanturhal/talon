# Runbook — Rotate `svc-talon-svctoken-bridge` GitLab access token

The svctoken credential-exchange substrate ([ADR 0030](../adr/0030-svctoken-iap.md))
swaps inbound Falcon-ID JWTs for an upstream GitLab credential before
proxying. The host-default credential for `github.com` is the
**GitLab Group Access Token** named `svc-talon-svctoken-bridge` on the
`hexxlock` group (id=6).

This token is a real GitLab access token with a hard 1-year expiry —
GitLab rejects access tokens with `expires_at > 365 days from now`
([gitlab-org/gitlab#369122](https://gitlab.com/gitlab-org/gitlab/-/issues/369122)).
**On expiry, every github.com call routed through Talon's
credexchange host-default path returns 401 cluster-wide.** This
runbook rotates the token without downtime.

## Quick reference

| Field | Value |
|-------|-------|
| Token name | `svc-talon-svctoken-bridge` |
| Group | `hexxlock` (id=6) |
| Role | Developer (access_level=30) |
| Scopes | `read_repository`, `write_repository` |
| **Expiry** | **2027-05-28** (set at creation 2026-05-29) |
| Vault path | `example/data/talon/upstream-creds/gitlab` |
| Vault fields | `username` (always `oauth2`), `password` (the token), `format` (`basic-oauth2`) |
| K8s Secret | `talon-upstream-creds-git-ops-example-com` in talon ns |
| ESO refresh | 1h |

## When to rotate

- **30 days before expiry** — calendar reminder set during creation.
  Rotation done early gives a 30-day window to detect downstream
  regressions before the old token actually dies.
- **Immediately on suspected compromise** — credential leak, audit
  finding, etc. The token has write_repository scope on every project
  in the hexxlock group; treat a leak as critical.
- **Scope/role change** — if a future consumer needs a different
  access level. Don't widen the existing token — create a per-client
  Secret using the talon!78 substrate ([Phase 5 doc](../specs/talon-service-tokens.md#phase-5-per-client-credexchange)).

## Pre-flight

1. Verify the live cluster state matches this runbook:
   ```
   kubectl -n talon get externalsecret talon-upstream-creds-git-ops-example-com
   kubectl -n talon get secret talon-upstream-creds-git-ops-example-com -o yaml
   ```
   Confirm the Secret has `username=oauth2`, `format=basic-oauth2`,
   `password=<glpat-...>` (51 chars). If any field drifted, fix that
   first — rotation assumes the schema.

2. Confirm the existing token still works (don't rotate a broken
   token without a known-good baseline):
   ```
   PAT=$(kubectl -n talon get secret talon-upstream-creds-git-ops-example-com -o jsonpath='{.data.password}' | base64 -d)
   curl -sk -u "oauth2:$PAT" https://github.com/api/v4/projects?per_page=1
   ```
   Should return 200 with a single project JSON. 401 means the token
   is already broken — escalate, don't follow this runbook.

## Rotation (zero-downtime, ~5 min)

The new token is created in GitLab first (so the old + new co-exist
briefly), then Vault is updated, then the old token is revoked once
every consumer has rotated to the new value.

### Step 1 — Create the new token

The token cannot be created via Terraform (the existing
`gitlab_group_access_token` resource doesn't manage this token —
it was bootstrapped pre-Atlantis). Two ways:

**A. GitLab UI** (recommended — leaves an audit trail):

1. Navigate to <https://github.com/groups/hexxlock/-/settings/access_tokens>
2. Click "Add new token"
3. Name: `svc-talon-svctoken-bridge-YYYY-MM`  (use current month)
4. Role: **Developer**
5. Scopes: `read_repository`, `write_repository` (only these two)
6. Expires at: 365 days from today
7. Click "Create group access token"
8. **Copy the token value** — it's shown only once. Treat as critical
   secret while in transit (do not paste into Slack, do not commit
   to git, do not write to /tmp).

**B. GitLab API** (when UI is unreachable):
```
curl -X POST "https://github.com/api/v4/groups/6/access_tokens" \
  -H "PRIVATE-TOKEN: <admin-pat>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "svc-talon-svctoken-bridge-YYYY-MM",
    "scopes": ["read_repository", "write_repository"],
    "access_level": 30,
    "expires_at": "YYYY-MM-DD"
  }'
```

### Step 2 — Write the new token to Vault

Vault writes require the Atlantis Terraform path OR a privileged
operator session. Both are documented; pick one:

**A. Direct vault CLI** (operator with `example-platform-write`
policy):
```
vault kv put example/talon/upstream-creds/gitlab \
  username=oauth2 \
  password=<the-new-token-value> \
  format=basic-oauth2
```

**B. Terraform via Atlantis** (the canonical path; takes ~5 min
including atlantis-plan + reviewer + atlantis-apply):
1. Create infrastructure-iac MR adding a `vault_kv_secret_v2`
   `talon_upstream_creds_gitlab` resource — same shape as the
   `argocd-image-updater` one in
   `datacenters/eu-west-1/core/gitlab-image-updater-bump-pat.tf`,
   with `name = "talon/upstream-creds/gitlab"` + the new token as a
   TF variable (not committed; passed via `-var` in atlantis
   command).
2. `atlantis plan -- -var "talon_bridge_token=<new-token>"` —
   reviewer verifies the diff (single resource, single field
   change).
3. `atlantis apply` — writes to Vault.

The Vault path is `example/data/talon/upstream-creds/gitlab` (KV-v2
auto-prepends `/data/`). The ExternalSecret in talon ns watches this
path with `refreshInterval: 1h`.

### Step 3 — Force ESO refresh (skip the 1h wait)

```
kubectl -n talon annotate externalsecret talon-upstream-creds-git-ops-example-com \
  force-sync="$(date +%s)" --overwrite
```

Wait for the Secret to update (~5s):
```
kubectl -n talon get secret talon-upstream-creds-git-ops-example-com \
  -o jsonpath='{.data.password}' | base64 -d | head -c 8
```
Should print the first 8 chars of the new token. If still old,
check ESO logs:
```
kubectl -n external-secrets logs deploy/external-secrets-webhook --tail=20
```

### Step 4 — Verify the new token works end-to-end

Talon reads the live Secret on every credexchange call (no caching),
so the next request through github.com uses the new token.

Smoke test via an existing svctoken consumer (e.g., a quick read of
the talon repo via Bearer flow):
```
kubectl -n argocd exec deploy/argocd-repo-server -c svctoken-refresher -- \
  /bin/sh -c 'JWT=$(cat /var/run/svctoken/jwt); \
    curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $JWT" \
    https://github.com/dogukanturhal/talon.git/info/refs?service=git-upload-pack'
```
Should return `200`. Anything else → roll back (Step 6).

Confirm Talon counters surface the swap:
```
# From any pod with access to the Talon /metrics port (9090):
curl -s http://talon-talon.talon.svc.cluster.local:9090/metrics | \
  grep -E 'talon_auth_decision_total.*credential_exchange'
```
The `decision=allow,reason=svctoken_credential_exchange` counter
should increment within ~30s of the smoke test.

### Step 5 — Revoke the old token

Once the new token is verified working for ≥10 min (lets ESO
propagate to every Talon pod replica, and lets at least one
production svctoken call land), revoke the old token to close the
overlap window:

1. GitLab UI → group access tokens list → find the old token by
   name (`svc-talon-svctoken-bridge` without the date suffix, or the
   previous month's date suffix) → click Revoke.
2. Or API:
   ```
   curl -X DELETE "https://github.com/api/v4/groups/6/access_tokens/<old-token-id>" \
     -H "PRIVATE-TOKEN: <admin-pat>"
   ```

Revoke is instant on GitLab side. Talon would never present the old
token again (Step 3 already replaced it in Vault → Secret → live
data), so revoking is purely cleanup.

### Step 6 — Roll back (if smoke test 401s)

If Step 4 fails:

1. **Don't revoke the old token yet** — it's still the working one.
2. Restore the previous token value in Vault:
   ```
   vault kv put example/talon/upstream-creds/gitlab \
     username=oauth2 \
     password=<previous-token-value> \
     format=basic-oauth2
   ```
   (Get the previous value from your terminal scrollback — Step 1
   captured it. Vault audit log also has the previous value at the
   prior version: `vault kv get -version=<N-1> example/talon/upstream-creds/gitlab`).
3. Force ESO refresh (Step 3 again).
4. Smoke test again — should return 200.
5. Investigate why the new token failed (typo in token value, wrong
   scopes selected in Step 1, GitLab API error). The new token can
   stay parked in GitLab until investigation completes; revoke it
   only after the root cause is understood.

## Post-rotation

- Update the "Expiry" row at the top of THIS runbook with the new
  date (open an MR; this file lives at `docs/operations/svctoken-
  bridge-rotation.md`).
- **Update the PromRule expiry constant** in
  `<gitops-bootstrap-repo>/addons/base/prometheus-alerts/talon.yaml`:
  the alerts `TalonSvctokenBridgePATExpiringSoon` (30d warning)
  and `TalonSvctokenBridgePATExpired` (3d critical) both pin the
  expiry as a Unix-epoch constant in the `expr:` line. Compute
  the new epoch with:
  ```
  python3 -c "import datetime; print(int(datetime.datetime(YYYY,MM,DD,0,0,0,tzinfo=datetime.timezone.utc).timestamp()))"
  ```
  Replace BOTH occurrences (one per alert). Without this update
  the alert will fire continuously after the actual rotation
  because the constant lags behind reality.
- Set a calendar reminder for 30 days before the new expiry
  (belt-and-suspenders with the PromRule — the rule is the
  load-bearing automated signal, calendar is the fallback if
  Prometheus is unhealthy).
- Update memory entry internal engineering notes
  if the rotation surfaced any operational gotchas.

## Why not full automation?

The token bootstrap is manual on purpose:

1. **No `gitlab_group_access_token` TF resource for this token** —
   it pre-dates Atlantis. Adding TF would require importing the
   existing token's id + a Vault read of the current value to seed
   the TF state, which is more risk than the once-a-year manual
   rotation.
2. **Group access tokens cannot be created by another group access
   token** — GitLab rejects this with 403 (group tokens have
   `can_create_group=false`). The bootstrap requires a personal
   access token of an admin (typically root), which is exactly the
   `<admin-pat>` placeholder in Step 1B / Step 5. Storing that
   bootstrap PAT anywhere automated reintroduces the same problem
   one level up — easier to keep humans on the path for the once-
   yearly rotation.
3. **Cross-validation gate** — the smoke test in Step 4 is the
   defense against bad token configuration (wrong scopes, wrong
   role). Automating the full rotation removes that gate without
   replacing it with anything better.

If the org grows past ~10 token rotations per year, revisit this
trade-off — the GitLab provider's `gitlab_group_access_token` +
`replace_triggered_by` pattern (see
`infrastructure-iac/datacenters/eu-west-1/core/gitlab-group-ro-pat.tf`)
is the canonical lane.

## See also

- ADR 0030 — talon-service-tokens architecture
- `docs/specs/talon-service-tokens.md` — Phase 4.5 + Phase 5 wire shape
- Memory: internal engineering notes —
  initial substrate
- Memory: internal engineering notes —
  per-client cred extension (the same Vault path lives next to
  this one with per-client scoping)
