# Per-app session lifetime + device-claim policy hooks

> Operator runbook for the per-host session-control fields on `TalonRoute`
> (Phase 4 batch). Cross-references the v1alpha1 CRD shipped in
> `deploy/helm/talon/crds/talonroute.yaml` and the router enforcement
> in `internal/router/perhost.go`.
>
> **Audience**: platform engineers authoring `*.internal.example.com` and
> customer-tier `TalonRoute` CRs. SOC analysts reading audit-stream
> events tagged with the new reasons.

## What changed

Before this batch a single cluster-wide `TALON_SESSION_TTL_SECONDS`
governed every protected host. Today every `TalonRoute` can declare:

| Field | Type | Default | Effect |
|---|---|---|---|
| `sessionTtlOverride` | int seconds | 0 = cluster default | Wall-clock cap. `now - blob.IAT > value` ⇒ deny + redirect to `/auth/start`. |
| `sessionIdleSeconds` | int seconds | 0 = no idle limit | Inactivity cap. `now - max(LastSeen, IAT) > value` ⇒ deny + redirect. |
| `reauthOnNetworkChange` | bool | false | When true, current request's source IP `/24` must match the CIDR bound at session issuance, else deny + redirect. NAT-tolerant within `/24`. IPv6 = exact-match. |
| `requireDeviceClaims[].claim`/`.equals` | array | empty = no gate | id_token claim must be present + match. Allow-listed names only. Missing/mismatch = deny (fail-closed). |
| `auditOnly` | bool | false | When true, the four checks above emit `would_have_denied_<reason>` audit events but DO NOT actually deny — soak mode for the one-week window before flipping a route to enforce. |

Existing fields (`mfaRequired`, `continuousVerifyMinutes`, `policyRego`,
`allowedGroups`, `permission`, etc.) are unaffected. The new checks
fire BEFORE the inline-CV check so an idle-out / per-host-expired
session doesn't trigger a wasted Falcon-ID userinfo round-trip.

## Industry-parity references

Each rule maps to a documented control in at least one peer IAP:

- `sessionTtlOverride` → Pomerium per-route [`timeout`](https://www.pomerium.com/docs/reference/timeouts);
  Cloudflare Zero Trust [application session duration](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-apps/);
  Google IAP [context-aware session policies](https://docs.cloud.google.com/iap/docs/concepts-overview).
- `sessionIdleSeconds` → Pomerium per-route `idle_timeout`;
  Microsoft Entra Conditional Access "sign-in frequency" idle policy.
- `reauthOnNetworkChange` → Pomerium [`force_reauth_on_address_change`](https://www.pomerium.com/docs/reference/timeouts).
- `requireDeviceClaims` → Microsoft Entra Conditional Access
  [device-compliance grant control](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-device-to-be-marked-as-compliant);
  Cloudflare Zero Trust [device posture](https://developers.cloudflare.com/cloudflare-one/identity/devices/).
- `auditOnly` → Microsoft Entra "report-only" mode; Cloudflare Access
  Audit Logs enforcement-mode preview.

## Recipe — tighten an admin host (full enforcement)

argocd is editor-tier with destructive sync power. Tier-1 standard:
1h absolute, 15m idle, IP-rebind on, no device-claim gate yet.

```yaml
apiVersion: gateway.talon.example.com/v1alpha1
kind: TalonRoute
metadata:
  name: argocd-ops
  namespace: argocd
spec:
  host: argocd.internal.example.com
  upstream: { service: argocd-server, port: 80 }
  permission: editor
  allowedGroups: [platform_admin]
  sessionTtlOverride: 3600     # 1h cap regardless of activity
  sessionIdleSeconds: 900      # 15m of no requests = bounce
  reauthOnNetworkChange: true  # /24 change forces fresh OIDC
  auditOnly: false             # enforcing — every check denies on breach
```

## Recipe — soak before enforce

Always land a TTL change in `auditOnly: true` first. After at least
one full working week (so a representative spread of operator
workflows occurs), grep the audit stream for `would_have_denied_`
events on the route's host. If the count is zero or only matches
known-stale-tab patterns, flip `auditOnly` to false (or remove the
field — `false` is the default).

```bash
# Count would-have-denied events for a specific host across the soak window:
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /path/to/kubeconfig \
     -n talon logs deploy/talon-talon --since=168h" \
  | grep '"event":"request.deny"' \
  | grep '"would_have_denied_' \
  | grep '"route":"argocd.internal.example.com"' \
  | jq -r '.reason' | sort | uniq -c | sort -rn
```

Expected output sketch (real production traffic):

```
   12 would_have_denied_per_host_idle_timeout
    2 would_have_denied_per_host_expired
    0 would_have_denied_network_change
```

If `network_change` count is non-zero on a route that isn't VPN-rotation-
heavy, investigate before enforcing — it's the strongest signal of
either NAT churn or an actual cookie replay.

## Recipe — device-claim gate (post-MDM)

The schema allows authoring policies today even though the IdP doesn't
yet emit device claims. The policy will deny every request to the
gated route until the MDM is online — that's why you keep
`auditOnly: true` until both:

1. The MDM is enrolled and its agents push compliance to Falcon-ID.
2. Falcon-ID claim-mapping rules emit the corresponding id_token claims.

Allow-listed claim names (CRD-enforced):

- `device_id`
- `device_compliant`
- `device_managed_by_mdm`
- `device_tpm_attested`
- `device_os_version`
- `device_attestation_chain`

Author your policy now so step (3) is just flipping `auditOnly`:

```yaml
spec:
  # ... allowedGroups, permission, etc.
  requireDeviceClaims:
    - { claim: device_compliant,      equals: "true" }
    - { claim: device_managed_by_mdm, equals: "true" }
  auditOnly: true   # stays true until MDM emits the claims
```

Booleans, numbers, and complex shapes all flow through `equals: "<string>"`
— see the table in `internal/oidc/rp.go` `stringifyClaim()` for the
exact normalisation per claim type.

## What the audit stream looks like

Both enforced and audit-only events carry the standard fields plus a
distinct reason. SOC dashboards filter on `event=request.deny` and
either `reason ∈ {per_host_expired, per_host_idle_timeout,
network_change, device_claim_missing, device_claim_mismatch}` for
real denies, or `reason=~ would_have_denied_*` for soak signal.

```json
// real per-host expiry deny:
{"event":"request.deny","reason":"per_host_expired","route":"argocd.internal.example.com",
 "sub":"...","src_ip":"10.0.50.5","sso_chain_id":"...","decision_id":"..."}

// audit-only "would have denied" during soak:
{"event":"request.deny","reason":"would_have_denied_per_host_idle_timeout",
 "route":"grafana.internal.example.com","sub":"...","sso_chain_id":"...",
 "decision_id":"..."}
```

## When the IdP doesn't emit a required device claim

Fail-closed. The router emits:

```json
{"event":"request.deny","reason":"device_claim_missing",
 "route":"vault.internal.example.com","sub":"..."}
```

Wazuh rule 200042 (or your equivalent) should alert on this with
"device claim X required by route Y but not present in token; configure
MDM or relax policy" — the message is enough for an operator on call to
understand the diagnosis without grepping code.

If you see `device_claim_missing` for a route that's been working
yesterday, suspect (in order): IdP claim-mapping rule was removed,
MDM agent stopped reporting, claim allow-list drift between the CRD
and `internal/oidc/rp.go` `allowedDeviceClaimNames` (a runtime test
guards this — see `internal/oidc/devclaims_test.go`).

## Validation rules the controller enforces

The reconciler refuses to register a `TalonRoute` (sets
`Registered=False, Reason=ValidationFailed`) when:

- `sessionIdleSeconds > sessionTtlOverride` (when both > 0) —
  catches operator typo where the idle window exceeds the absolute
  cap (the inner check could never fire).
- A `requireDeviceClaims[].claim` value is not in
  `api/v1alpha1.AllowedDeviceClaimNames` — defense in depth alongside
  the OpenAPI v3 enum on the CRD.
- A `requireDeviceClaims[].equals` is empty — operators express
  absence by omitting the requirement entirely, not via `equals: ""`.

Check the Status condition with:

```bash
kubectl get talonroute -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.status.conditions[?(@.type=="Registered")].reason}{"\n"}{end}'
```

## Hard "do nots"

- **Do not** add per-host TTLs to the Helm chart `values.yaml` — that
  re-establishes the cluster-wide global the per-host CR is escaping.
- **Do not** make the device-claim policy fail-open when the claim is
  missing. The CRD + router both fail-closed by design.
- **Do not** add wildcard claim matchers (`claim: "*"`, `equals: "any"`).
  Operators must enumerate; wildcards create silent drift.
- **Do not** rely on `Cookie: SameSite=Strict` for IP-rebind — the
  enforcement is server-side via the session-blob `src_ip` /24 compare.
- **Do not** widen `/admin/revoke` to accept per-app session-id payloads.
  That endpoint is the tier-1 streaming-revocation webhook; per-app
  session expiry is a Talon-internal Redis-state TTL.
- **Do not** flip a route from `auditOnly: true` to enforce without
  reading the soak-window audit grep. Tier-1 discipline is real-traffic
  data before the gate flip (the Linkerd authz gate also denies TCP,
  not just HTTP).

## Related

- `internal/router/perhost.go` — evaluator + helpers
- `internal/router/perhost_test.go` — pure-function coverage
- `internal/oidc/rp.go` — device-claim capture from id_token
- `internal/oidc/devclaims_test.go` — drift assertion + stringify table
- `api/v1alpha1/talonroute_types.go` — CRD Go types + `AllowedDeviceClaimNames`
- `deploy/helm/talon/crds/talonroute.yaml` — CRD OpenAPIv3 schema
- `internal/controller/talonroute_controller.go` `validateRoute()` —
  reconcile-time validation
- the internal Q2 2026 IAM/IAP audit
  IAP-11 — closed gap row + IAP-01 schema-landed note
