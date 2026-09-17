# Migrate an admin host onto Talon

This is the runbook for moving one `internal.example.com` admin host
off Pomerium (or off the Phase-1 oauth2-proxy-ops fronting if applicable)
and onto Talon. Phase 3 of the project schedules ~16 of these host
migrations across one week.

Each migration is **rollback-safe**: the Pomerium Ingress stays in git
as `<file>.disabled.yaml` for a 7-day soak window after Talon takes
over. Re-enabling it is one rename and one Argo sync.

---

## 0. Prerequisites (one-time per upstream namespace)

The first time a namespace gets a Talon-fronted host, you must allow
Talon's SPIFFE identity inbound on the upstream's Linkerd `Server` CR.
For monitoring this is already done in
`<gitops-repo>/observability/monitoring/linkerd-policy/authz-talon-iap.yaml`.

For a fresh namespace `<ns>` without any Talon authz yet:

1. Add `MeshTLSAuthentication talon-iap-controller` referencing
   `talon/talon-talon` SA.
2. Add `AuthorizationPolicy <upstream>-allow-talon-iap` (v1alpha1)
   targeting the existing `Server` CR.
3. Add `ServerAuthorization <upstream>-allow-talon-iap-sauth`
   (v1beta1) — same auth target with the legacy API for the
   dual-codepath defence per memory
   internal engineering notes.

Mirror the canonical pattern in `authz-talon-iap.yaml`. The Server's
`accessPolicy` should already be `audit` per Phase 2.a; if it's not,
**don't** touch it as part of the IAP migration — that's Phase 2.c
hardening.

## 1. Inventory the host

For each `<host>internal.example.com`, gather:

| Field | Source |
|-------|--------|
| Upstream Service name + ns | `kubectl get ingress -A | grep <host>` (the Pomerium Ingress) |
| Service port | `kubectl -n <ns> get svc <svc> -o jsonpath='{.spec.ports}'` |
| Group / role allow list | Today: always `[platform_admin]` |
| Permission level | `viewer` (read-only UIs), `editor` (e.g. argocd Sync), `admin` (vault/argocd write power) |
| MFA required? | Phase 4 routes that touch credentials/secrets get `mfaRequired: true` |

## 2. Author the TalonRoute CR

Add a YAML next to existing CRs in
`the GitOps repository/environments/prod-eu-west-1-workload/talon/talonroute-<name>.yaml`:

```yaml
apiVersion: gateway.talon.hexxlock.com/v1alpha1
kind: TalonRoute
metadata:
  name: <name>          # short, kebab-case
  namespace: <upstream-ns>
  labels:
    app.kubernetes.io/name: <name>
    hexxlock.com/iap: talon
    hexxlock.com/tier: admin
spec:
  host: <host>internal.example.com
  upstream:
    service: <svc>      # bare name resolves in this CR's ns
    port: <port>
  permission: viewer    # or editor / admin
  allowedGroups:
    - platform_admin
  # mfaRequired: true   # uncomment for sensitive routes
```

Add the file to that directory's `kustomization.yaml`.

## 3. Generate the chart-side IngressRoute

The Talon chart's `protectedHosts` loop generates the Traefik
`IngressRoute` for each entry in
`the GitOps repository/environments/prod-eu-west-1-workload/talon/values.yaml`:

```yaml
ingress:
  protectedHosts:
    - host: <host>internal.example.com
      upstream:
        service: <svc>.<upstream-ns>.svc.cluster.local
        port: <port>
      permission: viewer
```

(The static env-var entry is the Phase-1 fallback; once a TalonRoute
CR is in flight the reconciler is the source of truth, but the
IngressRoute generator hasn't migrated to CRD-driven yet — keep both
entries until that lands.)

## 4. Retire the Pomerium Ingress (or oauth2-proxy-ops IngressRoute)

In the same MR:

```bash
git mv environments/prod-eu-west-1-workload/pomerium/ingress-<name>-ops.yaml \
       environments/prod-eu-west-1-workload/pomerium/ingress-<name>-ops.disabled.yaml
```

Also remove the entry from that directory's `kustomization.yaml`
`resources:` list. Argo prunes the live Ingress on next sync.

## 5. Open + merge the MR

After CI green and merge, Argo syncs in this order:
1. Pomerium Ingress for the host disappears (Argo prune).
2. Talon chart's IngressRoute for the host appears; Talon's reconciler
   sees the TalonRoute CR and registers the upstream handler.
3. SpiceDB relationship `talon_route:<host>#viewer@group:platform_admin#member`
   gets touched.

## 6. Smoke test

```bash
# Cookieless — should 302 to /auth/start with full HTML body
curl -ski "https://<host>internal.example.com/" | head -20

# Verify the body is HTML-scaffolded (NOT bare-anchor) — iOS-safe
# per ADR 0001 §5.d. Look for <!DOCTYPE html> + <meta refresh> +
# <script> tags. Anything else fails the smoke test.
```

A real iPhone over cellular per `e2e/ios/README.md` gates the phase
exit — do that for at least one host per migration batch. The HAR
goes into `e2e/ios/captures/<date>_<host>_phase3.har`.

## 7. Soak (7 days)

Watch the Phase 3 PrometheusRule alerts in `<gitops-bootstrap-repo>/addons/base/prometheus-alerts/talon.yaml`:

- `TalonAuthFailureRate` — fires if ≥ 5% of requests on the migrated
  host get denied for 5 min consecutively.
- `TalonUpstreamErrorRate` — fires if ≥ 1% upstream-error rate.
- `TalonSessionStoreRedisDown` — Redis ping → readiness flips → page.

Any firing within the soak window: rename `.disabled.yaml` back, push,
sync. The TalonRoute CR can stay; Pomerium re-takes the host because
its Ingress is on `ingressClassName: pomerium` (different controller)
and Traefik's IngressRoute on the same host loses to the Pomerium
admission. Post-soak, delete the `.disabled.yaml` files in a Phase 5
cleanup MR.

## 8. Failure modes / common gotchas

| Symptom | Cause | Fix |
|---------|-------|-----|
| 404 on `<host>` from a meshed pod | TalonRoute CR not yet reconciled | Check `kubectl get talonroute -A`; reconciler logs in talon ns |
| 403 forbidden after sign-in | User lacks `platform_admin` role in Falcon-ID, OR SpiceDB relationship not yet written | `iam_user_roles` join + `zed relationship read group:platform_admin` |
| 502 Bad Gateway from Talon to upstream | Upstream Linkerd Server denies talon SA | Add `<svc>-allow-talon-iap` AuthorizationPolicy; mirror the prometheus pattern |
| iOS prompts to download | Body shape regression in Talon's redirect helper | Should be impossible (covered by `internal/oidc/redirect_test.go`); if it does happen, file a P0 — the entire project's premise depends on this |
| Continuous-verification false-positives | Currently no-op until Phase 4.1 | Not applicable yet |
