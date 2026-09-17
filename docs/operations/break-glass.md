# Break-glass — when Talon or Argo is stuck

> **Status:** Stub (filling during Gap 1 — week 1, ongoing)

This runbook covers the cases where the GitOps path is broken and you
need to apply Talon manifests imperatively. Memory:
internal engineering notes,
internal engineering notes.

> **NEVER** use these procedures as a workaround for a fixable
> root-cause bug. Memory: internal engineering notes.
> Every break-glass invocation gets a follow-up MR for the underlying
> issue.

## 1. Argo root retry-loop blocks new Talon Application

When the platform Argo root is stuck on a Degraded sibling and won't
materialise a new Talon child Application:

> **TODO** — full procedure:
>
> 1. `git fetch && git checkout master`
> 2. `kubectl apply -f <gitops-bootstrap-repo>/argocd/applications/talon.yaml`
> 3. Wait for Argo to reconcile the now-existing child.
> 4. Open the underlying Degraded-sibling MR; do not leave the
>    direct-applied manifest as drift.
> 5. Re-run `argocd app diff talon` and verify zero drift.

Reference: internal engineering notes.

## 2. Argo deny-window — manual sync from inside server pod

> **TODO** — full procedure:
>
> ```
> kubectl -n argocd exec -it deploy/argocd-server -- \
>   argocd app sync talon \
>     --auth-token "$(kubectl -n argocd get secret …)" \
>     --server localhost:8080 --grpc-web
> ```
>
> Reference: internal engineering notes.

## 3. Cookie-encrypt key emergency rotation

> **TODO** — refer to ADR 0002 §6.2. Operator command:
>
> ```
> vault kv put example/data/platform/prod/talon/cookie-encrypt-key \
>   version=N+1 current=<new-32-byte-base64> previous=
> ```
>
> Setting `previous=` empty drops the old key entirely. Every
> active session becomes undecryptable → users re-authenticate via
> OIDC (one extra redirect roundtrip per active admin).

## 4. Force-disable Talon for one host (escape hatch)

> **TODO** — when a TalonRoute misconfiguration locks out admins
> and Argo is also stuck:
>
> 1. `kubectl delete talonroute -n <ns> <name>` (reconciler removes
>    handler, host falls through to Talon's default 404).
> 2. Restore the route from a known-good manifest.
> 3. If kubectl fails too: scale Talon to 0, reapply Pomerium
>    Application from the *.disabled.yaml soak-window backup
>    (only valid during the Phase 5 soak grace period — DNS
>    `auth-internal.example.com` is gone post-Phase 5
>    decommission).

## 5. Talon SA token bypass (last resort)

> **TODO** — never document the actual command path here; the
> in-cluster SA token gives Talon the keys to the kingdom. Keep this
> in `SECRETS.local.txt` operator-only.

## 6. Post-incident requirements

After every break-glass invocation:

1. File an incident ticket within 24h.
2. Open the underlying-bug MR within 48h.
3. Update this runbook if the procedure was unclear or wrong.
4. Update the relevant ADR if the architecture rule was violated.

## 7. References

- Memory: internal engineering notes,
  internal engineering notes,
  internal engineering notes,
  internal engineering notes (escape hatch trap).
- ADR 0002 §6 (key rotation).
- ADR 0001 §10.b (Phase 5 one-way-door note).

---

*Stub. The §1-§5 procedures fill out as we use them and learn what
goes wrong.*
