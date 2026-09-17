# Incident response — Talon

> **Status:** Stub (filling during Gap 1 — week 1, ongoing)

This runbook is the on-call playbook for Talon-tier incidents. Each
section names the symptom, gives the 30-second triage step, then the
remediation path.

## 1. Quick reference — first commands to run

| Symptom (what the user reports) | First command |
|-----|-----|
| "Can't log in to anything `*.ops`" | `kubectl -n talon logs deploy/talon -c talon --tail=200 \| grep -E 'oidc|callback|err='` |
| "Logged in but `grafana.ops` says forbidden" | `kubectl -n talon exec deploy/talon -- /bin/talon test policy --user=<email> --host=internal.example.com` (TODO: implement command Gap 5) |
| "Falcon-ID disabled my account but I can still browse" | streaming-revocation gap; see §3 (TODO: streaming impl Gap 2) |
| "iOS Safari shows 'open in app' prompt" | violation of ADR 0001 §5.d redirect contract; capture `curl -v` of the failing 302 |
| "Argo CD says Talon is OutOfSync" | TODO — fill from Argo deny-window break-glass (internal engineering notes) |

## 2. Emergency session revocation

> **TODO** — full procedure for kicking all sessions of one user
> via the existing `DELETE /admin/sessions/{sub}` operator endpoint
> (`internal/handlers/admin.go`). Authentication: cookie+role.
> Reference command:
>
> ```
> curl -X DELETE \
>   --cookie "talon_session=<your-session>" \
>   https://internal.example.com/admin/sessions/<target-falcon-id-sub>
> ```
>
> Returns JSON `{target_sub, revoked, at}`. Audit emit per kick.
> The streaming-revocation webhook (Gap 2) is a separate code path
> — operator-driven kick-all uses the operator endpoint.

## 3. Force-logout-all (planet-wide kick)

> **TODO** — procedure for revoking every active session at once
> (e.g., during a key-compromise rotation per ADR 0002 §6.2).
> Currently: emergency key-rotation in Vault forces all sessions
> to fail decryption → re-OIDC. Document the exact `vault kv put`
> command + expected blast radius.

## 4. Break-glass: bypass Talon for one host

> **TODO** — covered in `break-glass.md`.

## 5. Diagnostic log greps

> **TODO** — list of canonical greps:
>
> - All OIDC handshake events for one user (last hour):
>   `kubectl -n talon logs … | jq 'select(.subsystem=="oidc" and .email=="…")'`
> - All deny decisions in last hour: `… | jq 'select(.decision=="deny")'`
> - Continuous-verification invalidations: `… | jq
>   'select(.subsystem=="cv" and .invalidated==true)'`

## 6. Escalation paths

> **TODO** — who's on call for what:
>
> - Talon proxy / OIDC bug: platform on-call.
> - SpiceDB outage: DB on-call.
> - Falcon-ID outage: IdP on-call.
> - Linkerd mesh: networking on-call.

## 7. References

- ADR 0001 §10 (operational implications)
- ADR 0002 §5.5 (admin revoke protocol)
- ADR 0002 §6 (key rotation)
- `internal/handlers/admin.go` — operator break-glass endpoint
- `internal/cv/runner.go` — continuous verification runner
- Memory: internal engineering notes,
  internal engineering notes,
  internal engineering notes (cascading-bug pattern).

---

*Stub. Each section fills as Gap 1 docs work proceeds. Each gap-impl
MR refines the relevant section with concrete commands.*
