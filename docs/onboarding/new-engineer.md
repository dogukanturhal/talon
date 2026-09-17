# Talon — new engineer onboarding

> **Status:** Stub (filling during Gap 1 — week 1)
> **Acceptance test:** an engineer reaches "I can deploy a TalonRoute
> to a new admin host" in ≤ 1 day using only `docs/`.

This is a half-day path for someone joining the Talon on-call rotation
or making their first contribution.

## Hour 1 — Read these in order

1. **`README.md`** (repo root) — what Talon is, what it isn't.
2. **ADR 0001** — architecture, NIST 800-207 mapping, threat model.
   Don't skip the threat model.
3. **ADR 0002** — cookie + session blob shape. The wire-format table
   in §3.1 is what matters; you don't need to memorise §4.2 byte
   layouts.
4. **ADR 0003** — TalonRoute CRD. You'll write one of these in
   hour 4.

## Hour 2 — Build, run, test locally

> **TODO** — concrete commands:
>
> ```
> git clone …/talon
> cd talon
> make build         # produces ./bin/talon
> make test          # unit + integration with miniredis
> make e2e-ios       # iOS smoke (needs a real iPhone or BrowserStack)
> ```
>
> Note: full e2e against the prod cluster requires `hexx-connect`
> (memory: `hexx-connect` skill). Local make targets cover everything
> short of the prod cluster.

## Hour 3 — Production layout

> **TODO** —
>
> - Where Talon runs: `talon` namespace in
>   `prod-eu-west-1-hub` (memory: internal engineering notes,
>   internal engineering notes).
> - HelmRelease at `the GitOps repository/talon/Application.yaml`,
>   chart at `deploy/helm/talon/`.
> - Argo deny-window: standard cluster-wide window.
> - SpiceDB: `spicedb` namespace, schema at `deploy/spicedb/talon.zed`.
> - Falcon-ID OAuth client: `svc-talon`, registered via
>   ServiceClientClaim XRD (memory:
>   internal engineering notes).

## Hour 4 — Add a new admin host

> **TODO** —
>
> 1. Pick a host (e.g., `internal.example.com`).
> 2. Verify the upstream service exists in its namespace.
> 3. `cp the GitOps repository/talonroutes/grafana-ops.yaml \
>     the GitOps repository/talonroutes/kibana-ops.yaml`
> 4. Edit the host + upstream + permission.
> 5. Open MR; check the validation webhook accepts it.
> 6. Wait for Argo sync; verify with `kubectl get talonroute
>    kibana-ops -o yaml`.
> 7. Test from your laptop and from a real iPhone (e2e/ios/README).
>
> See also: `docs/operations/migrate-host.md` (the 17-host
> Phase-3 migration runbook — same pattern).

## Hour 5-6 — On-call dry run

> **TODO** —
>
> 1. Read `docs/operations/incident-response.md`.
> 2. Read `docs/operations/observability.md`.
> 3. Read `docs/operations/break-glass.md`.
> 4. Walk through one incident from the last quarter (find one in
>    Wazuh; reconstruct the audit trail).
> 5. Pair with current on-call for one shadow shift.

## Hour 7 — Continuous verification + audit

> **TODO** —
>
> 1. Read ADR 0004 (continuous verification) — when implemented.
> 2. Read `docs/compliance/control-mapping.md` (SOC 2 mapping).
> 3. Run `talon evidence export --controls=CC6.6 --since=…
>    --format=csv` (Gap 4) and inspect the output.

## Hour 8 — Read the policy code

> **TODO** —
>
> - `internal/policy/group.go` — group filter (Phase 1 simple check).
> - `internal/policy/spicedb.go` — Zanzibar relationship eval (Phase 2.1).
> - `internal/policy/rego.go` — Rego escape hatch (Gap 5, when
>   implemented).

## Hour 9 — Write a test

> **TODO** — pick an open issue from the backlog or a
> "TODO during Gap N" line in any ADR; write a unit test that
> reproduces the case. Don't fix yet — just writing a failing test
> teaches you the codebase.

## Hour 10 — Optional reading

- Falcon-ID's `internal/handlers/oauth_provider_handler.go`
  (`writeOAuthHTMLRedirect` — the source pattern Talon's
  `internal/oidc/redirect.go` ports).
- Memory entries linked in
  `HANDOFF_TALON_TIER1_GAP_CLOSURE_PROMPT.md` §8.
- Pomerium architecture blog
  (https://www.pomerium.com/blog/identity-aware-proxy) — what we
  rejected and why.

## Acceptance test

By end of day:

- [ ] You can `make build && make test` cleanly on your laptop.
- [ ] You've deployed (or at least drafted MR for) one TalonRoute.
- [ ] You can read `kubectl -n talon logs deploy/talon` and identify
      an OIDC handshake, a SpiceDB CheckPermission, a CV tick.
- [ ] You know where ADR 0001 §5.d (the iOS redirect contract) is
      enforced in code.
- [ ] You've found internal engineering notes
      and can explain why Talon writes the cookie at OIDC callback
      and not also at /auth/login.

If you can't tick all five at end-of-day, this doc has a bug. File it
as an issue.

---

*Stub. Every "TODO" line is a Gap 1 deliverable.*
