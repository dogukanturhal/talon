# Chaos Mesh drill manifests for the ZTNA stack

Per ADR 0042 §9.c — Phase 9 chaos engineering framework.

These manifests target the **non-production tenant** in the live
cluster, NOT the prod tenant. Every drill is gated by a label selector
that excludes prod-tenant workloads; verify the selector before applying.

## Quick reference

| File | Experiment | Target | Schedule (Schedule CR) | Severity |
|------|------------|--------|------------------------|----------|
| `01-talon-pod-failure-weekly.yaml` | PodChaos / pod-failure | Talon controller (1 of N) | Weekly Sun 02:00 UTC | low |
| `02-falcon-id-db-partition-monthly.yaml` | NetworkChaos / partition | Falcon-ID ↔ falcon-id-pg | 1st of month 03:00 UTC | medium |
| `03-vault-ha-kill-quarterly.yaml` | StressChaos / kill | Vault HA voter (1 of 3) | Quarterly Mon 04:00 UTC | high |
| `04-posture-signer-partition-monthly.yaml` | NetworkChaos / partition | posture-signer ↔ Talon | 15th of month 03:00 UTC | medium |
| `05-spicedb-replica-lag-quarterly.yaml` | StressChaos / delay 500ms | SpiceDB read replicas | Quarterly Tue 04:00 UTC | medium |
| `06-caep-drainer-pod-failure-weekly.yaml` | PodChaos / pod-failure | Falcon-ID CAEP drainer | Weekly Wed 02:00 UTC | low |

## Apply / dry-run

These files are NOT auto-applied via Argo. Operator triggers each drill
manually after the T-7 announcement (§9.b drill calendar):

```bash
# Validate the manifest renders correctly
kubectl apply --dry-run=server -f docs/drills/01-talon-pod-failure-weekly.yaml

# Execute the drill (single shot — Schedule CR converts manual triggers
# into per-fire PodChaos / NetworkChaos / StressChaos resources)
kubectl apply -f docs/drills/01-talon-pod-failure-weekly.yaml

# Observe in real time
kubectl -n chaos-mesh logs -l app.kubernetes.io/component=chaos-controller-manager --since=10m -f
```

## Telemetry contract

Every drill emits these Prometheus signals (consumed by the `Chaos
calendar` Grafana dashboard per ADR 0042 §9.c):

- `chaos_mesh_experiment_started_total{kind, name}` — counter
- `chaos_mesh_experiment_finished_total{kind, name, outcome}` — counter
  - outcome ∈ {success, failed, timeout}
- `chaos_mesh_target_pod_recovery_seconds{kind, name}` — histogram
  (time from chaos-end to next-Healthy)

Drill SUCCESS is defined as:

1. The target component goes unhealthy at chaos-start.
2. The dependent components ride out the disruption (no user-visible
   error rate spike beyond the drill's documented tolerance).
3. The target component returns to Healthy within RTO per ADR 0042 §9.a.
4. No data loss (validated by post-drill audit-log replay for events
   that were in flight during the drill window).

A drill that fails any of these criteria becomes an action item in the
post-mortem.

## Severity scale

Severity is the BLAST RADIUS if the chaos itself misbehaves (not the
component being chaosed):

- **low** — single pod of an N-replica deployment; auto-recovers via
  Deployment/StatefulSet controller within ~30s.
- **medium** — single component restriction (network partition, slow
  replica); recovery is sub-RTO but requires the operator-on-call to
  confirm metrics returned to baseline before signing off.
- **high** — quorum-adjacent (Vault HA voter kill); pages on-call
  immediately at chaos-start. Requires pre-drill verification that
  the remaining voters are healthy.

## When to add a new drill

Per the ADR 0042 §9.b quarterly calendar, each quarter introduces ONE
new long-form drill (jess-ca rotation, device-cert revocation cascade,
DB restore, TPM key compromise). Long-form drills are NOT chaos-mesh
manifests; they live in `docs/runbooks/` and exercise a full restore
path. The files in THIS directory are the recurring lightweight
disruption probes that run on schedule between long-form drills.

Adding a new lightweight drill:

1. Pick the next `NN-` prefix (zero-padded, two digits).
2. Mirror the file structure of an existing manifest in this directory.
3. Set Schedule's `historyLimit: 5` so recent runs are visible in
   `kubectl -n chaos-mesh get podchaos` without unbounded growth.
4. Add the row to the Quick reference table above.
5. Add the experiment to the ADR 0042 §9.c table (single source of
   truth for what runs).

## ZTNA-specific drill design notes

The drills here are explicitly designed for the ZTNA stack's failure
modes:

- **Talon pod kill** — exercises the IAP-cache-loss path. With the
  posture verifier cache in pod-local memory, killing a Talon pod
  forces the next request to re-verify the posture JWS from scratch —
  the drill confirms the warmup window is sub-second.
- **Falcon-ID DB partition** — exercises the OIDC introspect failover.
  When the DB is unreachable, Falcon-ID must drop to a cache-only mode
  for already-issued tokens. The drill confirms the cache TTL is long
  enough to survive a 5-min DB outage without service-level errors.
- **Vault HA voter kill** — exercises the Vault Raft re-election. The
  drill confirms that the remaining 2 voters elect a new leader within
  30s and that PKI sign operations (jess-ca, jess-device-ca) continue
  during the election.
- **Posture-signer partition** — exercises the HexxLock Access fallback
  posture flow. When posture-signer is unreachable, HexxLock Access
  agents continue with their LAST issued posture JWS (up to its 1h
  expiry) — the drill confirms the agent-side cache-and-retry logic
  works.
- **SpiceDB replica lag** — exercises Talon's ReBAC check stale-read
  tolerance. The drill confirms that 500ms p99 SpiceDB latency does
  not cascade into Talon p99 > 1s.
- **CAEP drainer kill** — exercises the at-least-once delivery
  guarantee. The drill confirms that killing the drainer pod mid-flight
  does NOT lose any outbox row (validated via post-drill row inspection:
  no rows in `status='pending'` older than the drill window).

## Refs

- ADR 0042 — DR + chaos + soft-launch runbook (parent design)
- ADR 0040-A — STRIDE threat model + drill calendar
- ADR 0011 — CAEP + device posture (drill #6 context)
- Chaos Mesh docs: <https://chaos-mesh.org/docs/>
