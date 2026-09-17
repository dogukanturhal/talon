# ADR 0003 — TalonRoute CRD: schema, reconciler, SpiceDB binding

- **Status:** Accepted (locked 2026-04-26)
- **Date:** 2026-04-26
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Refines:** ADR 0001 §3 ("Routing config = CRD (`TalonRoute`) — not ConfigMap")
- **Related:** ADR 0001 §5.b (SpiceDB schema), ADR 0002 (cookie/session)

---

## 1. Status

Accepted. Phase 2 deliverable. Once this ADR's API ships at `v1alpha1`,
field shape changes require a `v1beta1` CRD + conversion webhook.

## 2. Context

ADR 0001 §3 locked the routing model at "Kubernetes-native CRD, not
ConfigMap." Phase 1 shipped a static `TALON_PROTECTED_HOSTS_JSON` env
var as a stop-gap (pilot host: prometheus.ops). Phase 2 replaces that
with a `TalonRoute` CRD + in-process controller-runtime reconciler so
operators add a host by `kubectl apply` and Talon picks it up without
a pod restart.

## 3. CRD

### 3.1 Group / version / kind

- Group: `gateway.talon.hexxlock.com`
- Version: `v1alpha1` (Phase 2); `v1beta1` once any field rename
  ships (ADR-superseded).
- Kind: `TalonRoute`
- Scope: namespaced. Each TalonRoute lives in the namespace of the
  upstream Service it fronts; the reconciler watches all namespaces
  the AppProject `platform` allows.

### 3.2 Spec

```yaml
apiVersion: gateway.talon.hexxlock.com/v1alpha1
kind: TalonRoute
metadata:
  name: prometheus-ops
  namespace: monitoring
spec:
  host: internal.example.com           # required, must end in internal.example.com
  upstream:                                    # required
    service: kube-prometheus-stack-prometheus  # k8s service name in this ns (or fully-qualified)
    port: 9090                                 # 1..65535
  permission: viewer                           # viewer|editor|admin (default: viewer); see ADR 0001 §5.b
  allowedGroups:                               # optional; AND-combined with permission
    - platform-admin
  allowedSubjects: []                          # optional list of Falcon-ID `sub` UUIDs (break-glass)
  sessionTtlOverride: 0                        # 0=use cluster default; else seconds (ADR 0002 §3.1 cap 8h)
  continuousVerifyMinutes: 0                   # 0=use cluster default (15m, ADR 0001 §6); Phase 4 uses
  mfaRequired: false                           # Phase 4 step-up: require id_token amr=mfa
status:
  observedGeneration: 1
  conditions:
    - type: Registered
      status: "True"
      lastTransitionTime: "2026-04-26T10:00:00Z"
      reason: ProxyHandlerInstalled
      message: ""
  upstreamReachable: true
```

### 3.3 Field validation (OpenAPIv3, enforced by k8s API server)

- `spec.host` — `pattern: ^[a-z0-9-]+(\.[a-z0-9-]+)+$`, `maxLength: 253`.
- `spec.upstream.service` — k8s DNS-1035 label or qualified
  `<svc>.<ns>.svc(.cluster.local)?` per ADR 0001 §7.a SSRF rule.
- `spec.upstream.port` — `format: int32`, `minimum: 1`, `maximum: 65535`.
- `spec.permission` — `enum: [viewer, editor, admin]`.
- `spec.continuousVerifyMinutes` — `minimum: 0`, `maximum: 1440`.
- `spec.sessionTtlOverride` — `minimum: 0`, `maximum: 28800`.

A validating admission webhook (Phase 2.1 follow-up) adds:
- Reject if `spec.host` is already claimed by another TalonRoute (host
  uniqueness across the cluster).
- Reject if `spec.upstream.service` doesn't resolve in the target
  namespace.
- Reject if the AppProject doesn't list the namespace in destinations.

For Phase 2 ship, OpenAPIv3 validation + reconciler-side host-uniqueness
check (Reject in `Reconcile` with a `Status: False` Condition) is the
first cut.

## 4. Reconciler

### 4.1 Architecture

`internal/controller/talonroute_controller.go` is a controller-runtime
`Reconciler` that:

1. Watches `TalonRoute` cluster-wide.
2. On each event, fetches the object, validates the spec (in addition
   to OpenAPIv3 — runtime-side checks for things the schema can't
   express, like host uniqueness).
3. Computes the desired upstream target.
4. Calls `router.RegisterUpstream(host, handler)` — atomically replaces
   the route entry. The Router's internal map is RWMutex-guarded.
5. Updates Status with `Registered: True` (or False + reason) and
   patches the resource.
6. On delete (finalizer-driven), calls `router.UnregisterUpstream(host)`.

### 4.2 Race / consistency

The reconciler runs in the same process as the HTTP server. Route table
mutations use a sync.RWMutex; reads (per request) take the read lock,
writes (per reconcile) take the write lock. No external coordination.

Two concurrent reconciles for the same TalonRoute serialise via
controller-runtime's per-object reconciliation. Two TalonRoutes
claiming the same host — first-write wins; second emits Status
`HostAlreadyClaimed` and is not registered.

### 4.3 Leader election

Replicated Talon pods all run a reconciler. Without leader election
they would all try to write Status. Two options:

- **A.** Enable controller-runtime leader election (Lease in the
  `talon` ns). Only one pod reconciles + writes Status; all pods read
  the cluster TalonRoute set independently to populate their local
  router table at startup.
- **B.** No leader election. Every pod reconciles independently and
  writes the same Status. Idempotent because all pods compute the same
  decision; Status writes are last-write-wins which is harmless when
  all pods agree.

Going with **A** (leader election) because writing Status from N pods
spams the API server and produces Status-history churn that confuses
audit. Coordinator runs as one pod; non-leader pods still watch + sync
their local router table from the cluster's TalonRoute set on every
event.

### 4.4 RBAC

Talon SA (`talon/talon-talon`) needs:

- `gateway.talon.hexxlock.com/talonroutes` — get, list, watch
- `gateway.talon.hexxlock.com/talonroutes/status` — patch, update
- `gateway.talon.hexxlock.com/talonroutes/finalizers` — update
- `coordination.k8s.io/leases` — get, list, watch, create, update,
  patch (in `talon` ns only, for leader election)

Cluster-wide for the first three (TalonRoutes are namespaced but live
in any namespace the chart's permitted to read).

## 5. SpiceDB binding

### 5.1 Schema

ADR 0001 §5.b locked the schema. `TalonRoute` reconciler does NOT
mutate the SpiceDB schema (one-time apply via Helm pre-sync hook), but
it DOES write a relationship per route:

```
talon_route:<host>#viewer@group:<allowedGroup>#member
talon_route:<host>#editor@group:<allowedGroup>#member  (if perm=editor or admin)
talon_route:<host>#admin@group:<allowedGroup>#member   (if perm=admin)
```

For each `allowedSubjects[i]`:

```
talon_route:<host>#viewer@user:<sub>
```

Reconciler writes these on Reconcile, deletes them on UnregisterUpstream
(via `WriteRelationships` / `DeleteRelationships`).

### 5.2 Permission check (PE upgrade)

Today's Phase 1 PE is the group filter alone. Phase 2 adds, after the
group filter passes:

```go
resp, err := spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
  Resource: &v1.ObjectReference{ObjectType: "talon_route", ObjectId: host},
  Permission: "access",
  Subject:    &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: blob.Sub}},
  Consistency: &v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}},
})
```

`MinimizeLatency` is the right consistency knob — admin tier can
tolerate ~1s of stale-read on a permission revoke, in exchange for
the per-request 5ms p95 SpiceDB delivers (per
[SpiceDB docs](https://github.com/authzed/spicedb)).

A 30s in-process LRU cache fronts the SpiceDB call (per ADR 0001 §7.b).

### 5.3 SpiceDB outage = fail closed

If SpiceDB unreachable or returns error, deny the request. Audit
emit. ADR 0001 §7.b §10.a both lock this posture.

## 6. Migration from static `TALON_PROTECTED_HOSTS_JSON`

Phase 2 ships the reconciler alongside the static env-var support.
Both populate the same router; whichever arrives last wins. After
Phase 2 lands:

1. Operator creates `TalonRoute prometheus-ops` in `monitoring` ns.
2. Reconciler registers handler.
3. Static env-var entry for prometheus.ops is removed from the
   chart's `protectedHosts` list (in env-overlay).
4. Pod restart → cleaner state with reconciler as sole owner.

Phase 3 bulk-migrates the remaining 16 admin hosts, each as a
TalonRoute CR. Phase 5 removes the static env-var fallback entirely.

## 7. Testing surface

- Unit: `internal/controller/talonroute_controller_test.go` — fake
  controller-runtime client, asserts Reconcile registers handler +
  writes correct Status conditions.
- Unit: `internal/policy/spicedb_test.go` — fake SpiceDB client,
  asserts allow/deny flows + cache TTL.
- Integration: `test/integration/crd_test.go` — kind cluster, apply
  TalonRoute, verify HTTP request to host gets routed.
- iOS: every Phase exit per `e2e/ios/README.md`.

## 8. References

- [SpiceDB on GitHub](https://github.com/authzed/spicedb)
- [Google Zanzibar relations](https://authzed.com/learn/google-zanzibar)
- [controller-runtime documentation](https://github.com/kubernetes-sigs/controller-runtime)
- ADR 0001 §3 (CRD over ConfigMap), §5.b (SpiceDB schema), §7.b (PE
  outage posture)

---

*Sub-section numbering (§3.x, §4.x, §5.x) is stable. Refinement requires
a superseding ADR.*
