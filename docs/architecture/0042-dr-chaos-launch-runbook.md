# ADR 0042 — ZTNA DR + chaos drills + soft-launch runbook (Phases 9 + 10)

**Status:** Proposed — Phases 9 + 10 of the ZTNA program
**Date:** 2026-06-06
**Phase:** ZTNA Phase 9 (DR + chaos) + Phase 10 (soft launch + training)
**Parent:** Talon ADR 0040 (master)

## Context

Phases 9 + 10 close the program: prove the system survives plausible
adverse conditions (Phase 9) and ship to users with a known-good
playbook (Phase 10). This ADR locks the drill calendar, the rollout
phases, the dashboards, and the training surface.

## Decision

### Phase 9 — DR + chaos engineering

#### 9.a — Disaster recovery runbook

Full DR for the ZTNA stack. Runbook documents the restore order +
RPO/RTO targets per component:

| Component | RPO | RTO | Runbook section |
|-----------|-----|-----|-----------------|
| Falcon-ID PG | 5 min (CNPG continuous WAL archive) | 15 min | §DR.1 |
| Vault PKI mounts (jess-ca, jess-device-ca, jess-ssh-ca, jess-posture-ca) | 0 min (Vault Transit auto-unseal) | 10 min | §DR.2 |
| SpiceDB | 30 min (zedtoken snapshot) | 20 min | §DR.3 |
| Talon session-store (Redis) | 0 min (session data is recoverable from Falcon-ID re-auth) | 5 min | §DR.4 |
| WORM audit-archive MinIO | n/a (immutable; PITR via replication) | 30 min | §DR.5 |
| Posture-signer service | 0 min (stateless; derives from Vault) | 5 min | §DR.6 |
| HexxLock Access agent fleet | 24h (next device-cert rotation re-establishes trust) | n/a (eventual) | §DR.7 |

Aggregate program RTO: **30 minutes** for service restoration; 24h
for full posture re-establishment across the fleet.

Restore order (when starting from zero):
1. Vault HA (auto-unseal via Transit)
2. Vault PKI mounts (all 4 + jess-ca-bundle ESO sync)
3. Falcon-ID PG → Falcon-ID app
4. SpiceDB → schema seed → Talon
5. Talon → posture-signer
6. jess controller + workers
7. Open Talon edge to user traffic
8. HexxLock Access fleet observes Talon up → resumes posture heartbeats

#### 9.b — Quarterly drill calendar

Per Talon ADR 0040-A §Drill calendar:

| Quarter | Drill | Threats exercised | Owner |
|---------|-------|---------------------|-------|
| Q1 | jess-ca root rotation | TF1, TF6 | jess maintainers |
| Q2 | Full device-cert revocation cascade | TD6, R2 | jess + posture-agent |
| Q3 | Falcon-ID DB lost (DR restore) | TI4, TT3, TT4 | falcon-id + SRE |
| Q4 | TPM key compromise drill (blocklist + cascade) | TD1, TD2, R2 | jess + posture-agent |

Each drill follows a structured plan:
- T-7 days: announce in #incident-prep; pre-drill checklist
- T-0: execute against a test tenant in the live cluster (NOT prod tenant)
- T+1d: post-mortem; gaps filed as tasks; runbook updates

#### 9.c — Chaos engineering framework

Chaos Mesh adopted (per Phase 0 P-006 default). Chaos experiments:

| Experiment | Mode | Schedule |
|------------|------|----------|
| Talon pod kill | NetworkChaos PodFailure 1 of N | weekly off-hours |
| Falcon-ID DB connection drop | NetworkChaos PartitionPods | monthly |
| Vault HA pod kill | StressChaos kill 1 voter | quarterly |
| posture-signer connection drop | NetworkChaos PartitionPods | monthly |
| SpiceDB read replica lag | StressChaos delay 500ms | quarterly |
| CAEP outbox drainer kill | PodFailure 1 of N | weekly |

All chaos runs emit telemetry to Grafana dashboard `Chaos calendar`
with green/red badges per experiment.

### Phase 10 — Soft launch + operator training

#### 10.a — Phased rollout pacing

| Week | Population | Gate | Rollback trigger |
|------|------------|------|------------------|
| 1 | Ops team (10 users) | Phase 8 pentest clean | >2 breakglass/wk → halt + tune |
| 2 | Eng (50 users) | Week 1 zero P1 incidents | Posture-deny FP rate >5% → tune Rego |
| 3 | Eng + contractors (80 users) | Week 2 SLO met | Audit-log gap detected → halt + investigate |
| 4-5 | All HexxLock users (200+) | Week 3 SLO met | Page rate >10/wk → halt + tune |
| 6+ | Customer tenants (separate ADR) | All weeks 1-5 SLO met + 0 critical findings | Customer escalation → halt |

SLO targets during rollout:
- Authn p99 < 2s (Talon authentication path)
- Posture-decision p99 < 50ms
- ZTNA-deny FP rate < 1% (per `data.talon.route.deny_reason`)
- Breakglass usage < 1/week per team

#### 10.b — Operator training surface

Training modules (each ~1h):

1. **Module 1 — ZTNA concepts** (60 min)
   - NIST 800-207 + BeyondCorp framing
   - Trust tiers (TIER_CORP / TIER_BYOD / TIER_BREAKGLASS)
   - Why posture + cert + AAL all matter together

2. **Module 2 — Operator UX** (60 min)
   - HexxLock Access install + enrolment
   - `kubectl-oidc-login` operational flow
   - SSH via jess (`ssh -J jess-internal.example.com target`)
   - RDP via HexxLock Access IronRDP bridge

3. **Module 3 — Decision auditing** (90 min)
   - Talon decision log shape (`audit-replay` CLI)
   - Reading per-(user, route, reason) deny stats
   - Common deny patterns + remediation

4. **Module 4 — Posture troubleshooting** (60 min)
   - Reading the posture-signer log + JWT contents
   - Per-probe diagnostic CLI (`hexxlock-posture-agent --diagnose`)
   - Re-enrolling a device that's been replaced

5. **Module 5 — Incident response** (90 min)
   - Breakglass procedure + audit trail expectations
   - DR drill participation
   - Compliance evidence generation (Phase 8)

Delivered as recorded video + interactive labs. Live Q&A sessions
during rollout weeks 1-3.

#### 10.c — Live dashboards

New Grafana dashboards (UIDs locked here so other docs can hyperlink):

| Dashboard | UID | Surface |
|-----------|-----|---------|
| `ZTNA decision rates` | `ztna-decisions` | Per-route deny rates; AAL distribution; tier distribution; top deny reasons |
| `Posture fleet health` | `ztna-posture-fleet` | Posture heartbeat rate; per-probe failure rate; agent version skew |
| `Device-cert lifecycle` | `ztna-device-certs` | Mint rate; rotation rate; revoke rate; per-tier counts; near-expiry watch |
| `Audit pipeline integrity` | `ztna-audit-pipeline` | Sequence-gap count; WORM write p99; replay query latency |
| `Breakglass usage` | `ztna-breakglass` | Per-team breakglass count; approval-token issuance; audit-flag tally |
| `CAEP transmitter health` | `ztna-caep-transmitter` | Outbox pending; drainer rate; per-receiver delivery p99; dead-row count |
| `Chaos calendar` | `ztna-chaos-calendar` | Experiment run history + outcomes |

All dashboards live in `<gitops-bootstrap-repo> addons/base/prometheus-alerts/`
with the standard kube-prometheus-stack folder structure.

#### 10.d — User-facing documentation

Operator-facing docs live in `infrastructure-iac/docs/`:

| Doc | Audience |
|-----|----------|
| `kubectl-oidc-operator-runbook.md` | Phase 1 — shipped |
| `hexxlock-access-install-guide.md` | Phase 10.a — to write |
| `posture-troubleshooting.md` | Phase 10.a — to write |
| `breakglass-procedure.md` | Phase 10.a — to write |
| `incident-response-zt-na.md` | Phase 10.a — to write |

Internal-team-facing docs live in each repo's `docs/runbooks/`:

| Doc | Repo |
|-----|------|
| `dr-restore.md` | infrastructure-iac |
| `chaos-experiments.md` | <gitops-bootstrap-repo> |
| `talon-decision-debug.md` | talon |
| `jess-device-cert-debug.md` | jess |
| `posture-signer-debug.md` | (talon namespace) |

## Consequences

### Positive

- Drill calendar + DR runbook turns Phase 9 from "we hope it works"
  into measured operational confidence
- Phased rollout (10.a) catches misconfiguration before fleet-wide
  exposure
- Dashboards 10.c map directly to operator decision-making + SOC
  workflows
- Training surface 10.b reduces "first call to platform" rate by
  giving operators the diagnostic CLIs

### Negative

- ~2 weeks total elapsed for both phases
- Drill cadence requires SRE bandwidth (1 drill/quarter × 4 = 4
  drill-weeks/year)
- Live dashboards add Prometheus + Loki storage cost (~5% over
  baseline)
- Training video recording requires sustained operator time

### Open questions

| # | Question | Lock by |
|---|----------|---------|
| Q1 | Customer-tenant rollout (post-Week 6) timing? | Separate ADR after Phase 10.a internal completion |
| Q2 | Training video hosting (in-cluster Loom-like vs external)? | Operator decision |
| Q3 | Drill calendar publication channel? | Default: `#incident-prep` Slack + this ADR refresh |

## References

- Talon ADR 0040 — ZTNA Platform (master, Phases 9 + 10)
- Talon ADR 0040-A — Threat Model (drill threats)
- Talon ADR 0041 — Audit WORM contract (Phase 8 deliverables this phase consumes)
- Chaos Mesh — https://chaos-mesh.org/
- NIST SP 800-207 §5 (Logical Components) + §6 (Migration Strategy)
- BeyondCorp Enterprise rollout case study
