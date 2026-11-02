# ADR 0041 — Audit log WORM JSON contract + replay tooling

**Status:** Proposed — Phase 8 of the ZTNA program (Talon ADR 0040)
**Date:** 2026-06-06
**Phase:** ZTNA Phase 8 — audit + compliance hardening
**Parent:** Talon ADR 0040 + 0040-A (threat model row TT1..TT4)

## Context

Talon's audit log is the durable record of every PDP decision, every
session lifecycle event, every Rego deny reason, every CAEP SET sent
or received. Today the audit emitter writes structured rows to
`audit-archive` MinIO with WORM object-lock (locked 2026-04-27).
What is missing:

1. **Codified JSON contract** — operators currently rely on field
   names matching `internal/audit/event.go` source-of-truth; no
   schema doc.
2. **Replay tooling** — drilled incidents reconstruct the timeline
   from raw JSONL; there's no canonical "play this user's session
   forward in time" CLI.
3. **Auto-generated compliance evidence** — NIST 800-207 + BeyondCorp
   + SOC2 control-mapping evidence is hand-curated today.

This ADR locks the contract + tooling.

## Decision

### 8.a — WORM event schema (`AuditEvent v1`)

Every row in the audit log is a single JSON object on one line
(NDJSON, RFC 7464 JSON Text Sequences). The schema:

```jsonc
{
  // -- envelope (all events) --
  "schema_version": "talon.audit.v1",
  "event_id": "01HZZ...",              // ULID; client-generated; primary key
  "event_time": "2026-06-06T17:00:00.123Z",  // RFC 3339 with milliseconds
  "ingest_time": "2026-06-06T17:00:00.456Z", // when the WORM writer received it
  "sequence": 1234567890,              // monotonic per-pod sequence number — gap-detectable
  "source": {
    "pod": "talon-talon-7d9c-x8t",
    "node": "node-app-01",
    "version": "v1.2.3"                // talon binary git SHA
  },

  // -- subject (all events) --
  "subject": {
    "user_sub": "01HZZ-...",            // Falcon-ID stable subject (RFC 9493)
    "tenant_id": "00000000-...-0002",
    "email": "ops@example.com",       // optional; redacted if data class < tier
    "device_uuid": "01HZZ-..."          // present when device-cert mTLS
  },

  // -- request (PDP events) --
  "request": {
    "method": "GET",
    "host": "grafana.internal.example.com",
    "path": "/api/dashboards/...",
    "src_ip": "10.0.50.42",
    "user_agent": "...",
    "jti": "01HZZ-..."                  // svctoken jti
  },

  // -- decision (PDP events) --
  "decision": {
    "allow": false,
    "deny_reason": "ztna: posture stale (iat too old for tier)",
    "rule_path": "data.talon.route.allow",
    "evaluation_ms": 4
  },

  // -- ZTNA context (PDP events; populated by ADR 0040 contract) --
  "ztna": {
    "tier": "TIER_CORP",
    "aal": "aal3",
    "webauthn_recency_seconds": 1800,
    "posture_fresh": false,
    "device_cert_valid": true,
    "device_cert_fingerprint": "sha256:abcd...",
    "network_class": "vpn",
    "route_sensitivity": "medium"
  },

  // -- session lifecycle (session events) --
  "session": {
    "lifecycle": "established | refreshed | revoked",
    "revoke_reason": "logout | logout_all_devices | caep | admin",
    "amr": ["pwd", "hwk"]
  },

  // -- CAEP (caep events) --
  "caep": {
    "direction": "received | transmitted",
    "event_type": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "stream_id": "...",
    "set_jti": "01HZZ-..."
  },

  // -- data classification --
  "data_class": "internal | confidential | restricted",
  // PII fields are auto-redacted via the data_class lookup table.
  // "internal" = full content; "confidential" = email→hash; "restricted" = subject hash only.
}
```

Top-level keys are optional except `schema_version`, `event_id`,
`event_time`, `ingest_time`, `sequence`, `source`. Event-type tells
schema validators which other top-level keys to expect.

### 8.b — Sequence number scheme

Per-pod monotonic integer issued by `internal/audit/sequencer.go`.
Resets on pod restart but is paired with `source.pod` in WORM, so
gap detection scopes to (pod, sequence). On pod restart, a new
sequencer instance starts at the next monotonic offset stored in a
local-disk checkpoint (`/var/lib/talon/audit-seq`) — guarantees
monotonicity across restarts.

The sweep tool (`audit-replay --check-gaps`) walks WORM and reports
any (pod, sequence_range) gaps. Threshold for paging: 0 unexplained
gaps; restart-boundary discontinuities are filtered.

### 8.c — Replay CLI (`audit-replay`)

New tool in `cmd/audit-replay/`:

```text
audit-replay --since 2026-06-06T17:00:00Z --until 2026-06-06T18:00:00Z \
             --subject "user_sub=01HZZ-..." \
             --output ndjson | jq .

audit-replay --since 2026-06-06T17:00:00Z --subject "user_sub=..." \
             --reconstruct-session > timeline.html

audit-replay --since 2026-06-06T17:00:00Z --check-gaps
audit-replay --since 2026-06-06T17:00:00Z --validate-schema talon.audit.v1
```

Subcommands:
- `--reconstruct-session` — chronologically orders all events for a
  subject + renders an HTML timeline grouping by request, session,
  caep direction.
- `--check-gaps` — sequence-gap detection (8.b).
- `--validate-schema` — JSON-schema enforcement against `talon.audit.v1`.
- `--ztna-decision-stats` — counts per `decision.deny_reason` across
  a time window; surfaces top-N reasons for operator triage.

Lives at `cmd/audit-replay`; built as a single static binary (Go,
no cgo). Operators install via `go install` or pre-built binary
shipped by the talon release pipeline.

### 8.d — Compliance evidence generator

New tool in `cmd/compliance-evidence/`:

```text
compliance-evidence \
  --framework nist-sp-800-207 \
  --window 2026-Q2 \
  --output ./evidence-bundle/

compliance-evidence \
  --framework beyondcorp \
  --window 2026-Q2 \
  --output ./evidence-bundle/

compliance-evidence \
  --framework soc2 \
  --control CC6.1 CC6.2 CC6.3 \
  --window 2026-Q2 \
  --output ./evidence-bundle/
```

Maps each control to a query over the audit log:

| Framework | Control | Query |
|-----------|---------|-------|
| NIST 800-207 §2.1 | Tenet 6 (dynamic policy) | `count(decision.evaluation_ms > 0)` |
| NIST 800-207 §3.4.1 | Continuous diagnostics | `count(ztna.posture_fresh == true) / count(*)` |
| BeyondCorp | CBA | `count(ztna.device_cert_valid == true) / count(*)` |
| BeyondCorp | dry-run policy | `count(decision.allow == false AND decision.rule_path == "would_allow")` |
| SOC2 CC6.1 | Restrict logical access | Decision deny count per period |
| SOC2 CC6.2 | Authentication | AAL distribution histogram |
| SOC2 CC6.3 | MFA enforcement | `count(aal == "aal3") / count(*)` |

Output: directory containing per-control JSON evidence files +
overall PDF report (rendered via embedded template).

### 8.e — Retention + deletion policy

- WORM retention: **7 years** (standing decision, 2026-04-27).
- Object-lock mode: **governance** (allows authorized deletion for
  GDPR Art. 17 erasure requests under explicit operator key).
- Cold-storage tier: after 90 days, objects transition to MinIO
  tier-2 (cheaper, slower retrieval). Replay tool transparently
  reads either tier.
- GDPR Art. 17 — erasure request handler in `internal/gdpr/erasure.go`
  (existing) emits `audit_log.subject.deleted` events but does NOT
  modify WORM objects; instead writes a tombstone object referencing
  the original ULID. Replay tool honors tombstones by redacting the
  PII fields in the reconstructed view while preserving the
  forensic-grade event chain.

### 8.f — External pentest scope

Phase 8.f schedules an external pentest in the rollout calendar
(Talon ADR 0040 Phase 8 + Phase 10 sequencing). Scope:

| Surface | Tests |
|---------|-------|
| Access Agent agent | Posture probe spoofing; JWT replay; cert exfiltration |
| jess `/device-cert` | Attestation evidence forgery; CSR manipulation; mass-mint DoS |
| Talon edge | mTLS bypass attempts; Rego policy fuzz; CAEP receiver tampering |
| Falcon-ID | OIDC consent bypass; PKCE downgrade; WebAuthn phishing simulation |
| Audit pipeline | WORM bypass; sequence-gap forgery |

Vendor candidates per pending decision P-005: Bishop Fox / NCC Group / Cure53.

## Consequences

### Positive

- Codified schema = audit consumers (Loki / Grafana / Vector / SIEM)
  no longer guess; schema-aware parsers can validate at ingestion
- Replay CLI = incident response cycle measured in minutes not hours
- Compliance evidence generator = SOC2 audit prep that takes days
  not weeks
- Sequence-gap detection catches a class of integrity attacks
  (audit log tampering by partial deletion)

### Negative

- Schema migration cost on `talon.audit.v1` field renames — version
  bumps to v2 require dual-write during cutover
- WORM governance mode = small but real risk of authorized deletion
  abuse (mitigated by per-deletion audit + Vault-rooted operator
  key)
- Compliance evidence generator = ongoing maintenance cost when
  control families evolve (NIST 800-207 rev 2 etc.)

### Open questions

| # | Question | Lock by |
|---|----------|---------|
| Q1 | Schema versioning strategy on field renames? | Implementation MR — recommend semver + dual-write window |
| Q2 | GDPR erasure tombstone storage location? | Same bucket with `<original_event_id>.tomb` suffix |
| Q3 | Pentest vendor selection? | P-005 — operator decision; default Bishop Fox unless cost prohibitive |
| Q4 | Replay CLI distribution channel? | Same as talon binary — Harbor + GitHub Releases mirror |

## References

- Talon ADR 0040 — ZTNA Platform (Phase 8)
- Talon ADR 0040-A — Threat Model (TT1..TT4 audit threats)
- NIST SP 800-207 §2.1 (Tenets) + §3.4.1 (Continuous diagnostics)
- BeyondCorp reference architecture (Cloudflare One)
- SOC2 Trust Services Criteria CC6 family
- RFC 7464 — JSON Text Sequences (NDJSON)
- RFC 9493 — Subject Identifiers
