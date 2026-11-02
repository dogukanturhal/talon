# Observability — metrics, logs, alerts

> **Status:** Stub (filling during Gap 1 — week 1, ongoing)

Authoritative reference for every metric Talon emits, every audit log
field, and every alert rule. If a section is missing, the metric/log/alert
either doesn't exist yet or hasn't been documented yet — both are bugs.

## 1. Metrics

### 1.a Existing (Phase 1-4)

> **TODO** — enumerate from `internal/observability/` source:
>
> - `talon_request_total{method,host,decision}` — proxy throughput.
> - `talon_request_duration_seconds{method,host,decision}` — latency.
> - `talon_session_total{state=created|refreshed|revoked|expired}` —
>   session lifecycle.
> - `talon_oidc_handshake_total{step=start|callback,result=ok|err}` —
>   OIDC dance.
> - `talon_spicedb_check_total{result=allow|deny|err}` —
>   PE decisions.
> - `talon_spicedb_check_duration_seconds` — SpiceDB call latency.
> - `talon_cv_tick_total{result=ok|err}` — CV tick frequency.
> - `talon_cv_invalidate_total{reason}` — CV invalidations by reason.

### 1.b Tier-1 gap-closure additions

> **TODO** — Gap 2/4/6/8 add:
>
> - `talon_continuous_verification_total{result=allow|deny|expired}` (Gap 2)
> - `talon_session_revoked_total{reason=user_disabled|groups_changed|admin_force|token_revoked|falco_compromised}` (Gap 2)
> - `talon_passkey_enforcement_total{decision=satisfied|step-up-required}` (Gap 3)
> - `talon_decision_cache_hit_ratio` (Gap 6)
> - `talon_jwks_cache_hit_ratio` (Gap 6)
> - `talon_forward_auth_total{result=200|401|503}` (Gap 7)
> - `talon_audit_evidence_export_total{controls,format}` (Gap 4)

## 2. Audit log fields

> **TODO** — JSON schema for every audit event type.
>
> Emitted by `internal/audit/audit.go`. Common fields: `ts`,
> `subsystem`, `event_type`, `decision_id` (ULID — Gap 4),
> `sso_chain_id` (Gap 4), `sub`, `email`, `host`, `route_id`,
> `decision`, `reason`, `policy_version`, `claims_hash`.
>
> Per-event type (OIDC start, OIDC callback, session create,
> session refresh, session revoke, CV invalidate, admin revoke,
> policy decision, forward-auth verify, evidence export):
> document required vs optional fields.

## 3. Alert rules

> **TODO** — full rule list with thresholds + rationale:
>
> - `TalonHighErrorRate`: 5xx rate > 1% for 5m.
> - `TalonOIDCHandshakeFailures`: handshake_total{result=err}/total > 5%
>   for 10m → IdP issue.
> - `TalonCVTickStalled`: no successful tick in 30 min → leader pod
>   stuck.
> - `TalonSpiceDBOutage`: spicedb_check_total{result=err}/total > 50%
>   for 1m → fail-closed kicking in.
> - `TalonRedisOutage`: any Redis read failure (graceful degradation
>   triggered) — info-level alert.
> - `TalonSessionStorageGrowth`: rate of increase in talon:session:*
>   key count anomalously high → possible session-fixation attack.
> - `TalonForwardAuthLatency`: p99 > 100ms for 5m → upstream APISIX
>   feels it.

Each alert rule includes:

- Threshold + rationale (why this number, not lower/higher).
- Severity (page / ticket / log-only).
- Runbook link (this repo or playbook).
- False-positive notes (when this fires for non-issues).

## 4. Dashboards

> **TODO** — link Grafana dashboards:
>
> - `Talon: overview` — RPS, latency, decision mix, error rate.
> - `Talon: OIDC` — handshake stages, JWKS cache.
> - `Talon: CV` — tick cadence, invalidation reasons.
> - `Talon: sessions` — keyspace size, revocation rate.
> - `Talon: forward-auth` (Gap 7) — verify volume per upstream.
> - `Talon: compliance` (Gap 4) — quarterly privileged-access counts.

## 5. Tracing

> **TODO** — OpenTelemetry trace coverage:
>
> - HTTP entry → policy → SpiceDB → upstream proxy.
> - OIDC handshake spans (start → token-exchange → JWKS verify).
> - CV tick (refresh → userinfo → invalidate).
> - Forward-auth verify (cookie read → policy → header inject).

## 6. References

- `internal/observability/` — code-side definitions
- ADR 0001 §9 (operational implications), §10 (consequences)
- `<your-iac-repo>/observability/` — Prometheus rules + Grafana
  dashboards (TODO: cross-link concrete files)

---

*Stub. Every metric / log / alert added by gap-impl MRs must update
this document in the same MR. PR template enforces.*
