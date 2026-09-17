# Compliance control mapping — SOC 2, ISO 27001:2022, GDPR

> **Status:** Active (canonical mapping; the runtime `controlMap` in
> `cmd/talon/evidence.go` mirrors this document and the `talon
> evidence export --controls=…` CLI reads the same identifiers).
> **Audience:** auditors, compliance team, on-call security engineer
> answering "show me evidence for control X."

Every Talon audit event maps to one or more SOC 2 Common Criteria, ISO
27001:2022 Annex A control(s), and (where applicable) GDPR Article(s).

The `talon evidence` CLI (in this repo's `cmd/talon`) is the
operator-facing surface for this mapping:

```
loki query '{namespace="talon"} |= "subsystem=audit"' \
  | talon evidence redact --user=<sub-to-tombstone>          # optional GDPR step
  | talon evidence export --since=YYYY-MM-DD --until=YYYY-MM-DD \
                          --controls=CC6.6,A.5.18 \
                          --hmac-key=/etc/talon/audit-hmac.key \
                          --manifest=q1.manifest.json \
                          > q1.csv
cosign sign-blob --key cosign.key \
                 --output-signature q1.manifest.sig \
                 q1.manifest.json
```

## 1. SOC 2 Common Criteria 6.x — Logical and physical access controls

| SOC 2 control | Description | Talon audit event types | Sample query |
|---|---|---|---|
| **CC6.1** | Logical access controls — restrict access | `oidc.callback`, `request.allow`, `request.deny`, `forward_auth.verify` | `talon evidence export --controls=CC6.1 --since=… --hmac-key=…` |
| **CC6.2** | User access provisioning | `session.create`, `serviceclient.created` (future event from the ServiceClient XRD) | `talon evidence export --controls=CC6.2 …` |
| **CC6.3** | Privileged access | `request.allow:permission=admin`, `admin.revoke`, `auth.mfa_challenge` (the `permission=admin` qualifier is enforced runtime-side — only allow events with `permission=admin` count for CC6.3) | `talon evidence export --controls=CC6.3 …` |
| **CC6.6** | Logical access removal | `cv.invalidate` (any reason — Falcon-ID-driven invalidation, including `user_disabled` / `groups_changed` / `oauth_token_revoked`), `admin.revoke` (operator + streaming webhook both feed this), `session.revoke` | `talon evidence export --controls=CC6.6 …` |
| **CC6.7** | Transmission of confidential information | `oidc.callback`, `forward_auth.verify` (every Talon ↔ Falcon-ID and Talon ↔ APISIX edge runs over Linkerd mTLS — the audit event is the transmission gate evidence) | `talon evidence export --controls=CC6.7 …` |

The `permission=admin` qualifier on CC6.3 / A.8.2 is what makes Talon's
SOC 2 evidence stronger than a plain log dump: viewer-tier events (read
dashboards) don't accidentally count as privileged access. The runtime
filter in `cmd/talon/evidence.go::filterAndEmit` parses
`request.allow:permission=admin` and only matches when the event's
`permission` field actually equals `admin`.

## 2. ISO/IEC 27001:2022 Annex A

Same audit event types, different control identifiers. The runtime
`controlMap` accepts both naming families so an auditor can use whichever
their certificate body prefers.

| ISO control | Description | Talon mapping |
|---|---|---|
| **A.5.15** | Access control policy | `request.allow`, `request.deny` — every per-route policy decision logged via `internal/policy.CompositePolicy.Evaluate` |
| **A.5.16** | Identity management | `oidc.callback`, `session.create` |
| **A.5.17** | Authentication information | `session.create` — sessions encrypted at rest (AES-256-GCM, ADR 0002 §4.2) |
| **A.5.18** | Access rights | `request.allow`, `request.deny` — SpiceDB CheckPermission decisions per ADR 0001 §5.b schema |
| **A.8.2** | Privileged access rights | `request.allow:permission=admin`, `admin.revoke` |
| **A.8.3** | Information access restriction | `request.allow`, `request.deny` |
| **A.8.5** | Secure authentication | `oidc.callback`, `auth.mfa_challenge` (WebAuthn step-up evidence lands here once Gap 3 ships) |
| **A.8.15** | Logging | `*` — every audit event is itself the evidence |
| **A.8.16** | Monitoring activities | `cv.invalidate` |

## 3. GDPR

| Article | Talon mechanism |
|---|---|
| **Art. 5(1)(c) — data minimisation** | Session blob (`internal/session.Blob`) carries only fields the policy evaluator needs: sub, email, groups, roles, tenant_id, AMR, src_ip, ua_hash. Scope creep is gated by ADR 0002 §4.1's locked schema — additions require a v→v+1 schema bump. |
| **Art. 5(1)(e) — storage limitation** | 8h sliding TTL on the session record, 8h hard `Exp`, 30d cap on the per-sub revocation index, 5min cap on OIDC handshake state. Audit-log WORM retention: 7 years (boot prompt §7 #2, paired with Platform Security Stack Gap 7 — see §5 below). |
| **Art. 17 — right to erasure** | `talon evidence redact --user=<sub>` rewrites the matching user's PII fields (sub, email, src_ip, session_id) to `sha256:<hex>` form, adds `redacted=true` + `redaction_reason=gdpr_art_17` + `redaction_at=<RFC3339>` markers, and pipes through into the export pipeline. The hash is deterministic across events so the auditor's count + sequence stay intact (Art. 17(3)(e) retention for legal claims). `ua_hash` is already SHA-256 in the upstream pipeline. |
| **Art. 30 — records of processing** | This document + ADR 0001 + ADR 0002. |
| **Art. 32 — security of processing** | AES-256-GCM session blob (ADR 0002 §4.2), Linkerd mTLS in-cluster (ADR 0001 §8 trust boundaries), JWKS-validated id_token, Vault-backed secrets, ServiceClient OAuth bootstrap (memory: internal engineering notes). |

## 4. Audit evidence chain — end-to-end reconstruction

Every audit event carries two correlation handles (live since !19):

- **`decision_id`** — UUIDv4 generated in `router.ServeHTTP` per request,
  threaded via `tlog.WithDecisionID` ctx so every audit emit during the
  request shares the same handle.
- **`sso_chain_id`** — generated at `/auth/start`, persisted into the
  session blob (`session.Blob.SSOChainID`), replayed onto every audit
  event for the lifetime of the session, AND forwarded to upstream apps
  as `X-Talon-Sso-Chain-Id` (proxy.go injectIdentityHeaders) so an
  upstream that emits its own audit can echo the same handle.

**Auditor walk:**

1. Pick a `decision_id` from a flagged event.
2. `talon evidence export --decision-id=<uuid> --hmac-key=…
   --manifest=…` returns the full row + adjacent context.
3. For chain-of-events analysis: `--sso-chain-id=<id>` ties together
   the user's full Talon → Falcon-ID → upstream-app trail (once
   Falcon-ID adds the field — separate `falcon-id` repo MR).
4. Verify the manifest with `cosign verify-blob --key cosign.pub
   --signature manifest.sig manifest.json`.
5. Replay the HMAC chain on the CSV: each `row_hmac[i]` = HMAC-SHA256(
   `row_hmac[i-1]` ‖ canonical_fields[i], key). Tamper to any byte
   breaks the chain at the offending row.

The HMAC chain is per-export — exporting the same NDJSON window twice
with the same key produces the same chain. Different keys = different
chains, so the `hmac_key_id` in the manifest pins which key signed.

## 5. WORM archive retention

> **Pending** — paired with Platform Security Stack Gap 7. Locked
> decisions (boot prompt §7 #2): 7-year retention on a MinIO
> `audit-archive` bucket with object lock; coordinate the bucket
> prefix with Platform Security Stack so Talon and falco audit streams
> share the same lifecycle policy. Talon-side prefix:
> `s3://audit-archive/talon/year=YYYY/month=MM/day=DD/`.
>
> ADR for this lands as a separate doc (planned: `docs/architecture/0011-worm-archive.md`).

## 6. Quarterly compliance dashboard

> **Pending** — Grafana dashboard wiring is the GitOps repository scope.
> Panels (sized against the runtime metrics already emitted by
> `internal/observability`):
>
> | Panel | Source metric / log query | Control |
> |---|---|---|
> | Privileged access events / week | `sum(rate(talon_auth_decision_total{decision="allow",permission="admin"}[7d]))` | CC6.3 / A.8.2 |
> | Users with admin role / quarter | `count by (sub) (max_over_time(talon_request_total{decision="allow"}[90d]) and on() vector(1))` filtered by audit log `permission=admin` | CC6.3 |
> | Denied access attempts / week | `sum(rate(talon_auth_decision_total{decision="deny"}[7d]))` | CC6.1 |
> | MFA enrollment rate per host | `count(talon_auth_decision_total{mfa="true"}) / count(talon_auth_decision_total)` per `route` | CC6.1 / A.8.5 |
> | CV invalidations by reason / quarter | Loki `{subsystem="cv"} |~ "invalidate"` count by `reason` | CC6.6 |
> | Cross-app SSO chains reconstructed / month | Loki distinct count of `sso_chain_id` per period | audit completeness |

## 7. Evidence CLI — command surface

Live (in this repo's `cmd/talon`):

| Command | Status |
|---|---|
| `talon evidence export --since=… --until=… --controls=… --format=csv|ndjson [--hmac-key=… --manifest=… --decision-id=… --sso-chain-id=… --user=…]` | Active (MR !21 + !23) |
| `talon evidence redact --user=<sub>` | Active (MR !24) |
| `talon evidence help` | Active |
| `talon evidence verify <manifest.json>` | Pending — auditor-side helper (planned follow-up) |
| `talon evidence query --decision-id=<ulid>` | Convenience wrapper around `export --decision-id=…` (planned) |

cosign-signing the manifest is a separate operator step:

```
cosign sign-blob --key cosign.key \
  --output-signature manifest.sig manifest.json
```

cosign-verifying:

```
cosign verify-blob --key cosign.pub \
  --signature manifest.sig manifest.json
```

## 8. References

- [SOC 2 Trust Services Criteria 2017 (with 2022 revision)](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [GDPR Art. 17 — Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [GDPR Art. 30 — Records of processing](https://gdpr-info.eu/art-30-gdpr/)
- [GDPR Art. 32 — Security of processing](https://gdpr-info.eu/art-32-gdpr/)
- [cosign sign-blob / verify-blob](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
- [GCP Audit Logs concepts](https://cloud.google.com/logging/docs/audit) (architectural anchor)
- [AWS CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) (architectural anchor)
- ADR 0001 §7 (threat model — repudiation mitigations).
- ADR 0002 §4.1 (session blob field set — data minimisation evidence).
- `cmd/talon/evidence.go::controlMap` — runtime mirror of §1 + §2.
- Memory: internal engineering notes (Vault + secrets dual-store).

---

*The §1 + §2 mapping table is canonical and tracks the runtime
`controlMap`. Update both in lockstep — `controlMap` is the runtime
filter; this document is the auditor-facing record.*
