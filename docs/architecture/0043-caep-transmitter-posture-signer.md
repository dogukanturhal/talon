# ADR 0043 — CAEP 1.0 transmitter (posture-signer → Talon receiver)

- **Status:** Proposed (2026-06-18)
- **Cross-refs:** ADR 0011 (CAEP receiver — the other half), ADR 0040 (ZTNA), ADR 0010 (fail-mode)

## Context

ADR 0011 made Talon a CAEP **receiver** (`internal/caep`, `POST /caep/events`)
but nothing in the platform **transmits** CAEP events — so the real-time
session-revocation / device-posture pipeline is half-built. posture-signer
already (a) sees every device posture heartbeat (device_uuid, user_sub,
tier, compliance map), and (b) signs with a Vault Transit RS256 key whose
public half it publishes at `/.well-known/jwks.json`. That makes it the
natural CAEP **transmitter**: it can emit signed SETs the existing Talon
receiver already knows how to verify (against posture-signer's JWKS) and
dispatch.

## Decision

posture-signer becomes a CAEP 1.0 transmitter (RFC 8935 push delivery).
The transmitter lives in `internal/caep` alongside the receiver so both
sides share one copy of the SET types — no drift between what's emitted
and what's accepted.

Events emitted:

| Trigger | CAEP event | Subject | Talon action (ADR 0011) |
|---|---|---|---|
| Device de-provisioned / cert revoked (heartbeat → 410/denied) | `session-revoked` | `iss_sub` {Falcon-ID iss, user_sub} | RevokeBySubject — kills the user's sessions in seconds |
| Posture flips compliant ↔ not-compliant | `device-compliance-change` | `iss_sub` {Falcon-ID iss, user_sub} | audit (future posture-policy hook) |

SET envelope:
- `iss` = posture-signer's issuer (`https://posture.example.com`) — the
  TRANSMITTER identity; Talon verifies the SET signature against this
  issuer's JWKS and matches it to `CAEPTransmitterIssuer`.
- `aud` = Talon auth host (`https://auth.internal.example.com`).
- event `subject` `iss` = **Falcon-ID** issuer (`https://id.example.com`)
  — the user-session owner Talon keys RevokeBySubject on. (Transmitter
  identity ≠ subject identity: posture-signer asserts a fact about a
  Falcon-ID user.)
- `jti` unique per SET (replay-cache key on the receiver).

Signing reuses the posture-signer Vault Transit key (RS256), header
`typ: secevent+jwt`. Delivery is an HTTP POST of the compact JWS with
`Content-Type: application/secevent+jwt` to Talon's `/caep/events`;
202 = accepted.

Compliance evaluation: a heartbeat is "compliant" when the baseline
posture facts hold (disk_encrypted, etc. per the route/tier policy);
posture-signer tracks the last per-device status in-memory and emits
`device-compliance-change` only on a transition (not every tick).

### Trust note
Talon's receiver must list posture-signer's issuer in
`CAEPTransmitterIssuer` (or the multi-transmitter trust set) so it
fetches posture-signer's JWKS. session-revoked from posture-signer is
powerful (kills sessions) — posture-signer is already a trusted
platform component (Vault-signed, Linkerd-meshed), so this is acceptable;
the receiver still validates signature + envelope + replay.

## Rollout (incremental)
1. **This slice:** transmitter SET-construction core + push delivery in
   `internal/caep` (Build* + Emit + Signer interface) + tests. No behavior
   change until wired.
2. JWSIssuer `SignSET` adapter (Vault Transit) + per-device compliance
   state + emit hooks in `handleSignPosture` + config
   (`POSTURE_CAEP_ENABLED`, receiver URL, Falcon-ID/Talon issuers).
3. Talon config: add posture-signer issuer to the trusted-transmitter set.
4. Live-verify: flip a device non-compliant → Talon audits the event;
   de-provision → Talon revokes the session.

## Alternatives rejected
- **SSF stream-management API (RFC 8936) + poll delivery** — full SSF
  control plane (stream CRUD, verification events) is overkill for one
  trusted in-cluster transmitter→receiver pair. Push delivery (RFC 8935)
  to the known `/caep/events` endpoint is sufficient; stream management
  can come later if we federate external receivers.
- **Falcon-ID as the only transmitter** — Falcon-ID doesn't see posture;
  posture-signer is where device-compliance/session-revoke facts originate.
