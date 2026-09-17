# ADR 0040 Appendix B — Decision Register

**Parent:** ADR 0040 — ZTNA Platform
**Status:** Living document — entries added as decisions are locked,
amended as drills surface new evidence.

This is the operator-amendable record of every design decision made
inside the ZTNA program. Each entry follows the same shape:

- **D-N** — short identifier
- **Decision** — what was decided (1 sentence)
- **Date** — YYYY-MM-DD
- **Phase** — which phase it relates to
- **Rationale** — why
- **Alternatives** — what was considered
- **Reversal cost** — how hard would it be to change later
- **Owner** — repo / role responsible
- **Cross-refs** — ADR / memory / commit pointers

---

## D-001 — Master TPM strategy: multi-OS, with explicit macOS gap

- **Decision**: Support Windows 11 TPM 2.0 + Linux TPM 2.0 + Android StrongBox/TEE + Apple App Attest (app integrity only, NOT device identity). macOS desktop device identity requires MDM-issued cert + App Attest layered.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: BeyondCorp-grade coverage required across user device fleet. Apple does not publish a server-verifiable Secure Enclave key-attestation chain — documented gap, mitigated by MDM-cert layering.
- **Alternatives considered**:
  - Windows-only (simpler, fails BeyondCorp coverage)
  - Wait for Apple SE attestation (no roadmap signal)
- **Reversal cost**: Low for adding/removing a platform; high for changing the macOS strategy because of the architectural mitigation
- **Owner**: jess (CA + attestation verifier)
- **Cross-refs**: ADR 0040 §Decision row 1; Approov 2024 + Apple Developer Forums + Guardsquare (cited in parent ADR References)

## D-002 — Device-cert lifetime: 24 hours

- **Decision**: All device certs minted by Jess have a 24-hour TTL. HexxLock Access client auto-renews at 12 hours (50% of TTL).
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: Minimises blast radius on compromise. Matches NIST SP 800-207 §3.4.1 corp-managed device guidance. Operator-cert (Jess `/operator-cert`) is 8h for human-driven access; device-cert at 24h reflects machine-driven background renewal.
- **Alternatives considered**:
  - 7 days (lower Jess CA load, worse blast radius)
  - 1 hour (matches SSH cert TTL, but breaks offline UX for mobile devices)
- **Reversal cost**: Low — TTL is a Vault PKI role parameter, change via Atlantis MR
- **Owner**: jess
- **Cross-refs**: ADR 0040 §Decision row 2

## D-003 — Posture cadence: 5 min corporate, 15 min BYOD

- **Decision**: Posture agent reports every 5 minutes on TIER_CORP devices; every 15 minutes on TIER_BYOD.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: 5 min matches BeyondCorp continuous-verification spirit; 15 min matches Zscaler ZPA production cadence. Battery/network impact lower on BYOD where we have less control over the device.
- **Alternatives considered**:
  - Single cadence (simpler, less optimal for BYOD battery life)
  - 1 min (too aggressive, posture probe overhead noticeable)
- **Reversal cost**: Low — agent config, no protocol change
- **Owner**: hexxlock-access (agent) + falcon-id (heartbeat endpoint)
- **Cross-refs**: ADR 0040 §Decision row 3; Zscaler Help docs 2025

## D-004 — Client UX framework: Tauri

- **Decision**: HexxLock Access desktop client built on Tauri (Rust + WebView) for Win/macOS/Linux.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: Aligns with Jess's Rust codebase + IronRDP. Tauri binary ~10MB vs Electron ~150MB. Native OS integration. Signed-release-channel built-in.
- **Alternatives considered**:
  - Electron (heavier runtime; not justified)
  - Native per-OS (Swift on macOS, C#/.NET on Win, GTK on Linux) — 3x maintenance burden
  - WebExtension only (cannot do device-cert mTLS or SE key access)
- **Reversal cost**: Very high — would mean rewriting the client
- **Owner**: hexxlock-access repo (new)
- **Cross-refs**: ADR 0040 §Decision row 4

## D-005 — Trust-domain naming: SPIFFE-aligned, no SPIRE deployment

- **Decision**: All new identities use SPIFFE-ID naming (`spiffe://hexxlock.com/<purpose>/<id>`). Linkerd's cluster-internal SPIFFE retained. **Do not deploy SPIRE server** in Phase 0–2.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: Linkerd already provides cluster-internal SPIFFE. SPIFFE naming preserves future multi-cluster federation without paying SPIRE's operational cost today. Concrete naming: device cert SAN = `spiffe://hexxlock.com/device/<device-uuid>`; svctoken `sub` URL form.
- **Alternatives considered**:
  - Full SPIRE deployment now (premature; no multi-cluster requirement)
  - Stick with current `talon:svctoken:*` URN scheme (closes future-federation door)
- **Reversal cost**: Medium — naming change touches every issuer + verifier
- **Owner**: All three identity-tier products
- **Cross-refs**: ADR 0040 §Decision row 5; SPIFFE docs

## D-006 — Trust tiers: TIER_CORP / TIER_BYOD / TIER_BREAKGLASS

- **Decision**: Three explicit trust tiers, each with its own Rego policy + posture cadence + AAL requirement.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: Differentiated trust matches real-world device fleet; explicit BYOD route allow-list prevents accidental high-trust grant on user-owned hardware.
- **Alternatives considered**:
  - Binary trusted/untrusted (loses BYOD nuance)
  - Risk-based scoring continuous (more complex, no clear vendor pattern)
- **Reversal cost**: Medium — tier is a label on the device cert + Rego inputs
- **Owner**: jess (cert label) + talon (Rego)
- **Cross-refs**: ADR 0040 §Trust tiers table

## D-007 — Phase sequencing: 0 → 3 → 4 → 5 → 7 → 9 → 10 is critical path

- **Decision**: Phase 1 (kubectl) ships in parallel with Phase 0. Phase 2 (SSH) + Phase 6 (CAEP outbox) parallel-safe with Phase 3. Phase 8 (audit) parallel with Phase 7. Total critical path ~22 weeks; wall-clock with parallel ~24-26 weeks.
- **Date**: 2026-06-06
- **Phase**: 0
- **Rationale**: Phase 3 (device-cert) blocks Phase 4 (posture agent); Phase 4 blocks Phase 5 (Rego); Phase 5 blocks Phase 7 (client) because client needs the gating policy to be live before it ships to users.
- **Alternatives considered**:
  - Sequential (longer, less efficient)
  - Phase 3 parallel with Phase 2 (resource contention, no clear win)
- **Reversal cost**: Low — replan
- **Owner**: program lead
- **Cross-refs**: ADR 0040 §Phase sequencing

---

## Pending decisions (to be locked in subsequent phases)

| ID | Question | Phase to lock | Notes |
|----|----------|---------------|-------|
| P-001 | TPM EK manufacturer trust list — exact roots accepted | 3a | Curate from Intel + AMD + Infineon + STMicro + Nuvoton + Microsoft (test); reject simulator EKs in prod |
| P-002 | Posture probe set — exact list per OS | 4 | Disk-encryption, OS version, EDR running, AV running, last reboot, hardware-ID match, screen-lock enabled — finalise in implementation |
| P-003 | Rego shadow-mode flag default | 5 | Recommend shadow-on for first 2 weeks per route to surface false positives without blocking |
| P-004 | Audit-log per-event sequence number scheme | 8 | Per-pod monotonic? Cluster-wide via PG? Lock in Phase 8 ADR |
| P-005 | External pentest vendor selection | 8 | Bishop Fox / NCC Group / Cure53 candidates; selection in Phase 8 |
| P-006 | Phase 9 chaos engineering framework | 9 | Chaos Mesh (cluster-native) vs Litmus vs bespoke; Chaos Mesh likely |
| P-007 | Phase 10 rollout pacing | 10 | Default 4-week phased; tighten/loosen based on Phase 9 drill results |

## Amendment log

| Date | ID | Change | Reason |
|------|----|--------|--------|
| 2026-06-06 | D-001..D-007 | Initial decisions locked at Phase 0 foundation | ZTNA program kickoff |

---

This register is the single source of truth for "why did we choose
X?" questions. Any future change to a locked decision must add a new
row to the amendment log + update the relevant entry.
