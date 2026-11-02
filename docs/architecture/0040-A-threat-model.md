# ADR 0040 Appendix A — ZTNA Threat Model

**Parent:** ADR 0040 — ZTNA Platform
**Status:** Accepted (Phase 0, 2026-06-06)
**Method:** STRIDE + Microsoft Zero Trust Six Pillars (Identity / Devices
/ Network / Apps / Data / Infrastructure)

## Asset inventory

| ID | Asset | Pillar | Owner |
|----|-------|--------|-------|
| A1 | User identity (Falcon-ID account + WebAuthn credential) | Identity | Falcon-ID |
| A2 | Session cookie + Talon session row | Identity | Talon |
| A3 | Device-cert private key (TPM/StrongBox-resident) | Devices | Access Agent client / Jess CA |
| A4 | Device-cert public chain (jess-device-ca) | Devices | Jess |
| A5 | Posture JWT (X-Talon-Posture, signed by device key) | Devices | Posture agent |
| A6 | SSH cert (Jess SSH-CA signed) | Devices | Jess SSH broker |
| A7 | svctoken (service-to-service JWT) | Apps | Talon |
| A8 | TalonRoute CR + SecurityPolicy CR | Apps | Talon controller |
| A9 | SpiceDB relationship graph | Apps | SpiceDB |
| A10 | Rego policy bundle | Apps | Talon (operator-authored) |
| A11 | CAEP SET (signed by Falcon-ID signing key) | Identity | Falcon-ID |
| A12 | Vault PKI mounts (jess-ca, jess-device-ca, jess-ssh-ca) | Infrastructure | Vault |
| A13 | WORM audit log | Data | Talon (audit-archive MinIO) |
| A14 | Linkerd identity (cluster-internal SPIFFE) | Network | Linkerd |
| A15 | Envoy data plane (customer-tier) | Network | Envoy Gateway |
| A16 | Talon decision-core (PDP) | Apps | Talon |
| A17 | OIDC discovery + JWKS (id.example.com) | Identity | Falcon-ID |

## Threat catalogue

### Identity (A1, A2, A11, A17)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TI1 | Spoofing | Phishing user into entering credentials on attacker site | High | WebAuthn passkey (phishing-resistant by spec); Falcon-ID does NOT accept password as primary on internal hosts (ADR 0006 §3); CSP + HSTS preload on all login surfaces (talon!94) |
| TI2 | Tampering | Attacker modifies session cookie | High | Cookie signed + encrypted (existing Talon); session row also persisted server-side; cookie validation rejects on signature mismatch |
| TI3 | Tampering | Attacker modifies CAEP SET in transit | Medium | RFC 8417: SET signed by issuer (Falcon-ID key, RS256 ≥ 2048-bit per CAEP Interop Profile); Talon receiver verifies signature against JWKS (talon!94) |
| TI4 | Repudiation | User denies action | Medium | WORM audit log with cryptographic chain (Phase 8); request `jti` recorded; sub claim from OIDC token preserved |
| TI5 | Information disclosure | OIDC JWKS rotated; Talon caches old key | Medium | Talon JWKS resolver fetches on cache miss + has 5-min TTL; key-rotation drill in Phase 9 |
| TI6 | Denial of service | Attacker spams Falcon-ID with fake login attempts | Medium | Falcon-ID rate-limit per IP + per username (existing); CrowdSec integration; Cloudflare Bot Management edge |
| TI7 | Elevation | Attacker steals valid session and replays | High | DPoP (RFC 9449) requires proof-of-possession — stolen cookie alone insufficient if route requires DPoP; Talon CV runner detects anomalous request rate from new IP and revokes |

### Devices (A3, A4, A5, A6)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TD1 | Spoofing | Attacker forges device-cert without TPM-backed key | Critical | Jess device-cert enrollment REQUIRES attestation evidence (TPM EK chain → AK → device key creation Certify); MDM-issued cert path (macOS) requires Apple Push Notification proof of MDM enrollment + App Attest |
| TD2 | Spoofing | Attacker uses simulated TPM (`tpm2-simulator`) | High | Jess attestation verifier REJECTS simulated EK in production (manufacturer cert chain check: Intel / AMD / Infineon / STMicro / Nuvoton / Microsoft Test EK rejected); test bench has explicit allowlist |
| TD3 | Tampering | Posture JWT modified | High | Posture JWT signed by key bound to device cert; Talon verifies signature against device-cert public key (which is in turn signed by jess-device-ca) |
| TD4 | Tampering | Attacker compromises endpoint and modifies posture probe output | Critical | Posture agent runs as system service with hardened binary (signed release); probes call OS-level APIs (Windows TPM service, macOS IOKit, Linux dm-verity), not user-mode logs; periodic remote-attestation refresh at every device-cert rotation (24h) catches drift |
| TD5 | Repudiation | Device denies posture report | Low | Each posture JWT carries `jti` + timestamp; audit log retains all |
| TD6 | Information disclosure | Attacker extracts device-cert private key | Critical | Key is TPM/SE/StrongBox-resident; non-extractable per attestation; if hardware is physically extracted, 24h TTL caps blast radius |
| TD7 | Denial of service | Posture endpoint flooded | Medium | Per-device-cert rate limit at Falcon-ID; gradual degradation (5 min → 15 min cadence) on overload |
| TD8 | Elevation | Compromised endpoint requests routes it shouldn't have | High | Per-route ReBAC check + Rego policy gate (Phase 5); posture-degrade revokes session via CAEP |

### Network (A14, A15)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TN1 | Spoofing | Attacker on adjacent VLAN MITMs cluster-internal traffic | High | Linkerd mTLS for every cluster-internal hop; no plaintext HTTP between meshed pods; AuthorizationPolicy default-deny |
| TN2 | Spoofing | Attacker bypasses Envoy Gateway and reaches upstream directly | High | NetworkPolicy denies non-EG traffic into upstream namespaces; Talon ext_authz gate at EG level |
| TN3 | Tampering | TLS termination at Traefik, plaintext to EG | Medium | Linkerd mTLS protects Traefik → EG hop; explicit `ProxyProtocol` configured per feedback memo internal engineering notes |
| TN4 | Information disclosure | Traffic mirror to attacker-controlled destination | High | Cluster network policy restricts egress; Falco rule for unusual outbound destinations |
| TN5 | Denial of service | Layer-7 flood at Envoy edge | Medium | Envoy rate-limit (envoy-ratelimit-redis) with 7 distinct rate-limit profiles on auth surfaces; Cloudflare edge DDoS |
| TN6 | Spoofing | Stolen Linkerd cluster identity | Critical | Linkerd identity rotated per-pod 24h; jess-ca compromise drill in Phase 9 covers this |

### Apps (A7, A8, A9, A10, A16)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TA1 | Tampering | Attacker modifies TalonRoute spec via GitOps PR | High | GitLab signed-commit requirement; GitOps PR review (CODEOWNERS); Talon controller validates spec server-side; SecurityPolicy regeneration always re-asserts intent |
| TA2 | Tampering | Attacker modifies Rego bundle | Critical | Rego bundle source-of-truth in GitOps repo; signed releases; Talon controller validates bundle hash on load; Rego compile gate at admission (failed compile → Registered=False, route remains in prior state) |
| TA3 | Spoofing | Service forges svctoken | High | svctoken signed by Talon (RS256 ≥ 2048-bit); short TTL (5 min); per-svctoken `jti` replay protection in Redis; svctoken `aud` claim per receiver |
| TA4 | Tampering | Attacker writes SpiceDB relationships | Critical | SpiceDB write via Talon-managed schema only; admin-only namespace write; audit log every write (Phase 8) |
| TA5 | Elevation | Privilege escalation via misconfigured ReBAC | Critical | SpiceDB schema review in code; semantic-versioned schema; pre-flight test bench covers every permission edge |
| TA6 | Denial of service | Attacker compiles enormous Rego bundle | Low | Bundle size + compile-time gates; Talon `internal/policy` validates before swap |
| TA7 | Information disclosure | Talon log leaks session token / posture JWT | High | Structured zap logger with `internal/log` field redactor; CI test verifies no token-shaped strings in log output; gitleaks pre-commit |
| TA8 | Tampering | Attacker forges Envoy SecurityPolicy | High | EG controller is the only writer; Talon controller uses SSA with FieldManager — concurrent operator edits surface as conflict |

### Data (A13)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TT1 | Tampering | Attacker modifies historical audit log | Critical | WORM bucket on `audit-archive` MinIO with object-lock governance; 7-year retention per internal engineering notes; immutable per-object after write |
| TT2 | Information disclosure | Audit log records PII | High | Audit schema defined in Phase 8 ADR; `subject` is pairwise per RP; no plaintext password / token in `event_data` |
| TT3 | Denial of service | Audit log floods due to per-request emission | Medium | Audit-event coalescing on the high-volume path (Talon `internal/audit`); WORM bucket scales horizontally on MinIO tenant |
| TT4 | Repudiation | Audit log gap during outage | High | Talon audit emitter has local buffer + retry; Phase 8 schema includes per-event sequence number — gaps detectable |

### Infrastructure (A12)

| ID | STRIDE | Threat | Impact | Mitigations |
|----|--------|--------|--------|-------------|
| TF1 | Spoofing | Attacker presents forged Vault PKI cert | Critical | Vault PKI roots stored in HSM-backed key store (HashiCorp Vault Transit); roots only signed by HW-attested operator action; jess-ca CDP/AIA/OCSP published live (2026-06-04 per internal engineering notes) |
| TF2 | Tampering | Attacker modifies Vault PKI role / mount config | Critical | Atlantis-managed Vault TF; per-mount `max_lease_ttl` capped (per feedback internal engineering notes); change-management via Atlantis MR |
| TF3 | Spoofing | Stolen Vault root token | Critical | Root token issued only via shamir-unseal quorum; rotated quarterly; AppRole + AppRole-secret-id for app paths; vault-ha-token-renewer kept short-TTL |
| TF4 | Denial of service | Vault sealed (e.g. all nodes down) | Critical | Vault HA 3-node Raft; auto-unseal via Transit (different mount); DR drill in Phase 9 |
| TF5 | Information disclosure | Vault PKI keys exposed | Critical | Vault Transit encrypts all-at-rest; audit log on every key access; vault-vm + Linkerd mTLS for transport |
| TF6 | Elevation | jess-ca compromise → forge device-certs | Critical | Vault PKI role bound to TLS client of `jess-controller` ServiceAccount via Linkerd mTLS; jess-controller code signed; key rotation drill in Phase 9 |

## Top residual risks (acknowledged in parent ADR §Consequences)

### R1 — Apple macOS device-identity gap

**Why residual**: Apple does not publish a server-verifiable
attestation chain over Secure Enclave-resident keys. Only **App Attest**
exists publicly, and it attests *app integrity*, not device identity.
There is no equivalent of Android's `KeyDescription` X.509 extension
or Windows TPM 2.0 EK chain for macOS desktops.

**Mitigation in scope**: TIER_BYOD policy on macOS desktops; layered
MDM-issued device cert (where MDM is enrolled) + App Attest (app-side);
AAL3 step-up on sensitive routes; posture cadence 15 min (BYOD tier);
explicit Rego rule that flags macOS-without-MDM as TIER_BYOD even if
user otherwise qualifies for TIER_CORP.

**Roadmap signal**: track WWDC 2026 keynote + Apple Developer release
notes for any SE attestation announcement; revisit if Apple publishes.

### R2 — TPM revocation in the field

**Why residual**: The TPM specification does not define an online
revocation mechanism for EK certs or AK keys. If a TPM is compromised
(physical extraction, vulnerability), the EK + AK remain "valid" by
spec.

**Mitigation in scope**: 24h device-cert TTL caps blast radius; manually
curated EK manufacturer trust list (~15-25 roots: Intel / AMD /
Infineon / STMicro / Nuvoton); Jess device-cert mint records the EK
fingerprint — operators can manually blocklist a compromised EK
fingerprint at the Jess CA layer; subsequent device-cert refresh fails
the blocklisted EK.

**Roadmap signal**: TCG EK-Based Key Attestation with TPM Firmware v1
(May 2025) adds firmware-version vouching — adopt when reference
implementation matures (currently RC1).

### R3 — BYOD trust ceiling

**Why residual**: For genuine BYOD (user-owned device, no MDM), we
cannot enforce MDM-issued certs or guarantee posture-agent integrity.
The user can uninstall or tamper with any agent we ship.

**Mitigation in scope**: TIER_BYOD policy explicitly disallows the most
sensitive routes (Vault admin UI, GitLab root, ArgoCD admin); requires
AAL3 + posture-fresh; logs and audits every BYOD-tier access with a
distinct `device.tier` field; per-tenant policy allows tenant admins to
disable BYOD entirely.

**Roadmap signal**: corp-managed device fleet expected to cover
~80% of access patterns; BYOD is the long tail.

## Drill calendar (Phase 9)

Quarterly drills mapped to threats:

| Quarter | Drill | Threats exercised |
|---------|-------|---------------------|
| Q1 | jess-ca root rotation | TF1, TF6 |
| Q2 | Full device-cert revocation cascade | TD6, R2 |
| Q3 | Falcon-ID database lost (DR restore) | TI4, TT3, TT4 |
| Q4 | TPM key compromise drill (blocklist + cascade) | TD1, TD2, R2 |

## Method notes

- STRIDE adapted from Microsoft's Threat Modelling tool taxonomy.
- Six Pillars per Microsoft Zero Trust model.
- Reviewed against NIST SP 800-207 §3 "Logical Components of Zero Trust Architecture".
- BeyondCorp control-mapping referenced where directly applicable.
- This appendix is living: any new asset added to the architecture
  needs an entry in the inventory + at least one STRIDE row per
  applicable threat category.
