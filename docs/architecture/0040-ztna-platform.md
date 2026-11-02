# ADR 0040 — ZTNA Platform (Talon + Falcon-ID + Jess)

**Status:** Accepted (Phase 0 Foundation, 2026-06-06)
**Supersedes:** none (extends 0006, 0009, 0010, 0011)
**Related siblings (to be written):**
- Jess device-cert profile (separate repository) — device attestation + cert lifecycle
- Jess SSH broker (separate repository) — Vault SSH-CA + Talon ext_authz integration
- Falcon-ID CAEP outbox (separate repository) — at-least-once SET delivery
- Falcon-ID posture heartbeat (separate repository) — agent → IdP posture refresh

## Context

HexxLock's three identity-tier products — Falcon-ID (OIDC IdP), Talon
(IAP + PEP + PDP for the data plane), Jess (CA + protocol broker for
RDP, soon SSH + device certs) — already implement the core BeyondCorp
control surfaces. The 2026-06-06 tier-1 IAP closeout wave (ADR 0011
implementation + 6 production MRs) closed the credential-mutation +
session-revoke gaps end-to-end via OpenID CAEP 1.0. The stack now
demonstrably enforces:

- Federated identity (Falcon-ID OIDC, phishing-resistant WebAuthn)
- DPoP proof-of-possession (RFC 9449)
- Continuous verification (Talon `internal/cv` runner)
- ReBAC fine-grained authz (SpiceDB)
- Rego operator policy with posture-claim input
- mTLS for every cluster-internal hop (Linkerd)
- WORM audit retention
- Per-host SecurityPolicy emission from TalonRoute (ADR 0009 + 0011)

But the **client side of the BeyondCorp model is missing**: there is no
hardware-rooted device identity, no per-endpoint posture agent, no
unified outside-client experience for non-HTTP protocols, and no
standardised gating policy that requires posture + device cert + AAL3
on the routes that need it. Operators today get cookie-based session
control without device assurance.

This ADR locks the 10-phase program to close that gap to **tier-1**
(NIST SP 800-207 + BeyondCorp + Cloudflare Zero Trust + Pomerium
reference-arch aligned), implemented across Talon, Falcon-ID, Jess,
and a new `Access Agent` desktop client.

## Decision

### Architecture

```
External client (any device, any network)
   │
   ├── Access Agent desktop client (Tauri, Rust)
   │     • WebAuthn enrollment + repeat-auth
   │     • Device-cert presentation
   │     • Posture agent (5-min cadence)
   │     • Embedded IronRDP frontend
   │     • SSH client (uses Jess-minted SSH certs)
   │     • Browser launcher (sets up loopback proxy that injects
   │       device-cert mTLS into HTTPS to Talon edge)
   │
   ├── Cloudflare edge (proxied DNS + WAF + DDoS)
   ↓
   Cloudflared Tunnel → Traefik public DMZ (TLS terminate)
   ↓
   ┌──────────────────────────────────────────────────────────────┐
   │  Envoy Gateway (customer-tier) ─── ext_authz ──► Talon       │
   │  Traefik internal (admin-tier)  ─── direct  ──► Talon        │
   │                                                              │
   │  Talon PDP/PEP:                                              │
   │    • OIDC RP (federated to Falcon-ID id.example.com)        │
   │    • DPoP proof-of-possession verifier (RFC 9449)            │
   │    • Device-cert mTLS at Envoy listener (Phase 3d)           │
   │    • Posture JWT verifier (X-Talon-Posture, Phase 4)         │
   │    • Session tombstone (CAEP receiver) — Phase 6 hardened    │
   │    • SpiceDB ReBAC check                                     │
   │    • Rego policy bundle (Phase 5)                            │
   │    • svctoken issuance (short-lived, behind Linkerd mTLS)    │
   │    • WORM audit (Phase 8 schema codified)                    │
   └──────────────────────────────────────────────────────────────┘
   ↓
   ┌──────────────────────────────────────────────────────────────┐
   │  Per-protocol brokers                                        │
   │    • HTTP → upstream service (Linkerd mTLS)                  │
   │    • RDP  → Jess IronRDP broker (existing)                   │
   │    • SSH  → Jess SSH broker (Phase 2, new)                   │
   │    • k8s  → kube-apiserver OIDC, Phase 1 (smallest delta)    │
   └──────────────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────────┐
   │  Jess CA (Vault PKI roots)                                   │
   │    • jess-ca   — operator-cert (existing)                    │
   │    • jess-device-ca — device-cert with TPM/SE/StrongBox      │
   │      attestation evidence (Phase 3a/3b/3c)                   │
   │    • jess-ssh-ca — Vault SSH backend (Phase 2)               │
   │  All issue CDP/AIA/OCSP per ADR 0010 (jess-ca live 2026-06-04)│
   └──────────────────────────────────────────────────────────────┘
```

### Phase 0 decisions (this ADR)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | **TPM strategy** | Multi-OS: Windows 11 TPM 2.0 + Linux TPM 2.0 + Android StrongBox/TEE + Apple **App Attest only (not device identity)** | Tier-1 BeyondCorp coverage. macOS desktop has no public Secure Enclave key-attestation chain — Apple does not publish a server-verifiable attestation over `kSecAttrTokenIDSecureEnclave` keys (Apple Developer Forums; Approov 2024; Guardsquare). Plan: macOS uses **MDM-issued device cert + App Attest** as a layered proxy; honest documentation gap, mitigated. |
| 2 | **Device-cert lifetime** | 24h, auto-rotated by Access Agent client at 12h (50% of TTL) | Minimises blast radius on compromise. Aligns with `jess-ca` operator-cert TTL pattern (8h for human-driven access, 24h for endpoint identity). Industry consensus on 24h corp-managed (NIST SP 800-207 §3.4.1). |
| 3 | **Posture cadence** | 5 minutes (corporate-managed) / 15 minutes (BYOD) | 5 min matches BeyondCorp continuous-verification spirit; 15 min matches Zscaler ZPA production cadence (Zscaler Help docs 2025). Cadence configurable per device tier. |
| 4 | **Client UX framework** | **Tauri** (Rust + WebView) | Aligns with Jess's Rust codebase + IronRDP broker stack. Smaller binary than Electron (~10MB vs ~150MB), native OS integration, signed-release-channel built-in. Electron's heavier runtime is not justified given we control the entire client stack. |
| 5 | **Trust-domain naming** | SPIFFE-aligned naming on all new identities (`spiffe://example.com/<purpose>/<id>`); Linkerd's cluster-internal SPIFFE retained; **no full SPIRE server deployment in Phase 0-2** | Linkerd already provides SPIFFE inside the cluster. Adopting SPIFFE-ID conventions in cert SANs preserves the future multi-cluster federation option without paying SPIRE's operational cost today. Concrete: device cert SAN = `spiffe://example.com/device/<device-uuid>`. svctoken `sub` claim → SPIFFE-aligned URI. |

### Trust tiers

| Tier | Device class | Attestation | Posture cadence | Default Rego |
|------|--------------|-------------|------------------|---------------|
| **TIER_CORP** | MDM-enrolled corporate hardware (TPM 2.0 / StrongBox) | Hardware-rooted device cert (Phase 3) + posture agent | 5 min | AAL2+ + posture-fresh + device-cert-valid |
| **TIER_BYOD** | User-owned device (App Attest on macOS desktop / Web client) | App-Attest + WebAuthn user binding (no device-cert claim) | 15 min | AAL3 + posture-fresh + step-up on sensitive routes |
| **TIER_BREAKGLASS** | Operator emergency access | Hardware FIDO2 token + offline signed exception | n/a (revoked after use) | AAL3 + manager-approval-token + audit-flag |

### Phase sequencing

| Phase | Owner repo(s) | Sequence | Parallel-safe |
|-------|---------------|----------|---------------|
| 0 — Foundation lock (THIS ADR) | talon + jess + falcon-id | First | n/a |
| 1 — kubectl broker | <gitops-bootstrap-repo> + falcon-id | After 0 | Yes |
| 2 — Jess SSH broker | jess + talon | After 0 | Yes (parallel to 1, 3, 6) |
| 3 — Jess device-cert profile | jess + talon | After 0 | Blocks 4 |
| 4 — Device posture agent | access-agent (new repo) | After 3 | Blocks 5 |
| 5 — Posture-gated Rego | talon | After 4 | Blocks 7 |
| 6 — CAEP outbox + drainer | falcon-id + talon | After 0 | Yes (parallel to 1, 2, 3, 4) |
| 7 — Access Agent client | access-agent | After 5, 6 | n/a |
| 8 — Audit + compliance | talon + falcon-id + jess | After 5 | Yes (parallel to 7) |
| 9 — DR + chaos | all | After 7, 8 | n/a |
| 10 — Soft launch + training | platform-tools (docs) + dashboards | Last | n/a |

**Critical path** (0 → 3 → 4 → 5 → 7 → 9 → 10): ~22 weeks.
**Wall-clock with parallel tracks**: ~24–26 weeks (~6 months).

### Threat model

Adopt **STRIDE** + augmented with the **Six Pillars of Zero Trust**
(Microsoft model: Identity, Devices, Network, Apps, Data,
Infrastructure). Per-asset analysis lives in the threat-model
appendix (`0040-A-threat-model.md`, separate file).

**Top 5 mitigated threats**:

| # | Threat | Pillar | Mitigation |
|---|--------|--------|------------|
| T1 | Stolen credential / phishing | Identity | WebAuthn passkey (phishing-resistant); DPoP proof-of-possession; AAL3 step-up on sensitive routes |
| T2 | Compromised endpoint | Devices | Hardware-rooted device cert (TPM/StrongBox); continuous posture (5 min); CAEP session-revoked on posture degrade |
| T3 | Privilege escalation lateral movement | Network + Apps | ReBAC per-resource authz; Linkerd mTLS every hop; per-host SecurityPolicy gating |
| T4 | CA compromise | Infrastructure | Vault PKI mount per role (jess-ca / jess-device-ca / jess-ssh-ca); jess-ca CDP/AIA/OCSP live (2026-06-04); 24h device-cert TTL caps blast radius |
| T5 | Replay / token theft | Identity + Apps | DPoP proof-of-possession; jti replay protection (Talon); short svctoken TTL (5 min); Talon CAEP receiver tombstones on session-revoked |

**Top 3 residual threats** (acknowledged):

| # | Threat | Why residual | Mitigation deferral |
|---|--------|--------------|---------------------|
| R1 | Apple macOS device-identity gap | No public Secure Enclave key-attestation chain | MDM-issued cert + App Attest layered; document gap; revisit when Apple publishes SE attestation (no roadmap signal as of 2025) |
| R2 | TPM revocation in the field | TPM spec does not define online revocation | Rely on 24h device-cert TTL; document EK-cert manufacturer trust list (~15-25 roots; manually curated) |
| R3 | BYOD trust ceiling | User owns the device; cannot enforce MDM | TIER_BYOD policy + AAL3 + posture + step-up; route allow-list per tier |

### Compliance mapping

NIST SP 800-207 (Zero Trust Architecture) tenets covered:

| Tenet | Component |
|-------|-----------|
| 1. All data sources and computing services are resources | TalonRoute = explicit resource registration |
| 2. All communication secured regardless of network location | Linkerd mTLS in-cluster; device-cert mTLS at edge (Phase 3d); HTTPS+DPoP user-side |
| 3. Access granted per-session | svctoken short TTL; session tombstone via CAEP |
| 4. Access determined by dynamic policy (identity + asset state) | Rego bundle with posture JWT input |
| 5. Enterprise monitors and measures integrity + security posture | Posture agent + CV runner + audit log |
| 6. All authentication and authorisation dynamic and strictly enforced before access | Talon PDP/PEP on every hop |
| 7. Enterprise collects + uses information about asset state and network | Posture heartbeat + Talon CV + WORM audit |

BeyondCorp Enterprise patterns covered:

- Certificate-Based Access (CBA) → device-cert mTLS at Envoy listener (Phase 3d)
- Dry-run policy → Rego bundle includes shadow-mode flag (Phase 5)
- Posture-driven access → Phase 4 posture agent
- Policy Remediator equivalent → audit-log replay tooling (Phase 8)

## Consequences

### Positive

- Tier-1 ZTNA end-to-end without vendor lock-in (Cloudflare, Zscaler, Tailscale all gave us reference patterns; we own the implementation)
- Three-product clean separation: Falcon-ID identity, Talon decision/enforcement, Jess workload identity + protocol brokers
- Existing investment leveraged: Talon's ext_authz, CV runner, Rego, SpiceDB; Falcon-ID's WebAuthn, CAEP, OIDC; Jess's CA + IronRDP
- BeyondCorp + NIST 800-207 control mapping is explicit; compliance evidence auto-generable (Phase 8)
- Future multi-cluster federation open (SPIFFE-aligned naming)

### Negative

- ~6 months engineering effort across the three repos + a new `access-agent` client repo
- macOS desktop device-identity is the platform's weakest link; partially mitigated by MDM-cert layering but not closed
- TPM Rust library landscape requires FFI to `tpm2-tss` (no Rust peer of `go-attestation`)
- Android key-attestation parser: no maintained Rust crate; port Google's Java reference using `rasn`/`der-parser`
- Operational burden: posture agent fleet (Windows + macOS + Linux), CA roots (Jess × 3 mounts), device-cert lifecycle (24h rotation × N devices)

### Open questions surfaced during research

| # | Question | Mitigation / next step |
|---|----------|----------------------|
| Q1 | Does Apple ever ship a public Secure Enclave key-attestation chain? | Track Apple Developer release notes; document the gap; layered MDM mitigation |
| Q2 | Should we stand up SPIRE server for cluster-internal SPIFFE? | Linkerd already provides; defer SPIRE to multi-cluster phase (no concrete timeline) |
| Q3 | How do we handle TPM EK trust roots in CI / test environments? | Allowlist `tpm2-software/tpm2-simulator` AK in test bench; reject simulated EKs in production (manufacturer cert verification) |
| Q4 | Cadence trade-off — 5 min posture too aggressive on battery / network? | Default 5 min corp / 15 min BYOD per Phase 0 decision; expose as policy knob; collect telemetry; revisit in Phase 10 |
| Q5 | Falcon-ID OIDC scope expansion for device claims? | Add `device_id` claim from device-cert SAN; document in Falcon-ID ADR 0010 (Phase 4 sibling) |

## References

### Standards + RFCs
- [NIST SP 800-207 — Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [RFC 8417 — Security Event Token (SET)](https://www.rfc-editor.org/rfc/rfc8417)
- [RFC 8935 — Push Delivery of SETs](https://www.rfc-editor.org/rfc/rfc8935)
- [RFC 8936 — Poll-Based Delivery of SETs](https://www.rfc-editor.org/rfc/rfc8936)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9493 — Subject Identifiers](https://www.rfc-editor.org/rfc/rfc9493)
- [OpenID CAEP 1.0 Final (2025-08-29)](https://openid.net/specs/openid-caep-1_0.html)
- [SPIFFE — Secure Production Identity Framework for Everyone](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)

### TPM 2.0
- [TCG EK Credential Profile TPM 2.0 v2.5 (Mar 2022)](https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf)
- [TCG EK-Based Key Attestation with TPM Firmware v1 RC1 (May 2025)](https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf)
- [Microsoft Learn — TPM Key Attestation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation)
- [tpm2-software remote attestation guide](https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html)
- [google/go-attestation (Go reference)](https://pkg.go.dev/github.com/google/go-attestation/attest)

### Apple
- [Apple Developer Forums — App Attest tag](https://developer.apple.com/forums/tags/app-attest)
- [Approov — Limitations of Apple DeviceCheck and App Attest](https://approov.io/blog/limitations-of-apple-devicecheck-and-apple-app-attest)
- [Guardsquare — Constraints of iOS App Attest](https://www.guardsquare.com/blog/remove-constraints-of-ios-app-attest)

### Android
- [AOSP — Key and ID Attestation](https://source.android.com/docs/security/features/keystore/attestation)
- [Android Developers Blog — FIDO2 attestation format change (Sept 2024)](https://android-developers.googleblog.com/2024/09/attestation-format-change-for-android-fido2-api.html)
- [Approov — Limitations of Google Play Integrity](https://approov.io/blog/limitations-of-google-play-integrity-api-ex-safetynet)
- [google/android-key-attestation (Java reference)](https://github.com/google/android-key-attestation)

### Production ZTNA references
- [Google BeyondCorp Enterprise / Chrome Enterprise Premium](https://cloud.google.com/beyondcorp-enterprise/docs/overview)
- [Cloudflare One — Posture Checks](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/)
- [Cloudflare One — Client Certificate Posture](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/warp-client-checks/client-certificate/)
- [Cloudflare Reference Arch — Designing ZTNA Access Policies](https://developers.cloudflare.com/reference-architecture/design-guides/designing-ztna-access-policies/)
- [Tailscale — Secure Node State Storage](https://tailscale.com/docs/features/secure-node-state-storage)
- [Tailscale — Device Posture Management](https://tailscale.com/docs/features/device-posture)
- [Pomerium — WebAuthn Device Identity](https://www.pomerium.com/docs/integrations/device-context/webauthn)
- [Zscaler — Device Posture Profiles (ZPA)](https://help.zscaler.com/z-app/configuring-device-posture-profiles-zpa)

### Internal cross-refs
- ADR 0001 — Overview (Talon)
- ADR 0003 — TalonRoute CRD
- ADR 0004 — Continuous Verification
- ADR 0006 — Falcon-ID integration
- ADR 0009 — Shared PDP ext_authz
- ADR 0010 — Fail-mode policy
- ADR 0011 — CAEP + device posture
- Wave 2 closure: internal engineering notes
