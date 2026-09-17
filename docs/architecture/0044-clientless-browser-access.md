# ADR 0044 — Clientless (Agentless) Browser Access

Status: Proposed (design only — multi-phase build)
Date: 2026-06-18
Supersedes: none
Related: ADR 0040 (ZTNA platform), ADR 0011 (CAEP + device posture),
ADR 0043 (CAEP transmitter), jess ADR 0049 (multi-protocol brokering),
jess ADR 0030 (SSH session recording / WORM)

## Context

HexxLock's ZTNA core is strong on device-cert provenance (TPM-backed
device certs, SPIFFE SANs), short-lived posture JWS, Talon IAP, and a
7-year WORM Merkle audit. The **#1 Gartner ZTNA table-stakes gap** we do
not yet cover is **clientless / agentless browser access**: letting an
authorized user reach an internal web app (and, via the broker, RDP / SSH
/ DB / k8s — see jess ADR 0049) from a plain browser, with **no HexxLock
Access desktop agent installed**.

Today every protected path assumes either (a) a browser session behind
Talon IAP for `*.ops`/`*.apps` HTTP apps, or (b) the desktop agent for
device-cert mTLS + posture. There is no path for:

- A contractor / auditor on an **unmanaged device** who must reach one
  internal app for a bounded window, without enrolling a device cert.
- **BYOD over the browser** where installing the agent is not acceptable.
- Break-glass access from a device that cannot run the agent.

This is the single most-requested capability for the open-core on-prem
ZTNA positioning (regulated / EU-sovereign buyers expect it; Teleport,
Cloudflare, Zscaler all ship it).

## Decision

Build a **clientless access tier** that brokers browser sessions to
internal resources through a HexxLock-controlled rendering/proxy plane,
gated by Talon IAP + Falcon-ID auth + (degraded) posture, fully WORM-
audited and CAEP-revocable — **without** requiring the desktop agent.

Two distinct surfaces, sharing the auth/audit spine:

1. **Clientless HTTP app access** (Phase 1 — smallest, highest value):
   a per-app reverse proxy at `https://<app>.access.hexxlock.com`. Talon
   already terminates IAP for `*.ops`/`*.apps`; this extends the model to
   an `access.` zone whose sessions are explicitly tagged
   `channel=clientless` (no device cert) so policy can apply a stricter
   posture/MFA/JIT bar. This is ~90% existing Talon machinery + a new
   route class.

2. **Clientless remote-desktop / terminal access** (Phase 2+): an
   in-browser RDP/SSH/VNC/k8s-exec client (canvas + WebSocket) rendered
   by a broker the user never installs. This is the heavy lift and
   depends on jess ADR 0049's protocol brokers; the browser is just the
   pixel/stream front-end.

### Trust model (the crux)

A clientless session has **no device cert**, so it cannot satisfy the
device-cert mTLS posture path. We do NOT pretend otherwise. Instead:

- `channel=clientless` is a first-class session attribute (alongside the
  existing `channel=cookie`/`bearer`). The router projects it into the
  Rego input (`input.session.channel`) and into audit/CAEP.
- Clientless sessions are **AAL-capped**: they MUST step up to WebAuthn
  (reuse ADR 0011/0043 + the RFC 9470 path we just completed) and are
  **denied** for any route whose `sensitivity=critical` unless an
  explicit `allowClientless: true` is set on the TalonRoute. Fail-closed.
- Posture degrades to **browser-attestable signals only**: Falcon-ID
  WebAuthn (proves a registered authenticator), optional WebAuthn device-
  bound passkey, IP/geo/UA, and — where available — a **server-issued
  short-lived session-bound token** (no client software). No disk-
  encryption / EDR / TPM claims are asserted (they can't be, honestly).
- Every clientless session is **time-boxed** (short absolute TTL) and
  **JIT-gated** for sensitive targets: reuse jess `internal/jit`
  (already built) so a human approver authorizes the window. The Path-B
  witness flow is the approver ceremony.

### Components

```
Browser (no agent)
  │  https://<app>.access.hexxlock.com   (or /access/desktop/<target>)
  ▼
Traefik (access zone)  ──►  Talon IAP  ──► Falcon-ID OIDC + WebAuthn step-up
  │                                          (channel=clientless, AAL2/3)
  ▼ (authorized)
  ├── HTTP app  ──►  Talon reverse-proxy ──► upstream Service (Phase 1)
  └── desktop   ──►  access-broker (NEW)  ──► jess protocol broker (ADR 0049)
                       (WebSocket ⇄ RDP/SSH/VNC/k8s; pixel/stream relay)
                       └── session recording ⇒ jess WORM (ADR 0030)
```

- **Talon**: new `channel=clientless` + `allowClientless`/`clientlessMaxTTL`
  TalonRoute fields; access-zone host class; Rego input projection;
  CAEP-revocable like any session.
- **access-broker (new service)**: terminates the browser WebSocket,
  authenticates the Talon session (signed IAP JWT — reuse the Phase-C
  bearer injection), opens the backend protocol stream via jess, relays
  frames, and tees the stream to jess session recording. Stateless,
  horizontally scalable, meshed (Linkerd mTLS to jess).
- **jess**: protocol brokers + recording (ADR 0049). The browser client
  is dumb; jess remains the policy + recording authority.

### Why not just expose apps directly behind Talon?

For pure HTTP apps, Phase 1 essentially IS that — the value is the
explicit `clientless` channel tag so policy treats agentless sessions
differently (stricter MFA/JIT, AAL cap, no false posture claims). For
desktop/terminal, a raw reverse proxy can't speak RDP/SSH/VNC to a
browser — hence the broker + in-browser client.

## Security considerations

- **No posture spoofing**: clientless sessions never assert device
  posture they can't prove. Routes that require real device posture stay
  agent-only; clientless is explicitly opt-in per route, fail-closed.
- **Full audit**: every clientless session + every brokered desktop
  session is WORM-recorded (HTTP access log + jess session recording),
  CAEP-revocable, and JIT-approved for sensitive targets.
- **Blast radius**: AAL cap + short TTL + JIT + per-route opt-in bound
  what an unmanaged device can reach.
- **Data exfil**: Phase 2 broker can enforce clipboard/file-transfer/
  download policy at the relay (a capability agent-based access lacks).

## Consequences

- Closes the headline ZTNA breadth gap; unlocks contractor/auditor/BYOD
  use cases central to the on-prem commercial story.
- New stateful-ish service (access-broker) to operate; depends on jess
  ADR 0049 for anything beyond HTTP.
- Honest degraded-posture model is a feature (provable claims only), not
  a workaround.

## Phased plan

- **Phase 1 — Clientless HTTP (weeks):** `access.` zone + Talon
  `channel=clientless` + `allowClientless`/`clientlessMaxTTL` TalonRoute
  fields + Rego projection + AAL cap + JIT gate for sensitive routes.
  Reuses existing IAP/WebAuthn/JIT. Shippable on its own.
- **Phase 2 — Clientless SSH/terminal (weeks):** access-broker + xterm.js
  front-end ⇄ jess SSH broker (jess already records SSH per ADR 0030).
- **Phase 3 — Clientless RDP/VNC (weeks):** ironrdp/guacd-class broker ⇒
  canvas client; clipboard/file-transfer policy at the relay.
- **Phase 4 — Clientless DB/k8s (weeks):** web SQL console + `kubectl
  exec`/logs over WebSocket via the jess broker.

Each phase is independently shippable and independently auditable. Phase 1
is the recommended next concrete build.
