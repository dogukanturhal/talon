# ADR 0009 — Talon as shared PDP exposing Envoy ext_authz (GEP-1494 alignment)

- **Status:** Proposed (Phase 7.1 in flight 2026-06-01)
- **Date:** 2026-06-01
- **Deciders:** dogukanturhal, Claude Opus 4.7
- **Refines:** ADR 0001 §3 (PEP/PDP roles), ADR 0005 (forward-auth)
- **Related:** ADR 0003 (TalonRoute CRD), Gateway API GEP-1494, Envoy
  service.auth.v3

---

## 1. Status

Proposed. Phase 7.1 (this MR) lands the gRPC adapter + listener wiring;
Phase 7.2 (separate the GitOps repository + <gitops-bootstrap-repo> MRs)
flips APISIX from the HTTP `/auth/verify` forward-auth path to the
new `ext_authz` gRPC path. ADR will move to Accepted once Phase 7.2
ships and a one-week soak confirms no decision divergence between
the two adapters.

## 2. Context

The HexxLock edge has two tiers with two data planes:

- **Admin** — Talon fronts 17 `internal.example.com` hosts. Browser
  sessions, MFA step-up, SpiceDB authz, per-host TalonRoute policy,
  audit chain (ADR 0031).
- **Customer** — APISIX fronts `*.hexxlock.com` + `api.example.app`.
  Rate-limit, WAF, transformation, public-internet adversary
  defense.

Today APISIX consults Talon for identity via the HTTP `/auth/verify`
forward-auth endpoint (ADR 0005). That works but is bespoke — no
other data plane speaks it natively. If we ever add a second
customer-tier data plane (Envoy Gateway for partner APIs, Cilium
ambient mesh, Istio waypoint, etc.) we'd have to teach each one to
speak Talon's HTTP forward-auth shape, OR re-build identity
termination in each data plane (which the prior research explicitly
killed as anti-pattern — see Netflix's "fragmented per-service
token consumption drove us to centralize identity at the edge").

The 2026-06-01 deep-research workflow (28 sources, 22 adversarially-
verified claims) closed three open questions:

1. **No tier-1 vendor publishes a single-CRD-to-heterogeneous-data-
   planes architecture.** Tetrate Service Bridge, Gloo Platform,
   Consul, Envoy Gateway, GAMMA — all bind to homogeneous data planes
   or use different CRD families. The pattern is genuinely novel.

2. **The canonical cross-data-plane forward-auth wire format is
   Envoy's `service.auth.v3` ext_authz.** Standardized in K8s Gateway
   API GEP-1494 (HTTPRoute ExternalAuth Filter, Experimental in
   v1.4.0). KubeCon London 2025 multi-dataplane consensus. Target
   implementations: Envoy Gateway, HAProxy Ingress, Traefik, Consul,
   Contour, Istio, ingress-nginx, Ambassador, GlooEdge, Cilium PoC.

3. **No published IAP-grew-into-gateway-and-failed retros surfaced**
   — failure mode probably exists privately but lacks canonical
   public write-up.

The verdict: keep the split (admin = Talon, customer = APISIX), and
invest in the **shared policy plane**. Talon evolves into a shared
PDP that BOTH data planes consume via the GEP-1494-aligned ext_authz
wire. Future data planes interoperate without bespoke contracts.

## 3. Decision

Make Talon a shared PDP exposing the Envoy `service.auth.v3.
Authorization` gRPC service alongside the existing HTTP data plane.
Both surface adapters (HTTP forward-auth, gRPC ext_authz) consume
ONE in-process decision core (`router.Verify`) so the two wire
formats produce IDENTICAL decisions for the same request.

## 4. Architecture

```
                Falcon-ID (OIDC + JWKS + RFC 8707)
                              ▲
                              │ identity claims
                              │
   ┌──────────────────────────────────────────────────────┐
   │                       Talon                          │
   │  ┌────────────────────────────────────────────────┐  │
   │  │  router.Verify  — shared decision core         │  │
   │  │  (host lookup, cookie, session, per-host gate, │  │
   │  │   policy eval, step-up, sliding refresh)       │  │
   │  └────────────────────────────────────────────────┘  │
   │           ▲                       ▲                  │
   │           │ HTTP                  │ gRPC ext_authz   │
   │           │                       │ (envoy.service.  │
   │           │                       │  auth.v3)        │
   │  ┌─────────────────┐    ┌─────────────────────────┐ │
   │  │ serveAuthVerify │    │  extauthz.Server        │ │
   │  │ /auth/verify    │    │  ListenExtAuthz=:9001   │ │
   │  │ HTTP forward-   │    │  GEP-1494-aligned       │ │
   │  │ auth (ADR 0005) │    │                         │ │
   │  └─────────────────┘    └─────────────────────────┘ │
   └──────────────────────────────────────────────────────┘
              ▲                       ▲              ▲
              │                       │              │
              │ HTTP                  │ gRPC         │ gRPC (future)
              │                       │              │
   ┌──────────────────┐   ┌────────────────────┐   ┌──────────────┐
   │  APISIX (today)  │   │ APISIX (Phase 7.2) │   │  Envoy GW /  │
   │  forward-auth    │   │ ext-plugin → grpc  │   │  Istio /     │
   │  plugin          │   │ ext_authz          │   │  Cilium /    │
   └──────────────────┘   └────────────────────┘   │  Traefik /   │
                                                    │  HAProxy /   │
                                                    │  ingress-nginx│
                                                    └──────────────┘
```

Both adapters land at the same `router.Verify` function. Same audit
emit, same metric increment, same decision. The wire format differs;
the decision does not.

## 5. Why h2c (no per-listener TLS)

Linkerd handles mTLS end-to-end for in-cluster service traffic.
Talon already runs meshed. Adding another TLS layer at the gRPC
listener would:

- Duplicate effort (Linkerd cert-manager + Talon cert-manager Cert)
- Require separate cert reload / rotation plumbing
- Defeat the SPIFFE identity assertion that AuthorizationPolicy
  enforces at the linkerd-proxy layer

So the gRPC server runs plain h2c on `TALON_LISTEN_EXTAUTHZ` (default
disabled). AuthorizationPolicy in the talon ns gates which mesh
identities may call. NetworkPolicy + Service type=ClusterIP prevent
external exposure. This matches the convention Talon already uses
for SpiceDB + audit-stream gRPC clients.

## 6. Why h2c WITHOUT a separate TLS port — defense-in-depth check

Risk: if Linkerd is misconfigured / removed / sidecar fails to inject,
the ext_authz port becomes unauthenticated. Mitigation:

1. Talon's Linkerd `inject: enabled` annotation is load-bearing — same
   risk as every other Talon listener. Removing the sidecar breaks
   admin-tier IAP too, so the operational pressure to fix it is
   high and immediate.
2. AuthorizationPolicy on the new Server requires `MeshTLSAuthentication`
   matching the apisix SA SPIFFE ID. Without mesh identity, requests
   are rejected at the linkerd-proxy layer before reaching Talon.
3. NetworkPolicy restricts ingress to the apisix and (future) Envoy-
   Gateway namespaces.

Defense-in-depth via three layers (sidecar + AuthzPolicy + NetPol)
matches the existing posture for the admin /metrics endpoint and the
SpiceDB write API.

## 7. Wire-format details

### 7.1 Request mapping (CheckRequest → router.VerifyInput)

| Talon field    | Envoy CheckRequest source                                         |
|----------------|-------------------------------------------------------------------|
| Host           | `Attributes.Request.Http.Headers["x-forwarded-host"]`             |
|                | fallback: `Attributes.Request.Http.Host` (= `:authority`)         |
| CookieValue    | parsed from `Attributes.Request.Http.Headers["cookie"]`           |
| Method         | `Attributes.Request.Http.Method`                                  |
| Path           | `Attributes.Request.Http.Path`                                    |
| SrcIP          | first IP in `Headers["x-forwarded-for"]`, fallback to             |
|                | `Attributes.Source.Address.SocketAddress.Address`                 |

Header keys lower-cased per Envoy proto guarantee. Cookie parsing
is identical to `net/http` semantics (RFC 6265).

### 7.2 Response mapping (router.VerifyDecision → CheckResponse)

**Allow:**
- `Status.Code = OK`
- `HttpResponse = OkHttpResponse{ Headers: [HeaderValueOption{
  AppendAction = OVERWRITE_IF_EXISTS_OR_ADD }] }`
- Identity headers identical to the HTTP adapter's
  `injectIdentityHeaders` set:
  `X-Talon-User`, `X-Talon-Subject`, `X-Talon-Email`,
  `X-Talon-Tenant-Id` (if present), `X-Talon-Groups`,
  `X-Talon-Issuer`, `X-Talon-Issued-At`.
- OVERWRITE semantics prevent a client-supplied `X-Talon-*` from
  spoofing trusted identity.

**Deny:**
- `Status.Code = PermissionDenied`
- `HttpResponse = DeniedHttpResponse{ Status: 401 Unauthorized,
  Headers: [X-Talon-Reason: <policy.ReasonX>, Cache-Control: no-store] }`
- Same `X-Talon-Reason` vocabulary the HTTP adapter has been emitting
  since ADR 0005. APISIX / Envoy Gateway / Istio branch on this
  header to decide redirect-to-login vs hard-fail.

**Step-up needed (mfaRequired/requireACR not satisfied):**
- Today: deny with `X-Talon-Reason="mfa_required"` (identical wire
  shape to current HTTP behaviour). Phase 6b will upgrade this path
  to emit the full RFC 9470 `WWW-Authenticate: Bearer error=
  "insufficient_user_authentication" acr_values="…"` once the
  per-path ACR plumbing lands.

### 7.3 Caching

CheckResponses are NOT cached by Envoy's ext_authz filter by default,
and we explicitly emit `Cache-Control: no-store` on deny responses
to preserve the session-revocation invariant (ADR 0001 §7.b / Gap 2
streaming revocation cascade).

## 8. Coexistence with HTTP `/auth/verify`

Both adapters stay live during transition:

- **Today (pre-Phase-7.2):** APISIX calls HTTP `/auth/verify`; new
  ext_authz listener is disabled by default (empty `TALON_LISTEN_
  EXTAUTHZ`).
- **Phase 7.2 (next MR):** Helm value sets `TALON_LISTEN_EXTAUTHZ=
  :9001`, ClusterIP Service exposes it, AuthorizationPolicy + Network
  Policy gate access. APISIX `ext-plugin-pre-req` or `forward-auth`
  plugin reconfigured to consume gRPC ext_authz.
- **Phase 7.3 (future):** soak validates decision-equivalence between
  the two adapters. ADR 0005 forward-auth path marked deprecated;
  not deleted yet (other future consumers may still want HTTP).

## 9. Consequences

**Positive:**
- Talon becomes interoperable with any future data plane that adopts
  GEP-1494 (the entire CNCF data-plane ecosystem, growing).
- One decision core ⇒ HTTP and gRPC adapters cannot drift apart;
  one audit event per decision regardless of wire format.
- APISIX gains lower-latency gRPC subrequest (HTTP/2 multiplexing,
  binary protocol) over today's HTTP/1.1 forward-auth.

**Negative:**
- New port to operate. NetworkPolicy + AuthorizationPolicy widened
  by one entry.
- Envoy proto dep adds ~hundreds of KB to the Talon binary.
- During the transition, two surface adapters cost double cognitive
  load on operator incidents (which one fired? — both, but for the
  same reason).

**Neutral:**
- Per the prior research, no published precedent for "IAP becomes
  shared PDP exposing ext_authz" exists. HexxLock may end up
  publishing the first canonical case study. Open question on the
  research workflow's openQuestions list.

## 10. Out of scope (deferred)

- TalonRoute v1beta1 pathRules consumption in `Verify` (Phase 7.3
  after Phase 6b matcher engine lands).
- RFC 9470 step-up wire format on the gRPC path (Phase 6b).
- Cross-protocol perf benchmarks (HTTP vs gRPC subrequest at 1k+
  RPS) — research workflow surfaced this as still-open; Phase 7.4
  will measure live once both adapters carry production traffic.
- APISIX ext-plugin migration MR — separate the GitOps repository +
  <gitops-bootstrap-repo> work, sequenced after this MR.

## 11. References

- Envoy `service.auth.v3.Authorization`:
  https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto
- GEP-1494 (HTTPRoute ExternalAuth Filter):
  https://gateway-api.sigs.k8s.io/geps/gep-1494/
- Netflix EAS-in-Zuul (centralize identity at the edge):
  https://netflixtechblog.com/edge-authentication-and-token-agnostic-identity-propagation-514e47e0b602
- Istio CUSTOM AuthorizationPolicy (canonical chaining order):
  https://istio.io/latest/blog/2021/better-external-authz/
- Research workflow: 22-claim adversarially-verified synthesis,
  2026-06-01
  (transcript: `~/.claude/projects/.../wf_ebc36449-c4a/`)
