# ADR 0001 — Talon: architecture overview, NIST SP 800-207 mapping, and threat model

- **Status:** Accepted
- **Date:** 2026-04-26
- **Deciders:** dogukanturhal (project owner)
- **Supersedes:** N/A (first ADR)
- **Superseded by:** N/A
- **Related:**
  - Options analysis behind the build-in-house decision (summarised in section 2)
  - ADR 0002 (planned) — cookie and session encoding details
  - ADR 0003 (planned) — TalonRoute CRD schema and conversion strategy

---

## 1. Status

Accepted. This ADR records the architectural contract for the next ~7 weeks of
Talon development (Phase 0 → Phase 5). Subsequent ADRs (0002+) refine specific
sub-decisions; deviations from §3–§7 of this document require a new ADR that
explicitly supersedes the relevant section.

## 2. Context

The HexxLock platform exposes ~17 administrative web applications under
`*.internal.example.com` (argocd, prometheus, grafana, alertmanager, vault,
longhorn, awx, atlantis, jaeger, netbox, sonarqube, defectdojo, dojo, wazuh,
falcon, admin, rollouts). Today they sit behind Pomerium IAP. Pomerium emits
HTTP 302 responses with bare-anchor bodies (`<a href>Found</a>`) plus
`X-Content-Type-Options: nosniff` and a cross-origin redirect chain — a
combination that triggers Mobile Safari's "is this a download?" heuristic. The
admin tier is therefore unreachable from iPhone, which is the most common
on-call device.

The options analysis evaluated
five paths: APISIX `openid-connect`, Authentik proxy provider, Authelia
forward-auth, fork-and-patch Pomerium, and an in-house IAP. Each was scored
against the standing rules:

1. **No workarounds** — eliminates Traefik + oauth2-proxy ForwardAuth.
2. **OSS-only** — eliminates Pomerium Enterprise, BeyondCorp, GCP IAP,
   Cloudflare Access, Auth0.
3. **Tier-1 enterprise grade** — eliminates Authelia (parallel user store
   antithetical to single-IdP intent).
4. **Always test on real iOS** — cannot eliminate any candidate before
   measurement, but the rig is the gating mechanism.
5. **Talon is the SOLE IAP after Phase 5** — eliminates Authentik
   (federation hop adds latency without addressing the actual bug).

The remaining candidates were APISIX `openid-connect` (mature, lua-resty-openidc
backed) and the in-house path. The project owner chose the **in-house path**, named it
**Talon**, and locked the architecture. This ADR documents
that decision and its consequences.

## 3. Decision

Build Talon, a single-binary Go reverse proxy that authenticates every request
against Falcon-ID via OIDC, evaluates per-route access policy through SpiceDB,
and forwards to admin upstreams over Linkerd-mTLS. Talon implements
NIST SP 800-207 §3 PEP/PE/PA in one process; it is the **sole** IAP for the
`*.internal.example.com` admin tier after Phase 5.

The single-binary form is deliberate. NIST 800-207 §3.1 defines the
Policy Decision Point (PDP) as a *logical* split into Policy Engine (PE) and
Policy Administrator (PA) — co-locating them in one process with the PEP is
permitted and is the same pattern Cloudflare Access and Pomerium use today
([NIST SP 800-207 §3](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf),
[Pomerium architecture](https://www.pomerium.com/blog/identity-aware-proxy)).
Splitting PE/PA into separate services is reserved for organisations whose
policy authoring lives in a different security boundary than enforcement;
HexxLock has no such requirement.

## 4. NIST SP 800-207 §3 component mapping

```
                  ┌───────────────────────────────────────────────────┐
                  │            Talon (single binary)                  │
   browser ─────► │  PEP: cmd/talon reverse-proxy entrypoint          │
                  │   │                                               │
                  │   ▼                                               │
                  │  PE:  internal/policy                             │
                  │   ├── claim verifier (Falcon-ID JWKS, cached)     │
                  │   ├── group filter (e.g. platform-admin)          │
                  │   └── SpiceDB CheckPermission (Zanzibar relations)│
                  │                                                   │
                  │  PA:  internal/oidc + TalonRoute reconciler       │
                  │   ├── OIDC RP authorization-code + PKCE           │
                  │   ├── session lifecycle (create / refresh / revoke)│
                  │   └── controller-runtime watch on TalonRoute CRs  │
                  └─────┬───────────────────────┬───────────────────┬─┘
                        │ session in            │ permission check  │ proxy → upstream
                        ▼                       ▼                   ▼
                   Redis (existing)        SpiceDB (existing)   Linkerd-meshed Service
                   keyspace talon:*        schema talon_route   (mTLS in-cluster)
```

| NIST role | Talon component | Notes |
|-----------|-----------------|-------|
| **Policy Enforcement Point (PEP)** | `cmd/talon` HTTP entrypoint + `internal/proxy` | Terminates browser TLS, forwards to upstream over Linkerd mTLS. Identity headers (`X-Talon-User`, `X-Talon-Email`, `X-Talon-Groups`, `X-Talon-Subject`) are *injected*, not relayed; any incoming header with that prefix is stripped first. |
| **Policy Engine (PE)** | `internal/policy` | Two-stage decision: (a) JWT claims valid + group filter passes, (b) SpiceDB `CheckPermission(talon_route:<host>#access@user:<id>)` returns `PERMISSIONSHIP_HAS_PERMISSION`. PE has no I/O *to* the request — it returns allow/deny only. |
| **Policy Administrator (PA)** | `internal/oidc` + `internal/route/reconciler.go` | OIDC handshake (start, callback, logout) + session lifecycle + dynamic `TalonRoute` CRD reconciler. Mutates session store, talks to Falcon-ID. |
| **Identity (subject store)** | Falcon-ID | OIDC IdP at `id.example.com`. Talon is just an RP. |
| **Authorization data (object store)** | SpiceDB | Zanzibar-style relations: `talon_route#access@user`. Schema in §5.b. |
| **Session store** | Redis (in-cluster, shared with Falcon-ID) | Talon keys under `talon:session:<uuid>` namespace; AES-GCM encrypted blob; 8h sliding TTL. |
| **Telemetry sink (CDM)** | Prometheus + Loki + Wazuh (Phase 4) | Per-decision audit log (allow/deny/error) → stdout JSON → Loki, then forwarded to Wazuh in Phase 4. |

## 5. Architecture details

### 5.a. Request flow (cookieless cold start)

```
1. GET https://prometheus.internal.example.com/                                   (browser)
2. Talon sees no talon_session cookie
3. 302 → https://auth.internal.example.com/auth/start?rd=https%3A%2F%2Fprometheus.internal.example.com%2F
   (full HTML body — see §5.d)                                                (Talon)
4. GET /auth/start                                                            (browser)
5. Talon writes handshake cookies (state, code_verifier), 302 → Falcon-ID
   /oauth/authorize?client_id=svc-talon&redirect_uri=…/auth/callback&PKCE     (Talon)
6. Falcon-ID interactive sign-in (or SSO if cookie present)                   (Falcon-ID)
7. 302 → https://auth.internal.example.com/auth/callback?code=…&state=…           (Falcon-ID)
8. Talon validates state, exchanges code for tokens (PKCE), validates id_token
   against Falcon-ID JWKS, applies group filter (platform-admin), creates
   session in Redis, sets talon_session=<uuid> cookie, 302 → original rd      (Talon)
9. GET https://prometheus.internal.example.com/  (now with talon_session cookie)  (browser)
10. Talon resolves cookie → Redis session → user claims
11. Talon evaluates SpiceDB CheckPermission for talon_route:prometheus.ops…
12. Allowed → ReverseProxy strips X-Talon-* headers from request, injects
    X-Talon-* identity headers, forwards to prometheus-server.monitoring:9090
    over Linkerd mTLS (PEP authenticated as sa/talon)                         (Talon → upstream)
13. 200 OK Prometheus UI                                                      (upstream)
```

### 5.b. SpiceDB schema (locked v1)

```zed
definition user {}

definition group {
    relation member: user
}

definition talon_route {
    relation viewer: user | group#member
    relation editor: user | group#member
    relation admin:  user | group#member

    permission access = viewer + editor + admin
    permission write  = editor + admin
    permission manage = admin
}
```

`access` is what the proxy checks; `write`/`manage` are reserved for future
upstreams that consult Talon for finer-grained authorisation (e.g. an admin
UI that hides destructive actions from `viewer`-only users). Schema lives at
`deploy/spicedb/talon.zed` and ships via the SpiceDB schema-write hook
pattern already used by Falcon-ID
(the Falcon-ID Helm chart's SpiceDB schema hook).

### 5.c. Cookie and session model (high-level — full detail in ADR 0002)

| Property | Value | Source |
|----------|-------|--------|
| Cookie name | `talon_session` | Locked at project start |
| Value shape | Opaque UUID v4, ≤ 200 bytes total cookie | Avoids 4 KB browser cap and iOS truncation |
| `Domain` | `.internal.example.com` | RFC 6265 §5.3.6; all admin hosts are subdomains, all share session |
| `HttpOnly` | true | Mitigate XSS session theft |
| `Secure` | true | TLS-only |
| `SameSite` | `Lax` | Allows Falcon-ID redirect-back to set cookie; blocks CSRF |
| TTL | 8 h with sliding refresh on every request | Matches admin shift length |
| Server state | AES-GCM encrypted JSON blob in Redis under `talon:session:<uuid>` | Cookie is just an opaque ID |
| Encryption key | 32-byte key in Vault `example/data/platform/talon/cookie-encrypt-key`, ExternalSecret-materialised | Key rotation = generate new key, dual-decrypt window, retire old |

### 5.d. Cross-origin redirect contract (the iOS bug fix, codified)

Every `302` Talon emits — at any layer — must satisfy at least one of:

1. `Content-Length: 0` with no body, OR
2. A complete `<!DOCTYPE html><html><head><title>…</title></head><body>…</body></html>`
   document of nonzero length.

A `302` with `Content-Type: text/html`, `X-Content-Type-Options: nosniff`,
and a partial body (e.g. `<a href>Found</a>`) is **forbidden** — that is the
combination that triggers iOS WebKit's download prompt. This rule is codified
in `internal/oidc/redirect.go::WriteHTMLRedirect` (port of Falcon-ID's
`internal/handlers/oauth_provider_handler.go::writeOAuthHTMLRedirect`) and
enforced via a unit test that asserts response shape against the canonical
form.

Reference: an iOS verification rig (not published).

## 6. Comparison with peer IAPs

The candidates the project rejected, and why each comparison still informs
Talon's design (so we don't reinvent worse versions of their good ideas):

| IAP | Architecture | iOS 302 shape | Continuous verification | Why rejected | Patterns Talon adopts |
|-----|--------------|---------------|-------------------------|--------------|----------------------|
| **Pomerium OSS** | Envoy + Authorize/Authentication services | Bare-anchor body — fails iOS | Per-request session check; ~5min OIDC token refresh | This is the bug we are fixing | Three-role split (PE/PA/PEP) collocated, OIDC RP pattern |
| **APISIX `openid-connect` plugin** | Lua plugin atop OpenResty (lua-resty-openidc) | Untested on iOS at decision time; SameSite cookie pitfalls documented upstream ([APISIX docs](https://apisix.apache.org/docs/apisix/plugins/openid-connect/)) | Manual via plugin re-introspect | Adds a second strategic gateway in front of the admin tier; couples admin auth to APISIX upgrade cadence | Per-route configuration as first-class data; Redis-backed session for cookie-size containment |
| **Authentik proxy provider** | Outpost (Go) + Authentik server (Python/Django) + DB + Redis | Untested on iOS | Per-request | Adds a second IdP-in-name (federated to Falcon-ID), two OIDC dances per sign-in, parallel user store | Per-application policies, embedded outpost pattern |
| **Authelia forward-auth** | Single Go binary | OK on iOS in casual testing | Optional WebAuthn re-prompt | Authelia is a full IdP — incompatible with single-IdP rule (Falcon-ID is canonical) | Single-binary deployability |
| **Fork-and-patch Pomerium** | As above | Patchable | As above | Owning a Pomerium fork is unbounded maintenance for one bug | N/A |
| **GCP IAP** ([reference](https://cloud.google.com/iap/docs/concepts-overview)) | Google-hosted, cookie-bound, header-injection to upstream | Reference shape | TLS-bound session token rotation | Not OSS; cloud-hosted only | `X-Goog-IAP-JWT-Assertion` header pattern → our `X-Talon-*` injection |
| **Cloudflare Access** ([reference](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)) | Cloudflare edge, JWT-based | Reference shape | "Posture checks evaluated at session start; ongoing sessions remain uninterrupted" — non-identity attributes polled per request ([Cloudflare One docs](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/)) | Not OSS; commercial only | Continuous-verification cadence as a tunable, default per session start |
| **Google BeyondCorp** ([reference](https://cloud.google.com/beyondcorp)) | Trust-score model, context-aware access engine, per-transaction evaluation | Reference shape | "Continuous and real-time end-to-end protection ... for every transaction" | Reference architecture; not deployable software | Per-transaction policy evaluation (Phase 4 continuous verification); context attributes as first-class signals |

Talon's continuous verification cadence (Phase 4 spec): every N minutes
(default **15 min**) re-fetch Falcon-ID `/oauth/userinfo` per active session
and invalidate on disabled/groups-changed/token-revoked. This is **stricter**
than Cloudflare Access's "at session start" baseline (admin tier warrants the
extra cost) and **looser** than BeyondCorp's "every transaction" (which would
DoS the IdP for an interactive admin who refreshes a Grafana dashboard once
per second). The cadence is a per-route config (`TalonRoute.spec.continuousVerifyInterval`).

## 7. Threat model (STRIDE per component)

This is a documenting threat model. A hardening review at Phase 4 exit will
reassess.

### 7.a. PEP (`internal/proxy`)

| Threat | Vector | Mitigation |
|--------|--------|-----------|
| **S**poofing — fake identity headers | Client sends `X-Talon-User: admin@…` | PEP **strips** all `X-Talon-*` headers from incoming request before injection. Codified test `proxy_test.go::TestStripsIncomingTalonHeaders`. |
| **T**ampering — header smuggling | `X-Forwarded-For` injection to bypass IP filter | PEP overwrites all `X-Forwarded-*` headers from authoritative source (the connecting socket addr); upstream sees Talon's view, not the client's. |
| **R**epudiation — no audit | Admin denies action | Per-request audit emit with user, route, decision, timestamp → Loki → Wazuh. |
| **I**nformation disclosure — error leakage | Upstream 5xx page exposes internal hostname | PEP rewrites `Location: http://internal-svc.foo.svc.cluster.local/…` to public-host form on 3xx; never proxies internal names back. |
| **D**oS — slowloris on Talon | Slow-read attack | Per-request read deadline (10s default), `MaxHeaderBytes` 1MB, idle-timeout 5min. HPA scales on CPU + connection count. |
| **E**levation — SSRF via TalonRoute upstream | Operator with TalonRoute write rights points upstream at `169.254.169.254/…` | Validating admission webhook restricts `upstream.host` to `^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.svc(\.cluster\.local)?$` (k8s service form only). Direct IPs and external hosts rejected. |

### 7.b. PE (`internal/policy`)

| Threat | Vector | Mitigation |
|--------|--------|-----------|
| **S**poofing — forged JWT | Client mints id_token signed with self-issued key | PE verifies against Falcon-ID JWKS (cached 1h, kid-checked). `iss` must match `https://id.example.com`. |
| **T**ampering — claim editing | MITM rewrites groups claim | id_token is signature-verified before claim read; tamper invalidates signature. |
| **R**epudiation — no decision log | Allow/deny disputed | Each `CheckPermission` decision logged with user, resource, permissionship result, ZedToken. |
| **I**nformation disclosure — SpiceDB enumeration | `LookupResources` reveals route names | Talon never exposes SpiceDB to clients; only `CheckPermission` per-request, never `LookupResources`/`LookupSubjects`. |
| **D**oS — SpiceDB pressure | Cache-bypassing request volume | SpiceDB call wrapped in a 200ms deadline; per-user CheckPermission cached for 30s (consistency=`MinimizeLatency`); on SpiceDB outage, fail **closed** (deny) — not open. |
| **E**levation — privilege escalation via group claim trust | Client gains group `platform-admin` outside Falcon-ID | Group source is *only* the id_token claim; SpiceDB binds users to groups by Falcon-ID subject, not by self-asserted group strings. |

### 7.c. PA (`internal/oidc` + reconciler)

| Threat | Vector | Mitigation |
|--------|--------|-----------|
| **S**poofing — replay of code | Attacker captures `?code=…` mid-flight | PKCE `code_verifier` stored in handshake cookie (HttpOnly, SameSite=Lax, 5min TTL); Falcon-ID rejects code without matching verifier. |
| **T**ampering — state CSRF | Attacker initiates flow with attacker's account, tricks victim into completing it | `state` in handshake cookie pinned to victim's browser; mismatch on callback → reject + audit log. |
| **R**epudiation — session origin | Disputed session creation | Session record in Redis carries: source IP, User-Agent, Falcon-ID `sub`, creation timestamp, last-touched timestamp. |
| **I**nformation disclosure — session blob in plaintext Redis | Operator with Redis read access dumps sessions | Session blob AES-GCM encrypted with key from Vault; Redis sees ciphertext only. Key rotation via dual-decrypt window. |
| **D**oS — Redis outage | Session store dies | Graceful degradation: on Redis read failure, treat as "no session" → re-run OIDC. Avoids 5xx bricking; cost is one extra OIDC roundtrip per request during outage. |
| **E**levation — TalonRoute hijack | Cluster operator with `talonroute` create rights points at sensitive upstream and assigns themselves admin | RBAC: only platform-admin group members get `talonroute` write rights (Kyverno policy `talonroute-write-restriction`). Validating admission webhook also requires `permission_required` field per route. |

### 7.d. Identity boundary (Falcon-ID)

Out of scope for Talon's threat model — Falcon-ID's threat model lives in
its own repo. Talon trusts Falcon-ID's id_token signature, JWKS publication,
and PKCE enforcement. **Compromise of Falcon-ID compromises Talon entirely.**
This is the same trust assumption Pomerium has today; Talon does not regress.

### 7.e. Session store boundary (Redis)

Treated as **untrusted** — all session data is encrypted at rest in Redis
(AES-GCM with key from Vault). Compromise of Redis reveals session
*existence and timing*, not session *contents*.

## 8. Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PUBLIC INTERNET                                │
│                                                                         │
│  iPhone Safari ─── TLS ────── DNAT 203.0.113.10 ──── traefik-internal   │
│                                                                         │
└──────────────────────────────────────────────┬──────────────────────────┘
                                               │
┌──────────────────────────────────────────────┼──────────────────────────┐
│ CLUSTER (Linkerd mesh, mTLS everywhere)      │                          │
│                                               ▼                         │
│   ┌─────────────────────────────────────────────────────────────┐       │
│   │  Talon (talon ns, sa/talon, mesh-injected)                  │       │
│   │   ▲                                                         │       │
│   │   │ OIDC + JWKS (HTTPS in-cluster)                          │       │
│   │   ▼                                                         │       │
│   │  Falcon-ID (falcon-id ns) ──── CNPG falcon-id-pg            │       │
│   │   │                                                         │       │
│   │   ▼ AES-GCM encrypted blobs                                 │       │
│   │  Redis (falcon-id-redis-0) ◄─── ExternalSecret ◄── Vault    │       │
│   │                                                             │       │
│   │  SpiceDB (spicedb ns) ──── CockroachDB                      │       │
│   │   ▲                                                         │       │
│   │   │ gRPC (Linkerd mTLS)                                     │       │
│   │   ▼                                                         │       │
│   │  Talon                                                      │       │
│   │   │                                                         │       │
│   │   ▼ HTTP (Linkerd mTLS), AuthorizationPolicy(sa/talon-only) │       │
│   │  upstream (e.g. prometheus-server)                          │       │
│   └─────────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────┘
```

Three trust boundaries cross Talon:

1. **Public ↔ Cluster** — TLS terminated at `traefik-internal`; Talon sees
   pre-TLS HTTP, but the connecting socket is a meshed proxy pod, not the
   browser. Use `X-Forwarded-For` set by Traefik (validated source).
2. **Talon ↔ Upstream** — Linkerd mTLS in both directions. Each upstream
   workload deploys an `AuthorizationPolicy` accepting only
   `talon.talon.serviceaccount.identity.linkerd.cluster.local` as caller.
   This is the Phase 4 deliverable; Phase 1 lands without the policy and
   adds it before Phase 5 decommissions Pomerium.
3. **Talon ↔ Identity/Authz/Session stores** — Linkerd mTLS to Falcon-ID,
   SpiceDB, Redis. Each store has its own AuthorizationPolicy gating Talon's
   ServiceAccount.

## 9. Operational implications

- **Falcon-ID outage = total admin lockout.** Same posture as today with
  Pomerium; not a regression. Mitigation lives in Falcon-ID's own HA story
  (CNPG + multi-replica + Linkerd mesh).
- **Redis outage degrades to OIDC-per-request.** No 5xx; users see extra
  redirect roundtrips. Acceptable; Redis HA already in place.
- **SpiceDB outage = deny-by-default.** Per §7.b, `CheckPermission` failure
  is treated as "deny". Operators are already on call for SpiceDB; this
  rule is documented in the runbook (Phase 3 deliverable).
- **Argo CD deny-window.** Talon Application rolls under the same deny
  window as the rest of the platform. Manual Argo sync from inside the
  argocd-server pod is the documented break-glass
  procedure.
- **Per-route blast radius.** A bad TalonRoute hits one host; Pomerium
  config errors today hit the whole admin tier. Net improvement.
- **Continuous verification cadence (Phase 4) puts Falcon-ID under load.**
  N concurrent admins × (60/15 min refreshes) × (1 `/oauth/userinfo` call)
  = 4N requests/h. For N=20 admins: 80 req/h baseline. Trivial.

## 10. Consequences

### 10.a. Positive

- iPhone Safari/Chrome admin sign-in works. The user-visible bug that
  motivated this whole project is fixed by §5.d.
- Single auth control plane for the admin tier. After Phase 5, no
  Pomerium, no oauth2-proxy, no Authentik, no Authelia — one Go binary
  with one OIDC trust path.
- Per-route policy in Kubernetes-native form (`TalonRoute` CRD) with
  RBAC, OpenAPI validation, and admission webhooks. ConfigMap-driven
  routes were rejected for losing all of these.
- The Falcon-ID `writeOAuthHTMLRedirect` pattern gets a second
  implementation site, hardening the cross-origin-redirect contract
  across the platform.
- Identity is single-sourced from Falcon-ID. No federated dance, no
  parallel user store, no second cookie domain to reason about.
- SpiceDB authorisation reuses the same store the platform already runs;
  amortises the operational cost.

### 10.b. Negative

- We own security-critical IAP code. Session encryption, CSRF/replay,
  cookie attribute correctness, header smuggling — all become
  HexxLock's problem instead of Pomerium's. Mitigation: reuse Falcon-ID's
  proven primitives (bcrypt + Redis + JWT) where possible; weekly trivy
  scans; cosign-signed images; SLSA L3 provenance via the same CI
  template as falcon-id; explicit threat model in §7 to be reviewed at
  every Phase exit.
- Phase 5 is a one-way door. Once Pomerium is decommissioned and DNS for
  `auth-pomerium.internal.example.com` is gone, rollback to Pomerium would
  take days. Mitigation: Phase 3's 7-day soak window with Pomerium
  Ingresses parked as `*.disabled.yaml` — easy revert.
- 7-week timeline competes for attention with other tier-1 platform
  work. Phases are gated on iOS verification (Phase 1) and a 48h soak
  (Phase 3); slippage is allowed.

### 10.c. Neutral

- Talon adds one more in-cluster Linkerd identity to manage. Fits the
  existing cert-manager + Linkerd issuer pattern; no new operational
  surface.
- New OIDC client `svc-talon` registered in Falcon-ID via the existing
  ServiceClientClaim Crossplane pattern.
  No new bootstrap flow.

## 11. Open questions / deferred to subsequent ADRs


| Question | Deferred to | Reason |
|----------|-------------|--------|
| Session blob exact JSON shape, encryption-key rotation procedure | ADR 0002 | Detail-level, doesn't change architecture |
| `TalonRoute` CRD schema, conversion-webhook strategy for v1alpha1→v1beta1 | ADR 0003 | Locks before Phase 2 starts |
| Device-posture signal source(s) | Phase 6 (backlog) | Out of scope for Phases 0–5 + Tier-1 |
| Adaptive risk integration with Slice F | Phase 6 (backlog) | As above |

## 12. References

### Standards / canonical

- [NIST SP 800-207 — Zero Trust Architecture (PDF)](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf)
- [RFC 6265 — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)

### Reference architectures (for comparison)

- [Cloudflare Access posture checks](https://developers.cloudflare.com/cloudflare-one/reusable-components/posture-checks/)
- [Cloudflare ZTNA reference architecture — designing access policies](https://developers.cloudflare.com/reference-architecture/design-guides/designing-ztna-access-policies/)
- [Google BeyondCorp Enterprise](https://cloud.google.com/beyondcorp)
- [Google BeyondCorp Enterprise — ESG technical validation (PDF)](https://services.google.com/fh/files/misc/esg_tech_val_report_bce.pdf)
- [GCP Identity-Aware Proxy concepts overview](https://cloud.google.com/iap/docs/concepts-overview)
- [Pomerium — Identity-Aware Proxy architecture](https://www.pomerium.com/blog/identity-aware-proxy)
- [APISIX `openid-connect` plugin docs](https://apisix.apache.org/docs/apisix/plugins/openid-connect/)
- [Authentik proxy provider — Traefik integration](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_traefik/)
- [Authelia](https://www.authelia.com/)

### Authorization data model

- [SpiceDB — open-source Zanzibar implementation](https://github.com/authzed/spicedb)
- [Google Zanzibar — relationship-based access control concepts](https://authzed.com/learn/google-zanzibar)
- [SpiceDB Zanzibar concepts in docs](https://authzed.com/docs/spicedb/concepts/zanzibar)

### iOS Safari redirect-shape research

- [WebKit Bugzilla — URL redirect category](https://bugs.webkit.org/show_bug.cgi?id=24175)
- Live captured Pomerium 302 evidence —
  the original options analysis
- Falcon-ID `writeOAuthHTMLRedirect` reference impl —
  `/home/dogukanturhal/projects/falcon-id/internal/handlers/oauth_provider_handler.go`



---

*This ADR is the architectural contract for Talon Phases 0–5. Section
numbering is stable; future ADRs reference §3, §4, §5 etc. by number.
Material change to any section requires a new ADR that explicitly
supersedes the section.*
