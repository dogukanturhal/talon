# Talon Service Tokens — Machine Identity at the IAP

Author: dogukanturhal · 2026-05-28 · Status: DRAFT for review
Supersedes: nothing (new capability)
Companion ADR: ADR 0030 §"Pattern C — Service tokens"

## Summary

Talon today is a browser-only IAP: every request must carry a `talon_session`
cookie populated by an OIDC dance. Machine consumers (ArgoCD, image-updater,
Atlantis, Renovate, CI runners, kubelets for external pulls) cannot follow
that dance, so they're stuck either bypassing Talon entirely or living on
separate hostnames.

This spec adds a **second authentication channel** to Talon: a Bearer JWT
issued by Falcon-ID via the `client_credentials` grant. The browser channel
keeps working unchanged; machine clients send `Authorization: Bearer <jwt>`
and skip the OIDC dance.

End state: **one hostname per service** can serve both human and machine
traffic. `github.com` can be Talon-fronted. `registry.example.com`
can be Talon-fronted. Path Y (rename to `*.ops`) becomes optional rather
than required.

## What we already have (audited 2026-05-28)

This spec deliberately reuses existing primitives — listed here so the
implementation stays small.

1. **Falcon-ID `client_credentials` grant** is fully implemented end-to-end:
   - Handler: `falcon-id/internal/handlers/oauth_provider_handler.go:44,831-855`
   - Service: `falcon-id/internal/services/oauth_provider_service.go:1593-1639`
   - JWT shape for the no-user path:
     `falcon-id/internal/services/oauth_provider_service_tokens.go:195-212`
   - Discovery already advertises it
     (`oauth_provider_service_tokens.go:519`)
   - RFC 8707 `resource` parameter binds the token's `aud` claim to a
     specific Talon-fronted host (`:42-46`)
   - DPoP-bound where required by scope (RFC 9449 §6)
   - Reference c_c-only client: `svc-serviceclient-provisioner` already
     exists and works
2. **Crossplane `ServiceClientClaim` XRD** accepts `grantTypes:
   [client_credentials]` as default
   (in the GitOps repository).
   Each machine consumer is a sibling YAML; **zero XRD changes**.
3. **Falcon-ID JWKS** at `https://id.example.com/.well-known/jwks.json`
   (route at `falcon-id/cmd/routes_admin.go:1611`).
4. **Talon `identityjwt.Verifier`** in `talon/internal/identityjwt/verifier.go`
   already encodes RS256-only + iss-pin + aud-pin + JWKS-cache + key
   rotation. This is the template for the new inbound verifier — different
   issuer, different audience, same shape.
5. **Audit funnel** exists (`audit_service.go:44,288-330`). The only gap is
   that `ClientCredentialsGrant` does **not** emit an audit-log row today —
   the `iam_oauth_tokens` INSERT is the de-facto record. One-line addition
   to fix.

So the build surface is: **one new middleware in Talon** + **one audit hook
in Falcon-ID** + **a `ServiceClientClaim` YAML per consumer**. Nothing else
moves.

## Wire format

### Token issuance (machine consumer ← Falcon-ID)

Standard OAuth 2.0 `client_credentials` per RFC 6749 §4.4:

```
POST https://id.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials
&scope=talon:github.com:read
&resource=https://github.com
```

Response:

```json
{
  "access_token": "<RS256-signed JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "talon:github.com:read"
}
```

JWT claims (per `oauth_provider_service_tokens.go:195-212`):

```json
{
  "iss": "https://id.example.com",
  "sub": "svc-argocd-repo-server",
  "aud": "https://github.com",
  "iat": 1748430000,
  "exp": 1748433600,
  "jti": "<random>",
  "scope": "talon:github.com:read",
  "client_id": "svc-argocd-repo-server",
  "tenant_id": "00000000-0000-0000-0000-000000000001"
}
```

The `aud` is the Talon-fronted host (RFC 8707 binding). The `sub` is the
machine identity. **No human user is in the picture**; this is a workload
identity assertion.

### Token presentation (machine consumer → Talon)

```
GET /api/v4/projects/123/merge_requests HTTP/1.1
Host: github.com
Authorization: Bearer <jwt>
```

### Token lifetime

- Default `expires_in: 3600` (1h). Configurable per-client in
  `iam_oauth_clients.access_token_ttl`.
- No refresh tokens for `client_credentials` (per RFC 6749 §4.4.3) — the
  client just re-runs the token endpoint when expiring.
- Talon caches verification results per `jti` to avoid re-verifying every
  request within a single token's lifetime (LRU of ~10k entries, ~5MB).

### Scope namespace

Format: `talon:<host>:<verb>` where `<host>` is the lower-case Talon-fronted
hostname (regex-stripped to `[a-z0-9.-]+`) and `<verb>` is one of:

- `read` — `GET`, `HEAD`, `OPTIONS`
- `write` — `POST`, `PUT`, `PATCH`, `DELETE`
- `pull` — Docker registry V2 reads (`GET /v2/...`)
- `push` — Docker registry V2 writes (`PUT/POST/PATCH /v2/...`)
- `admin` — anything; reserved for break-glass

Special scope `talon:proxy` is the broad single-scope (any host, any verb);
allowed only for clients with a `is_break_glass: true` flag, gated by a
secondary review on issuance.

Examples:

```
svc-argocd-repo-server         scope = talon:github.com:read
svc-argocd-image-updater       scope = talon:github.com:write
                                       talon:registry.example.com:pull
svc-atlantis                   scope = talon:github.com:read
                                       talon:github.com:write
svc-renovate-bot               scope = talon:github.com:write
                                       talon:registry.example.com:pull
svc-ci-runner-platform         scope = talon:github.com:read
                                       talon:registry.example.com:push
```

Scope validation lives in Talon, NOT in Falcon-ID — Falcon-ID just enforces
that the requested scope ⊂ registered scopes for the client. Talon then
checks the scope-vs-host-vs-verb tuple at proxy time.

## Talon middleware design

### Position in router

Insert a new middleware **between the per-host gate (`evaluatePerHost`) and
the cookie/session lookup** in `talon/internal/router/router.go:395` (start
of protected catch-all). Order matters: per-host first to short-circuit
unauthorized hosts; then service-token; then cookie (for browsers); then
deny.

```go
// router.go (sketch)
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // ... healthz/readyz/auth-host paths above ...

    // Protected catch-all
    upstream, ok := r.routeByHost(req)
    if !ok { http.Error(w, "not found", 404); return }

    if !r.evaluatePerHost(req, upstream) {
        http.Error(w, "forbidden", 403); return
    }

    // [NEW] Service-token Bearer auth
    if tok := bearerFromHeader(req); tok != "" {
        claims, err := r.svctoken.Verify(req.Context(), tok, req.Host)
        if err == nil {
            // skip cookie/session entirely; synthesize for the proxy
            blob := session.SynthesizeFromSvcToken(claims)
            r.proxy(w, req, upstream, blob)
            return
        }
        // verification failed; record + fall through to cookie path
        r.metrics.SvctokenVerifyFailures.WithLabelValues(err.Reason()).Inc()
    }

    // Existing cookie / session path
    sess, err := r.store.Read(ctx, cookieVal)
    if err != nil { r.redirectToOIDC(w, req); return }
    r.proxy(w, req, upstream, sess.Blob)
}
```

Key properties:

1. **Bearer-first when present**. If `Authorization: Bearer <jwt>` exists
   and verifies, the request flows. No cookie required, no OIDC dance.
2. **Bearer failure does NOT auto-401**. It falls back to the cookie path
   so a stale cookie can still complete a browser dance. This avoids the
   "machine consumer accidentally hits with broken token, browser-using
   operator gets denied" cross-talk.
3. **Verification cache**. A successful `Verify` result is cached by `jti`
   for `(exp - now) - 30s` to amortize JWKS hits.
4. **Synthesized session blob**. The policy evaluator reads from
   `session.Blob`; we populate it from JWT claims (`sub`, `scope`,
   `client_id`, `tenant_id`, plus a marker `IsMachine=true`) so the
   existing policy engine doesn't need a parallel branch.
5. **Talon's `X-Talon-Identity-Token`** for the upstream proxy
   (`identityjwt.Signer`) is still minted — the upstream sees the machine
   identity stamped in the same place a human identity would be. Same
   header, distinguishable by claims.

### Verifier specification

New `internal/svctoken/verifier.go`:

```go
type Verifier struct {
    issuer    string                       // https://id.example.com
    jwksURL   string                       // https://id.example.com/.well-known/jwks.json
    expectedAudience func(host string) string  // returns the expected `aud` for a Host header
    cache     *lru.Cache[string, *Claims]  // jti → claims, TTL-bounded
}

type Claims struct {
    Issuer    string
    Subject   string                       // svc-argocd-repo-server
    Audience  string                       // https://github.com
    Scopes    []string                     // ["talon:github.com:read"]
    ClientID  string                       // svc-argocd-repo-server
    TenantID  string
    ExpiresAt time.Time
    JTI       string
}

func (v *Verifier) Verify(ctx context.Context, raw, host string) (*Claims, error) {
    // 1. Parse + verify signature against JWKS (RS256 only; cf. identityjwt/verifier.go:88)
    // 2. Verify iss == v.issuer (exact match)
    // 3. Verify aud == v.expectedAudience(host) (exact match)
    // 4. Verify exp > now (with 5s clock tolerance)
    // 5. Verify scope contains a token matching `talon:<host>:<verb>` for the request's verb
    // 6. Cache by jti
}
```

The pattern mirrors `identityjwt/verifier.go` line-by-line. Reuse:
- JWKS cache (5-min, refresh on unknown kid)
- RS256-only allowlist
- 5s clock tolerance
- jti tracking for replay-resistance

### Falcon-ID audit hook

One-line addition in `falcon-id/internal/services/oauth_provider_service.go`
inside `ClientCredentialsGrant` after `generateTokens` returns successfully:

```go
// Existing:
tokens, err := s.generateTokens(ctx, client, nil, scopes, ...)
if err != nil { return nil, err }

// NEW:
if s.auditSvc != nil {
    _ = s.auditSvc.LogPlatformAction(ctx, audit.PlatformActionEvent{
        Action:   "oauth.client_credentials.issued",
        ActorClientID: client.ClientID,
        TenantID: client.TenantID,
        Target:   audienceOrEmpty(resource),
        Scopes:   scopes,
        IP:       clientIP,
        UA:       userAgent,
    })
}

return tokens, nil
```

This makes machine-token issuance visible in Loki alongside human logins.
The `iam_oauth_tokens` row remains, but operators get one audit-funnel
signal for every credential mint event.

## Migration strategy

### Phase 0 — Spec review (this doc)
Land in `/home/dogukanturhal/projects/talon/docs/specs/talon-service-tokens.md`.
Operator review before any code lands.

### Phase 1 — Talon middleware (talon repo)

**Scope:**
- New package `internal/svctoken/{verifier,cache,blob}.go`
- Router wire-in
- Config: `cfg.SvctokenIssuer`, `cfg.SvctokenJWKSURL`, `cfg.SvctokenExpectedAudienceTemplate`
- Metrics emitted through the cluster's `talon_auth_decision_total{route, decision, reason}` counter, with `reason` ∈ {`svctoken`, `svctoken_rejected`, `svctoken_passthrough`, `svctoken_fallthrough`, `svctoken_credential_exchange`, `svctoken_credential_exchange_uncfg`, `svctoken_credential_exchange_load`}. The verifier publishes a `VerifierMetrics` interface (`internal/svctoken/metrics.go`) but the binary wires only `noopMetrics` today — the dedicated `talon_svctoken_verify_total` series originally specced in this section was never registered; all svctoken-related observability flows through the auth-decision counter. Spec updated 2026-05-29 after Phase 4.5 verification.
- Unit tests covering each verification branch
- Integration test against staging Falcon-ID

**Verification gate before next phase:**
- All tests green
- Helm values default `enabled: false` — middleware no-ops until a per-cluster opt-in
- Soak in staging cluster (if it exists; otherwise feature-flag on prod)

**Rollback:** disable feature flag — middleware no-ops, cookie path still
serves browser traffic unchanged.

### Phase 2 — Falcon-ID audit hook (falcon-id repo)

**Scope:**
- One-line addition in `ClientCredentialsGrant`
- New entry in audit-service catalogs (`Action: oauth.client_credentials.issued`)
- Unit test for the audit row shape

**Verification gate:** unit test green; existing tests pass.

**Rollback:** revert the one line.

### Phase 3 — Pilot consumer: ArgoCD repo-server

**Why ArgoCD first:**
- Internal-only today; failure mode is "Argo sync stops" which surfaces
  in 60s via the existing `ArgoCDAppOperationStuckRunning` alert
- Bounded scope: one Deployment, one repoCreds config
- Easy to revert by flipping the repoCreds back to PAT auth

**Steps:**
1. New `ServiceClientClaim` `svc-argocd-repo-server` (the GitOps repository)
   - `grantTypes: [client_credentials]`
   - `scopes: [talon:github.com:read]`
2. Wait for provisioner → Vault KV → ESO → `argocd-repo-server-svctoken` Secret
3. Add an ArgoCD repoCreds Secret with `type=git` and `username=oauth2`.
   The password field carries the Falcon-ID Bearer JWT — GitLab accepts
   `oauth2:<jwt>` over HTTPS Basic auth for any clone where the JWT is
   bound to the repo's host via RFC 8707. ArgoCD doesn't natively re-mint
   JWTs, so either:
   - **3a.** A sidecar (`svctoken-refresher`) on `argocd-repo-server`
     that periodically calls Falcon-ID `/oauth/token` AND PATCHes the
     repoCreds Secret's `data.password` field with the fresh JWT on
     every mint. The repo-server's Secret-watcher reloads credentials
     within seconds, so the next clone presents the rotated Bearer
     without a pod restart. The same sidecar also writes the JWT to
     a shared file at `/var/run/svctoken/jwt` for observability and
     so file-only consumers (CI runners, Atlantis, image-updater,
     Renovate) can reuse the binary in their own pods without the
     Secret-patch RBAC surface. Cleanest.
   - **3b.** A CronJob that refreshes the Secret every 30 minutes; Argo
     re-reads it on next sync. Lower-fidelity (drift between refresh and
     use, ~1 sync hiccup per rotation).
   - Pick 3a.
   - Why not a git credential.helper? ArgoCD repo-server's HTTPS clones
     use `go-git` (the pure-Go git library), which does not honour
     `credential.helper` from `git config` — file-based credential
     resolution is silently ignored. The Secret-patch path is the only
     credential rotation channel repo-server actually consumes.
4. Front `github.com` with Talon — new Server CR + IngressRoute on
   traefik-public-dmz. Phase B-style cert (per-host SANs).
5. Verify Argo sync still works with Bearer instead of PAT.
6. Verify a sample human curl still works via cookie (browser dance).
7. Measure: token-mint latency (Falcon-ID `/oauth/token` p99), Talon verify
   p99, end-to-end clone duration delta.

**Verification gate:**
- 24h soak with `ArgoCDAppOperationStuckRunning` not firing
- `talon_auth_decision_total{decision="allow",reason="svctoken",route="github.com"}`
  > 0 (and, after Phase 4.5 credential exchange,
  `reason="svctoken_credential_exchange"` increments alongside it)
- Argo's `repo_server_git_request_duration_seconds_p99` not regressing by
  >20%

**Rollback:**
- ArgoCD repoCreds Secret reverted to PAT auth (one MR)
- Talon Server CR / IngressRoute removed (github.com no longer
  Talon-fronted; falls back to direct-to-gitlab path)
- Service token revoked in Falcon-ID

### Phase 4 — Front gitlab/harbor at their existing hostnames

After Phase 3 proves the pattern works for one consumer:

**Steps (parallel, both services):**
1. `github.com` Server CR + IngressRoute on traefik-public-dmz
   — covers Phase 3's earlier work; this stage's contribution is to also
   accept browser traffic (Talon dance for humans).
2. `registry.example.com` same pattern.
3. Issue an `LE` cert covering both names (cert-manager, DNS-01 via CF).
4. Update Falcon-ID OIDC clients (`svc-gitlab`, `svc-harbor`) to add the
   `auth.internal.example.com/auth/callback` redirect URI — Talon dance ends
   on Talon's auth host, then proxies to gitlab/harbor.
5. Verify:
   - human browser at `https://github.com` → Talon → OIDC → GitLab UI
   - human browser at `https://registry.example.com` → Talon → OIDC → Harbor UI
   - `git clone https://github.com/...` with Bearer JWT works
   - `docker pull registry.example.com/...` with Bearer JWT works (NB:
     Docker's bearer-token flow is a separate animal — see Phase 5 quirk)

**Verification gate:** all four flows green; CrowdSec brute-force counters
flat (no spike from publishing the hostnames).

**Rollback:** remove Talon Server CR for the failing service — Traefik
falls back to direct routing.

### Phase 5 — Migrate remaining machine consumers

In rough order of risk/scope:

| Wave | Consumers | Notes |
|---|---|---|
| 5.1 | Renovate, Atlantis, Terraform `gitlab`/`harbor` providers | Each is a single `ServiceClientClaim` + a credential rotation; no code changes in the consumer beyond fetching the JWT |
| 5.2 | image-updater (write-back), 22 Applications' git-repository annotations | Same sidecar pattern as Phase 3.3a |
| 5.3 | CI runners | Each `.gitlab-ci.yml` adds a `id_tokens:` block (GitLab JWT) traded for a Falcon-ID JWT via the RFC 8693 token-exchange path that Falcon-ID already supports |
| 5.4 | kubelet image pulls | **Special case** — kubelet uses Docker registry v2 bearer flow, NOT raw HTTP Bearer. Two options:<br>(a) Keep kubelet on `harbor.monitoring.svc:80` (internal mirror, bypasses Talon entirely) — recommended.<br>(b) Run a node-local proxy that translates kubelet's bearer flow into Talon-aware HTTP — complex, deferred. |
| 5.5 | External CI pushers (Renovate-Docker, occasional ops scripts) | Each gets its own client, narrow scope |

### Phase 6 — Optional: Path Y URL move

Once Phase 4 + 5 are stable, IF there's still a desire to move human
bookmarks to `*.internal.example.com`, the work is now small:

- Add Talon Server CR for `github.com` + `harbor.internal.example.com`
  routing to the same backends
- Update Falcon-ID client redirect URIs
- Update docs / runbooks / alert links
- Old hostnames keep working (Phase 4)
- This is reversible at any point

The original "rename catastrophic" concerns (Go module paths, image refs,
kubelet config, cosign identity) are **all sidestepped** because the old
identifiers stay — only the human browser URL changes.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Falcon-ID token-mint latency adds to every machine request | Medium | Medium | 60-min TTL + Talon jti-cache make this once-per-hour per client. p99 should be <50ms. |
| Talon JWKS-cache miss-storm if Falcon-ID JWKS rotates | Low | High (1-min outage) | Multi-key publish window: Falcon-ID announces new key 24h before activation, Talon picks it up on next refresh. Same pattern as identityjwt today. |
| Bearer middleware misfires on existing cookie traffic | Low | Low | Bearer-first only when header present; absent header → cookie path. No regression for browsers. |
| Scope-vs-path enforcement drifts as new paths land on GitLab | Medium | Medium | Per-host policy table updates via GitOps; new paths default-deny until explicitly mapped. Audit log shows denied attempts. |
| ArgoCD sidecar pattern (Phase 3.3a) is brittle | Medium | Medium | Use a well-tested OIDC token refresher library (e.g. `golang.org/x/oauth2/clientcredentials`); land unit tests; pilot for 1 week before Phase 5. |
| Service-token leak from a compromised consumer | Low | High | Per-consumer rotation policy; short TTL (1h max); audit-log on issuance; per-jti revocation list in Falcon-ID. |

## Decisions (LOCKED 2026-05-28 — tier-1 enterprise baseline)

### D1. Auth mode — **per-Server-CR `authMode`** (DYNAMIC)

Each `Server` CR declares one of: `cookie`, `bearer`, `both`,
`bearer_or_passthrough` (default `cookie` for back-compat). Mirrors
Cloudflare Access per-application auth policy and Pomerium per-route
auth policy.

| Mode | Bearer-valid | Bearer-invalid | No Bearer | Use case |
|---|---|---|---|---|
| `cookie` | ignored | ignored | cookie path | pure browser hosts (grafana.ops, argocd.ops) |
| `bearer` | proxy with claims | 401 | 401 | machine-only hosts (dedicated API, registry endpoint) |
| `both` | proxy with claims | cookie path | cookie path | mixed-traffic hosts that want IAP for browsers + Bearer for machines on same name |
| `bearer_or_passthrough` | proxy with claims | 401 | proxy with original Authorization header (PAT/Basic/native), no OIDC | mixed-traffic hosts where machines use legacy native auth (PAT) and we want to add Bearer additively without breaking existing CI consumers |

**The `bearer_or_passthrough` mode is the enterprise canary unblocker.**
Without it, putting Talon in front of `github.com` with
`authMode=both` would break every existing PAT consumer (Atlantis,
Renovate, image-updater, ArgoCD-today) because they send
`Authorization: Basic` (not `Bearer`) and would get redirected into
the browser OIDC dance which they can't follow. With this mode, the
canary just works: ArgoCD-repo-server sends Bearer → svctoken path;
Atlantis sends Basic PAT → passthrough → GitLab does its native PAT
auth.

**Critical safety property** (defended by `TestDecide_BearerOrPassthrough_BadHeader_Rejected`):
a present-but-broken Bearer in `bearer_or_passthrough` mode does NOT
fall through to passthrough — it 401s. Otherwise an attacker who can
mint a forged Bearer could downgrade to no-auth on permissive
upstreams.

This is the Cloudflare Access / Pomerium / Boundary / Teleport pattern
for single-hostname mixed-protocol IAP — explicitly listed as Pattern C
in ADR 0030's BeyondCorp evolution map.

### D2. Default token TTL — **1h, per-client `iam_oauth_clients.access_token_ttl` override**

1h is the OAuth2 spec norm (RFC 6749 §5.1). Google IAP defaults to 1h;
AWS IAM session tokens default to 1h. Talon jti-cache makes the
Falcon-ID hit rate once-per-hour per client even under heavy request
load. Per-client override allows tightening to 5min for sensitive scopes
or loosening to 24h for low-risk batch consumers.

### D3. Scope namespace — **`talon:<host>:<verb>` hierarchical**

Format spec at "Scope namespace" section above. Talon owns the
verb→method mapping; Falcon-ID enforces scope-membership only.
Hierarchical structure follows RFC 8693 token-exchange best practice;
future path scopes (Phase 5) extend naturally as
`talon:<host>:<verb>:<path-prefix>`.

### D4. Refresh pattern — **sidecar + `golang.org/x/oauth2/clientcredentials`**

Canonical Go OAuth2 client library, used by every major Go cloud SDK.
Sidecar binary writes the token to a shared `emptyDir` volume; consumer
reads via standard file-mount. Same pattern as Vault Agent. Single
implementation reused across every machine consumer (ArgoCD,
image-updater, Atlantis, Renovate, CI runners) via a small base image
(`registry.example.com/svctoken-refresher`). CronJob and ESO
custom-provider options remain available but not the default.

### D5. Scope enforcement — **method-only Phase 1, path-policies Phase 5**

Verb→method mapping (in Talon):
```
GET, HEAD, OPTIONS  → read
POST, PUT, PATCH, DELETE  → write
Docker registry v2 GET /v2/...  → pull
Docker registry v2 PUT|POST|PATCH /v2/...  → push
```

Phase 5 adds path rules per upstream where finer-grained control is
needed (e.g., GitLab `/api/v4/admin/*` requires `talon:gitlab:admin`,
not just `talon:gitlab:write`). Additive, non-breaking.

### D6. DPoP — **Phase 6 (optimal stage)**

Bearer Tier-1 sufficient for Phase 1–5. DPoP (RFC 9449) is the
optimal-stage upgrade. Falcon-ID already supports it; consumers opt in
by declaring DPoP-required scopes in their `ServiceClientClaim`. Phase
6 flips the cluster default to require DPoP for high-sensitivity scopes.

### Additional tier-1 baseline (locked, no further decision needed)

- **JWKS rotation**: 24h advance announcement; Talon picks up new keys on
  next refresh interval (5min). Failed-key retries fall through to
  cookie path, no outage.
- **Signature alg**: RS256 only (RFC 8725 §3.1). Matches existing
  `identityjwt/verifier.go:88`.
- **Clock skew**: 5s tolerance (matches existing pattern).
- **Replay protection**: per-jti LRU cache (10k entries, TTL = token exp).
- **Revocation**: per-jti revocation list in Falcon-ID; Talon pulls
  delta-updates every 60s; emergency-broadcast via CAEP/SSF (Phase 6).
- **Introspection**: RFC 7662 introspection endpoint at Falcon-ID
  (`/oauth/introspect`); optional, used by audit downstream.
- **Continuous re-evaluation**: long-lived proxy connections (WebSocket,
  SSE, git-upload-pack) re-verify token every 60s on a background tick.
- **Rate limiting**: per-client `/oauth/token` rate-limit (Falcon-ID
  existing middleware); per-host inbound rate-limit at Talon
  (Traefik middleware). Defaults: 60 RPS per client for token mint;
  600 RPS per host for bearer requests.
- **Audit emission**: every `client_credentials` mint + every Talon
  bearer-verify (outcome=ok|fail) lands in Loki via the audit funnel.
- **Observability**:
  - Prometheus (Talon, on the registered `prometheus.Registry` —
    talon !65 fix):
    `talon_auth_decision_total{route, decision, reason}` with
    svctoken-relevant reasons `svctoken`, `svctoken_rejected`,
    `svctoken_passthrough`, `svctoken_fallthrough`,
    `svctoken_credential_exchange`, `svctoken_credential_exchange_uncfg`,
    `svctoken_credential_exchange_load`. Refresher sidecar emits
    `svctoken_refresher_refresh_total{outcome}`,
    `svctoken_refresher_secret_patch_total{outcome}`,
    `svctoken_refresher_token_expires_at`,
    `svctoken_refresher_last_refresh_at`.
    Falcon-ID emits
    `falcon_id_oauth_token_issued_total{grant=client_credentials,client}`
  - OTel: span attributes `talon.svctoken.client_id`, `.host`, `.outcome`
- **SPIFFE binding hook**: opt-in via Server CR `bindToSPIFFE: true`;
  Linkerd already mints the SVID; Talon ties token verify to peer SVID
  in mTLS connection. Phase 6 enable.
- **mTLS-bound tokens (RFC 8705)**: complementary to SPIFFE; opt-in via
  client credential type `tls_client_auth`. Phase 6 enable.

## What this enables strategically

This isn't just about gitlab/harbor. Once Talon has machine identity:

- **Single-hostname per service** is the default — Path X / Y / Z become
  branding choices, not technical constraints.
- **Jess and Talon share the same identity model**: Jess workers
  authenticate via the same `client_credentials` flow (`jess-worker-<region>`
  service clients); Jess's L4 brokering benefits from the same JWKS,
  audit, and scope model.
- **CAEP / SSF event push** (the optimal-stage capability in ADR 0030
  Phase 6) lands cleanly: Falcon-ID broadcasts revocation events, Talon
  consumes them mid-session, kicks out the offending Bearer.
- **mTLS-bound tokens (RFC 8705)** is a natural extension: bind the
  service-token JWT to the consumer's SPIFFE SVID. Linkerd already
  mints those.
- **Path-based zero-trust** (per D5) becomes the foundation for fine-
  grained policy as the platform grows.

## References

- RFC 6749 §4.4 (Client Credentials Grant)
- RFC 8707 (Resource Indicators for OAuth 2.0)
- RFC 8725 §3.1 (JWT Best Current Practices — per-host audience binding)
- RFC 9449 (DPoP)
- Cloudflare Access service tokens documentation
- Pomerium service accounts documentation
- BeyondCorp Enterprise — service-token reference architecture
- HexxLock ADR 0030 §"Pattern C"
- internal engineering notes
- internal engineering notes
