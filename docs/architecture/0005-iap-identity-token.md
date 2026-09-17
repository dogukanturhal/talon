# ADR 0005 — Tier-1 Signed Identity Token (`X-Talon-Identity-Token`)

**Status:** Phase A live · Phase B ready · Phase C ready (opt-in)
**Date:** 2026-05-13
**Supersedes:** [ADR 0001 §7.a — unsigned X-Talon-* headers](./0001-pep-design.md) (extends, does not replace)

## Context

Talon is the IAP for `internal.example.com`. Before this ADR, identity was
conveyed to upstream services via unsigned `X-Talon-*` HTTP headers:

```
X-Talon-User: dogukanturhal@example.com
X-Talon-Email: dogukanturhal@example.com
X-Talon-Subject: 5e163cc4-87aa-4c0c-8985-db1134f8b436
X-Talon-Groups: platform_admin,iam_admin
X-Talon-Tenant: 00000000-0000-0000-0000-000000000002
X-Talon-Sso-Chain-Id: tngd5Pq1qG5-gS7HSggrFQ
```

Trust was network-layer: Linkerd `Server` + `AuthorizationPolicy` +
`MeshTLSAuthentication` pin each upstream's inbound to Talon's
ServiceAccount via mTLS. A request that doesn't come from Talon never
reaches the pod, so it can't spoof a header.

The shortcoming: **trust is a property of the network configuration,
not of the bytes that arrive.** A code reviewer reading
`req.headers.get('X-Talon-User')` six months from now has no
cryptographic proof of authenticity. A future namespace recovery that
forgets to re-apply an `AuthorizationPolicy` reopens the spoofing
attack surface silently. Every reference IAP in the industry has moved
beyond this:

| IAP | Signed header | JWKS endpoint pattern |
|---|---|---|
| Google Cloud IAP | `x-goog-iap-jwt-assertion` | `https://www.gstatic.com/iap/verify/public_key-jwk` |
| Cloudflare Access | `Cf-Access-Jwt-Assertion` | `<team>.cloudflareaccess.com/cdn-cgi/access/certs` |
| AWS ALB OIDC | `x-amzn-oidc-data` | `public-keys.auth.elb.<region>.amazonaws.com/<kid>` |
| Pomerium | `X-Pomerium-Jwt-Assertion` | `<authenticate>/.well-known/jwks.json` |

The [Google IAP signed-headers doc](https://docs.cloud.google.com/iap/docs/signed-headers-howto)
states it explicitly:

> If an attacker bypasses IAP, the attacker can forge the IAP unsigned
> identity headers. The IAP JWT provides a more secure alternative.

## Decision

Talon emits an RS256-signed JWT on `X-Talon-Identity-Token` in addition
to the existing unsigned `X-Talon-*` headers. Upstreams that consume
identity (the `@hexxlock/falcon-id-client/nextjs` SDK + any future
stock-OAuth2 service) verify the JWT cryptographically against Talon's
JWKS endpoint at `https://internal.example.com/.well-known/jwks.json`.

### Claims

```json
{
  "iss": "https://internal.example.com",
  "sub": "5e163cc4-87aa-4c0c-8985-db1134f8b436",
  "aud": "internal.example.com",
  "iat": 1715712000,
  "exp": 1715712060,
  "jti": "a3f0c6e2-1d4b-4e8f-9c2a-7e5b9d3f1a02",
  "email": "dogukanturhal@example.com",
  "groups": ["platform_admin", "iam_admin"],
  "tenant_id": "00000000-0000-0000-0000-000000000002",
  "sso_chain_id": "tngd5Pq1qG5-gS7HSggrFQ",
  "sid": "<Talon session cookie UUID>"
}
```

`jti` is a per-mint UUIDv4 (RFC 7519 §4.1.7) — verifiers MAY refuse a
recently-seen jti as defense-in-depth against intercepted-token
replay within the 60s exp window. The Go verifier exposes this as
`VerifierConfig.ReplayCacheSize` (in-memory LRU) or
`VerifierConfig.ReplayCache` (custom backend, e.g. Redis for
cross-pod uniqueness).

Per [RFC 8725 (JWT BCP)](https://datatracker.ietf.org/doc/html/rfc8725):

- **§3.1 audience binding.** `aud` is the per-route public host. A
  JWT minted for `falcon.ops` cannot be replayed against `argocd.ops`
  even if either upstream is partially compromised.
- **§3.3 alg whitelist.** Verifiers accept ONLY `RS256`. Defeats the
  classic `alg=none` confused-deputy attack.
- **§3.7 issuer pinning.** `iss` is verified against the operator-
  supplied expected issuer.
- **`exp = 60s`.** Matches Cloudflare Access's default. JWT is minted
  per request inline at proxy time, so even an intercepted token is
  useless after a minute.

### Signing key

- **RS256, ≥2048-bit** RSA key. Below 2048 bits is rejected at startup
  per NIST SP 800-131A.
- **Dedicated** — separate from Talon's session-encryption AEAD key,
  per NIST SP 800-57 §5.2 ("key usage separation") + OWASP ASVS V6.2.1.
- **Vault-stored** at `example/platform/talon/iap-identity-key#key`.
- **Projected** via ExternalSecret → Secret `talon-iap-identity-key` →
  env `TALON_IAP_SIGNING_KEY_PEM`. The Deployment mounts this `optional:
  true` so a missing Secret doesn't CrashLoop the pod during initial
  provisioning — Talon logs `IAP identity-token signing disabled` and
  proxies with unsigned headers only.
- **`kid`** is derived from SHA-256(SPKI), so the same key produces the
  same `kid` across pod restarts; rotation produces a new `kid`.

### JWKS endpoint

- Published at `/.well-known/jwks.json` on Talon's auth host
  (`internal.example.com`).
- `Content-Type: application/jwk-set+json`.
- `Cache-Control: public, max-age=300` — 5 minutes matches Cloudflare
  Access and Google IAP defaults.
- Verifier libraries (jose's `createRemoteJWKSet`) handle cooldown +
  cache-TTL + parallel-fetch coalescing transparently.

## Trust model

A request flowing through Talon to an admin-tier upstream carries
**two compounding layers of trust:**

1. **Network layer.** Linkerd `AuthorizationPolicy` denies any inbound
   request to the upstream pod that isn't from Talon's
   `ServiceAccount`. Bypassing this requires breaking Linkerd's mTLS.
2. **Cryptographic layer.** Even if (1) is breached, the request must
   still carry an `X-Talon-Identity-Token` signed by Talon's private
   key. Forging this requires breaking RSA-2048 OR exfiltrating the
   key from Vault.

Either layer alone is industry-standard. Both layers together is what
the [zero-trust principle](https://www.nist.gov/publications/zero-trust-architecture)
prescribes.

## Phased rollout

The migration is staged to minimise blast radius:

### Phase A — additive (this commit)

- Talon stamps `X-Talon-Identity-Token` alongside the existing unsigned
  headers.
- SDK verifies the JWT when present, **falls back to unsigned
  `X-Talon-User`** when absent. A partial deploy (e.g. Talon shipped
  before the matching SDK build) cannot break auth.
- Soak 24-48 hours. Watch Loki for `auth_source=talon_iap_jwt` on
  ≥99% of `/api/auth/me` responses.

### Phase B — enforce (separate MR, after Phase A soaks)

- SDK removes the unsigned-header fallback for verifier-configured
  apps. Any request without a verified JWT bounces to login.
- Closes the network-layer-only attack surface.
- Talon is unchanged.

### Phase C — Authorization: Bearer (opt-in, this commit)

- Per-route `TalonRoute.spec.injectAuthorizationBearer: true` makes
  Talon ALSO stamp `Authorization: Bearer <jwt>`.
- For upstreams that consume stock OAuth2 / OIDC middleware (Grafana
  `auth.jwt`, Argo CD `accounts.<name>.enabled: apiKey`, generic Go
  services using `github.com/coreos/go-oidc`).
- Off by default — Authorization is owned by the upstream when this
  flag is unset. When set, inbound Authorization is stripped before
  authoritative injection, preventing client-supplied Bearer spoofing.
- Cloudflare Access and Pomerium follow the same pattern (opt-in).

### Fail-closed minting — `RequireSignedIdentityToken` (opt-in, ASVS 5.0 V9)

Phases A–C leave enforcement of the *signed* token entirely to the
upstream SDK: if Talon's own `Signer.Sign()` fails, `injectSignedIdentity
Token` logs it and **proxies anyway** with the unsigned `X-Talon-*`
fallback (fail open). That is correct during the transition — an
unmigrated downstream still depends on those unsigned headers — but it
means a Talon-side mint failure silently downgrades a request instead of
being enforceable at the PEP. ASVS 5.0 V9 requires that signed-identity
minting be *able* to fail closed.

The knob (default **false** everywhere, so nothing breaks unattended):

- **Per route:** `TalonRoute.spec.requireSignedIdentityToken: true`
  (v1beta1: `spec.defaultPolicy.requireSignedIdentityToken`). When set, a
  request whose signed token cannot be minted — `Sign()` error *or* an
  unwired signer — is denied `503 Service Unavailable` instead of
  proxying unsigned.
- **Fleet-wide floor:** `TALON_REQUIRE_SIGNED_IDENTITY_TOKEN=true`. Applies
  to every route (including the static `TALON_PROTECTED_HOSTS_JSON`
  break-glass routes that carry no per-route knob).
- **Composition:** effective = `global OR per-route`. A route can only
  *tighten*; it can never drop below the global floor. This is the secure
  direction — enabling either turns fail-closed on, and neither can turn
  the other off.

**Migration path.** Keep the default (fail open) while downstreams still
read unsigned headers. Every fail-open fallback now emits a WARN audit
`iap.token.mint_failed` (`reason=fail_open_unsigned_fallback`) — watch its
rate per route to see how often minting fails and to confirm a downstream
is ready. As each downstream ships its SDK verifier (Phase B), flip that
route's `requireSignedIdentityToken: true`. Once the **last** downstream
is verifying, trip the global `TALON_REQUIRE_SIGNED_IDENTITY_TOKEN=true`
floor. Fail-closed denials emit WARN audit `iap.token.mint_denied` and
surface as `503`s in `talon_request_total`.

## Operational

### First-time provisioning

```bash
# 1. Generate the dedicated signing key (RS256, ≥2048-bit)
openssl genrsa 2048 > /tmp/talon-iap.pem

# 2. Write to Vault
vault kv put example/platform/talon/iap-identity-key key=@/tmp/talon-iap.pem

# 3. Wipe local copy
shred -u /tmp/talon-iap.pem

# 4. Verify JWKS endpoint responds within ~30s of Talon pod start
curl -s https://internal.example.com/.well-known/jwks.json | jq '.keys[0] | {kid, alg, use}'
# Expected: {"kid": "<base64url>", "alg": "RS256", "use": "sig"}
```

### Key rotation (zero-downtime, N+1 overlap)

Multi-key JWKS publication lets Talon roll the active signing key
without any verifier seeing an unrecognised-kid window. Matches
Cloudflare Access's N+1 pattern and Google IAP's daily-rotation model
(multiple kids concurrently valid).

1. **Copy the old key aside** in Vault before generating the new one:
   ```
   vault kv get -field=key example/platform/talon/iap-identity-key \
     | vault kv patch example/platform/talon/iap-identity-key key_previous=-
   ```
2. **Write the NEW key** to the `key` field (overwrites the old):
   ```
   openssl genrsa 2048 > /tmp/talon-iap-new.pem
   vault kv patch example/platform/talon/iap-identity-key key=@/tmp/talon-iap-new.pem
   shred -u /tmp/talon-iap-new.pem
   ```
3. **Force-refresh ExternalSecret** (refreshInterval is 1h):
   ```
   kubectl -n talon annotate externalsecret talon-iap-identity-key \
     force-sync=$(date +%s) --overwrite
   ```
4. **Roll Talon**: `kubectl -n talon rollout restart deploy/talon-talon`.
   Talon's `TALON_IAP_SIGNING_KEY_PEM` reads the new active key;
   `TALON_IAP_PREVIOUS_SIGNING_KEY_PEM` reads `key_previous`. The
   JWKS endpoint now publishes BOTH `kid`s; verifiers accept JWTs
   signed by either during the overlap.
5. **Wait the overlap window**: 60s JWT lifetime + 300s JWKS cache TTL
   ≈ 6 minutes. Past that, no outstanding JWT signed by the old key
   can possibly be in flight.
6. **Drop the previous key** from Vault:
   ```
   vault kv patch example/platform/talon/iap-identity-key key_previous=""
   kubectl -n talon annotate externalsecret talon-iap-identity-key \
     force-sync=$(date +%s) --overwrite
   kubectl -n talon rollout restart deploy/talon-talon
   ```
7. JWKS now publishes only the new kid; rotation complete.

For an emergency rotation (suspected key compromise) skip step 1 and
do steps 2-4 immediately — verifiers re-fetch JWKS within 30s
(jose's `cooldownDuration` default) and any JWT still in flight from
the compromised key is unverifiable.

### Observability

**Audit events** (subsystem=audit, persisted 7 years per Tier-1 WORM
target):

| Event | Source | When |
|---|---|---|
| `iap.token.mint_failed` (**WARN**) | Talon proxy.injectSignedIdentityToken | Signer.Sign() returns a non-nil error (rare; signals key misload or corrupt session blob). Fires on every mint failure, fail-open OR fail-closed; `reason` distinguishes `fail_open_unsigned_fallback` vs `fail_closed_denied`. On a fail-open route this is the migration-driving signal (each occurrence = a request that fell back to unsigned headers). Fields: `iap_kid`, `iap_audience`, `sub`, `email`, `tenant_id`, `session_id`, `sso_chain_id`, `reason`, `err`. |
| `iap.token.mint_denied` (**WARN**) | Talon proxy.injectSignedIdentityToken | Fail-closed enforcement: route has `requireSignedIdentityToken` (or the global floor) enabled and the signed token could not be minted, so the request was denied `503`. `reason=signer_not_wired` when no signer is loaded, else carries the propagated `Sign()` error. Fields: same as above plus `decision=deny`. |

**Verifier-side telemetry** (SDK, console.log → Loki):

| Event | Source | Routing |
|---|---|---|
| `iap.verify.no_token` | iap-jwt-verifier | stdout |
| `iap.verify.failed` (+ `iap_reason`: `signature_failed` / `expired` / `issuer_mismatch` / `audience_mismatch` / `not_yet_valid` / `alg_not_allowed` / `jwt_invalid` / `unknown`) | iap-jwt-verifier | stdout |
| `iap.verify.malformed_claim` | iap-jwt-verifier | stdout |
| `iap.verify.jwks_unavailable` | iap-jwt-verifier (non-JOSEError, e.g. DNS / AuthorizationPolicy) | **stderr** |
| `iap.verifier.init_failed` | middleware / handleMe construction | **stderr** |
| `iap.prefetch.success` | createTalonIapVerifier (background warm-up) | stdout |
| `iap.prefetch.retry` | createTalonIapVerifier (transient warm-up failure) | stdout |
| `iap.prefetch.gave_up` | createTalonIapVerifier (warm-up exhausted retries) | **stderr** |

**Prometheus metrics** (Talon `/metrics`):

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `talon_iap_token_sign_total` | counter | `route`, `result` (success/fail), `kid` | per-route mint volume + failure rate. Correlate `result=fail` count with `iap.token.mint_failed` audit events. |
| `talon_iap_jwks_request_total` | counter | `result` (success/unconfigured/error) | sustained `unconfigured` = Vault→ESO→Secret pipeline broken. |
| `talon_iap_active_kid` | gauge (constant 1) | `kid` | "what kid is signing right now" — dashboards select `kid` directly. |
| `talon_iap_retired_kids_published` | gauge | — | non-zero only during the rotation overlap window. Alert if non-zero for > 6 min. |

Recommended PromQL recording rules + alerts:

```promql
# Sign failure rate per route (alert if > 1% for 5m)
sum by (route) (rate(talon_iap_token_sign_total{result="fail"}[5m]))
  /
sum by (route) (rate(talon_iap_token_sign_total[5m]))

# JWKS unconfigured (Vault pipeline broken)
talon_iap_jwks_request_total{result="unconfigured"} > 0

# Rotation overlap window stuck open (operator forgot step 6)
talon_iap_retired_kids_published > 0
  and on() (time() - max(timestamp(talon_iap_retired_kids_published)) > 600)
```

### Failure modes + recovery

| Symptom | Cause | Recovery |
|---|---|---|
| Talon logs `IAP identity-token signing disabled (TALON_IAP_SIGNING_KEY_PEM empty)` | Vault path empty OR ESO degraded | Provision Vault key (above); ESO refresh on 1h tick OR force-sync annotation. |
| Talon logs `IAP identity-token signer init failed` | Malformed PEM in Vault | Fix Vault, force-refresh ESO. Talon proxies with unsigned-only until fixed (Phase A fallback). |
| Talon `/readyz` returns 503 with `iap signer unhealthy: …` (pod pulled from Service rotation; kube-proxy 503s upstream) | Signer loaded but synthetic mint+verify roundtrip fails (corrupted key, runtime jose anomaly) | Triage signer state. Check `talon_iap_token_sign_total{result="fail"}` and the `iap.token.mint_failed` audit stream for the failure category. Typically resolved by rolling the pod onto a fresh signer load from Vault. |
| SDK logs `/api/auth/me Talon IAP JWT verify raised` | Talon's JWKS endpoint unreachable (Talon down, DNS, AuthorizationPolicy mis-applied) | Triage Talon; Phase A SDK falls back to unsigned, Phase B SDK fails closed (401). |
| Upstream sees `Authorization: Bearer` from an unfamiliar token | Phase C accidentally enabled for a route whose upstream consumes Authorization for its own purposes | Set `TalonRoute.spec.injectAuthorizationBearer: false` (default), reconcile takes effect within ~5s. |

## Upstream verifier SDKs

Verifying the IAP JWT in the upstream service closes Phase B for the
platform. Two reference implementations:

**TypeScript / Next.js** — `@hexxlock/falcon-id-client/nextjs`:

```ts
import { createTalonIapVerifier } from '@hexxlock/falcon-id-client/nextjs'

const verifier = createTalonIapVerifier({
  jwksUrl: 'https://internal.example.com/.well-known/jwks.json',
  expectedIssuer: 'https://internal.example.com',
  expectedAudience: 'internal.example.com',
})
const claims = await verifier.verifyRequest(request)  // claims | null
```

**Go** — `github.com/dogukanturhal/talon/internal/identityjwt` (re-export
target after the next public module cut). Three usage tiers:

*Low-level — direct verifier calls* (for services that need custom
failure-mode handling):

```go
v, err := identityjwt.NewVerifier(identityjwt.VerifierConfig{
    JWKSURL:          "https://internal.example.com/.well-known/jwks.json",
    ExpectedIssuer:   "https://internal.example.com",
    ExpectedAudience: "registry.example.com",
})
if err != nil { /* config defect */ }

claims, err := v.VerifyRequest(r)  // *IdentityClaims, error
switch {
case errors.Is(err, identityjwt.ErrNoToken):
    // header absent — fall back / 401 per phase
case errors.Is(err, identityjwt.ErrAudienceMismatch),
     errors.Is(err, identityjwt.ErrIssuerMismatch),
     errors.Is(err, identityjwt.ErrSignatureInvalid):
    // security-relevant reject — 401 + audit
case errors.Is(err, identityjwt.ErrTokenExpired):
    // expected after 60s — 401
case errors.Is(err, identityjwt.ErrJWKSUnavailable):
    // ops issue — fail closed per Phase B
}
```

*Replay protection (opt-in defense-in-depth)*:

```go
v, _ := identityjwt.NewVerifier(identityjwt.VerifierConfig{
    JWKSURL:          "...",
    ExpectedIssuer:   "...",
    ExpectedAudience: "...",
    ReplayCacheSize:  8192, // per-process LRU keyed by jti
})
// claims, err := v.VerifyRequest(r)
// errors.Is(err, identityjwt.ErrReplay) → token already seen within TTL
```

Per-process. For multi-pod upstreams that need cross-pod replay
protection, wire a shared backend via the ReplayCache interface
(Redis SET NX EX is the canonical implementation). The 60s exp
window is the primary defense regardless — the cache is layered on
top, not a replacement.

*Drop-in middleware — one-line mount* for any service using net/http
or a router that accepts an `http.Handler` middleware chain (chi,
gorilla/mux, gin via http.Handler adapter, etc.):

```go
mux := http.NewServeMux()
mux.Handle("/api/", identityjwt.Middleware(v)(apiHandler))

// downstream handler reads the verified identity from context:
func apiHandler(w http.ResponseWriter, r *http.Request) {
    claims := identityjwt.ClaimsFromContext(r.Context())
    // claims.Subject, claims.Email, claims.Groups, …
}
```

The middleware default policy is Phase B fail-closed: missing or
invalid tokens get a JSON 401 with a stable code field:

```json
{"error": "Not authenticated", "code": "iap_token_missing"}
{"error": "Identity token invalid", "code": "iap_token_invalid", "reason": "audience_mismatch"}
{"error": "Identity verification temporarily unavailable", "code": "iap_jwks_unavailable"}
```

`code` is the high-level discriminator (matches the SDK's logIapEvent
taxonomy) and `reason` narrows the iap_token_invalid case using the
same enum as the TypeScript verifier: `signature_failed`, `expired`,
`not_yet_valid`, `issuer_mismatch`, `audience_mismatch`,
`alg_not_allowed`, `jwt_invalid`, `unknown`.

Operators can opt out of fail-closed by passing
`MiddlewareOptions{AllowMissing: true}` (Phase A backwards-compat)
or supply a custom `OnUnverified` callback to render HTML, plumb a
correlation header, or log additional context.

Both verifiers share:

- RS256-only algorithm whitelist (RFC 8725 §3.3)
- Audience binding pinned at construction (§3.1)
- Issuer pinning (§3.7)
- 5-second clock tolerance
- 5-minute JWKS cache TTL
- Refresh-on-unknown-kid (rotation overlap handled transparently)
- Failure-reason taxonomy that joins across both verifiers via
  `iap_kid` correlation (Go side: `*identityjwt.Verifier`; TS side:
  `logIapEvent` taxonomy)

## References

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 — JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7638 — JWK Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Google Cloud IAP — Signed Headers](https://docs.cloud.google.com/iap/docs/signed-headers-howto)
- [Cloudflare Access — Authorization](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/)
- [AWS ALB — User Claims Encoding](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- [Pomerium — Signed JWT](https://www.pomerium.com/docs/topics/getting-users-identity)
- [NIST SP 800-131A — Key Length Recommendations](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [NIST SP 800-57 §5.2 — Key Usage Separation](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP ASVS V6.2 — Cryptographic Key Management](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST — Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
