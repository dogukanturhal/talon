# iap-upstream-go — reference Go service behind Talon

Minimal but production-shaped Go HTTP service that adopts cryptographic
Talon IAP trust via the `identityjwt` middleware. Copy this directory
as the starting point for any new Go service that sits behind Talon.

## What you get

- **`/api/*`** — protected by `identityjwt.Middleware(verifier)`. Every
  request must carry a valid `X-Talon-Identity-Token` JWT signed by
  Talon. Missing / invalid tokens return a JSON 401 with the stable
  `code` / `reason` taxonomy.
- **`/api/whoami`** — demonstrates `ClaimsFromContext(r.Context())`,
  the canonical way to read the verified identity inside a handler.
- **`/api/echo`** — demonstrates RBAC inside the handler (gates POST
  on `platform_admin` group). Middleware handles authentication;
  authorization decisions stay in your service.
- **`/readyz`** — fails 503 when Talon's JWKS endpoint is unreachable.
  Kube-proxy pulls the pod from rotation so callers get a clean 503
  instead of cascading 401s with no health signal.
- **`/healthz`** — always 200. Kubelet must never RESTART the pod on
  IAP misconfig; readiness is the right signal.

## Run locally against the production Talon

```bash
TALON_JWKS_URL='https://internal.example.com/.well-known/jwks.json' \
TALON_EXPECTED_ISSUER='https://internal.example.com' \
TALON_EXPECTED_AUDIENCE='internal.example.com' \
LISTEN_ADDR=':8080' \
go run .
```

Then mint a test token (see `internal/identityjwt/signer_test.go` for
the pattern) and call:

```bash
curl -H 'X-Talon-Identity-Token: <jwt>' http://localhost:8080/api/whoami
```

## Tests

`integration_test.go` spins up a Talon-side signer + JWKS server + the
example handler chain in-process and exercises the full
mint → JWKS-serve → middleware-verify → handler path:

```bash
go test ./examples/iap-upstream-go/...
```

The tests live alongside the example so developers copying the pattern
get the integration-test pattern too. Six tests cover:

| Test | What it proves |
|---|---|
| `Healthz_AlwaysOK` | Liveness is decoupled from IAP state |
| `Readyz_OKWhenJWKSReachable` | Readiness reflects real JWKS health |
| `API_RejectsUnauthed` | Default fail-closed posture (Phase B) |
| `API_WhoamiSurfacesClaims` | `ClaimsFromContext` returns the verified payload (sub, email, jti, …) |
| `API_GroupGatingEnforced` | Middleware passes the claims through; in-handler RBAC works |
| `API_RejectsWrongAudience` | RFC 8725 §3.1 audience binding enforced; reason narrows to `audience_mismatch` |

## Production deploy checklist

1. **TalonRoute** pointing at your service's ClusterIP. The `host`
   field on the TalonRoute MUST match the `TALON_EXPECTED_AUDIENCE`
   you configure — that's how Talon stamps the `aud` claim on the
   JWT.
2. **Linkerd AuthorizationPolicy + MeshTLSAuthentication** so only
   Talon's ServiceAccount can reach the upstream Service. Defense-
   in-depth — IAP JWT is the cryptographic layer; Linkerd is the
   network layer. Tier-1 means both.
3. **Readiness probe** at `/readyz`. The default `httpGet.path` in
   most charts is `/healthz`; flip it to `/readyz` so a JWKS outage
   pulls the pod from rotation.
4. **Liveness probe** at `/healthz` (default). Kubelet must never
   restart the pod on IAP misconfig.
5. **Replay protection** (optional). Uncomment `ReplayCacheSize:
   8192` in `main.go` to enable per-process LRU. For multi-pod
   uniqueness, wire `ReplayCache` to Redis (`SET NX EX`).

## Trust model + claim schema

See `docs/architecture/0005-iap-identity-token.md` for the full
threat model, claim shape, key rotation runbook, and observability
contract.
