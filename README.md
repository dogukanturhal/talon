# Talon

[![CI](https://github.com/dogukanturhal/talon/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/talon/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/talon.svg)](https://pkg.go.dev/github.com/dogukanturhal/talon)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dogukanturhal/talon/badge)](https://securityscorecards.dev/viewer/?uri=github.com/dogukanturhal/talon)

An identity-aware reverse proxy that signs users in through OIDC and decides
per request, with SpiceDB relationships, whether they may reach an internal
app.

## Who it is for

Teams that run internal tools (dashboards, admin UIs, CI, registries) behind
Kubernetes and want one place that handles login, authorization and audit
instead of each app doing it differently. It is built around NIST SP 800-207:
Talon is the policy enforcement point (PEP), `internal/policy` is the policy
engine (PE), and the OIDC relying party plus the TalonRoute reconciler are the
policy administrator (PA).

It runs in production in front of the author's own internal tier. It has not
been through a third-party audit and it is pre-1.0 (see
[Status and limitations](#status-and-limitations)).

## Features

Each item below exists in this repository. Paths point at the code.

- **OIDC relying party.** Authorization code flow with PKCE and, when the
  provider advertises it, pushed authorization requests. Sessions are an opaque
  cookie id; the session blob lives in Redis, AES-GCM encrypted
  (`internal/oidc`, `internal/session`).
- **Route policy as Kubernetes resources.** `TalonRoute` (`v1alpha1`, `v1beta1`
  with a conversion webhook) declares host, upstream, allowed groups and
  subjects, MFA/ACR requirements, session TTLs, per-path rules and public
  paths (`api/`, `internal/controller`, `deploy/helm/talon/crds`).
- **Relationship-based authorization.** Each request is checked against
  SpiceDB (`talon_route#access`), with a short-lived cache and a signed
  offline decision window for SpiceDB outages (`internal/spicedb`).
- **Rego policy.** An optional global baseline and a per-route Rego module can
  deny a request after the SpiceDB check (`internal/policy`,
  `docs/policy/ztna`).
- **Device posture.** Verifies signed device-posture assertions and optional
  device-certificate identity forwarded by Envoy; `posture-signer` is a small
  service that issues the assertions (`internal/posture`,
  `internal/posturesigner`, `internal/devicemtls`). The signer uses Vault
  Transit.
- **Continuous verification.** A leader-elected loop refreshes each session's
  tokens at the IdP and drops sessions whose token was revoked or whose role
  was lost (`internal/cv`). CAEP security event tokens and OIDC back-channel
  logout can end sessions immediately (`internal/caep`, `internal/handlers`).
- **Identity for upstreams.** Talon forwards `X-Talon-*` headers and can mint a
  short-lived signed identity JWT (JWKS at `/.well-known/jwks.json` on the auth
  host) so an upstream can verify who is calling without trusting headers
  (`internal/identityjwt`; a Go example is in `examples/iap-upstream-go`).
- **Other ways to ask Talon for a decision.** An HTTP forward-auth endpoint
  (`/auth/verify`) and an Envoy `ext_authz` gRPC server
  (`TALON_LISTEN_EXTAUTHZ`) share the same decision code (`internal/extauthz`).
- **Machine clients.** Bearer service tokens with optional DPoP binding for
  non-browser callers (`internal/svctoken`, `internal/dpop`), and `talonctl`, a
  loopback-PKCE CLI login that mints host-scoped tokens (`cmd/talonctl`).
- **Browser access to non-HTTP targets.** `access-broker` bridges SSH, kubectl,
  RDP and SQL sessions into a browser terminal behind the same checks
  (`cmd/access-broker`, `internal/accessbroker`). It needs a backend that issues
  short-lived credentials and is not usable standalone.
- **Audit.** One JSON line per decision on stdout, hash-chained, with
  `audit-replay` to turn logs into CSV or a per-session timeline and
  `talon evidence` for control-mapped exports (`internal/audit`,
  `cmd/audit-replay`, `docs/compliance`).

## Quickstart (about five minutes)

You need Docker with Compose v2 and a free port 443. No Kubernetes is
involved: the demo uses Talon's static route list instead of `TalonRoute`
resources.

```sh
git clone https://github.com/dogukanturhal/talon
cd talon/examples/quickstart
docker compose up --build
```

This starts Talon, Redis, SpiceDB (in-memory, with a schema and one
relationship preloaded), a mock OIDC provider, and `traefik/whoami` as the
protected app. When the logs settle:

1. Open <https://whoami.demo.localtest.me/> and accept the self-signed
   certificate warning (do the same once for `auth.demo.localtest.me`).
2. You are redirected to the mock IdP. Sign in as `alice`, any password.
   You land on the whoami page with the `X-Talon-*` headers Talon added.
3. Open a private window and sign in as `bob`. Sign-in works, but Talon answers
   `403`: SpiceDB has no relationship between `bob` and the route.
4. Give bob access and reload:

   ```sh
   docker compose run --rm zed relationship create \
     talon_route:whoami_demo_localtest_me viewer user:bob \
     --endpoint spicedb:50051 --token demo-preshared-key --no-verify-ca
   ```

   (Decisions are cached briefly, so allow a few seconds.)

[`examples/quickstart/README.md`](examples/quickstart/README.md) explains each
setting and what to do when a step fails. For Kubernetes, `deploy/helm/talon`
is the chart used by the author; see the limitations below before relying on
it.

## How it compares

These tools overlap with Talon but are aimed at different setups.

- **Pomerium** is the closest match: an identity-aware proxy with its own
  policy language, a console, and a much larger feature set and user base.
  Talon's differences are that authorization is a SpiceDB relationship check
  rather than policy in the proxy's config, and that routes are Kubernetes
  custom resources. If you do not already run SpiceDB, Pomerium is the simpler
  choice.
- **oauth2-proxy** authenticates users against an OIDC provider and passes
  identity upstream, usually with allow-lists of emails or groups. It is small
  and widely deployed. It has no per-route relationship checks, device posture
  or continuous verification.
- **Cloudflare Access** is a hosted service with its own network and device
  agent. Talon is self-hosted and does not ship a device agent; it consumes
  posture assertions produced elsewhere.
- **Authelia** is a self-hosted sign-on portal with a local user store, 2FA
  and forward-auth for nginx, Traefik or Envoy. Talon does not store users or
  credentials; it relies on an external OIDC provider.

## Architecture

```
                         +----------------+
   browser / CLI ------> |     Talon      | ---- OIDC code flow + PKCE ----> OIDC provider
   (cookie or bearer)    |   (PEP + PE)   |
                         |                | ---- sessions -----------------> Redis
                         |                | ---- CheckPermission -----------> SpiceDB
                         |                | ---- Rego (optional) -----------> in-process
                         +-------+--------+
                                 |  X-Talon-* headers, optional signed identity JWT
                                 v
                           upstream app

   TalonRoute resources --> controller (PA) --> route table + SpiceDB relationships
   Envoy / other proxies --> ext_authz gRPC or /auth/verify --> same decision code
   posture-signer --> signed posture assertions --> Talon (optional)
```

Design records are in [`docs/architecture`](docs/architecture), starting with
`0001-overview.md`.

## Status and limitations

- **Pre-1.0.** No stable release has been cut, and the configuration surface
  (environment variables, chart values) can still change. The TalonRoute API is
  `v1alpha1`/`v1beta1`.
- **Single-author, single-environment history.** The code was written for one
  deployment: Kubernetes with Linkerd, Traefik or Envoy Gateway, cert-manager
  and External Secrets, plus the author's own OIDC provider (Falcon-ID). Other
  OIDC providers should work but the code has only been exercised against
  that one; the quickstart uses a mock provider.
- **The Helm chart reflects that environment.** It assumes those components and
  is a starting point, not a general-purpose chart.
- **Redis is required** for sessions. SpiceDB is optional in code (without it,
  only the group check applies), but you give up the main feature.
- **Static route mode is limited.** `TALON_PROTECTED_HOSTS_JSON` accepts only
  upstreams in Kubernetes service form (`name.namespace[:port]`); the demo works
  around this with a network alias. Continuous verification needs the
  controller and its leader election, so it is off in the quickstart.
- **Hosts must be served on the standard port.** The auth host is matched on
  the Host header without a port, so Talon has to be reachable on 443.
- **Some features need services not in this repository:** the posture signer
  needs Vault Transit, and the access broker needs a credential-issuing
  backend.
- **Some docs under `docs/` are design notes** written for the original
  environment; hostnames in them are placeholders.
- **No independent security audit.** See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off.
Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
