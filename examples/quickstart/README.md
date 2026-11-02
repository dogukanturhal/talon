# Quickstart: Talon with Docker Compose

Runs Talon in front of `traefik/whoami` with real session, SpiceDB and OIDC
code paths, on one machine, with no Kubernetes. Demo credentials only.

```sh
docker compose up --build
```

First start builds the Talon image from the repository `Dockerfile`, which
takes a few minutes. Talon restarts itself until the OIDC provider and SpiceDB
are up; a few `restart` lines in the first seconds are normal.

Requirements: Docker with Compose v2, outbound access to pull the images, and
host port 443 free. On rootless Docker, allow low ports first
(`sudo sysctl net.ipv4.ip_unprivileged_port_start=443`) or change the
`443:8443` mapping and put a TLS-forwarding proxy in front, because Talon only
recognises its auth host when the Host header carries no port.

## What runs

| Service | Image | Role |
|---|---|---|
| `talon` | built from `../../Dockerfile` | the proxy, on `https://*.demo.localtest.me` |
| `oidc` | `ghcr.io/navikt/mock-oauth2-server` | stand-in identity provider on `http://oidc.localtest.me:8080` |
| `spicedb` | `authzed/spicedb` | authorization, in-memory, preloaded from `spicedb-bootstrap.yaml` |
| `redis` | `redis` | session storage |
| `whoami` | `traefik/whoami` | the protected app; echoes request headers |
| `certs` | `alpine/openssl` | one-shot job that writes a self-signed certificate |
| `zed` | `authzed/zed` | optional SpiceDB CLI (`--profile tools`) |

`*.localtest.me` resolves to 127.0.0.1 in public DNS. If you are offline, add
`oidc.localtest.me`, `auth.demo.localtest.me` and `whoami.demo.localtest.me`
to `/etc/hosts` pointing at 127.0.0.1.

## Try it

1. Browse to <https://whoami.demo.localtest.me/>. Accept the certificate
   warning, and again for `auth.demo.localtest.me` when you are redirected.
2. On the mock login page enter username `alice` (the field labelled for
   claims can stay empty). You should see the whoami output including
   `X-Talon-Subject: alice`.
3. In a private window sign in as `bob`. You get `403`. Bob authenticated
   fine, but SpiceDB holds no relationship for him:

   ```
   talon_route:whoami_demo_localtest_me#viewer@user:alice
   ```

   That one line in `spicedb-bootstrap.yaml` is the whole policy. The object
   id is the route host with dots replaced by underscores.
4. Add bob and reload (allow a few seconds for the decision cache):

   ```sh
   docker compose run --rm zed relationship create \
     talon_route:whoami_demo_localtest_me viewer user:bob \
     --endpoint spicedb:50051 --token demo-preshared-key --no-verify-ca
   ```

SpiceDB uses the in-memory datastore, so relationships added this way are gone
after `docker compose down`.

## Settings worth knowing

- `TALON_PROTECTED_HOSTS_JSON` replaces `TalonRoute` resources here. The
  upstream must be written as `service.namespace[:port]`, so `whoami` gets the
  network alias `whoami.demo`.
- `TALON_REQUIRED_ROLE` is still checked at sign-in against the `groups` or
  `roles` claim. `mock-oidc.json` adds `groups: ["demo-user"]` to every token.
  With `TALON_ROLE_GATE_MODE=off`, SpiceDB alone decides each request after
  that.
- `TALON_OIDC_SCOPES` drops `roles` from the default list, which not every
  provider recognises.
- The issuer URL is the same inside and outside the containers (the `oidc`
  service has the alias `oidc.localtest.me`), because Talon checks the `iss`
  claim against it.

## If something fails

- **Talon exits repeatedly.** `docker compose logs talon`. Usually the OIDC
  provider or SpiceDB was not ready yet, or the SpiceDB schema was not
  accepted.
- **403 for everyone, "required group missing" in the Talon log.** The mock
  provider did not add the `groups` claim. On the login page put
  `{"groups":["demo-user"]}` in the optional claims box.
- **Browser cannot resolve `localtest.me`.** See the `/etc/hosts` note above.
- **Port 443 in use.** Stop the other listener; see the rootless note above.

Clean up with `docker compose down -v`.

This setup is for trying Talon out. It uses a fixed cookie key, a fixed
SpiceDB key, a self-signed certificate and an identity provider that accepts any
password. Do not reuse any of it.
