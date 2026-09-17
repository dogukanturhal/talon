# Talon

Identity-aware proxy gating internal.example.com via Falcon-ID OIDC.

Pairs with Falcon-ID — Falcon-ID issues the identity, Talon enforces what
that identity can reach. Implements NIST SP 800-207 Zero-Trust Architecture:

- **PEP** — `cmd/talon` reverse proxy
- **PE**  — `internal/policy` evaluator (group filter + SpiceDB CheckPermission)
- **PA**  — OIDC RP machinery + TalonRoute reconciler

Sole IAP for the internal.example.com admin tier. Replaces Pomerium and the
short-lived oauth2-proxy-ops migration; both are decommissioned at Phase 5.

See `docs/architecture/` for the full design.
