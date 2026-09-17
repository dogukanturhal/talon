// SPDX-License-Identifier: AGPL-3.0-or-later

// Package svctoken implements Talon's machine-identity authentication
// channel — RFC 6749 §4.4 client_credentials Bearer tokens minted by
// Falcon-ID, verified by Talon, and accepted alongside the existing
// browser cookie path.
//
// This is the in-bound counterpart to identityjwt (which is the
// out-bound, Talon-mints-for-upstream path). The two packages share
// the same crypto + claims hygiene contracts (RFC 8725 BCP) but
// differ in three ways that justify a separate package rather than a
// shared abstraction:
//
//  1. Issuer — svctoken expects Falcon-ID's JWKS
//     (https://id.hexxlock.com/.well-known/jwks.json), identityjwt
//     expects Talon's own
//     (https://internal.example.com/.well-known/jwks.json).
//  2. Audience — svctoken accepts a per-request audience computed
//     from the HTTP Host header (RFC 8707 resource→aud binding),
//     identityjwt pins one audience at construction.
//  3. Scope — svctoken enforces RFC 6749 §3.3 scope tokens of the
//     form `talon:<host>:<verb>`; identityjwt has no scope concept.
//
// The Tier-1 contract this package upholds (matches Cloudflare Access
// service-tokens, Pomerium service-accounts, Google IAP context-aware
// access):
//
//   - RS256 signature only (RFC 8725 §3.3) — defeats "alg=none" CDA.
//   - iss pinned (RFC 8725 §3.7).
//   - aud pinned to the request's Host header (RFC 8725 §3.1).
//   - exp/nbf enforced with 5s clock tolerance (RFC 7519 §4.1).
//   - jti replay-cache opt-in (RFC 7519 §4.1.7) for defense-in-depth.
//   - JWKS lazy-fetched + 5-min TTL + refresh-on-unknown-kid for
//     transparent rotation.
//   - Scope check is method-first: GET/HEAD/OPTIONS → :read,
//     POST/PUT/PATCH/DELETE → :write, Docker v2 GET → :pull,
//     Docker v2 push → :push. Path-policies are an additive Phase 5
//     extension.
//
// See talon/docs/specs/talon-service-tokens.md for the architectural
// reasoning, decision log, and migration phases.
package svctoken
