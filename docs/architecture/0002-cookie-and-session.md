# ADR 0002 — Cookie attributes, session blob encoding, key rotation

- **Status:** Accepted (locked 2026-04-26)
- **Date:** 2026-04-26
- **Deciders:** dogukanturhal
- **Supersedes:** N/A
- **Refines:** ADR 0001 §5.c (high-level cookie + session table)
- **Related:** ADR 0003 (planned, TalonRoute CRD)

---

## 1. Status

Accepted. ADR 0001 §5.c locked the cookie attribute set and the "opaque
ID, server state in Redis, AES-GCM blob" shape; this ADR fixes the
remaining details a `cmd/talon` implementation needs in order to be
unambiguous: byte layouts, JSON shape, nonce policy, key rotation, Redis
keyspace, sliding refresh, logout/revoke. The §3.x sub-numbering in this
document is stable; refinements come via a superseding ADR.

## 2. Context

The on-disk session encoding is a foot-gun if left unspecified: missing
nonce, AAD on the wrong field, lost-update race on sliding refresh, or a
key-rotation procedure that doesn't actually rotate. The Falcon-ID team
has been bitten by RFC 6265 §5.3.6 (`Domain=` rejection) and
`Set-Cookie` write-site splits already this quarter
so the same class of bug
should not recur in Talon. This ADR is the contract a reviewer holds
`internal/session/` against.

## 3. Cookie wire format

### 3.1 Attribute set (re-stated from ADR 0001 §5.c, byte-exact)

A correctly-emitted Talon session cookie on the wire reads:

```
Set-Cookie: talon_session=<UUIDv4>; Domain=.internal.example.com; Path=/; Expires=<RFC1123>; Max-Age=28800; HttpOnly; Secure; SameSite=Lax
```

| Token | Value | Why this exact value |
|-------|-------|----------------------|
| Cookie name | `talon_session` | Distinct from `_pomerium_*`, `_oauth2_proxy*`, `falcon_idp_session`. Single-cookie design (no `_csrf` sibling) — CSRF is handled inside the encrypted blob. |
| Cookie value | UUIDv4 hex with dashes (36 ASCII chars) | Opaque to client; lookup key into Redis. UUIDv4 is sufficient (122-bit randomness; collision probability over 1 year × 10⁶ admins is < 2⁻⁴⁰ per the birthday bound). No JWT, no signed value — the cookie is *only* an ID. |
| `Domain=` | `.internal.example.com` (with leading dot) | Per RFC 6265 §5.3.6: domain must be a suffix of the host that issued the cookie. Talon issues from `auth.internal.example.com`; `.internal.example.com` is a valid suffix and shares with all sibling admin hosts. **Must not** be `.example.com` (would also match the customer tier — privilege spillover) and **must not** be a cluster-internal hostname (browsers reject). |
| `Path=` | `/` | Cookie must accompany every admin-tier request. |
| `Expires=` + `Max-Age=` | both, set to creation time + 8 h (28800 s) | Both attributes for compatibility (Expires for HTTP/1.0-ish behaviour; Max-Age preferred per RFC 6265 §5.2.1). Sliding refresh updates *both* on every successful request — see §5.3. |
| `HttpOnly` | present | Mitigates XSS-driven session theft from upstream apps that may render user-controlled HTML (Grafana annotations, Argo CD app names, etc.). |
| `Secure` | present | TLS-only. Talon never serves on cleartext HTTP — :8080 redirects to :8443. |
| `SameSite=Lax` | present | Required: `Strict` would break the Falcon-ID OIDC redirect-back (the cookie is set inside a cross-origin 302 callback and a `Strict` cookie isn't sent on the subsequent navigation to the original host within 2 minutes — Lax handles this case correctly per RFC 6265bis §5.5). `Lax` is also sufficient CSRF protection here; the encrypted-blob `csrf_token` field (see §4) is the per-request token for state-changing endpoints. |

### 3.2 Anti-patterns (forbidden)

- `Domain=.example.com` — over-broad, cookie spills to the customer tier.
- `Domain=auth.internal.example.com` (no leading dot, exact host) — modern
  browsers treat it the same as a leading-dot domain *for the issuing
  host* but reject other admin-tier subdomains. Use `.internal.example.com`.
- `Domain=` set to a cluster-internal hostname (`*.svc.cluster.local`,
  the falcon-id BFF bug). Talon must read `Host:` from the original
  client request via Traefik's `X-Forwarded-Host`, **not** from
  `Request.Host` of the in-cluster connection.
- `SameSite=None; Secure` — invites cross-site embedding; admin tier
  must not be embeddable.
- `SameSite=Strict` — breaks the OIDC redirect-back as above.
- Storing JWT in the cookie value — exceeds 4 KB browser cap with the
  Falcon-ID claim set; truncated by some iOS Safari versions; reveals
  identity to anyone with cookie visibility.

## 4. Session blob (server side, in Redis)

### 4.1 JSON shape (versioned)

```json
{
  "v": 1,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "alice@example.com",
  "groups": ["platform-admin", "sre-oncall"],
  "tenant_id": "00000000-0000-0000-0000-000000000002",
  "iss": "https://id.example.com",
  "amr": ["pwd", "mfa"],
  "iat": 1745654400,
  "exp": 1745683200,
  "last_touched": 1745655001,
  "src_ip": "203.0.113.45",
  "ua_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "csrf_token": "8f7a2b9c4d3e1f6a5b8c7d4e3f2a1b9c",
  "id_token_jti": "eyJhbGciOi...truncated-32chars...",
  "refresh_token_enc": "AES-GCM(refresh_token)"
}
```

| Field | Type | Purpose | Source |
|-------|------|---------|--------|
| `v` | int | Schema version (current: 1). Decoder rejects unknown versions; rotation procedure for v→v+1 documented in §6. | this ADR |
| `sub` | UUID string | Falcon-ID `sub` claim; primary subject identifier. | id_token |
| `email` | string | For audit logs and X-Talon-Email injection. | id_token (or /userinfo if missing) |
| `groups` | array of string | For group-filter and SpiceDB user-group binding. | id_token `groups` claim |
| `tenant_id` | UUID string | For multi-tenant routing if Talon ever fronts a per-tenant admin tier. | id_token `tenant_id` claim |
| `iss` | string | Verify on read; rejects sessions issued by a non-canonical IdP. | id_token `iss` |
| `amr` | array of string | For Phase 4 step-up MFA gating (`mfa` value present iff Falcon-ID asserted MFA). | id_token `amr` |
| `iat` | unix seconds | Session creation time. Immutable. | server clock |
| `exp` | unix seconds | Hard expiry. Sliding refresh extends `last_touched`, not `exp` (see §5.3). | server clock + 8 h |
| `last_touched` | unix seconds | Updated on every successful request that passes auth. Drives sliding TTL. | server clock |
| `src_ip` | string | Source IP at session creation. Compared on read; mismatch is an audit signal but does not invalidate (admins on roaming devices). | request `X-Forwarded-For` first hop |
| `ua_hash` | string | SHA-256 of User-Agent at creation. Same audit-signal-only treatment as `src_ip`. | request `User-Agent` |
| `csrf_token` | hex string | 32-byte hex, generated at session creation. Echoed in `X-Talon-CSRF` response header on first GET; required on any non-safe-method (`POST`/`PUT`/`PATCH`/`DELETE`) request *to Talon's own admin endpoints* (e.g., `/auth/logout`). Upstream apps that need their own CSRF protection are not affected. | crypto/rand |
| `id_token_jti` | string | The id_token's `jti` claim. Used to deduplicate replay-on-callback attacks. | id_token |
| `refresh_token_enc` | string | The OIDC refresh_token, **encrypted** with the cookie-encrypt-key (separate AES-GCM nonce). Used by Phase 4 continuous-verification poll to call Falcon-ID `/oauth/userinfo`. | OIDC token response |

The blob is JSON-marshalled, then encrypted as a whole with AES-256-GCM
(see §4.2); the ciphertext is what lands in Redis.

### 4.2 AES-256-GCM envelope

Wire format of the Redis value (single byte string):

```
┌─────────────┬──────────────┬───────────────────────────────────┐
│ KEY-VER (1) │ NONCE (12)   │ CIPHERTEXT-WITH-AUTH-TAG (var)    │
└─────────────┴──────────────┴───────────────────────────────────┘
   1 byte        12 bytes      len(plaintext) + 16 bytes (GCM tag)
```

- **KEY-VER**: the version byte of the encryption key in use. Permits
  envelope-level key rotation per §6 — readers can decrypt with multiple
  key versions concurrently.
- **NONCE**: 12 random bytes per encryption (NIST SP 800-38D §8.2.1
  recommendation for AES-GCM with random nonces). Generated via
  `crypto/rand.Read`; never reused. Birthday-bound nonce-reuse
  probability for 2⁹⁶ space and N encryptions is N²/2⁹⁷ — for 10⁹
  encryptions per year per cluster, P < 2⁻⁷⁸.
- **CIPHERTEXT**: GCM-encrypted JSON blob. Authentication tag (16 bytes)
  is appended by the AEAD construction; decoder verifies before
  returning plaintext.
- **AAD**: the cookie value (the UUIDv4 in the cookie) is bound as
  Additional Authenticated Data. This guarantees a stolen Redis blob
  cannot be re-attached to a different cookie ID and replayed.

### 4.3 Redis keyspace

| Key | Type | TTL | Purpose |
|-----|------|-----|---------|
| `talon:session:<uuid>` | string (binary, AES-GCM envelope) | 8 h initial, refreshed by `EXPIRE` on every successful access (sliding) | The session record. Cookie value is the `<uuid>` portion. |
| `talon:revoked:<uuid>` | string (`"1"`) | matches the original session's `exp` time | Tombstone for explicitly-revoked sessions. Talon checks this *before* the session record on every request. Outlives the session record so a revocation cannot be undone by a delayed write. |
| `talon:handshake:<state>` | string (JSON: `{verifier, rd, src_ip, created_at}`) | 5 m | OIDC handshake state. Holds the PKCE `code_verifier`, the original `rd` (return destination), source IP for binding, and creation timestamp for cleanup. |
| `talon:revoke-by-sub:<sub>` | sorted set of `<uuid>` keyed by `<exp>` | 30 d | Index for "kick all sessions of user X" admin operation. Talon adds entries on session create and removes on revoke; ZREMRANGEBYSCORE drops expired entries on each access. |

Redis is shared with Falcon-ID; namespace prefix `talon:` is the only
collision-avoidance mechanism (Redis ACL would be ideal but is not in
scope for Phase 0). Falcon-ID's prefixes (`falcon_id:*`) and Talon's
must remain disjoint forever.

## 5. Lifecycle

### 5.1 Create

```
1. OIDC callback validates state, exchanges code, validates id_token.
2. Generate uuid := crypto/rand UUIDv4.
3. Generate csrf_token := 16-byte crypto/rand hex.
4. Build JSON blob per §4.1. Set v=1, iat=now, exp=now+8h, last_touched=now.
5. Encrypt blob per §4.2 with current key version, AAD=uuid.
6. SETEX talon:session:<uuid> 28800 <ciphertext>
7. ZADD talon:revoke-by-sub:<sub> <exp> <uuid>
8. Set-Cookie talon_session=<uuid> per §3.1.
9. 302 → original rd (with full HTML body per ADR 0001 §5.d).
```

### 5.2 Read (per request)

```
1. Read talon_session cookie. Absent → start OIDC handshake.
2. EXISTS talon:revoked:<uuid> → if 1, refuse + start OIDC handshake.
3. GET talon:session:<uuid>. Nil → start OIDC handshake.
4. Decrypt envelope. Try current KEY-VER; on mismatch try previous KEY-VER
   (rotation window per §6). Auth-tag failure or wrong AAD → audit, refuse,
   delete cookie, start OIDC handshake.
5. Verify v == 1, iss matches canonical, exp >= now. Else → refuse + handshake.
6. Compare src_ip / ua_hash; mismatch → audit (do not refuse, see §4.1 note).
7. Sliding refresh per §5.3.
8. Return claims to PEP / PE for downstream policy evaluation.
```

### 5.3 Sliding refresh

The sliding refresh extends `last_touched` and the Redis TTL, **not** the
hard `exp`. Hard `exp` is the absolute upper bound (8 h from creation).

```
threshold := exp - 1h          // start refreshing in the last hour
if (now - last_touched) > 60 {  // throttle: at most 1 refresh/min
    last_touched := now
    re-encrypt blob (new nonce!) with current key
    SETEX talon:session:<uuid> <remaining_ttl_to_exp> <new_ciphertext>
}
```

Two policies the implementation must follow:

1. **Re-encrypt with a fresh nonce on every write.** Reusing the nonce
   from the previous write would break GCM's IND-CPA property if any
   blob field changes (which `last_touched` always does).
2. **Lost-update tolerance.** Two concurrent requests refreshing the
   same session is the dominant race. Mitigation: writes are
   idempotent in steady state (the only changing field is
   `last_touched`, which is monotonic-ish; one refresh winning over
   another is harmless). Phase 4 may revisit if `amr` updates start
   landing on session refresh — at that point a Redis Lua-CAS
   becomes mandatory.

### 5.4 Logout

```
DELETE /auth/logout (Talon's own endpoint, requires CSRF token)
1. uuid := cookie value
2. SETEX talon:revoked:<uuid> <session.exp - now> "1"
3. DEL talon:session:<uuid>
4. ZREM talon:revoke-by-sub:<sub> <uuid>
5. Set-Cookie: talon_session=; Max-Age=0; Domain=.internal.example.com; ...
6. Optionally: Falcon-ID RP-Initiated Logout to revoke the IdP session as well.
7. 302 → /auth/logged-out (with full HTML body per ADR 0001 §5.d)
```

### 5.5 Admin revoke (Phase 4)

`DELETE /admin/sessions/{sub}` — kicks all live sessions of a user.

```
1. Authorize the caller (must be platform-admin with admin permission_required on talon).
2. ZRANGE talon:revoke-by-sub:<sub> 0 -1 WITHSCORES
3. For each (uuid, exp_score):
     SETEX talon:revoked:<uuid> <exp_score - now> "1"
     DEL talon:session:<uuid>
4. DEL talon:revoke-by-sub:<sub>
5. Audit log emit per kick.
```

### 5.6 Continuous verification (Phase 4)

Background goroutine polls `/oauth/userinfo` per active session every N
minutes (default 15 per ADR 0001 §6). On any of:

- Falcon-ID returns `invalid_token` (refresh failed),
- `/oauth/userinfo` `groups` no longer contains a group required by an
  active session's most-recent route check,
- Falcon-ID admin API marks the user disabled,

→ Treat as logout (§5.4) and emit a continuous-verification audit event.

## 6. Key rotation

The cookie-encryption key is stored in Vault at
`example/data/platform/prod/talon/cookie-encrypt-key` and projected into
the Talon pod via ExternalSecret. The path follows the platform-wide
ServiceClientClaim convention `platform/{environment}/{service}/<thing>`
so that all per-service Vault entries cluster under one prefix.

### 6.1 Key versions and rotation window

Talon supports up to **two concurrent key versions** at any time:

- `current` (KEY-VER byte = N): used to *encrypt* new and refreshed sessions.
- `previous` (KEY-VER byte = N-1): used to *decrypt* envelopes still
  bearing N-1 in the version byte. Never used for new encryption.

Rotation procedure (no operator downtime):

```
T+0   :  Generate new key in Vault under …/cookie-encrypt-key, advance
         the `version` field to N+1, leave `previous` field set to N.
         Set `rotation_started_at` = now.

T+0..30s : External-Secrets reconciles, k8s Secret updates.
         Talon SIGHUP / re-load picks up both versions.

T+30s..8h: All NEW or REFRESHED sessions encrypt with N+1.
         Reads of any session ciphertext: try N+1 first; on auth-tag
         failure, try N; success → re-encrypt with N+1 on next sliding
         refresh.

T+8h    : All sessions either refreshed (now N+1) or expired (hard exp).
         Drop `previous` from Vault, advance: previous := N+1, current := N+2
         is unused yet; Talon re-loads, only N+1 active.
```

The rotation is bounded by the 8 h hard session TTL — after one TTL
window past `T+0`, no N-encrypted ciphertext can exist.

### 6.2 Emergency key revocation

If the current key is compromised:

```
1. Generate the new key in Vault (as in §6.1) AND `vault kv delete` the previous.
2. Talon re-load: current := N+1 only; N is gone.
3. Every session encrypted with N becomes undecryptable → on next request
   the user re-authenticates via OIDC.
4. Audit log emits one mass-invalidation event.
```

This is acceptable downtime (one OIDC roundtrip per active admin) for a
key-compromise scenario; Pomerium and oauth2-proxy both have the same
all-or-nothing posture for cookie-secret rotation.

### 6.3 Schema rotation (v → v+1)

When a session-blob field changes shape:

```
1. ADR superseding §4.1 of this document.
2. Talon code update: decoder accepts v=N AND v=N+1; new sessions
   encode as N+1; v=N readers do best-effort field translation.
3. After 8 h (one TTL window), new code update drops v=N decoder.
```

## 7. Failure modes

| Failure | Symptom | Recovery |
|---------|---------|----------|
| Redis unreachable on read | Talon treats as "no session" → OIDC handshake | Per ADR 0001 §10.a; users see one extra redirect roundtrip per request during outage. |
| Redis unreachable on write (sliding refresh) | Refresh silently dropped; session remains valid until exp | Acceptable; refresh retries on next request. |
| AES-GCM auth-tag failure | Decryption returns error before plaintext exposed | Audit, force OIDC re-handshake, set `talon:revoked:<uuid>` to prevent retry-attacks. |
| Cookie domain mismatch (browser drops cookie) | Every request acts cookieless → infinite OIDC loop | Talon detects this via "OIDC succeeded but next request is cookieless" pattern; emits a `cookie_drop_loop` metric and degrades to a hard error 400 with an HTML body explaining the misconfiguration. The unit test for §3.1 asserts this case during CI. |
| Clock drift between Talon and Falcon-ID | id_token `exp` validated incorrectly | NTP via chrony on every node (already in place, `<your-iac-repo>/.../ntp.tf`). Talon allows 30s clock skew on `iat` / `exp` checks. |
| Vault outage during key rotation | New key not delivered; old key stays current | Tolerant — current state stays valid until next ExternalSecret reconcile. Rotation deferred. |

## 8. Test surface (asserted in CI)

- Unit: `internal/session/encode_test.go` round-trips JSON blob with
  envelope; verifies AAD binding; verifies KEY-VER 1 and 2 both
  decrypt during rotation window.
- Unit: `internal/session/cookie_test.go` asserts wire-format byte
  string of `Set-Cookie` matches the §3.1 table for a known UUID +
  fixed clock.
- Unit: `internal/session/redis_test.go` asserts `talon:session:*`,
  `talon:revoked:*`, `talon:handshake:*` keyspace shapes and TTL math.
- Integration: `test/integration/session_lifecycle_test.go` against a
  miniredis backend, full Create→Read→Refresh→Revoke cycle.
- iOS: every phase exit re-verifies the wire-format `Set-Cookie`
  shape from a real iPhone capture, per an unpublished e2e test.

## 9. References

- [RFC 6265 — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
- [RFC 6265bis (work-in-progress, current SameSite semantics)](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- [NIST SP 800-38D — AES-GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [Go `crypto/aes` and `crypto/cipher.NewGCM`](https://pkg.go.dev/crypto/cipher#NewGCM)
- ADR 0001 §5.c — high-level cookie + session table this ADR refines

---

*Sub-section numbering (§3.x, §4.x, §5.x, §6.x) is stable. Refinement
requires a superseding ADR.*
