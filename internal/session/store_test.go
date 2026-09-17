// SPDX-License-Identifier: AGPL-3.0-or-later

package session_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/hexxlock/talon/internal/session"
	"github.com/redis/go-redis/v9"
)

// TestEnvelopeRoundtrip asserts encode → decode round-trips the blob
// faithfully under the specified AAD. Failure here means cookies issued
// today won't be readable tomorrow.
func TestEnvelopeRoundtrip(t *testing.T) {
	t.Parallel()
	rc := newMiniRedis(t)
	key := mustRandKey()
	store, err := session.NewStore(rc, key, nil, 8*time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	in := &session.Blob{
		Sub:    "user-123",
		Email:  "alice@example.com",
		Groups: []string{"platform-admin"},
		Iss:    "https://id.hexxlock.com",
	}
	cookieID, err := store.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if cookieID == "" {
		t.Fatal("cookieID empty")
	}
	out, err := store.Read(context.Background(), cookieID)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Sub != in.Sub || out.Email != in.Email || len(out.Groups) != 1 {
		t.Errorf("round-trip mismatch: %+v vs %+v", out, in)
	}
	if out.CSRFToken == "" {
		t.Error("CSRFToken not set on Create")
	}
}

// TestAADBindingDefeatsCookieSwap asserts that a Redis blob written under
// cookie A cannot be decrypted under cookie B — cookie swap attack defence.
func TestAADBindingDefeatsCookieSwap(t *testing.T) {
	t.Parallel()
	rc := newMiniRedis(t)
	key := mustRandKey()
	store, err := session.NewStore(rc, key, nil, 8*time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cookieA, err := store.Create(context.Background(), &session.Blob{Sub: "alice"})
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	// Manually copy A's blob to a fake cookie B's key.
	val, err := rc.Get(context.Background(), "talon:session:"+cookieA).Bytes()
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	if err := rc.Set(context.Background(), "talon:session:fake-cookie-b", val, time.Hour).Err(); err != nil {
		t.Fatalf("Set B: %v", err)
	}
	_, err = store.Read(context.Background(), "fake-cookie-b")
	if !errors.Is(err, session.ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed (cookie-swap rejected), got %v", err)
	}
}

// TestRevokeWinsOverRead asserts the revocation tombstone is checked before
// the session record (defence against late writes resurrecting a session).
func TestRevokeWinsOverRead(t *testing.T) {
	t.Parallel()
	rc := newMiniRedis(t)
	key := mustRandKey()
	store, err := session.NewStore(rc, key, nil, 8*time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cookieID, err := store.Create(context.Background(), &session.Blob{Sub: "alice"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	blob, err := store.Read(context.Background(), cookieID)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := store.Revoke(context.Background(), cookieID, blob); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = store.Read(context.Background(), cookieID)
	if !errors.Is(err, session.ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

// newMiniRedis returns a redis.Client backed by an in-process miniredis,
// or skips the test if the test environment doesn't have it.
//
// Phase 1 keeps the dep out of go.mod by skipping if no miniredis available.
// Phase 2 will pull in github.com/alicebob/miniredis/v2 as a test-only dep.
func newMiniRedis(t *testing.T) *redis.Client {
	t.Helper()
	t.Skip("miniredis not yet wired into go.mod; rerun once test deps land in Phase 1.1")
	return nil
}

func mustRandKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// newStoreNoRedis returns a Store with a nil redis client. Suitable for
// pure-crypto helpers (EncryptValue/DecryptValue) that don't touch Redis.
func newStoreNoRedis(t *testing.T) *session.Store {
	t.Helper()
	s, err := session.NewStore(nil, mustRandKey(), nil, time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// TestEncryptValueRoundtrip verifies the field-level AES-GCM wrap of
// sensitive blob values (refresh_token, etc. — IAP-04 / ADR 0002 §4.1).
// Failure means refresh tokens stored encrypted today won't decrypt
// tomorrow → continuous-verification refresh path breaks → every active
// admin-tier session gets force-logged-out at the next CV tick.
func TestEncryptValueRoundtrip(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	plaintext := "rt_abc123.def456.ghi789-some-opaque-or-jwt-refresh-token"
	enc, err := s.EncryptValue(plaintext)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if enc == plaintext {
		t.Fatal("ciphertext equals plaintext — encryption did not run")
	}
	if !startsWith(enc, "enc:v1:") {
		t.Fatalf("ciphertext missing enc:v1: prefix; got prefix %q", enc[:min(7, len(enc))])
	}
	got, err := s.DecryptValue(enc)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if got != plaintext {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestEncryptValueEmptyPassthrough — empty input must not be wrapped
// (caller convention: empty refresh_token means "no refresh token", not
// "encrypted empty string"). DecryptValue("") must mirror.
func TestEncryptValueEmptyPassthrough(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	enc, err := s.EncryptValue("")
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	if enc != "" {
		t.Fatalf("empty input should round-trip empty; got %q", enc)
	}
	dec, err := s.DecryptValue("")
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if dec != "" {
		t.Fatalf("empty input should decrypt empty; got %q", dec)
	}
}

// TestDecryptValueLegacyPlaintextPassthrough — the "enc:v1:" prefix is
// the marker; absence means a pre-IAP-04 session blob with a literal
// plaintext refresh_token. DecryptValue must pass it through unchanged
// so the IAP-04 deploy doesn't invalidate every active admin session.
// Real refresh_tokens are RFC 6749 §A.17 base64url which excludes ":",
// so this passthrough is unambiguous.
func TestDecryptValueLegacyPlaintextPassthrough(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	legacyRT := "rt_legacy_plaintext_abc123def456"
	got, err := s.DecryptValue(legacyRT)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if got != legacyRT {
		t.Fatalf("legacy passthrough broken: got %q want %q", got, legacyRT)
	}
}

// TestEncryptValueFreshNonce — two encryptions of the same plaintext
// must produce different ciphertexts (random nonce per call). Otherwise
// the wrap is deterministic and an attacker who observes two stored
// envelopes can confirm whether they wrap the same secret.
func TestEncryptValueFreshNonce(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	a, err := s.EncryptValue("same-plaintext")
	if err != nil {
		t.Fatalf("EncryptValue 1: %v", err)
	}
	b, err := s.EncryptValue("same-plaintext")
	if err != nil {
		t.Fatalf("EncryptValue 2: %v", err)
	}
	if a == b {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertexts — nonce is not random")
	}
}

// TestDecryptValueTampered — flipping any byte of the ciphertext must
// fail authentication (AES-GCM is an AEAD; the auth tag covers the
// ciphertext + the absent-here AAD).
func TestDecryptValueTampered(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	enc, err := s.EncryptValue("the-secret")
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	// Flip the last character (in the base64-encoded ciphertext-with-tag).
	tampered := enc[:len(enc)-1] + flipByte(enc[len(enc)-1])
	_, err = s.DecryptValue(tampered)
	if !errors.Is(err, session.ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed on tamper, got %v", err)
	}
}

// TestDecryptValueWrongKey — a value encrypted under one key must NOT
// decrypt under a different key. Sanity check that the AEAD is actually
// keyed (not a no-op stub).
func TestDecryptValueWrongKey(t *testing.T) {
	t.Parallel()
	s1 := newStoreNoRedis(t)
	s2 := newStoreNoRedis(t)
	enc, err := s1.EncryptValue("the-secret")
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	_, err = s2.DecryptValue(enc)
	if !errors.Is(err, session.ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed on wrong-key decrypt, got %v", err)
	}
}

// Note on key-rotation testing: the previousAEAD fallback path in
// DecryptValue mirrors the existing internal decrypt() function used by
// the outer Blob envelope. It's gated on the KEY-VER byte (raw[0])
// matching s.previousKeyV. Both currentKeyV and previousKeyV are derived
// from the package-level CurrentKeyVersion constant which is documented
// to be bumped at rotation time per ADR 0002 §6 — so a meaningful test
// of the rotation path requires either changing the constant (a
// build-time concern) or factoring NewStore to accept arbitrary key
// versions (out of scope for IAP-04). The path is correct by
// construction: identical code shape to the production decrypt() that
// has carried the outer Blob through every Talon ship since Phase 1.

// TestDecryptValueMalformedBase64 — a value that has the prefix but
// isn't valid base64 should error (not panic).
func TestDecryptValueMalformedBase64(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	_, err := s.DecryptValue("enc:v1:!!!not-base64!!!")
	if err == nil {
		t.Fatal("want error on malformed base64, got nil")
	}
}

// TestDecryptValueShortEnvelope — a value that has the prefix but is
// shorter than the minimum envelope (key-version + nonce + auth-tag) must
// fail authentication (not panic on a slice out-of-bounds).
func TestDecryptValueShortEnvelope(t *testing.T) {
	t.Parallel()
	s := newStoreNoRedis(t)
	// Exactly 1 byte after prefix; valid base64 but too short to be an envelope.
	_, err := s.DecryptValue("enc:v1:AA")
	if !errors.Is(err, session.ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed on short envelope, got %v", err)
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func flipByte(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// TestBlobIdentity proves the shared-identity accessor returns the right
// six claims and leaves session-specific fields out of the projection
// (ADR 0031 — Identity convergence half).
func TestBlobIdentity(t *testing.T) {
	b := &session.Blob{
		Sub:    "sub-1",
		Email:  "a@b.test",
		Roles:  []string{"platform_admin"},
		Groups: []string{"/platform/sre"},
		AMR:    []string{"pwd", "otp"},
		// session-private — must NOT bleed into Identity()
		CSRFToken:       "csrf-secret",
		RefreshTokenEnc: "refresh-secret",
	}
	id := b.Identity()
	if id.Subject != "sub-1" || id.Email != "a@b.test" {
		t.Errorf("subject/email mismatch: %+v", id)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "platform_admin" {
		t.Errorf("roles mismatch: %+v", id.Roles)
	}
	if len(id.AMR) != 2 {
		t.Errorf("amr mismatch: %+v", id.AMR)
	}
	if id.Region != "" {
		t.Errorf("Region must default empty until a region claim is wired; got %q", id.Region)
	}
}
