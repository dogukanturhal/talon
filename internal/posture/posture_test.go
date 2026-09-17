// SPDX-License-Identifier: AGPL-3.0-or-later

package posture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type staticResolver struct{ key any }

func (s *staticResolver) Keys(_ context.Context, _, _ string) ([]any, error) {
	return []any{s.key}, nil
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func signPosture(t *testing.T, key *ecdsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

func basePosture() map[string]any {
	return map[string]any{
		"iss": "https://posture.test",
		"sub": "device:abc",
		"aud": "https://auth.test",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(30 * time.Minute).Unix(),
		"compliance": map[string]any{
			"disk_encrypted":  true,
			"edr_running":     true,
			"screen_lock_min": 5,
			"os":              "macos",
			"os_version":      "15.2.0",
			"managed":         true,
			"jailbroken":      false,
		},
	}
}

func newVerifierFixture(t *testing.T) (*Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)
	v, err := NewVerifier(VerifierConfig{
		TrustedIssuers:   []string{"https://posture.test"},
		ExpectedAudience: "https://auth.test",
		Resolver:         &staticResolver{key: &key.PublicKey},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, key
}

func TestVerify_HappyPath(t *testing.T) {
	v, key := newVerifierFixture(t)
	tok := signPosture(t, key, basePosture())

	c, err := v.Verify(context.Background(), tok, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "device:abc" {
		t.Errorf("subject = %q", c.Subject)
	}
	if c.Compliance["disk_encrypted"] != true {
		t.Errorf("disk_encrypted: %v", c.Compliance["disk_encrypted"])
	}
}

func TestVerify_MissingHeader(t *testing.T) {
	v, _ := newVerifierFixture(t)
	_, err := v.Verify(context.Background(), "", "")
	if !errors.Is(err, ErrMissing) {
		t.Errorf("want ErrMissing, got %v", err)
	}
}

func TestVerify_UntrustedIssuer(t *testing.T) {
	v, key := newVerifierFixture(t)
	p := basePosture()
	p["iss"] = "https://attacker.example"
	tok := signPosture(t, key, p)
	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrIssuerUntrusted) {
		t.Errorf("want ErrIssuerUntrusted, got %v", err)
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	v, key := newVerifierFixture(t)
	p := basePosture()
	p["aud"] = "https://different.example"
	tok := signPosture(t, key, p)
	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("want ErrAudienceMismatch, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	v, key := newVerifierFixture(t)
	p := basePosture()
	p["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	p["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	tok := signPosture(t, key, p)
	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrExpired) {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

func TestVerify_BadSig(t *testing.T) {
	v, _ := newVerifierFixture(t)
	other := newKey(t)
	tok := signPosture(t, other, basePosture())
	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrSignature) {
		t.Errorf("want ErrSignature, got %v", err)
	}
}

func TestVerify_UserBindingMismatch(t *testing.T) {
	v, key := newVerifierFixture(t)
	p := basePosture()
	p["user_sub"] = "user-original"
	tok := signPosture(t, key, p)
	_, err := v.Verify(context.Background(), tok, "user-different")
	if !errors.Is(err, ErrUserMismatch) {
		t.Errorf("want ErrUserMismatch, got %v", err)
	}
}

func TestVerify_UserBindingMatch(t *testing.T) {
	v, key := newVerifierFixture(t)
	p := basePosture()
	p["user_sub"] = "user-abc"
	tok := signPosture(t, key, p)
	c, err := v.Verify(context.Background(), tok, "user-abc")
	if err != nil {
		t.Errorf("user binding match: got error %v", err)
	}
	if c.UserSub != "user-abc" {
		t.Errorf("UserSub = %q", c.UserSub)
	}
}

// --- DDIL P3.10 governed posture-grace ------------------------------------

// gracePosture builds a posture with explicit iat/exp and a device tier so
// the grace tests can pin the exact freshness relationship to a fixed clock.
func gracePosture(iat, exp time.Time, tier string) map[string]any {
	return map[string]any{
		"iss": "https://posture.test",
		"sub": "device:abc",
		"aud": "https://auth.test",
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		"compliance": map[string]any{
			"disk_encrypted": true,
			"tier":           tier,
		},
	}
}

// newGraceVerifier returns a verifier with a FIXED clock (so grace windows are
// deterministic) and the given per-tier grace budgets. MaxAge is 1h so the exp
// gate and the iat/MaxAge gate can be exercised independently.
func newGraceVerifier(t *testing.T, now time.Time, graceCorp, graceByod time.Duration) (*Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key := newKey(t)
	v, err := NewVerifier(VerifierConfig{
		TrustedIssuers:   []string{"https://posture.test"},
		ExpectedAudience: "https://auth.test",
		MaxAge:           time.Hour,
		GraceCorp:        graceCorp,
		GraceByod:        graceByod,
		Resolver:         &staticResolver{key: &key.PublicKey},
		Clock:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, key
}

// A fresh posture (now < exp, within MaxAge) is never degraded even when a
// grace budget is configured.
func TestVerify_Grace_FreshNotDegraded(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	// exp 5m in the future, iat 1m ago — comfortably fresh on both gates.
	tok := signPosture(t, key, gracePosture(now.Add(-1*time.Minute), now.Add(5*time.Minute), TierByod))

	c, err := v.Verify(context.Background(), tok, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Degraded {
		t.Errorf("fresh posture marked Degraded")
	}
	if !c.GraceUntil.IsZero() {
		t.Errorf("fresh posture has non-zero GraceUntil %s", c.GraceUntil)
	}
}

// A posture past exp but within the tier grace budget is served DEGRADED (no
// error), with GraceUntil == exp+grace.
func TestVerify_Grace_WithinExpGraceDegraded(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	// exp 5m in the PAST, iat 10m ago (age 10m < MaxAge so only the exp gate
	// fires). BYOD grace 30m → exp+grace = now+25m > now ⇒ degraded, not error.
	exp := now.Add(-5 * time.Minute)
	tok := signPosture(t, key, gracePosture(now.Add(-10*time.Minute), exp, TierByod))

	c, err := v.Verify(context.Background(), tok, "")
	if err != nil {
		t.Fatalf("within-grace posture should NOT error, got %v", err)
	}
	if !c.Degraded {
		t.Fatalf("within-grace posture not marked Degraded")
	}
	want := exp.Add(RecommendedGraceByod)
	if c.GraceUntil.Unix() != want.Unix() {
		t.Errorf("GraceUntil = %s, want exp+grace %s", c.GraceUntil, want)
	}
}

// A posture past exp+grace fails closed with ErrExpired.
func TestVerify_Grace_PastExpGraceExpired(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	// exp 40m ago, BYOD grace 30m → exp+grace = now-10m < now ⇒ fail closed.
	// iat 45m ago keeps the age gate (MaxAge 1h) from firing first.
	tok := signPosture(t, key, gracePosture(now.Add(-45*time.Minute), now.Add(-40*time.Minute), TierByod))

	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrExpired) {
		t.Errorf("past-grace posture: want ErrExpired, got %v", err)
	}
}

// The iat/MaxAge gate is grace-aware too: a stale-iat-but-within-grace posture
// is degraded, not rejected; past MaxAge+grace it fails closed.
func TestVerify_Grace_IatMaxAgeGate(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	// exp far in the future (exp gate fresh) so ONLY the iat/MaxAge gate fires.
	freshExp := now.Add(2 * time.Hour)

	// Within grace: iat = now-65m ⇒ age 65m > MaxAge 60m, but iat+MaxAge+grace
	// = now+25m > now ⇒ degraded (BYOD grace 30m).
	tokDegraded := signPosture(t, key, gracePosture(now.Add(-65*time.Minute), freshExp, TierByod))
	c, err := v.Verify(context.Background(), tokDegraded, "")
	if err != nil {
		t.Fatalf("within-MaxAge-grace posture should NOT error, got %v", err)
	}
	if !c.Degraded {
		t.Errorf("within-MaxAge-grace posture not marked Degraded")
	}

	// Past grace: iat = now-100m ⇒ iat+MaxAge+grace = now-10m < now ⇒ expired.
	tokExpired := signPosture(t, key, gracePosture(now.Add(-100*time.Minute), freshExp, TierByod))
	if _, err := v.Verify(context.Background(), tokExpired, ""); !errors.Is(err, ErrExpired) {
		t.Errorf("past-MaxAge-grace posture: want ErrExpired, got %v", err)
	}
}

// Grace NEVER bypasses attestation: a posture signed by an untrusted key is
// rejected with ErrSignature even when its timing sits within the grace window.
func TestVerify_Grace_BadSigStillRejected(t *testing.T) {
	now := time.Now()
	v, _ := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	other := newKey(t) // NOT the verifier's trusted key
	// Same timing as the within-grace happy case.
	tok := signPosture(t, other, gracePosture(now.Add(-10*time.Minute), now.Add(-5*time.Minute), TierByod))

	_, err := v.Verify(context.Background(), tok, "")
	if !errors.Is(err, ErrSignature) {
		t.Errorf("bad-signature posture within grace window: want ErrSignature (grace must not bypass attestation), got %v", err)
	}
}

// Corp and Byod budgets differ: the SAME posture age (20m past exp) is expired
// under the tighter corp budget (10m) but degraded-served under byod (30m).
func TestVerify_Grace_CorpVsByodBudgetsDiffer(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, RecommendedGraceCorp, RecommendedGraceByod)
	exp := now.Add(-20 * time.Minute) // 20m past exp on both
	iat := now.Add(-25 * time.Minute) // age 25m < MaxAge so exp gate is the only one

	// TIER_CORP: exp+10m = now-10m < now ⇒ fail closed.
	corpTok := signPosture(t, key, gracePosture(iat, exp, TierCorp))
	if _, err := v.Verify(context.Background(), corpTok, ""); !errors.Is(err, ErrExpired) {
		t.Errorf("corp (10m grace) 20m-past-exp: want ErrExpired, got %v", err)
	}

	// TIER_BYOD: exp+30m = now+10m > now ⇒ degraded, served.
	byodTok := signPosture(t, key, gracePosture(iat, exp, TierByod))
	c, err := v.Verify(context.Background(), byodTok, "")
	if err != nil {
		t.Fatalf("byod (30m grace) 20m-past-exp should serve degraded, got %v", err)
	}
	if !c.Degraded {
		t.Errorf("byod 20m-past-exp not marked Degraded")
	}
}

// Grace disabled (both budgets 0 — the backward-compatible default) preserves
// the pre-P3.10 hard fail-closed-at-exp behaviour.
func TestVerify_Grace_DisabledHardFails(t *testing.T) {
	now := time.Now()
	v, key := newGraceVerifier(t, now, 0, 0)
	// 1m past exp — would be within grace if enabled, but grace is off.
	tok := signPosture(t, key, gracePosture(now.Add(-10*time.Minute), now.Add(-1*time.Minute), TierByod))

	if _, err := v.Verify(context.Background(), tok, ""); !errors.Is(err, ErrExpired) {
		t.Errorf("grace disabled: past-exp posture must ErrExpired (backward compat), got %v", err)
	}
}

func TestEvaluate_BoolRequired(t *testing.T) {
	c := &Claims{Compliance: map[string]any{
		"disk_encrypted": true, "jailbroken": false,
	}}
	if ok, _ := Evaluate(c, map[string]any{"disk_encrypted": true}); !ok {
		t.Errorf("disk_encrypted=true should pass")
	}
	if ok, k := Evaluate(c, map[string]any{"jailbroken": false}); !ok {
		t.Errorf("jailbroken=false should pass, failed on %q", k)
	}
	if ok, _ := Evaluate(c, map[string]any{"disk_encrypted": false}); ok {
		t.Errorf("disk_encrypted=false on true device should fail")
	}
}

func TestEvaluate_IntMinimum(t *testing.T) {
	// JSON numbers decode as float64; toInt() converts. Verify
	// requirement of screen_lock_min=5 passes for 5 and 10 but fails
	// for 3.
	c5 := &Claims{Compliance: map[string]any{"screen_lock_min": float64(5)}}
	c10 := &Claims{Compliance: map[string]any{"screen_lock_min": float64(10)}}
	c3 := &Claims{Compliance: map[string]any{"screen_lock_min": float64(3)}}
	req := map[string]any{"screen_lock_min": 5}

	if ok, _ := Evaluate(c5, req); !ok {
		t.Errorf("5 == 5 should pass")
	}
	if ok, _ := Evaluate(c10, req); !ok {
		t.Errorf("10 >= 5 should pass")
	}
	if ok, k := Evaluate(c3, req); ok || k != "screen_lock_min" {
		t.Errorf("3 < 5 should fail on screen_lock_min, got ok=%v k=%q", ok, k)
	}
}

func TestEvaluate_StringExact(t *testing.T) {
	c := &Claims{Compliance: map[string]any{"os": "macos"}}
	if ok, _ := Evaluate(c, map[string]any{"os": "macos"}); !ok {
		t.Errorf("exact match should pass")
	}
	if ok, _ := Evaluate(c, map[string]any{"os": "windows"}); ok {
		t.Errorf("mismatch should fail")
	}
}

func TestEvaluate_MissingFact(t *testing.T) {
	c := &Claims{Compliance: map[string]any{}}
	ok, k := Evaluate(c, map[string]any{"disk_encrypted": true})
	if ok || k != "disk_encrypted" {
		t.Errorf("missing required fact should fail on that key, got ok=%v k=%q", ok, k)
	}
}

func TestEvaluate_NilClaims(t *testing.T) {
	ok, k := Evaluate(nil, map[string]any{"disk_encrypted": true})
	if ok || k != "_no_claims" {
		t.Errorf("nil claims should fail with _no_claims, got ok=%v k=%q", ok, k)
	}
}

// TestRawAud_BothShapes asserts that the audience decoder handles
// string + array forms AND that array members containing commas /
// quotes round-trip through encoding/json correctly. The earlier
// hand-rolled parser broke on "https://x,y/" — the encoding/json-
// based parser does not.
func TestRawAud_BothShapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"single-string", `"https://x/"`, []string{"https://x/"}},
		{"two-element-array", `["https://x/","https://y/"]`, []string{"https://x/", "https://y/"}},
		{"empty-array", `[]`, nil},
		{"null", `null`, nil},
		{"value-contains-comma", `["https://x,y/","https://z/"]`, []string{"https://x,y/", "https://z/"}},
		{"value-contains-quotes", `["https://x\"y/"]`, []string{`https://x"y/`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var a rawAud
			if err := a.UnmarshalJSON([]byte(c.input)); err != nil {
				t.Fatalf("unmarshal %s: %v", c.input, err)
			}
			if len(a) != len(c.want) {
				t.Fatalf("len mismatch: got %d (%v), want %d (%v)", len(a), []string(a), len(c.want), c.want)
			}
			for i := range a {
				if a[i] != c.want[i] {
					t.Errorf("[%d] got %q want %q", i, a[i], c.want[i])
				}
			}
		})
	}
}

func TestRawAud_BadShape(t *testing.T) {
	var a rawAud
	if err := a.UnmarshalJSON([]byte("42")); err == nil {
		t.Errorf("numeric aud should fail unmarshal")
	}
}
