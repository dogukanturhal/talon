// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// --- fixtures ---------------------------------------------------------

type fakeRevoker struct {
	mu      sync.Mutex
	calls   []revokeCall
	stub    int
	stubErr error
}

type revokeCall struct{ iss, sub, reason string }

func (f *fakeRevoker) RevokeBySubject(_ context.Context, iss, sub, reason string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, revokeCall{iss, sub, reason})
	return f.stub, f.stubErr
}

func (f *fakeRevoker) callsCopy() []revokeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]revokeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

type memCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newMemCache() *memCache { return &memCache{seen: make(map[string]time.Time)} }

func (m *memCache) SeenOrAdd(jti string, ttl time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.seen[jti]; ok && time.Now().Before(t) {
		return true
	}
	m.seen[jti] = time.Now().Add(ttl)
	return false
}

type fakeAudit struct {
	mu     sync.Mutex
	events []auditCall
}

type auditCall struct {
	eventType string
	fields    map[string]any
}

func (f *fakeAudit) Emit(eventType string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, auditCall{eventType, fields})
}

func (f *fakeAudit) snapshot() []auditCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditCall, len(f.events))
	copy(out, f.events)
	return out
}

type staticResolver struct {
	pubKey any
}

func (s *staticResolver) Keys(_ context.Context, _ string) ([]any, error) {
	return []any{s.pubKey}, nil
}

// --- helpers ----------------------------------------------------------

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func signSET(t *testing.T, key *rsa.PrivateKey, claims SETClaims) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("secevent+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

func baseClaims() SETClaims {
	return SETClaims{
		Iss: "https://id.test",
		Aud: audienceField{"https://auth.test/caep/events"},
		IAT: time.Now().Unix(),
		JTI: "fixture-jti-1",
		Events: map[string]EventPayload{
			EventSessionRevoked: {
				Subject: Subject{
					Format: "iss_sub",
					Iss:    "https://id.test",
					Sub:    "user-abc",
				},
				EventTimestamp: time.Now().Unix(),
				ReasonAdmin:    LangMap{"en": "Test revoke"},
			},
		},
	}
}

func newReceiverFixture(t *testing.T) (*Receiver, *rsa.PrivateKey, *fakeRevoker, *fakeAudit, *memCache) {
	t.Helper()
	key := newRSAKey(t)
	rev := &fakeRevoker{stub: 3}
	audit := &fakeAudit{}
	cache := newMemCache()
	r, err := NewReceiver(ReceiverConfig{
		ExpectedIssuer:   "https://id.test",
		ExpectedAudience: "https://auth.test/caep/events",
		Resolver:         &staticResolver{pubKey: &key.PublicKey},
		Revoker:          rev,
		Replay:           cache,
		Audit:            audit,
	})
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	return r, key, rev, audit, cache
}

// --- tests ------------------------------------------------------------

func TestProcessSET_HappyPath_SessionRevoked(t *testing.T) {
	r, key, rev, audit, _ := newReceiverFixture(t)
	setJWT := signSET(t, key, baseClaims())

	res, err := r.ProcessSET(context.Background(), setJWT)
	if err != nil {
		t.Fatalf("ProcessSET: %v", err)
	}
	if res.RevokedCount != 3 || res.RevokedSubject != "user-abc" {
		t.Errorf("result = %+v", res)
	}
	calls := rev.callsCopy()
	if len(calls) != 1 || calls[0].sub != "user-abc" || calls[0].iss != "https://id.test" {
		t.Errorf("revoke calls: %+v", calls)
	}
	if calls[0].reason != "Test revoke" {
		t.Errorf("reason should derive from reason_admin.en, got %q", calls[0].reason)
	}
	emitted := audit.snapshot()
	if len(emitted) != 1 || emitted[0].eventType != "caep.revoke" {
		t.Errorf("audit events: %+v", emitted)
	}
}

func TestProcessSET_WrongIssuer(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.Iss = "https://attacker.example"
	setJWT := signSET(t, key, claims)

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("want ErrIssuerMismatch, got %v", err)
	}
}

func TestProcessSET_WrongAudience(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.Aud = audienceField{"https://different.example"}
	setJWT := signSET(t, key, claims)

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("want ErrAudienceMismatch, got %v", err)
	}
}

func TestProcessSET_BadSignature(t *testing.T) {
	r, _, _, _, _ := newReceiverFixture(t)
	otherKey := newRSAKey(t)
	setJWT := signSET(t, otherKey, baseClaims())

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrSignature) {
		t.Errorf("want ErrSignature, got %v", err)
	}
}

func TestProcessSET_StaleIAT(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.IAT = time.Now().Add(-1 * time.Hour).Unix()
	setJWT := signSET(t, key, claims)

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrTooOld) {
		t.Errorf("want ErrTooOld, got %v", err)
	}
}

func TestProcessSET_Replay(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	setJWT := signSET(t, key, baseClaims())

	if _, err := r.ProcessSET(context.Background(), setJWT); err != nil {
		t.Fatalf("first process: %v", err)
	}
	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrReplay) {
		t.Errorf("second presentation: want ErrReplay, got %v", err)
	}
}

func TestProcessSET_RiskLevelChange_AuditOnly(t *testing.T) {
	r, key, rev, audit, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.JTI = "risk-change-jti"
	claims.Events = map[string]EventPayload{
		EventRiskLevelChange: {
			Subject:       Subject{Format: "iss_sub", Iss: "https://id.test", Sub: "user-xyz"},
			CurrentLevel:  "HIGH",
			PreviousLevel: "MEDIUM",
		},
	}
	setJWT := signSET(t, key, claims)

	res, err := r.ProcessSET(context.Background(), setJWT)
	if err != nil {
		t.Fatalf("ProcessSET: %v", err)
	}
	if res.RevokedCount != 0 {
		t.Errorf("risk-change should not revoke, got %d", res.RevokedCount)
	}
	if len(rev.callsCopy()) != 0 {
		t.Errorf("revoker should not be called for risk-change")
	}
	emitted := audit.snapshot()
	if len(emitted) != 1 || emitted[0].eventType != "caep.signal" {
		t.Errorf("audit events: %+v", emitted)
	}
}

func TestProcessSET_UnknownEvent_Tolerated(t *testing.T) {
	r, key, _, audit, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.JTI = "unknown-event-jti"
	claims.Events = map[string]EventPayload{
		"https://schemas.example.com/future/unknown-event": {
			Subject: Subject{Format: "iss_sub", Iss: "https://id.test", Sub: "user-xyz"},
		},
	}
	setJWT := signSET(t, key, claims)

	res, err := r.ProcessSET(context.Background(), setJWT)
	if err != nil {
		t.Fatalf("ProcessSET: %v", err)
	}
	if len(res.IgnoredEvents) != 1 {
		t.Errorf("expected 1 ignored event, got %v", res.IgnoredEvents)
	}
	emitted := audit.snapshot()
	if len(emitted) != 1 || emitted[0].eventType != "caep.unknown_event" {
		t.Errorf("audit events: %+v", emitted)
	}
}

func TestProcessSET_EmptyEvents(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.JTI = "empty-events"
	claims.Events = map[string]EventPayload{}
	setJWT := signSET(t, key, claims)

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrEmptyEvents) {
		t.Errorf("want ErrEmptyEvents, got %v", err)
	}
}

func TestProcessSET_UnknownSubjectFormat(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	claims := baseClaims()
	claims.JTI = "bad-subject-format"
	for k, v := range claims.Events {
		v.Subject = Subject{Format: "phone_number", Email: "+1-555-0000"}
		claims.Events[k] = v
	}
	setJWT := signSET(t, key, claims)

	_, err := r.ProcessSET(context.Background(), setJWT)
	if !errors.Is(err, ErrUnknownSubjectFmt) {
		t.Errorf("want ErrUnknownSubjectFmt, got %v", err)
	}
}

func TestAudienceField_BothShapes(t *testing.T) {
	var a audienceField
	if err := a.UnmarshalJSON([]byte(`"https://x/"`)); err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0] != "https://x/" {
		t.Errorf("string aud: %v", a)
	}
	var b audienceField
	if err := b.UnmarshalJSON([]byte(`["https://x/","https://y/"]`)); err != nil {
		t.Fatal(err)
	}
	if len(b) != 2 {
		t.Errorf("array aud: %v", b)
	}
	if !b.contains("https://y/") {
		t.Errorf("contains: %v", b)
	}
}

func TestHTTPHandler_HappyPath(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	setJWT := signSET(t, key, baseClaims())

	h := HTTPHandler(r)
	req := httptest.NewRequest("POST", "/caep/events", strings.NewReader(setJWT))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Errorf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandler_WrongCT(t *testing.T) {
	r, _, _, _, _ := newReceiverFixture(t)
	h := HTTPHandler(r)
	req := httptest.NewRequest("POST", "/caep/events", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 415 {
		t.Errorf("want 415, got %d", rec.Code)
	}
}

func TestHTTPHandler_MethodNotAllowed(t *testing.T) {
	r, _, _, _, _ := newReceiverFixture(t)
	h := HTTPHandler(r)
	req := httptest.NewRequest("GET", "/caep/events", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Errorf("want 405, got %d", rec.Code)
	}
}

func TestHTTPHandler_BadSig401(t *testing.T) {
	r, _, _, _, _ := newReceiverFixture(t)
	wrong := newRSAKey(t)
	setJWT := signSET(t, wrong, baseClaims())

	h := HTTPHandler(r)
	req := httptest.NewRequest("POST", "/caep/events", strings.NewReader(setJWT))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("want 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPHandler_Replay429(t *testing.T) {
	r, key, _, _, _ := newReceiverFixture(t)
	setJWT := signSET(t, key, baseClaims())

	h := HTTPHandler(r)
	for i, want := range []int{202, 429} {
		req := httptest.NewRequest("POST", "/caep/events", strings.NewReader(setJWT))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("attempt %d: want %d got %d (%s)", i+1, want, rec.Code, rec.Body.String())
		}
	}
}
