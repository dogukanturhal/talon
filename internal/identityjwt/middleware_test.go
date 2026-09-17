// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hexxlock/talon/internal/session"
)

// endToEndTestRig builds a complete Talon-mint → JWKS-serve →
// Middleware-verify chain in-process. Returns:
//   - signer (mint tokens for tests)
//   - verifier (the SUT)
//   - mountedHandler (call this with httptest.ResponseRecorder)
//   - capturedClaims (filled by the inner handler on success)
func endToEndTestRig(t *testing.T, opts ...MiddlewareOptions) (
	signer *Signer, verifier *Verifier,
	mountedHandler http.Handler,
	capturedClaims **IdentityClaims,
) {
	t.Helper()
	s, err := NewSignerFromPEM(genTestKey(t), "https://internal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	jwksURL, _ := jwksTestServer(t, s)

	v, err := NewVerifier(VerifierConfig{
		JWKSURL:          jwksURL,
		ExpectedIssuer:   "https://internal.example.com",
		ExpectedAudience: "ghcr.io/dogukanturhal",
	})
	if err != nil {
		t.Fatal(err)
	}

	var captured *IdentityClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ClaimsFromContext(r.Context())
		_, _ = io.WriteString(w, "ok")
	})

	return s, v, Middleware(v, opts...)(inner), &captured
}

func TestMiddleware_EndToEnd_PropagatesClaims(t *testing.T) {
	signer, _, mounted, capturedRef := endToEndTestRig(t)

	blob := &session.Blob{
		Sub:        "5e163cc4-87aa-4c0c-8985-db1134f8b436",
		Email:      "dogukanturhal@example.com",
		Groups:     []string{"platform_admin", "iam_admin"},
		TenantID:   "tenant-1",
		SSOChainID: "chain-1",
	}
	token, err := signer.Sign(blob, "ghcr.io/dogukanturhal")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set(HeaderName, token)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	got := *capturedRef
	if got == nil {
		t.Fatal("inner handler ran but ClaimsFromContext returned nil — context propagation broken")
	}
	if got.Subject != blob.Sub {
		t.Errorf("claims.sub = %q, want %q", got.Subject, blob.Sub)
	}
	if got.Email != blob.Email {
		t.Errorf("claims.email = %q", got.Email)
	}
	if len(got.Groups) != 2 {
		t.Errorf("claims.groups len = %d, want 2", len(got.Groups))
	}
}

func TestMiddleware_RejectsNoToken_WithJSON401(t *testing.T) {
	_, _, mounted, capturedRef := endToEndTestRig(t)

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	// No header — Phase B fails closed.
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("content-type = %q, want application/json", got)
	}
	var body struct {
		Error  string `json:"error"`
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Code != "iap_token_missing" {
		t.Errorf("code = %q, want iap_token_missing", body.Code)
	}
	if *capturedRef != nil {
		t.Error("inner handler must NOT run when verify fails")
	}
}

func TestMiddleware_AllowMissingFallsThrough(t *testing.T) {
	_, _, mounted, capturedRef := endToEndTestRig(t, MiddlewareOptions{AllowMissing: true})

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (AllowMissing path)", rr.Code)
	}
	if *capturedRef != nil {
		t.Error("ClaimsFromContext should be nil when AllowMissing let the request through without a token")
	}
}

func TestMiddleware_RejectsBadAudience_WithReasonCode(t *testing.T) {
	signer, _, mounted, _ := endToEndTestRig(t)
	// Mint for the wrong audience.
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "internal.example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set(HeaderName, token)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	var body struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Code != "iap_token_invalid" {
		t.Errorf("code = %q, want iap_token_invalid", body.Code)
	}
	if body.Reason != "audience_mismatch" {
		t.Errorf("reason = %q, want audience_mismatch", body.Reason)
	}
}

func TestMiddleware_RejectsExpired_WithReasonCode(t *testing.T) {
	signer, _, mounted, _ := endToEndTestRig(t)

	// Mint a token whose exp is far in the past.
	expiredToken := signerMintExpired(t, signer, "ghcr.io/dogukanturhal")

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set(HeaderName, expiredToken)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	var body struct {
		Code, Reason string
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Code != "iap_token_invalid" {
		t.Errorf("code = %q, want iap_token_invalid", body.Code)
	}
	if body.Reason != "expired" {
		t.Errorf("reason = %q, want expired", body.Reason)
	}
}

func TestMiddleware_JWKSUnavailable_DistinctCode(t *testing.T) {
	signer, _ := NewSignerFromPEM(genTestKey(t), "https://auth.ops")
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "a")

	// JWKS server returns 503 — distinguishable from "bad token".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no key", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	v, _ := NewVerifier(VerifierConfig{
		JWKSURL: srv.URL, ExpectedIssuer: "https://auth.ops", ExpectedAudience: "a",
	})
	mounted := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should not reach")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderName, token)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	var body struct{ Code string }
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Code != "iap_jwks_unavailable" {
		t.Errorf("code = %q, want iap_jwks_unavailable (distinguishes ops issue from client-bad-token)", body.Code)
	}
}

func TestMiddleware_NilVerifierFailsClosed(t *testing.T) {
	mounted := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should not reach")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("nil verifier should fail closed, got %d", rr.Code)
	}
}

func TestMiddleware_CustomOnUnverifiedReceivesClassification(t *testing.T) {
	captured := struct {
		Code   string
		Reason string
		Err    error
	}{}
	signer, _, mounted, _ := endToEndTestRig(t, MiddlewareOptions{
		OnUnverified: func(w http.ResponseWriter, _ *http.Request, f VerifyFailure) {
			captured.Code = f.Code
			captured.Reason = f.Reason
			captured.Err = f.Err
			http.Error(w, "custom", http.StatusForbidden)
		},
	})

	// Sign for the wrong issuer.
	wrongIssSigner, _ := NewSignerFromPEM(genTestKey(t), "https://wrong.issuer")
	_ = signer
	token, _ := wrongIssSigner.Sign(&session.Blob{Sub: "u"}, "ghcr.io/dogukanturhal")
	// The verifier won't find this signer's kid in the JWKS, so the
	// failure will surface as ErrSignatureInvalid (the JWKS publishes
	// the test rig's signer, not wrongIssSigner). Test that the
	// classification reaches OnUnverified.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderName, token)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("custom OnUnverified should have set 403, got %d", rr.Code)
	}
	if captured.Code != "iap_token_invalid" {
		t.Errorf("captured.Code = %q, want iap_token_invalid", captured.Code)
	}
	if captured.Reason != "signature_failed" {
		t.Errorf("captured.Reason = %q, want signature_failed (wrong-kid JWT)", captured.Reason)
	}
	if captured.Err == nil {
		t.Error("captured.Err should be non-nil for logging")
	}
}

func TestClaimsFromContext_NilSafe(t *testing.T) {
	//nolint:staticcheck // explicit nil context to assert defensive behaviour
	if got := ClaimsFromContext(nil); got != nil {
		t.Errorf("nil context should return nil, got %+v", got)
	}
	if got := ClaimsFromContext(context.Background()); got != nil {
		t.Errorf("empty context should return nil, got %+v", got)
	}
}

// signerMintExpired produces a valid-signature token whose exp is far
// in the past. Verifier must reject with ErrTokenExpired.
func signerMintExpired(t *testing.T, s *Signer, audience string) string {
	t.Helper()
	// Hack: temporarily swap lifetime to negative so Sign produces an
	// already-expired token.
	s.mu.Lock()
	origLifetime := s.lifetime
	s.lifetime = -10 * 60 * 1_000_000_000 // -10 minutes in nanoseconds
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.lifetime = origLifetime
		s.mu.Unlock()
	}()
	tok, err := s.Sign(&session.Blob{Sub: "u"}, audience)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestMiddleware_VerifierErrorOpaqueToClient(t *testing.T) {
	// Defense-in-depth: a verify failure should NEVER leak the internal
	// error message to the client. The default response is a stable
	// JSON shape; the raw err is only available to the OnUnverified
	// callback (for logging).
	signer, _, mounted, _ := endToEndTestRig(t)
	token, _ := signer.Sign(&session.Blob{Sub: "u"}, "argocd.ops")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderName, token)
	rr := httptest.NewRecorder()
	mounted.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatal()
	}
	bodyStr := rr.Body.String()
	if strings.Contains(bodyStr, "got") || strings.Contains(bodyStr, "want") {
		t.Errorf("response leaks internal verifier-error wording: %q", bodyStr)
	}
}

// Sanity: errors.Is on a wrapped ErrTokenExpired still classifies.
func TestClassifyReason_WrappedErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ErrSignatureInvalid, "signature_failed"},
		{ErrTokenExpired, "expired"},
		{ErrIssuerMismatch, "issuer_mismatch"},
		{ErrAudienceMismatch, "audience_mismatch"},
		{ErrTokenNotYetValid, "not_yet_valid"},
		{ErrAlgNotAllowed, "alg_not_allowed"},
		{ErrTokenMalformed, "jwt_invalid"},
		{errors.New("something else"), "unknown"},
	} {
		if got := classifyReason(tc.err); got != tc.want {
			t.Errorf("classifyReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
