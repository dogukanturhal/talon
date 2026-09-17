// SPDX-License-Identifier: AGPL-3.0-or-later

package extauthz

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	codes "google.golang.org/grpc/codes"

	"github.com/dogukanturhal/talon/internal/router"
)

// fakeVerifier substitutes the production Router so tests don't have
// to construct sessions/SpiceDB/audit/etc. The test asserts the wire
// adapter (extauthz.Server) faithfully translates between Envoy
// CheckRequest/Response and router.VerifyInput/Decision — NOT the
// decision flow itself (that's tested in internal/router).
type fakeVerifier struct {
	lastIn    router.VerifyInput
	decision  router.VerifyDecision
}

func (f *fakeVerifier) Verify(_ context.Context, in router.VerifyInput) router.VerifyDecision {
	f.lastIn = in
	return f.decision
}

func makeReq(host, cookie, method, path, xff string) *authv3.CheckRequest {
	hdrs := map[string]string{}
	if host != "" {
		hdrs["x-forwarded-host"] = host
	}
	if cookie != "" {
		hdrs["cookie"] = cookie
	}
	if xff != "" {
		hdrs["x-forwarded-for"] = xff
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  method,
					Path:    path,
					Headers: hdrs,
				},
			},
		},
	}
}

func TestCheck_Allowed_InjectsIdentityHeaders(t *testing.T) {
	fv := &fakeVerifier{
		decision: router.VerifyDecision{
			Allowed: true,
			IdentityHeaders: map[string]string{
				"X-Talon-User":    "sub-abc",
				"X-Talon-Email":   "user@example.com",
				"X-Talon-Subject": "sub-abc",
				"X-Talon-Groups":  "admin,sre",
			},
		},
	}
	s := NewServer(fv)

	resp, err := s.Check(context.Background(),
		makeReq("internal.example.com", "talon_session=abc123", "GET", "/api/v1/query", ""))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if got := resp.GetStatus().GetCode(); got != int32(codes.OK) {
		t.Errorf("status code: want OK(%d), got %d", codes.OK, got)
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected OkResponse, got %T", resp.GetHttpResponse())
	}
	gotHeaders := map[string]string{}
	for _, h := range ok.GetHeaders() {
		gotHeaders[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
		if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Errorf("header %q: want OVERWRITE_IF_EXISTS_OR_ADD, got %v",
				h.GetHeader().GetKey(), h.GetAppendAction())
		}
	}
	for k, v := range fv.decision.IdentityHeaders {
		if gotHeaders[k] != v {
			t.Errorf("header %q: want %q, got %q", k, v, gotHeaders[k])
		}
	}
}

func TestCheck_Denied_EmitsRFC9470Challenge(t *testing.T) {
	// Phase 6b-3 — when Verify returns MFARequired=true with a
	// WWWAuthenticate header value, the gRPC adapter MUST surface it
	// in DeniedHttpResponse.Headers so APISIX / Envoy / Istio
	// downstreams can branch on the RFC 9470 challenge.
	fv := &fakeVerifier{
		decision: router.VerifyDecision{
			Allowed:         false,
			Reason:          "mfa_required",
			MFARequired:     true,
			WWWAuthenticate: `Bearer error="insufficient_user_authentication", acr_values="urn:hexxlock:aal2"`,
		},
	}
	s := NewServer(fv)

	resp, err := s.Check(context.Background(),
		makeReq("internal.example.com", "talon_session=x", "GET", "/admin/", ""))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected DeniedResponse")
	}
	gotWWW := ""
	for _, h := range denied.GetHeaders() {
		if h.GetHeader().GetKey() == "WWW-Authenticate" {
			gotWWW = h.GetHeader().GetValue()
		}
	}
	if !contains(gotWWW, "insufficient_user_authentication") {
		t.Errorf("WWW-Authenticate must carry RFC 9470 error param; got %q", gotWWW)
	}
	if !contains(gotWWW, "urn:hexxlock:aal2") {
		t.Errorf("WWW-Authenticate must carry acr_values; got %q", gotWWW)
	}
}

func TestCheck_Denied_NoWWWAuthenticateWhenAbsent(t *testing.T) {
	// Regular deny (not step-up) MUST NOT emit WWW-Authenticate —
	// otherwise calling proxies see a phantom challenge that doesn't
	// match the route's actual step-up policy.
	fv := &fakeVerifier{
		decision: router.VerifyDecision{
			Allowed: false,
			Reason:  "no_session",
		},
	}
	s := NewServer(fv)

	resp, err := s.Check(context.Background(),
		makeReq("h", "", "GET", "/", ""))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, h := range resp.GetDeniedResponse().GetHeaders() {
		if h.GetHeader().GetKey() == "WWW-Authenticate" {
			t.Errorf("regular deny should NOT emit WWW-Authenticate; got %q",
				h.GetHeader().GetValue())
		}
	}
}

// contains is a tiny helper so the test file stays strings-import-free.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestCheck_Denied_Returns401WithReason(t *testing.T) {
	fv := &fakeVerifier{
		decision: router.VerifyDecision{
			Allowed: false,
			Reason:  "no_session",
		},
	}
	s := NewServer(fv)

	resp, err := s.Check(context.Background(),
		makeReq("internal.example.com", "", "GET", "/", ""))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if got := resp.GetStatus().GetCode(); got != int32(codes.PermissionDenied) {
		t.Errorf("status code: want PermissionDenied(%d), got %d", codes.PermissionDenied, got)
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected DeniedResponse, got %T", resp.GetHttpResponse())
	}
	if denied.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
		t.Errorf("HTTP status: want 401 Unauthorized, got %v", denied.GetStatus().GetCode())
	}
	gotReason := ""
	gotCacheControl := ""
	for _, h := range denied.GetHeaders() {
		if h.GetHeader().GetKey() == "X-Talon-Reason" {
			gotReason = h.GetHeader().GetValue()
		}
		if h.GetHeader().GetKey() == "Cache-Control" {
			gotCacheControl = h.GetHeader().GetValue()
		}
	}
	if gotReason != "no_session" {
		t.Errorf("X-Talon-Reason: want no_session, got %q", gotReason)
	}
	if gotCacheControl != "no-store" {
		t.Errorf("Cache-Control: want no-store, got %q", gotCacheControl)
	}
}

func TestCheck_HostExtraction_PrefersXForwardedHost(t *testing.T) {
	fv := &fakeVerifier{decision: router.VerifyDecision{Allowed: true}}
	s := NewServer(fv)

	req := makeReq("internal.example.com", "talon_session=x", "GET", "/", "")
	// Also set the :authority/Host on the underlying httpReq — extauthz
	// must prefer x-forwarded-host (APISIX sets that as the original
	// host, while :authority is the auth-host the subrequest targets).
	req.Attributes.Request.Http.Host = "internal.example.com"

	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fv.lastIn.Host != "internal.example.com" {
		t.Errorf("Host: want x-forwarded-host (internal.example.com), got %q", fv.lastIn.Host)
	}
}

func TestCheck_HostExtraction_FallsBackToAuthority(t *testing.T) {
	fv := &fakeVerifier{decision: router.VerifyDecision{Allowed: true}}
	s := NewServer(fv)

	req := makeReq("", "talon_session=x", "GET", "/", "")
	req.Attributes.Request.Http.Host = "internal.example.com"

	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fv.lastIn.Host != "internal.example.com" {
		t.Errorf("Host: want :authority fallback, got %q", fv.lastIn.Host)
	}
}

func TestCheck_CookieExtraction(t *testing.T) {
	fv := &fakeVerifier{decision: router.VerifyDecision{Allowed: true}}
	s := NewServer(fv)

	// Multiple cookies, target one is in the middle of the list.
	req := makeReq("h", "_ga=GA1.123; talon_session=xyz789; theme=dark", "GET", "/", "")
	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fv.lastIn.CookieValue != "xyz789" {
		t.Errorf("CookieValue: want xyz789, got %q", fv.lastIn.CookieValue)
	}
}

func TestCheck_CookieAbsent_PassesEmpty(t *testing.T) {
	fv := &fakeVerifier{decision: router.VerifyDecision{Allowed: false, Reason: "no_session"}}
	s := NewServer(fv)

	// No Cookie header at all.
	req := makeReq("h", "", "GET", "/", "")
	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fv.lastIn.CookieValue != "" {
		t.Errorf("CookieValue: want empty, got %q", fv.lastIn.CookieValue)
	}
}

func TestCheck_SrcIPExtraction_PrefersXFF(t *testing.T) {
	fv := &fakeVerifier{decision: router.VerifyDecision{Allowed: true}}
	s := NewServer(fv)

	req := makeReq("h", "talon_session=x", "GET", "/", "203.0.113.42, 198.51.100.1")
	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if fv.lastIn.SrcIP != "203.0.113.42" {
		t.Errorf("SrcIP: want first-XFF (203.0.113.42), got %q", fv.lastIn.SrcIP)
	}
}

func TestExtractCookieValue_Edge(t *testing.T) {
	cases := []struct {
		header, name, want string
	}{
		{"", "talon_session", ""},
		{"talon_session=abc", "talon_session", "abc"},
		{"foo=bar; talon_session=abc", "talon_session", "abc"},
		{"foo=bar; talon_session=abc; baz=qux", "talon_session", "abc"},
		{"talon_session=", "talon_session", ""},
		{"talon=abc", "talon_session", ""}, // prefix-match must NOT match
		{"talon_session_x=abc", "talon_session", ""}, // suffix-match must NOT match
	}
	for _, tc := range cases {
		if got := extractCookieValue(tc.header, tc.name); got != tc.want {
			t.Errorf("extractCookieValue(%q, %q) = %q, want %q",
				tc.header, tc.name, got, tc.want)
		}
	}
}

func TestFirstIPFromHeader_Edge(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4, 5.6.7.8", "1.2.3.4"},
		{"  1.2.3.4  ,  5.6.7.8  ", "1.2.3.4"},
		{",1.2.3.4", ""},
	}
	for _, tc := range cases {
		if got := firstIPFromHeader(tc.in); got != tc.want {
			t.Errorf("firstIPFromHeader(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
