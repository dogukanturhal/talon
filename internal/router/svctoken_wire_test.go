// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"testing"

	"github.com/dogukanturhal/talon/internal/proxy"
	"github.com/dogukanturhal/talon/internal/svctoken"
)

// TestRegisterUpstream_AuthModeDefaults verifies the back-compat
// invariant: an upstream registered without an explicit AuthMode
// resolves to svctoken.AuthModeCookie. Phase 3 of talon-service-tokens
// adds the bearer path additively — existing callers (env-var
// ProtectedHosts that don't set authMode, TalonRoute CRs created
// before this change) MUST keep browser-only behaviour.
func TestRegisterUpstream_AuthModeDefaults(t *testing.T) {
	r := &Router{upstreams: map[string]upstreamEntry{}}
	r.RegisterUpstream("test.example.com", RegisterUpstreamParams{
		Handler: proxy.NewHandler("test.example.com",
			proxy.Upstream{Service: "svc.ns:80"}, nil),
		Permission: "viewer",
		// AuthMode deliberately unset.
	})
	got := r.upstreams["test.example.com"].authMode
	if got != svctoken.AuthModeCookie {
		t.Errorf("AuthMode default = %q, want %q (back-compat)",
			got, svctoken.AuthModeCookie)
	}
}

// TestRegisterUpstream_AuthModeCarried verifies that an explicit
// AuthMode value plumbed through RegisterUpstreamParams reaches the
// upstreamEntry verbatim. Covers the three valid values: bearer, both,
// cookie.
func TestRegisterUpstream_AuthModeCarried(t *testing.T) {
	for _, mode := range []svctoken.AuthMode{
		svctoken.AuthModeCookie,
		svctoken.AuthModeBearer,
		svctoken.AuthModeBoth,
	} {
		t.Run(string(mode), func(t *testing.T) {
			r := &Router{upstreams: map[string]upstreamEntry{}}
			r.RegisterUpstream("host."+string(mode)+".test", RegisterUpstreamParams{
				Handler: proxy.NewHandler("host", proxy.Upstream{Service: "svc.ns:80"}, nil),
				AuthMode: mode,
			})
			got := r.upstreams["host."+string(mode)+".test"].authMode
			if got != mode {
				t.Errorf("AuthMode = %q, want %q", got, mode)
			}
		})
	}
}

// TestRegisterUpstream_InvalidAuthMode_FallsBackToCookie verifies the
// defensive coercion of an unrecognised AuthMode string to
// AuthModeCookie. This is the safe default — a typoed value should not
// silently downgrade a host into bearer-only or both mode (which would
// open the bearer code path unexpectedly).
func TestRegisterUpstream_InvalidAuthMode_FallsBackToCookie(t *testing.T) {
	r := &Router{upstreams: map[string]upstreamEntry{}}
	r.RegisterUpstream("typo.example.com", RegisterUpstreamParams{
		Handler: proxy.NewHandler("typo.example.com",
			proxy.Upstream{Service: "svc.ns:80"}, nil),
		AuthMode: svctoken.AuthMode("garbage-value"),
	})
	got := r.upstreams["typo.example.com"].authMode
	if got != svctoken.AuthModeCookie {
		t.Errorf("invalid AuthMode = %q, want %q (defensive coerce)",
			got, svctoken.AuthModeCookie)
	}
}

// TestSetSvctokenVerifier_NilByDefault verifies the constructor leaves
// the verifier nil — i.e., the legacy cookie-only path is active until
// SetSvctokenVerifier is explicitly called from cmd/talon/main.go with
// cfg.SvctokenEnabled=true. Critical for back-compat: an operator who
// hasn't flipped the flag must see ZERO behaviour change after this
// change ships.
func TestSetSvctokenVerifier_NilByDefault(t *testing.T) {
	r := &Router{upstreams: map[string]upstreamEntry{}}
	if r.svctokenVerifier != nil {
		t.Errorf("svctokenVerifier = %v, want nil (default)", r.svctokenVerifier)
	}
}

// TestSetSvctokenVerifier_SetsField verifies that SetSvctokenVerifier
// actually plumbs the verifier into the Router struct.
func TestSetSvctokenVerifier_SetsField(t *testing.T) {
	r := &Router{upstreams: map[string]upstreamEntry{}}
	v, err := svctoken.NewVerifier(svctoken.VerifierConfig{
		JWKSURL:        "https://id.test/.well-known/jwks.json",
		ExpectedIssuer: "https://id.test",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	r.SetSvctokenVerifier(v)
	if r.svctokenVerifier != v {
		t.Error("SetSvctokenVerifier did not plumb the verifier into the Router")
	}
}
