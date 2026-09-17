// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tests for AuthModeCookieOrBearerOrPassthrough (Path B unified mode).
// Pairs with TestDecide_CredentialExchange_* / TestDecide_BearerOrPassthrough_*
// to enforce the wire-shape-driven dispatch documented at
// AuthModeCookieOrBearerOrPassthrough's godoc block. Adding a new
// mode that hits any of these branches should add a sibling test
// here.

// TestDecide_CookieOrBearerOrPassthrough_NoHeader_NotAttempted — the
// browser branch. No Authorization header at all → cookie/OIDC path
// runs next. This is the differentiator from
// AuthModeBearerOrBasicWithCredentialExchange (which passthroughs)
// and AuthModeBoth (which fallthroughs without checking Bearer first).
func TestDecide_CookieOrBearerOrPassthrough_NoHeader_NotAttempted(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeNotAttempted {
		t.Fatalf("no-auth must route to cookie path: got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims != nil {
		t.Errorf("no claims should be attached for cookie path: got %+v", d.Claims)
	}
}

// TestDecide_CookieOrBearerOrPassthrough_BearerSvctoken_Authorised —
// the machine branch. ArgoCD / posture-signer / other Talon-aware
// consumers send Bearer<svctoken>; verify → claims attached →
// router runs the credential-exchange substitution downstream.
func TestDecide_CookieOrBearerOrPassthrough_BearerSvctoken_Authorised(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/api/v4/projects", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeAuthorised {
		t.Fatalf("valid Bearer svctoken must authorise: got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.ClientID != "svc-argocd-repo-server" {
		t.Errorf("claims = %+v", d.Claims)
	}
}

// TestDecide_CookieOrBearerOrPassthrough_BasicWithJWT_Authorised —
// the wire shape Argo go-git produces from a repoCreds Secret
// (`Authorization: Basic base64(oauth2:<jwt>)`). Same authorise
// outcome as the explicit Bearer form so the new mode is parity
// with bearer_or_basic_with_credential_exchange on the machine path.
func TestDecide_CookieOrBearerOrPassthrough_BasicWithJWT_Authorised(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/dogukanturhal/repo.git/info/refs", nil)
	r.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("oauth2:"+tok)))
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeAuthorised {
		t.Fatalf("Basic<*:svctoken> must authorise: got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims == nil || d.Claims.ClientID != "svc-argocd-repo-server" {
		t.Errorf("claims = %+v", d.Claims)
	}
}

// TestDecide_CookieOrBearerOrPassthrough_LegacyPAT_Passthrough — the
// legacy compat branch. Atlantis/Renovate/image-updater send
// `Authorization: Basic oauth2:glpat-<PAT>`; the JWT extractor finds
// no svctoken-shape content in the password slot, returns ErrNoToken,
// and the dispatch routes to OutcomePassthrough so the upstream
// (GitLab) handles its own native PAT auth. Without this, the new
// mode would break every existing PAT caller the moment it ships.
func TestDecide_CookieOrBearerOrPassthrough_LegacyPAT_Passthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodPost, "https://github.com/api/v4/projects/2/merge_requests", nil)
	r.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-LegacyAtlantisPAT12345"))) // gitleaks:allow — test fixture, not a real credential
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Fatalf("legacy PAT must passthrough: got %v err=%v", d.Outcome, d.Err)
	}
	if d.Claims != nil {
		t.Errorf("no claims should be attached on passthrough: got %+v", d.Claims)
	}
}

// TestDecide_CookieOrBearerOrPassthrough_BadBearer_Rejected — the
// Envoy CVE-2021-21378 invariant. A present-but-broken Bearer is an
// explicit identity assertion; silently downgrading to either the
// cookie path or passthrough would let an attacker with a forged
// Bearer get free access on permissive upstreams. Must 401.
func TestDecide_CookieOrBearerOrPassthrough_BadBearer_Rejected(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Header.Set("Authorization", "Bearer aaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc")
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeRejected {
		t.Fatalf("forged Bearer must reject: got %v err=%v", d.Outcome, d.Err)
	}
}

// TestAuthMode_CookieOrBearerOrPassthrough_IsValid — guards against
// the bug class where a new mode is added to the CRD enum but not to
// the in-process IsValid() allowlist, causing every request on the
// new mode to fail Talon's defensive bad-mode check at the top of
// Decide(). The CRD enum validates at API-server admission time;
// IsValid() validates at request time. Both must accept the value.
func TestAuthMode_CookieOrBearerOrPassthrough_IsValid(t *testing.T) {
	if !AuthModeCookieOrBearerOrPassthrough.IsValid() {
		t.Error("AuthModeCookieOrBearerOrPassthrough must validate")
	}
	if !AuthMode("cookie_or_bearer_or_passthrough").IsValid() {
		t.Error("string form must validate")
	}
}

// TestAuthMode_SupportsCredentialExchange pins which modes the router
// must run the upstream-credential substitution on.
//
// Regression guard. The router previously gated substitution on a
// direct equality check against AuthModeBearerOrBasicWithCredentialExchange,
// which silently excluded AuthModeCookieOrBearerOrPassthrough even
// though that mode's godoc promises credential exchange (and the
// sibling test above says the router "runs the credential-exchange
// substitution downstream" for exactly this branch).
//
// The failure mode was invisible rather than loud: Talon verified the
// caller's token, authorised the request, and forwarded it WITHOUT a
// credential the upstream could understand. On internal.example.com
// (Verdaccio, which cannot validate Falcon-ID JWTs) a correctly-scoped
// token produced `GET /-/whoami -> 200 {}` and 401 on every private
// package — an authorised caller unable to read its own packages.
//
// A new AuthMode whose doc comment mentions credential exchange must
// be added to BOTH the predicate and this table.
func TestAuthMode_SupportsCredentialExchange(t *testing.T) {
	for _, tc := range []struct {
		mode AuthMode
		want bool
		why  string
	}{
		{AuthModeBearerOrBasicWithCredentialExchange, true,
			"Phase 4.5 mode — credential exchange IS the mode"},
		{AuthModeCookieOrBearerOrPassthrough, true,
			"Path B unified mode — godoc promises credential exchange on the Bearer branch"},
		{AuthModeCookie, false, "browser-only; Bearer ignored, nothing to exchange"},
		{AuthModeBearer, false, "machine-only, no substitution in its contract"},
		{AuthModeBoth, false, "Bearer+cookie, but explicitly 'no credential substitution'"},
		{AuthModeBearerOrPassthrough, false, "forwards the original Authorization intact"},
		{AuthModeBearerOrFederatedPassthrough, false, "federated trust, still passthrough"},
		{AuthMode(""), false, "unset defaults to cookie behaviour"},
		{AuthMode("nonsense"), false, "unknown modes must not trigger substitution"},
	} {
		if got := tc.mode.SupportsCredentialExchange(); got != tc.want {
			t.Errorf("AuthMode(%q).SupportsCredentialExchange() = %v, want %v (%s)",
				tc.mode, got, tc.want, tc.why)
		}
	}
}

// TestAuthMode_SupportsCredentialExchange_ImpliesValid guards against a
// predicate that returns true for a mode the router would reject
// upstream — substitution must never be reachable on an invalid mode.
func TestAuthMode_SupportsCredentialExchange_ImpliesValid(t *testing.T) {
	for _, m := range []AuthMode{
		AuthModeCookie, AuthModeBearer, AuthModeBoth,
		AuthModeBearerOrPassthrough,
		AuthModeBearerOrBasicWithCredentialExchange,
		AuthModeBearerOrFederatedPassthrough,
		AuthModeCookieOrBearerOrPassthrough,
		AuthMode(""), AuthMode("nonsense"),
	} {
		if m.SupportsCredentialExchange() && !m.IsValid() {
			t.Errorf("AuthMode(%q) supports credential exchange but is not valid", m)
		}
	}
}
