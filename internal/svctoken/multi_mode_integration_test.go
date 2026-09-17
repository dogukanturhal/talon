// SPDX-License-Identifier: AGPL-3.0-or-later

package svctoken

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Integration tests for AuthModeCookieOrBearerOrPassthrough that
// cross-check interaction with other features layered on top of the
// dispatch — federated trust, the cookie/Bearer arbitration boundary,
// and edge cases that the per-test surface in multi_mode_test.go
// would miss.

// TestIntegration_CookieOrBearerOrPassthrough_FederatedBearer_Passthrough —
// the new mode SHOULD compose with federated trust. A foreign-issuer
// Bearer (e.g. a future GitLab CI runner OIDC token, or any partner-
// signed Bearer) verifies against the federated registry and proxies
// through with the Bearer preserved. This is the same wire shape as
// AuthModeBearerOrFederatedPassthrough's federated branch, layered on
// top of the new mode's no-auth=cookie semantics.
func TestIntegration_CookieOrBearerOrPassthrough_FederatedBearer_Passthrough(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "gitlab-runner-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"github.com"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := fs.mint(t, "gitlab-runner-issuer", "gitlab-api", time.Time{})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/api/v4/jobs/request", nil)
	r.Host = "github.com"
	r.Header.Set("Authorization", "Bearer "+tok)
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomePassthrough {
		t.Errorf("federated Bearer on the new mode: want OutcomePassthrough, got %v (err=%v)", d.Outcome, d.Err)
	}
	if d.Claims != nil {
		t.Errorf("federated passthrough: want nil Claims (foreign issuer shape), got %+v", d.Claims)
	}
}

// TestIntegration_CookieOrBearerOrPassthrough_NoAuthWithFederated_StillCookie —
// the differentiator from AuthModeBearerOrFederatedPassthrough. Even
// with federated issuers configured on the route, a no-Authorization
// request MUST route to the cookie path — not passthrough. This is the
// invariant that prevents the new mode from sneaking past device-
// posture enforcement on browser-shaped no-auth requests, which is the
// whole point of the new mode for ZTNA defense-in-depth.
func TestIntegration_CookieOrBearerOrPassthrough_NoAuthWithFederated_StillCookie(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "gitlab-runner-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"github.com"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://github.com/", nil)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeNotAttempted {
		t.Errorf("no-auth + federated configured: want OutcomeNotAttempted (cookie path), got %v (err=%v)", d.Outcome, d.Err)
	}
}

// TestIntegration_CookieOrBearerOrPassthrough_ForeignUnknownIssuer_Rejected —
// composition of the federated invariant (unknown iss → reject) with
// the new mode. A Bearer minted by an issuer NOT in either the
// primary or federated registry MUST OutcomeRejected, not silently
// downgrade to cookie or passthrough. Same CVE-2021-21378 invariant
// as AuthModeBearerOrFederatedPassthrough.
func TestIntegration_CookieOrBearerOrPassthrough_ForeignUnknownIssuer_Rejected(t *testing.T) {
	fid := newTokenFactory(t)
	fs := newForeignSigner(t)
	attacker := newForeignSigner(t)
	v, err := NewVerifier(VerifierConfig{
		JWKSURL:        fid.jwksURL,
		ExpectedIssuer: "https://id.test",
		FederatedIssuers: []FederatedIssuerConfig{{
			Issuer:          "gitlab-runner-issuer",
			StaticPublicKey: fs.pubKey(),
			AllowedHosts:    []string{"github.com"},
		}},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := attacker.mint(t, "evil-issuer", "gitlab-api", time.Time{})
	r := httptest.NewRequest(http.MethodGet, "https://github.com/api/v4/projects", nil)
	r.Host = "github.com"
	r.Header.Set("Authorization", "Bearer "+tok)
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeRejected {
		t.Errorf("unknown-iss Bearer: want OutcomeRejected, got %v (err=%v)", d.Outcome, d.Err)
	}
}

// TestIntegration_CookieOrBearerOrPassthrough_TokenInvalid_NeverPassthrough —
// the no-silent-downgrade invariant across the new mode's full
// dispatch matrix. Verifies that a valid-issuer-but-broken-signature
// Bearer does NOT fall through to either cookie or passthrough.
// Without this invariant, an attacker who knows the issuer URL
// could mint a malformed token and ride the passthrough.
func TestIntegration_CookieOrBearerOrPassthrough_TokenInvalid_NeverPassthrough(t *testing.T) {
	f := newTokenFactory(t)
	v := newVerifierAgainst(t, f, "https://id.test")
	// Use a known issuer but tamper with the signature.
	tok := f.mint(t, claimOpts{
		issuer:   "https://id.test",
		subject:  "svc-argocd-repo-server",
		audience: "https://github.com",
		clientID: "svc-argocd-repo-server",
		scope:    "talon:github.com:read",
	})
	// Tamper the signature in the MIDDLE, not at the end.
	//
	// Flipping the LAST base64url character is flaky: trailing bits of
	// the encoded signature can map to padding bits that get masked
	// out during decode, so the underlying signature bytes are
	// sometimes unchanged. Caught live 2026-06-14: CI failed ~40% of
	// runs even though the test asserts strict rejection. Mutating a
	// character in the middle of the signature segment guarantees the
	// decoded byte stream differs from the legitimate signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 segments, got %d", len(parts))
	}
	sig := parts[2]
	if len(sig) < 4 {
		t.Fatalf("signature segment too short to tamper safely: %q", sig)
	}
	mid := len(sig) / 2
	flipped := byte('A')
	if sig[mid] == 'A' {
		flipped = 'B'
	}
	tampered := parts[0] + "." + parts[1] + "." + sig[:mid] + string(flipped) + sig[mid+1:]
	if tampered == tok {
		t.Fatalf("tamper produced identical token; mid byte was already %q", flipped)
	}
	r := httptest.NewRequest(http.MethodGet, "https://github.com/api/v4/projects", nil)
	r.Header.Set("Authorization", "Bearer "+tampered)
	r.Host = "github.com"
	d := v.Decide(r, AuthModeCookieOrBearerOrPassthrough)
	if d.Outcome != OutcomeRejected {
		t.Errorf("tampered-sig Bearer: want OutcomeRejected, got %v (err=%v)", d.Outcome, d.Err)
	}
}
