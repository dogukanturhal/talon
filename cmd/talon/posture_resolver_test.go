// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import "testing"

func TestNewPostureJWKSResolver_DerivesPerIssuerURL(t *testing.T) {
	r := newPostureJWKSResolver([]string{"https://posture.hexxlock.com"}, "")
	c, ok := r.clients["https://posture.hexxlock.com"]
	if !ok {
		t.Fatal("issuer not registered")
	}
	want := "https://posture.hexxlock.com/.well-known/jwks.json"
	if c.url != want {
		t.Fatalf("derived URL = %q, want %q", c.url, want)
	}
}

func TestNewPostureJWKSResolver_OverrideAppliesToAllIssuers(t *testing.T) {
	override := "http://posture-signer.talon.svc.cluster.local:8080/.well-known/jwks.json"
	issuers := []string{"https://posture.hexxlock.com", "https://posture.tenant-b.example"}
	r := newPostureJWKSResolver(issuers, override)
	for _, iss := range issuers {
		c, ok := r.clients[iss]
		if !ok {
			t.Fatalf("issuer %q not registered", iss)
		}
		// The override fetches the key from the in-cluster Service for every
		// issuer; the `iss` claim itself is still verified separately against
		// the trusted set by the posture verifier.
		if c.url != override {
			t.Fatalf("issuer %q URL = %q, want override %q", iss, c.url, override)
		}
	}
}
