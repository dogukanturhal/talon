// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func certWithURIs(t *testing.T, uris ...string) *x509.Certificate {
	t.Helper()
	c := &x509.Certificate{}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestAttestedTierFromCert(t *testing.T) {
	const spiffe = "spiffe://example.com/device/abc"
	cases := []struct {
		name string
		uris []string
		want string
	}{
		{"corp", []string{spiffe, "urn:hexxlock:device-tier:TIER_CORP"}, "TIER_CORP"},
		{"byod", []string{spiffe, "urn:hexxlock:device-tier:TIER_BYOD"}, "TIER_BYOD"},
		{"breakglass", []string{spiffe, "urn:hexxlock:device-tier:TIER_BREAKGLASS"}, "TIER_BREAKGLASS"},
		{"no tier SAN defaults to BYOD", []string{spiffe}, "TIER_BYOD"},
		{"unknown tier defaults to BYOD", []string{spiffe, "urn:hexxlock:device-tier:TIER_ROOT"}, "TIER_BYOD"},
		{"conflicting tiers default to BYOD", []string{spiffe, "urn:hexxlock:device-tier:TIER_CORP", "urn:hexxlock:device-tier:TIER_BYOD"}, "TIER_BYOD"},
		{"duplicate same tier ok", []string{spiffe, "urn:hexxlock:device-tier:TIER_CORP", "urn:hexxlock:device-tier:TIER_CORP"}, "TIER_CORP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := attestedTierFromCert(certWithURIs(t, tc.uris...)); got != tc.want {
				t.Errorf("tier=%q want %q", got, tc.want)
			}
		})
	}
}

func TestApplyAttestedCompliance_OverridesAgentClaims(t *testing.T) {
	req := &HeartbeatRequest{Compliance: map[string]any{
		"tier":              "TIER_CORP", // agent lies
		"device_cert_valid": false,
		"disk_encrypted":    true,
	}}
	applyAttestedCompliance(req, certWithURIs(t, "spiffe://example.com/device/abc"))
	if got := req.Compliance["tier"]; got != "TIER_BYOD" {
		t.Errorf("tier=%v want TIER_BYOD (no tier SAN)", got)
	}
	if got := req.Compliance["device_cert_valid"]; got != true {
		t.Errorf("device_cert_valid=%v want true", got)
	}
	if got := req.Compliance["disk_encrypted"]; got != true {
		t.Errorf("unrelated fact lost: disk_encrypted=%v", got)
	}
}

func TestApplyAttestedCompliance_CorpFromCert(t *testing.T) {
	req := &HeartbeatRequest{Compliance: map[string]any{"tier": "TIER_BYOD"}}
	applyAttestedCompliance(req, certWithURIs(t,
		"spiffe://example.com/device/abc", "urn:hexxlock:device-tier:TIER_CORP"))
	if req.Compliance["tier"] != "TIER_CORP" || req.Compliance["device_cert_valid"] != true {
		t.Errorf("compliance=%v", req.Compliance)
	}
}

func TestApplyAttestedCompliance_DropsAgentPolicyInputs(t *testing.T) {
	req := &HeartbeatRequest{Compliance: map[string]any{
		"route_sensitivity": "low",
		"network_class":     "corp",
		"disk_encrypted":    true,
	}}
	applyAttestedCompliance(req, certWithURIs(t, "spiffe://example.com/device/abc"))
	if _, ok := req.Compliance["route_sensitivity"]; ok {
		t.Error("route_sensitivity must be removed")
	}
	if _, ok := req.Compliance["network_class"]; ok {
		t.Error("network_class must be removed")
	}
	if req.Compliance["disk_encrypted"] != true {
		t.Error("unrelated fact lost")
	}
}

func TestAttestedUserSub_FromCertCN(t *testing.T) {
	c := &x509.Certificate{}
	c.Subject.CommonName = "04ad2960"
	if got := attestedUserSub(c); got != "04ad2960" {
		t.Errorf("attestedUserSub=%q want 04ad2960", got)
	}
}
