// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// mintTestCert produces a self-signed P-256 cert PEM for XFCC parser
// tests. The cert content does NOT need to chain to a real CA — these
// tests only exercise the header parser, not chain verification.
func mintTestCert(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestParseXFCC_HappyPath exercises the normal Envoy-emitted header:
// one element with By/Hash/Cert/Subject/URI. Cert= carries URL-
// encoded PEM (newlines as %0A).
func TestParseXFCC_HappyPath(t *testing.T) {
	pemBytes := mintTestCert(t, "device-001")
	encoded := url.QueryEscape(string(pemBytes))

	header := "By=spiffe://hexxlock.com/sa/envoy-gateway;" +
		"Hash=abcdef;" +
		"Cert=" + encoded + ";" +
		`Subject="CN=device-001";` +
		"URI=spiffe://hexxlock.com/device/foo"

	leaf, err := ParseXFCC(header)
	if err != nil {
		t.Fatalf("ParseXFCC failed: %v", err)
	}
	if leaf == nil {
		t.Fatal("leaf cert is nil")
	}
	if leaf.Subject.CommonName != "device-001" {
		t.Errorf("CN = %q, want device-001", leaf.Subject.CommonName)
	}
}

// TestParseXFCC_MissingHeader_Returns_ErrXFCCMissing locks the empty-
// header behavior (production mis-routing detection).
func TestParseXFCC_MissingHeader_Returns_ErrXFCCMissing(t *testing.T) {
	_, err := ParseXFCC("")
	if !errors.Is(err, ErrXFCCMissing) {
		t.Errorf("err = %v, want ErrXFCCMissing", err)
	}
}

// TestParseXFCC_NoCertField_Returns_ErrXFCCMissingCert locks the
// "Envoy was misconfigured" detection (forward_client_cert_details
// did not include Cert).
func TestParseXFCC_NoCertField_Returns_ErrXFCCMissingCert(t *testing.T) {
	header := "By=spiffe://...;Hash=abc;URI=spiffe://hexxlock.com/device/foo"
	_, err := ParseXFCC(header)
	if !errors.Is(err, ErrXFCCMissingCert) {
		t.Errorf("err = %v, want ErrXFCCMissingCert", err)
	}
}

// TestParseXFCC_GarbagePEM_Returns_ErrXFCCMalformed locks the
// truncated/corrupted-PEM detection.
func TestParseXFCC_GarbagePEM_Returns_ErrXFCCMalformed(t *testing.T) {
	header := "Cert=" + url.QueryEscape("-----BEGIN CERTIFICATE-----\nthisIsNotBase64@@@\n-----END CERTIFICATE-----")
	_, err := ParseXFCC(header)
	if !errors.Is(err, ErrXFCCMalformed) {
		t.Errorf("err = %v, want ErrXFCCMalformed", err)
	}
}

// TestParseXFCC_MultiElement_TakesLast locks the multi-hop semantics:
// when traffic traverses two Envoy proxies, only the LAST element is
// the upstream-most-trusted one (the one we configured).
func TestParseXFCC_MultiElement_TakesLast(t *testing.T) {
	earlier := mintTestCert(t, "edge-hop")
	later := mintTestCert(t, "trusted-upstream")

	header := "Cert=" + url.QueryEscape(string(earlier)) + "," +
		"By=spiffe://...;Cert=" + url.QueryEscape(string(later))

	leaf, err := ParseXFCC(header)
	if err != nil {
		t.Fatalf("ParseXFCC: %v", err)
	}
	if leaf.Subject.CommonName != "trusted-upstream" {
		t.Errorf("CN = %q, want trusted-upstream (rightmost element)", leaf.Subject.CommonName)
	}
}

// TestParseXFCC_QuotedSubjectWithComma exercises the quoted-region
// parser: an XFCC field whose value is a quoted DN containing a
// comma must not split the element boundary at that comma.
func TestParseXFCC_QuotedSubjectWithComma(t *testing.T) {
	pemBytes := mintTestCert(t, "device-002")
	header := `By=spiffe://...;Subject="CN=device,O=HexxLock";Cert=` + url.QueryEscape(string(pemBytes))

	leaf, err := ParseXFCC(header)
	if err != nil {
		t.Fatalf("ParseXFCC: %v", err)
	}
	if leaf.Subject.CommonName != "device-002" {
		t.Errorf("CN = %q, want device-002", leaf.Subject.CommonName)
	}
}

// TestStripVaultVersionPrefix_V10AndAbove locks the regex fix for
// signature parsing. The previous hard-coded v1/v2/v3 list silently
// failed at v10+; with auto-rotate every 90d the production key hits
// v10 in ~2 years and would corrupt EVERY signature thereafter.
func TestStripVaultVersionPrefix_V10AndAbove(t *testing.T) {
	cases := []struct {
		raw    string
		expect string
	}{
		{"vault:v1:abcdef", "abcdef"},
		{"vault:v9:xyz123", "xyz123"},
		{"vault:v10:future_sig", "future_sig"}, // would break old code
		{"vault:v42:much_later", "much_later"},
		{"vault:v100:far_future", "far_future"},
		// No prefix — return unchanged.
		{"raw_signature_no_prefix", "raw_signature_no_prefix"},
		// Empty — return unchanged.
		{"", ""},
	}
	for _, c := range cases {
		if got := stripVaultVersionPrefix(c.raw); got != c.expect {
			t.Errorf("stripVaultVersionPrefix(%q) = %q, want %q", c.raw, got, c.expect)
		}
	}
}

// TestHeartbeat_FutureSkew_Rejected locks the asymmetric clock-skew
// guard (B2 from review): a future-dated iat beyond ±2s ceiling is
// rejected even though the symmetric ±30s window would have admitted
// up to 30s. Prevents replay where an attacker forward-stamps a
// harvested nonce to stretch its dedup-cache lifetime.
func TestHeartbeat_FutureSkew_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	// 15s in the future — would have passed the OLD symmetric ±30s
	// window but MUST fail the new asymmetric ±2s ceiling.
	r := HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Tier:       TierCorp,
		Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 bytes b64url
		IAT:        now.Add(15 * time.Second).Unix(),
		Compliance: map[string]any{},
	}

	err := r.Validate(now)
	if err == nil {
		t.Fatal("expected rejection of 15s-future iat (asymmetric guard)")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("err should mention future-timestamp; got: %v", err)
	}
}

// TestHeartbeat_PastSkewWithinWindow_Accepted preserves the existing
// past-skew tolerance — 25s in the past is honest NTP slop.
func TestHeartbeat_PastSkewWithinWindow_Accepted(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	r := HeartbeatRequest{
		DeviceUUID: "550e8400-e29b-41d4-a716-446655440000",
		Tier:       TierCorp,
		Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 bytes b64url
		IAT:        now.Add(-25 * time.Second).Unix(),
		Compliance: map[string]any{},
	}

	if err := r.Validate(now); err != nil {
		t.Errorf("25s-past iat should be accepted; got: %v", err)
	}
}

// TestNonceCache_StopIsIdempotent locks the sync.Once fix for B3.
// A second Stop must NOT panic (the original close-of-closed channel
// would). The chart's deployment runs main.go which explicitly calls
// Stop() during graceful shutdown; any future refactor that
// reintroduces a `defer` would otherwise crash the pod.
func TestNonceCache_StopIsIdempotent(t *testing.T) {
	c := NewNonceCache()
	c.Stop()
	// Recover from any panic the second Stop might trigger if the
	// guard was removed.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Stop panicked: %v", r)
		}
	}()
	c.Stop() // must be a no-op
}
