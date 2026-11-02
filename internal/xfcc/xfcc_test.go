// SPDX-License-Identifier: AGPL-3.0-or-later

package xfcc

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

// TestParse_HappyPath exercises the normal Envoy-emitted header:
// one element with By/Hash/Cert/Subject/URI. Cert= carries URL-
// encoded PEM (newlines as %0A).
func TestParse_HappyPath(t *testing.T) {
	pemBytes := mintTestCert(t, "device-001")
	encoded := url.QueryEscape(string(pemBytes))

	header := "By=spiffe://example.com/sa/envoy-gateway;" +
		"Hash=abcdef;" +
		"Cert=" + encoded + ";" +
		`Subject="CN=device-001";` +
		"URI=spiffe://example.com/device/foo"

	leaf, err := Parse(header)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if leaf == nil {
		t.Fatal("leaf cert is nil")
	}
	if leaf.Subject.CommonName != "device-001" {
		t.Errorf("CN = %q, want device-001", leaf.Subject.CommonName)
	}
}

// TestParse_MissingHeader_Returns_ErrMissing locks the empty-
// header behavior (production mis-routing detection).
func TestParse_MissingHeader_Returns_ErrMissing(t *testing.T) {
	_, err := Parse("")
	if !errors.Is(err, ErrMissing) {
		t.Errorf("err = %v, want ErrMissing", err)
	}
}

// TestParse_NoCertField_Returns_ErrMissingCert locks the
// "Envoy was misconfigured" detection (forward_client_cert_details
// did not include Cert).
func TestParse_NoCertField_Returns_ErrMissingCert(t *testing.T) {
	header := "By=spiffe://...;Hash=abc;URI=spiffe://example.com/device/foo"
	_, err := Parse(header)
	if !errors.Is(err, ErrMissingCert) {
		t.Errorf("err = %v, want ErrMissingCert", err)
	}
}

// TestParse_GarbagePEM_Returns_ErrMalformed locks the
// truncated/corrupted-PEM detection.
func TestParse_GarbagePEM_Returns_ErrMalformed(t *testing.T) {
	header := "Cert=" + url.QueryEscape("-----BEGIN CERTIFICATE-----\nthisIsNotBase64@@@\n-----END CERTIFICATE-----")
	_, err := Parse(header)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

// TestParse_MultiElement_TakesLast locks the multi-hop semantics:
// when traffic traverses two Envoy proxies, only the LAST element is
// the upstream-most-trusted one (the one we configured).
func TestParse_MultiElement_TakesLast(t *testing.T) {
	earlier := mintTestCert(t, "edge-hop")
	later := mintTestCert(t, "trusted-upstream")

	header := "Cert=" + url.QueryEscape(string(earlier)) + "," +
		"By=spiffe://...;Cert=" + url.QueryEscape(string(later))

	leaf, err := Parse(header)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if leaf.Subject.CommonName != "trusted-upstream" {
		t.Errorf("CN = %q, want trusted-upstream (rightmost element)", leaf.Subject.CommonName)
	}
}

// TestParse_QuotedSubjectWithComma exercises the quoted-region
// parser: an XFCC field whose value is a quoted DN containing a
// comma must not split the element boundary at that comma.
func TestParse_QuotedSubjectWithComma(t *testing.T) {
	pemBytes := mintTestCert(t, "device-002")
	header := `By=spiffe://...;Subject="CN=device,O=HexxLock";Cert=` + url.QueryEscape(string(pemBytes))

	leaf, err := Parse(header)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if leaf.Subject.CommonName != "device-002" {
		t.Errorf("CN = %q, want device-002", leaf.Subject.CommonName)
	}
}
