// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// testPKI is a minimal in-process PKI for verifier tests. It creates a
// root CA (simulating jess-device-ca) and can mint leaf certs signed by
// that root, optionally with customisable properties.
type testPKI struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate
	pool     *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-jess-device-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return &testPKI{rootKey: rootKey, rootCert: rootCert, pool: pool}
}

type leafOptions struct {
	deviceUUID string
	notBefore  time.Time
	notAfter   time.Time
	ekus       []x509.ExtKeyUsage
	spiffeURI  string // override the default spiffe://hexxlock.com/device/<uuid>
	wrongCA    bool   // sign with a fresh unrelated key (not jess-device-ca)
}

func (p *testPKI) mintLeaf(t *testing.T, opts leafOptions) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	nb := opts.notBefore
	if nb.IsZero() {
		nb = time.Now().Add(-time.Minute)
	}
	na := opts.notAfter
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	ekus := opts.ekus
	if ekus == nil {
		ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	spiffeStr := opts.spiffeURI
	if spiffeStr == "" && opts.deviceUUID != "" {
		spiffeStr = deviceSPIFFEPrefix + opts.deviceUUID
	}
	var uris []*url.URL
	if spiffeStr != "" {
		u, err := url.Parse(spiffeStr)
		if err != nil {
			t.Fatalf("parse SPIFFE URI %q: %v", spiffeStr, err)
		}
		uris = append(uris, u)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "device-" + opts.deviceUUID},
		NotBefore:    nb,
		NotAfter:     na,
		ExtKeyUsage:  ekus,
		URIs:         uris,
	}
	var signerKey any = p.rootKey
	if opts.wrongCA {
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate wrong CA key: %v", err)
		}
		// Sign with wrongKey but keep p.rootCert as the claimed issuer —
		// chain verification against the rootCert trust pool will then
		// reject the cert because its signature doesn't verify against
		// the claimed issuer's public key.
		signerKey = wrongKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.rootCert, &leafKey.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

func connState(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: certs}
}

func TestDeviceCertVerifier_ValidChain(t *testing.T) {
	pki := newTestPKI(t)
	v, err := NewDeviceCertVerifier(pki.pool)
	if err != nil {
		t.Fatalf("NewDeviceCertVerifier: %v", err)
	}
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	leaf := pki.mintLeaf(t, leafOptions{deviceUUID: uuid})

	if err := v.Verify(connState(leaf), uuid); err != nil {
		t.Fatalf("expected valid chain to pass, got: %v", err)
	}
}

func TestDeviceCertVerifier_NoCert(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)

	err := v.Verify(&tls.ConnectionState{}, "any-uuid")
	if !errors.Is(err, ErrNoCertPresented) {
		t.Fatalf("expected ErrNoCertPresented, got: %v", err)
	}
}

func TestDeviceCertVerifier_NilConnectionState(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)

	err := v.Verify(nil, "any-uuid")
	if !errors.Is(err, ErrNoCertPresented) {
		t.Fatalf("expected ErrNoCertPresented, got: %v", err)
	}
}

func TestDeviceCertVerifier_WrongCA(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	// Mint a cert signed with a key not in the trust pool.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(deviceSPIFFEPrefix + uuid)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "rogue-device"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	// Create a self-signed wrong CA cert first.
	wrongCADER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "wrong-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "wrong-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &wrongKey.PublicKey, wrongKey)
	wrongCA, _ := x509.ParseCertificate(wrongCADER)
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, wrongCA, &leafKey.PublicKey, wrongKey)
	leaf, _ := x509.ParseCertificate(der)

	err := v.Verify(connState(leaf), uuid)
	if !errors.Is(err, ErrCertChainInvalid) {
		t.Fatalf("expected ErrCertChainInvalid for wrong CA, got: %v", err)
	}
}

func TestDeviceCertVerifier_WrongSAN(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	differentUUID := "660e8400-e29b-41d4-a716-446655440001"

	// Mint cert for uuid, but verify against differentUUID.
	leaf := pki.mintLeaf(t, leafOptions{deviceUUID: uuid})
	err := v.Verify(connState(leaf), differentUUID)
	if !errors.Is(err, ErrSANMismatch) {
		t.Fatalf("expected ErrSANMismatch for UUID mismatch, got: %v", err)
	}
}

func TestDeviceCertVerifier_ExpiredLeaf(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	// Mint a cert with notAfter in the past.
	leaf := pki.mintLeaf(t, leafOptions{
		deviceUUID: uuid,
		notBefore:  time.Now().Add(-2 * time.Hour),
		notAfter:   time.Now().Add(-time.Hour),
	})
	err := v.Verify(connState(leaf), uuid)
	if !errors.Is(err, ErrCertExpired) && !errors.Is(err, ErrCertChainInvalid) {
		t.Fatalf("expected ErrCertExpired or ErrCertChainInvalid for expired cert, got: %v", err)
	}
}

func TestDeviceCertVerifier_MissingClientAuth(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	// Mint cert without ClientAuth EKU (e.g. only ServerAuth).
	leaf := pki.mintLeaf(t, leafOptions{
		deviceUUID: uuid,
		ekus:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	err := v.Verify(connState(leaf), uuid)
	if !errors.Is(err, ErrCertMissingClientAuth) {
		t.Fatalf("expected ErrCertMissingClientAuth, got: %v", err)
	}
}

func TestDeviceCertVerifier_NoSPIFFESAN(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	// Mint cert with ClientAuth but no SPIFFE SAN.
	leaf := pki.mintLeaf(t, leafOptions{
		deviceUUID: uuid,
		spiffeURI:  "https://example.com/not-spiffe",
	})
	err := v.Verify(connState(leaf), uuid)
	if !errors.Is(err, ErrSANMismatch) {
		t.Fatalf("expected ErrSANMismatch for missing SPIFFE SAN, got: %v", err)
	}
}

func TestNewDeviceCertVerifier_NilPool(t *testing.T) {
	_, err := NewDeviceCertVerifier(nil)
	if err == nil {
		t.Fatal("expected error for nil pool, got nil")
	}
}

// TestDeviceCertVerifier_RealVaultPKIShape verifies the full happy path
// matches the certificate shape that jess-device-ca (Vault PKI) mints:
//   - Root CA directly signs leaf (no intermediates)
//   - SPIFFE SAN URI = spiffe://hexxlock.com/device/<uuid>
//   - EKU = ClientAuth only
//   - 24h TTL (verify options work at any point in that window)
func TestDeviceCertVerifier_RealVaultPKIShape(t *testing.T) {
	pki := newTestPKI(t)
	v, _ := NewDeviceCertVerifier(pki.pool)
	uuid := "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3040506"

	leaf := pki.mintLeaf(t, leafOptions{
		deviceUUID: uuid,
		notBefore:  time.Now().Add(-time.Minute),
		notAfter:   time.Now().Add(24 * time.Hour),
	})
	// Pass leaf only (no intermediates — Vault PKI root-direct pattern).
	if err := v.Verify(connState(leaf), uuid); err != nil {
		t.Fatalf("root-direct leaf should verify: %v", err)
	}
}
