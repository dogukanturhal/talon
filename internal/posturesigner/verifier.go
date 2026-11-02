// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// computeX5tS256 returns the RFC 8705 §3.1 x5t#S256 thumbprint of the
// given certificate: base64url-no-pad of SHA-256(DER). This is the
// canonical confirmation-method value the issuer embeds in the cnf
// claim and downstream verifiers compare against the inbound mTLS
// cert.
func computeX5tS256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// deviceSPIFFEPrefix is the SPIFFE URI scheme and authority for HexxLock
// device identities (ADR 0040 D-005 — SPIFFE-aligned naming, no SPIRE).
// Format: spiffe://example.com/device/<device-uuid>
const deviceSPIFFEPrefix = "spiffe://example.com/device/"

// DeviceCertVerifier validates the leaf X.509 certificate presented by
// the agent over mTLS. It checks the full trust chain against the
// jess-device-ca cert pool AND cross-validates the SPIFFE SAN URI
// against the device_uuid in the heartbeat body.
//
// Security property: even if an attacker steals a valid heartbeat JSON
// body, they cannot replay it over a connection whose TLS cert encodes a
// different device UUID — the SAN/UUID mismatch check catches this.
type DeviceCertVerifier struct {
	pool *x509.CertPool
	now  func() time.Time // injectable for tests
}

// NewDeviceCertVerifier constructs a verifier backed by the given cert
// pool. The pool must contain the jess-device-ca root (and any
// intermediates) that signed agent device certs. Returns an error if the
// pool is nil.
func NewDeviceCertVerifier(pool *x509.CertPool) (*DeviceCertVerifier, error) {
	if pool == nil {
		return nil, errors.New("posturesigner: device CA cert pool is required")
	}
	return &DeviceCertVerifier{pool: pool, now: time.Now}, nil
}

// Verify validates the device certificate from cs against the trust pool
// and confirms the SPIFFE SAN URI matches deviceUUID.
//
// Error classes returned (use errors.Is for dispatch):
//   - ErrNoCertPresented: TLS state has no peer certificates
//   - ErrCertChainInvalid: chain does not verify to the pool
//   - ErrCertExpired: the verified time fell outside the cert validity window
//   - ErrCertMissingClientAuth: leaf lacks id-kp-clientAuth EKU
//   - ErrSANMismatch: SPIFFE URI SAN does not match deviceUUID
func (v *DeviceCertVerifier) Verify(cs *tls.ConnectionState, deviceUUID string) error {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return ErrNoCertPresented
	}
	leaf := cs.PeerCertificates[0]

	// Extended key usage: leaf must have ClientAuth (RFC 5280 §4.2.1.12
	// id-kp-clientAuth). Jess-device-ca sign role configures this; an
	// absent EKU indicates the cert was not minted by the device-cert
	// pipeline.
	if !hasClientAuth(leaf) {
		return fmt.Errorf("%w: leaf cert CN=%q lacks id-kp-clientAuth EKU",
			ErrCertMissingClientAuth, leaf.Subject.CommonName)
	}

	// Build intermediate pool from any certificates the client presented
	// after the leaf (indices 1+). Jess-issued device certs are currently
	// leaf-only (jess-device-ca is a Vault PKI root directly signing leaf
	// certs), so this will typically be empty — but we handle
	// intermediates correctly for future sub-CA flexibility.
	intermediates := x509.NewCertPool()
	for _, ic := range cs.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}

	opts := x509.VerifyOptions{
		Roots:         v.pool,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		// Wrap to distinguish chain errors from other failures.
		var certErr x509.CertificateInvalidError
		if errors.As(err, &certErr) && certErr.Reason == x509.Expired {
			return fmt.Errorf("%w: %w", ErrCertExpired, err)
		}
		return fmt.Errorf("%w: %w", ErrCertChainInvalid, err)
	}

	// Extract the SPIFFE SAN URI from the verified leaf.
	spiffeURI, err := extractDeviceSPIFFE(leaf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSANMismatch, err)
	}

	// Cross-validate SPIFFE URI device segment against the heartbeat
	// device_uuid. This is the key security property: it defeats the
	// "steal one device's heartbeat and present it with another device's
	// cert" attack class.
	wantURI := deviceSPIFFEPrefix + deviceUUID
	if spiffeURI != wantURI {
		return fmt.Errorf("%w: cert SPIFFE %q does not match heartbeat device_uuid %q",
			ErrSANMismatch, spiffeURI, deviceUUID)
	}
	return nil
}

// Sentinel errors for Verify. Callers should use errors.Is to test for
// specific failure classes and return appropriate HTTP status codes.
var (
	ErrNoCertPresented       = errors.New("posturesigner: no client certificate presented")
	ErrCertChainInvalid      = errors.New("posturesigner: device certificate chain validation failed")
	ErrCertExpired           = errors.New("posturesigner: device certificate is expired")
	ErrCertMissingClientAuth = errors.New("posturesigner: device certificate missing ClientAuth EKU")
	ErrSANMismatch           = errors.New("posturesigner: device certificate SPIFFE SAN does not match heartbeat UUID")
)

// VerifyRequest extracts the device certificate from the appropriate
// source (XFCC header preferred; r.TLS state as fallback for dev/test
// direct-mTLS), then runs the full chain + SPIFFE-SAN check.
//
// Source selection (production vs dev):
//   - Production behind Envoy Gateway: pod sees plain HTTP on the
//     Linkerd mesh hop; `r.TLS` is nil; device cert arrives in
//     X-Forwarded-Client-Cert. XFCC parsing reconstructs the leaf.
//   - Dev / standalone HTTPS: `r.TLS.PeerCertificates` has the cert
//     directly (no Envoy in front). Used by integration tests
//     (httptest.NewTLSServer) and by single-binary local runs.
//
// Order is XFCC-first because production is the dominant case. If
// XFCC is present but invalid, we DO NOT fall back to r.TLS — that
// would let a malicious upstream feed a malformed XFCC and then
// silently use the wrong (proxy) identity from r.TLS. Fail closed.
//
// The X-Forwarded-Client-Cert input is trusted only because the chart
// configures Envoy with `forward_client_cert_details: SANITIZE_SET`
// (Envoy strips any client-supplied XFCC and writes its own) AND the
// chart's Linkerd policy only admits the envoy-gateway-system SA as
// an inbound caller. A client cannot inject XFCC; only trusted Envoy
// can.
//
// Returns the verified leaf certificate on success so the caller can
// compute the cnf.x5t#S256 thumbprint to embed in the JWS (RFC 8705)
// — this binds the issued JWS to a specific device cert, defeating
// cross-mTLS-connection replay of the JWS at downstream verifiers.
func (v *DeviceCertVerifier) VerifyRequest(r *http.Request, deviceUUID string) (*x509.Certificate, error) {
	if r == nil {
		return nil, errors.New("posturesigner: nil http.Request")
	}

	xfcc := r.Header.Get("X-Forwarded-Client-Cert")
	if xfcc != "" {
		leaf, err := ParseXFCC(xfcc)
		if err != nil {
			// Fail closed — see method doc. Do NOT fall back to r.TLS
			// when XFCC was attempted but unparseable.
			return nil, err
		}
		// Wrap the parsed leaf in a tls.ConnectionState shape so the
		// existing Verify() logic (chain + EKU + SPIFFE match) is
		// reused without duplication.
		cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		if err := v.Verify(cs, deviceUUID); err != nil {
			return nil, err
		}
		return leaf, nil
	}

	// No XFCC — fall through to direct TLS state (dev/test path).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoCertPresented
	}
	leaf := r.TLS.PeerCertificates[0]
	if err := v.Verify(r.TLS, deviceUUID); err != nil {
		return nil, err
	}
	return leaf, nil
}

// hasClientAuth returns true if the certificate has id-kp-clientAuth in
// its extended key usage list.
func hasClientAuth(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// extractDeviceSPIFFE returns the SPIFFE URI SAN from the leaf cert that
// starts with deviceSPIFFEPrefix. Returns an error if none is found or
// if multiple device SPIFFE URIs are present (ambiguous — reject).
func extractDeviceSPIFFE(cert *x509.Certificate) (string, error) {
	var found []string
	for _, u := range cert.URIs {
		if isDeviceSPIFFE(u) {
			found = append(found, u.String())
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no %s* SPIFFE SAN URI in cert CN=%q", deviceSPIFFEPrefix, cert.Subject.CommonName)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("ambiguous: %d device SPIFFE SAN URIs in cert CN=%q", len(found), cert.Subject.CommonName)
	}
}

func isDeviceSPIFFE(u *url.URL) bool {
	return u.Scheme == "spiffe" &&
		u.Host == "example.com" &&
		strings.HasPrefix(u.Path, "/device/")
}
