// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
)

// ------------------------------------------------------------------
// PKI helpers for server tests
// ------------------------------------------------------------------

type serverTestPKI struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate
	pool     *x509.CertPool
}

func newServerTestPKI(t *testing.T) *serverTestPKI {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv-test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &serverTestPKI{rootKey: rootKey, rootCert: root, pool: pool}
}

// mintLeafWithKey mints a device leaf cert + private key signed by the test root.
// Returns (cert, certDER, privKeyDER) for use in building a tls.Certificate.
func (p *serverTestPKI) mintLeafWithKey(t *testing.T, deviceUUID string) (leaf *x509.Certificate, certDER []byte, leafKey *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spiffeURI, _ := url.Parse("spiffe://hexxlock.com/device/" + deviceUUID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: deviceUUID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{spiffeURI},
	}
	certDER, _ = x509.CreateCertificate(rand.Reader, tmpl, p.rootCert, &leafKey.PublicKey, p.rootKey)
	leaf, _ = x509.ParseCertificate(certDER)
	return leaf, certDER, leafKey
}

// tlsCertFor builds a tls.Certificate (for use as a TLS client certificate)
// from the given device UUID.
func (p *serverTestPKI) tlsCertFor(t *testing.T, deviceUUID string) tls.Certificate {
	t.Helper()
	_, certDER, leafKey := p.mintLeafWithKey(t, deviceUUID)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert
}

// ------------------------------------------------------------------
// Vault stub
// ------------------------------------------------------------------

func newVaultStub(t *testing.T, pubPEM string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Distinguish sign from keys by requiring "/sign/" in path.
		// Must NOT match "/posture-signer" (which contains "sign") — use "/sign/".
		if strings.Contains(r.URL.Path, "/sign/") {
			sig := make([]byte, 256)
			resp := map[string]any{"data": map[string]string{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
			}}
			json.NewEncoder(w).Encode(resp) //nolint:errcheck
			return
		}
		resp := map[string]any{"data": map[string]any{
			"keys": map[string]any{"1": map[string]string{"public_key": pubPEM}},
		}}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ------------------------------------------------------------------
// Test server fixture using real mTLS
// ------------------------------------------------------------------

// serverFixture holds a posture-signer server backed by a real mTLS
// listener. Clients must present a valid device cert to reach the sign
// endpoint — the same trust model as production.
type serverFixture struct {
	httpSrv *httptest.Server
	pki     *serverTestPKI
	nonces  *NonceCache
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()

	log := zaptest.NewLogger(t)
	pki := newServerTestPKI(t)

	// Vault stub RSA pubkey for JWKS.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}))
	vaultStub := newVaultStub(t, rsaPEM)

	origRead := readFileOnce
	t.Cleanup(func() { readFileOnce = origRead })
	readFileOnce = func(_ string) ([]byte, error) { return []byte("test-tok"), nil }

	iss, err := NewJWSIssuer(JWSIssuerConfig{
		VaultAddr: vaultStub.URL, KeyName: "posture-signer",
		Issuer:    "https://posture.hexxlock.com",
		Audience:  "https://internal.example.com",
		TokenPath: "/vault/secrets/token",
	})
	if err != nil {
		t.Fatalf("NewJWSIssuer: %v", err)
	}
	iss.httpCl = vaultStub.Client()
	if err := iss.RefreshJWKS(context.Background()); err != nil {
		t.Fatalf("RefreshJWKS: %v", err)
	}

	nonces := NewNonceCache()
	t.Cleanup(nonces.Stop)

	verifier, err := NewDeviceCertVerifier(pki.pool)
	if err != nil {
		t.Fatalf("NewDeviceCertVerifier: %v", err)
	}

	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	srv := NewServer(ServerConfig{
		Logger: log, Issuer: iss, Nonces: nonces,
		DeviceVerifier: verifier, Metrics: metrics,
	})
	t.Cleanup(srv.Close) // stop the reconcile dedup GC goroutine

	// Use a real TLS listener that requests (but does not require) a client
	// cert — matching the production Envoy Gateway model where the device
	// cert is optional at the TLS layer (Envoy does the enforcement) but
	// present when the agent sends one.
	tlsSrv := httptest.NewUnstartedServer(srv.Handler())
	tlsSrv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  pki.pool,
		MinVersion: tls.VersionTLS12,
	}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)

	return &serverFixture{httpSrv: tlsSrv, pki: pki, nonces: nonces}
}

// clientWithCert builds an *http.Client that presents the given tls.Certificate
// as its client certificate to the test TLS server. The server cert is always
// accepted (InsecureSkipVerify) because httptest uses a self-signed cert.
func (f *serverFixture) clientWithCert(cert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, //nolint:gosec // test-only
			},
		},
	}
}

// clientWithoutCert builds an *http.Client with no client certificate.
func (f *serverFixture) clientWithoutCert() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test-only
			},
		},
	}
}

// doSign sends POST /v1/sign-posture with the given body and optional client cert.
func (f *serverFixture) doSign(t *testing.T, body []byte, deviceUUID string) *http.Response {
	t.Helper()
	var cl *http.Client
	if deviceUUID != "" {
		cl = f.clientWithCert(f.pki.tlsCertFor(t, deviceUUID))
	} else {
		cl = f.clientWithoutCert()
	}
	req, _ := http.NewRequest(http.MethodPost, f.httpSrv.URL+"/v1/sign-posture", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("doSign: %v", err)
	}
	return resp
}

// validBody builds a heartbeat request body for the given device UUID.
func (f *serverFixture) validBody(t *testing.T, deviceUUID string) []byte {
	t.Helper()
	nonceBuf := make([]byte, 32)
	rand.Read(nonceBuf) //nolint:errcheck
	r := HeartbeatRequest{
		DeviceUUID: deviceUUID, Tier: TierCorp,
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBuf),
		IAT:   time.Now().Unix(), Compliance: map[string]any{"disk_encrypted": true},
	}
	b, _ := json.Marshal(r)
	return b
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

func TestServer_Healthz(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	resp, err := cl.Get(f.httpSrv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: expected 200, got %d", resp.StatusCode)
	}
}

func TestServer_Readyz_Ready(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	resp, err := cl.Get(f.httpSrv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz: expected 200, got %d", resp.StatusCode)
	}
}

func TestServer_JWKS(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	resp, err := cl.Get(f.httpSrv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("jwks: expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["keys"]; !ok {
		t.Errorf("expected 'keys' field in JWKS body")
	}
}

func TestServer_MethodNotAllowed_SignPosture(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	resp, err := cl.Get(f.httpSrv.URL + "/v1/sign-posture")
	if err != nil {
		t.Fatalf("GET /v1/sign-posture: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on sign-posture, got %d", resp.StatusCode)
	}
}

func TestServer_MalformedJSON(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	req, _ := http.NewRequest(http.MethodPost, f.httpSrv.URL+"/v1/sign-posture",
		bytes.NewReader([]byte(`{not valid json`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON: expected 400, got %d", resp.StatusCode)
	}
}

func TestServer_UnknownFields_Rejected(t *testing.T) {
	f := newServerFixture(t)
	cl := f.clientWithoutCert()
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	body, _ := json.Marshal(map[string]any{
		"device_uuid": "550e8400-e29b-41d4-a716-446655440000",
		"tier":        "TIER_CORP", "nonce": nonce,
		"iat": time.Now().Unix(), "compliance": map[string]any{},
		"unknown_field": "reject me",
	})
	req, _ := http.NewRequest(http.MethodPost, f.httpSrv.URL+"/v1/sign-posture",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown fields: expected 400, got %d", resp.StatusCode)
	}
}

func TestServer_MissingDeviceCert_Unauthorized(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	// Send without presenting any client certificate.
	resp := f.doSign(t, f.validBody(t, uuid), "" /* no cert */)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no device cert: expected 401, got %d", resp.StatusCode)
	}
}

func TestServer_DeviceCertUUIDMismatch_Forbidden(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	differentUUID := "660e8400-e29b-41d4-a716-446655440001"

	// Body claims uuid, but present cert for differentUUID.
	body := f.validBody(t, uuid)
	// Build client that presents differentUUID cert.
	cl := f.clientWithCert(f.pki.tlsCertFor(t, differentUUID))
	req, _ := http.NewRequest(http.MethodPost, f.httpSrv.URL+"/v1/sign-posture",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("uuid mismatch: expected 403, got %d", resp.StatusCode)
	}
}

func TestServer_NonceReplay_Rejected(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	makeBody := func() []byte {
		r := HeartbeatRequest{
			DeviceUUID: uuid, Tier: TierCorp, Nonce: nonce,
			IAT: time.Now().Unix(), Compliance: map[string]any{},
		}
		b, _ := json.Marshal(r)
		return b
	}

	// First request — must succeed.
	resp1 := f.doSign(t, makeBody(), uuid)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", resp1.StatusCode)
	}

	// Second request with same nonce — must be rejected.
	resp2 := f.doSign(t, makeBody(), uuid)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay: expected 401, got %d", resp2.StatusCode)
	}
}

func TestServer_HappyPath_ResponseShape(t *testing.T) {
	f := newServerFixture(t)
	uuid := "550e8400-e29b-41d4-a716-446655440000"

	resp := f.doSign(t, f.validBody(t, uuid), uuid)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("happy path: expected 200, got %d", resp.StatusCode)
	}
	var body HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.JWS == "" {
		t.Error("jws field is empty")
	}
	if body.ExpiresAt == "" {
		t.Error("expires_at field is empty")
	}
	if _, err := time.Parse(time.RFC3339, body.ExpiresAt); err != nil {
		t.Errorf("expires_at %q is not RFC3339: %v", body.ExpiresAt, err)
	}
}

func TestServer_NewServer_NopLogger_DoesNotPanic(t *testing.T) {
	log := zaptest.NewLogger(t)
	_ = NewServer(ServerConfig{Logger: log})
}
