// SPDX-License-Identifier: AGPL-3.0-or-later

package devicemtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const trusted = "eg.envoy-gateway-system.serviceaccount.identity.linkerd.cluster.local"

func xfccFor(t *testing.T, uris ...string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, s := range uris {
		u, _ := url.Parse(s)
		tpl.URIs = append(tpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	return "By=spiffe://envoy;Hash=abc;Cert=" + p + ";Subject=\"CN=x\""
}

func hdr(caller, x string) http.Header {
	h := http.Header{}
	if caller != "" {
		h.Set(CallerIDHeader, caller)
	}
	if x != "" {
		h.Set(XFCCHeader, x)
	}
	return h
}

var cfg = &Config{TrustedClientID: trusted, Mode: ModeAudit}

const dev = "11111111-2222-3333-4444-555555555555"

func TestUntrustedCallerStripsXFCC(t *testing.T) {
	h := hdr("evil.ns.serviceaccount.identity.linkerd.cluster.local", xfccFor(t, deviceSPIFFEPrefix+dev))
	id := Resolve(cfg, h, time.Now())
	if id.Present || id.DeviceID != "" {
		t.Fatalf("untrusted caller must not yield identity: %+v", id)
	}
	if h.Get(XFCCHeader) != "" {
		t.Fatal("XFCC not stripped")
	}
}

func TestMissingCallerIDStrips(t *testing.T) {
	h := hdr("", xfccFor(t, deviceSPIFFEPrefix+dev))
	if id := Resolve(cfg, h, time.Now()); id.Present {
		t.Fatalf("no l5d-client-id must not be trusted: %+v", id)
	}
	if h.Get(XFCCHeader) != "" {
		t.Fatal("XFCC not stripped")
	}
}

func TestDisabledConfigStrips(t *testing.T) {
	h := hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev))
	if id := Resolve(nil, h, time.Now()); id.Present {
		t.Fatalf("nil cfg: %+v", id)
	}
	if h.Get(XFCCHeader) != "" {
		t.Fatal("XFCC not stripped")
	}
}

func TestTrustedBrowserAndDeviceKinds(t *testing.T) {
	b := Resolve(cfg, hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev, browserKindURI)), time.Now())
	if !b.Present || !b.Valid || b.DeviceID != dev || b.Kind != KindBrowser || b.Channel != "device-mtls" {
		t.Fatalf("browser: %+v", b)
	}
	d := Resolve(cfg, hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev)), time.Now())
	if !d.Present || !d.Valid || d.DeviceID != dev || d.Kind != KindDevice {
		t.Fatalf("device: %+v", d)
	}
}

func TestNoXFCCNotPresent(t *testing.T) {
	id := Resolve(cfg, hdr(trusted, ""), time.Now())
	if id.Present || id.Valid {
		t.Fatalf("%+v", id)
	}
	if Check(id, "") != ReasonAbsent {
		t.Fatal("want absent")
	}
}

func TestExpiredCertInvalid(t *testing.T) {
	id := Resolve(cfg, hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev)), time.Now().Add(48*time.Hour))
	if !id.Present || id.Valid {
		t.Fatalf("%+v", id)
	}
	if Check(id, "") != ReasonInvalid {
		t.Fatal("want invalid")
	}
}

func TestPostureBinding(t *testing.T) {
	id := Resolve(cfg, hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev, browserKindURI)), time.Now())
	if r := Check(id, deviceSPIFFEPrefix+dev); r != "" {
		t.Fatalf("match: %q", r)
	}
	if r := Check(id, "device:"+dev); r != "" {
		t.Fatalf("device: form: %q", r)
	}
	if r := Check(id, deviceSPIFFEPrefix+"99999999-0000-0000-0000-000000000000"); r != ReasonPostureMismatch {
		t.Fatalf("mismatch: %q", r)
	}
	if r := Check(id, ""); r != "" {
		t.Fatalf("no posture: %q", r)
	}
}

func TestAppliesTo(t *testing.T) {
	c := &Config{TrustedClientID: trusted, Hosts: []string{"argocd.internal.example.com"}}
	if !c.AppliesTo("ARGOCD.internal.example.com:443") || c.AppliesTo("vault.internal.example.com") {
		t.Fatal("host filter")
	}
	if !(&Config{TrustedClientID: trusted}).AppliesTo("anything") {
		t.Fatal("empty hosts = all")
	}
}

func TestParseMode(t *testing.T) {
	if ParseMode("") != ModeAudit || ParseMode("junk") != ModeAudit || ParseMode("Enforce") != ModeEnforce {
		t.Fatal("mode")
	}
}

func TestDecideAuditVsEnforce(t *testing.T) {
	audit := &Config{TrustedClientID: trusted, Mode: ModeAudit}
	enf := &Config{TrustedClientID: trusted, Mode: ModeEnforce}
	id := Resolve(audit, hdr(trusted, xfccFor(t, deviceSPIFFEPrefix+dev)), time.Now())
	other := deviceSPIFFEPrefix + "99999999-0000-0000-0000-000000000000"

	if d := Decide(audit, id, other, "argocd.internal.example.com"); d.Reason != ReasonPostureMismatch || d.Deny {
		t.Fatalf("audit: %+v", d)
	}
	if d := Decide(enf, id, other, "argocd.internal.example.com"); d.Reason != ReasonPostureMismatch || !d.Deny {
		t.Fatalf("enforce: %+v", d)
	}
	if d := Decide(enf, id, deviceSPIFFEPrefix+dev, "x"); d.Reason != "" || d.Deny {
		t.Fatalf("match: %+v", d)
	}
	absent := Identity{Channel: ChannelDeviceMTLS}
	if d := Decide(audit, absent, "", "x"); d.Reason != ReasonAbsent || d.Deny {
		t.Fatalf("absent audit: %+v", d)
	}
	scoped := &Config{TrustedClientID: trusted, Mode: ModeEnforce, Hosts: []string{"argocd.internal.example.com"}}
	if d := Decide(scoped, absent, "", "vault.internal.example.com"); d.Reason != "" {
		t.Fatalf("out-of-scope host absence must pass: %+v", d)
	}
	if d := Decide(scoped, absent, "", "argocd.internal.example.com"); !d.Deny {
		t.Fatalf("in-scope absence must deny in enforce: %+v", d)
	}
	if d := Decide(nil, absent, "", "x"); d.Reason != "" {
		t.Fatal("nil cfg")
	}
}

// The plaintext mesh-only edge listener has no TLS identity of its own: if the
// Linkerd inbound proxy did not stamp l5d-client-id (or stamped something
// else), XFCC must never be believed and must be stripped.
func TestPlainListenerWithoutL5dClientIDNeverTrustsXFCC(t *testing.T) {
	for _, caller := range []string{"", "   ", "other.ns.serviceaccount.identity.linkerd.cluster.local"} {
		h := hdr("", xfccFor(t, deviceSPIFFEPrefix+dev, browserKindURI))
		if caller != "" {
			h.Set(CallerIDHeader, caller)
		}
		id := Resolve(cfg, h, time.Now())
		if id.Present || id.Valid || id.DeviceID != "" {
			t.Fatalf("caller %q: trusted XFCC: %+v", caller, id)
		}
		if h.Get(XFCCHeader) != "" {
			t.Fatalf("caller %q: XFCC not stripped", caller)
		}
	}
	// An empty configured identity must not "match" an empty l5d-client-id.
	h := hdr("", xfccFor(t, deviceSPIFFEPrefix+dev))
	if id := Resolve(&Config{}, h, time.Now()); id.Present {
		t.Fatalf("empty trusted id matched empty caller: %+v", id)
	}
}
