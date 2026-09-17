// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ParseXFCC parses an Envoy X-Forwarded-Client-Cert header value into
// the device leaf certificate. Used when the posture-signer pod runs
// behind Envoy Gateway (production): Envoy terminates the agent's
// device-cert mTLS at the edge and forwards the validated cert via
// XFCC, while the pod sees plain HTTP on the Linkerd mesh-mTLS hop.
//
// In that topology `r.TLS.PeerCertificates` is empty (Linkerd-injected
// proxy cert is consumed at the mesh layer and not surfaced to the
// app); the *device* identity travels in this header. Without XFCC
// parsing the server would 401 every legitimate request.
//
// Envoy XFCC format (Envoy docs §x-forwarded-client-cert):
//
//	XFCC := element (, element)*
//	element := key=value (; key=value)*
//	key := By | Hash | Cert | Chain | Subject | URI | DNS
//
// Quoted values use double-quote semantics; URL-encoded PEM bodies
// arrive in `Cert=` and `Chain=`. Multiple elements appear when the
// request traversed multiple Envoy hops — the LAST element is from
// the upstream (closest-to-this-pod) proxy and is the one we trust.
//
// Trust model: Envoy must be configured with
// `forward_client_cert_details: SANITIZE_SET` so it strips any
// client-supplied XFCC and writes its own element. The posture-signer
// MUST be reachable only from Envoy (enforced by the chart's
// Linkerd Server / AuthorizationPolicy / MeshTLSAuthentication that
// only allows the envoy-gateway-system SA). Combined: a client
// cannot forge XFCC; the only source the pod sees is trusted Envoy.
//
// Returns the parsed leaf certificate. Subsequent chain validation
// uses the existing DeviceCertVerifier.Verify path against the
// jess-device-ca trust pool.
func ParseXFCC(header string) (*x509.Certificate, error) {
	if header == "" {
		return nil, ErrXFCCMissing
	}

	// Take the LAST element. Envoy appends; the rightmost is the most-
	// recent (closest-to-pod) Envoy hop. Earlier hops (e.g. edge Envoy
	// → cluster-internal Envoy) leave traces but only the upstream-
	// most-trusted hop is the one we configured.
	element := lastXFCCElement(header)
	fields, err := parseXFCCElement(element)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrXFCCMalformed, err)
	}

	encodedPEM, ok := fields["cert"]
	if !ok || encodedPEM == "" {
		// Some Envoy configurations only forward Hash/Subject/URI and
		// omit Cert= for header-size reasons. We cannot accept that
		// posture: chain validation requires the full leaf cert. The
		// chart's values.yaml mandates `Cert` inclusion in the Envoy
		// `forward_client_cert_details` set.
		return nil, fmt.Errorf("%w: XFCC element has no Cert= field", ErrXFCCMissingCert)
	}

	// URL-decode (Envoy URL-encodes the PEM body, including newlines as
	// %0A and equals padding as %3D in some configs).
	decodedPEM, err := url.QueryUnescape(encodedPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: URL-decode Cert= failed: %w", ErrXFCCMalformed, err)
	}

	block, rest := pem.Decode([]byte(decodedPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: Cert= value is not valid PEM", ErrXFCCMalformed)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: PEM block type %q is not CERTIFICATE", ErrXFCCMalformed, block.Type)
	}
	// Extra PEM blocks (e.g. an intermediate appended after the leaf)
	// MUST be silently dropped here — chain validation reconstructs the
	// chain from the Chain= field if Envoy provided it, not from
	// trailing Cert= data. Be defensive against double-encoded weirdness.
	_ = rest

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: x509 parse: %w", ErrXFCCMalformed, err)
	}
	return leaf, nil
}

// ParseXFCCWithChain returns the leaf PLUS any intermediates from the
// XFCC Chain= field. Used when device certs are signed by an
// intermediate sub-CA (not the current topology — jess-device-ca
// directly signs leaf certs — but the chart supports both shapes).
func ParseXFCCWithChain(header string) (leaf *x509.Certificate, intermediates []*x509.Certificate, err error) {
	if header == "" {
		return nil, nil, ErrXFCCMissing
	}
	element := lastXFCCElement(header)
	fields, perr := parseXFCCElement(element)
	if perr != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrXFCCMalformed, perr)
	}

	encodedLeaf, ok := fields["cert"]
	if !ok || encodedLeaf == "" {
		return nil, nil, fmt.Errorf("%w: XFCC element has no Cert= field", ErrXFCCMissingCert)
	}
	decoded, derr := url.QueryUnescape(encodedLeaf)
	if derr != nil {
		return nil, nil, fmt.Errorf("%w: URL-decode Cert= failed: %w", ErrXFCCMalformed, derr)
	}
	block, _ := pem.Decode([]byte(decoded))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%w: Cert= is not a valid CERTIFICATE PEM", ErrXFCCMalformed)
	}
	leaf, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf x509 parse: %w", ErrXFCCMalformed, err)
	}

	if encodedChain, has := fields["chain"]; has && encodedChain != "" {
		decodedChain, cerr := url.QueryUnescape(encodedChain)
		if cerr != nil {
			return nil, nil, fmt.Errorf("%w: URL-decode Chain= failed: %w", ErrXFCCMalformed, cerr)
		}
		rest := []byte(decodedChain)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			ic, ierr := x509.ParseCertificate(blk.Bytes)
			if ierr != nil {
				return nil, nil, fmt.Errorf("%w: intermediate x509 parse: %w", ErrXFCCMalformed, ierr)
			}
			intermediates = append(intermediates, ic)
		}
	}
	return leaf, intermediates, nil
}

// lastXFCCElement returns the last comma-separated element of an XFCC
// header. Envoy chains multiple elements when traversing N proxies;
// only the upstream-most-trusted (which is the one we configured) is
// the one whose trust we evaluate.
//
// We do NOT use strings.LastIndex(", "): the value of `Cert=` is
// URL-encoded so it never contains a raw comma — but `Subject=` is
// quoted DER which CAN contain a comma inside double-quotes. Parse
// element-aware: split on commas that are NOT inside double-quote
// regions.
func lastXFCCElement(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}

	depth := 0
	lastStart := 0
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '"':
			// Track quoted regions. An escape-aware parser would handle
			// \" — Envoy does not emit those (it URL-encodes problematic
			// chars instead), so a flat depth toggle is sufficient.
			depth ^= 1
		case ',':
			if depth == 0 {
				lastStart = i + 1
			}
		}
	}
	return strings.TrimSpace(header[lastStart:])
}

// parseXFCCElement parses a single XFCC element (semi-colon-separated
// key=value pairs) into a map. Keys are lowercased. Values are
// returned as-is (URL-encoded for Cert/Chain; quoted-stripped for
// Subject).
//
// Spec: Envoy's serializer joins fields with `;` and pairs with `=`.
// Quoted values use `"..."` to surround commas/semicolons. Quoted
// values are stripped of their surrounding quotes here.
func parseXFCCElement(element string) (map[string]string, error) {
	out := make(map[string]string, 7)
	depth := 0
	pairStart := 0
	pairs := []string{}
	for i := 0; i < len(element); i++ {
		switch element[i] {
		case '"':
			depth ^= 1
		case ';':
			if depth == 0 {
				pairs = append(pairs, element[pairStart:i])
				pairStart = i + 1
			}
		}
	}
	pairs = append(pairs, element[pairStart:])

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx <= 0 {
			return nil, fmt.Errorf("malformed key=value pair %q", pair)
		}
		k := strings.ToLower(strings.TrimSpace(pair[:eqIdx]))
		v := strings.TrimSpace(pair[eqIdx+1:])
		// Strip surrounding double quotes from quoted values.
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, nil
}

// XFCC error sentinels — used by callers to map to HTTP status codes
// + distinct Prometheus outcome labels.
var (
	// ErrXFCCMissing — the X-Forwarded-Client-Cert header was empty or
	// absent. In production this means the request did not traverse
	// Envoy Gateway (mis-routing) or Envoy did not configure
	// forward_client_cert_details. 401 + alert.
	ErrXFCCMissing = errors.New("posturesigner: X-Forwarded-Client-Cert header is empty or absent")

	// ErrXFCCMalformed — the XFCC header is present but cannot be
	// parsed (truncated, bad URL-encoding, non-PEM). Likely Envoy
	// misconfiguration. 400 + alert.
	ErrXFCCMalformed = errors.New("posturesigner: X-Forwarded-Client-Cert is malformed")

	// ErrXFCCMissingCert — the XFCC element is parseable but lacks
	// the Cert= field carrying the leaf PEM. Envoy MUST be configured
	// to include Cert in forward_client_cert_details — the chart
	// values.yaml documents this. 401 + alert.
	ErrXFCCMissingCert = errors.New("posturesigner: X-Forwarded-Client-Cert lacks Cert= field")
)
