// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"crypto/x509"

	"github.com/dogukanturhal/talon/internal/xfcc"
)

// XFCC parsing moved to the shared internal/xfcc package so Talon's
// device-mTLS path can reuse it. These aliases keep the posturesigner API
// (and its callers/tests) unchanged.

// ParseXFCC — see xfcc.Parse.
func ParseXFCC(header string) (*x509.Certificate, error) { return xfcc.Parse(header) }

// ParseXFCCWithChain — see xfcc.ParseWithChain.
func ParseXFCCWithChain(header string) (*x509.Certificate, []*x509.Certificate, error) {
	return xfcc.ParseWithChain(header)
}

// XFCC error sentinels (identical values to the xfcc package's).
var (
	ErrXFCCMissing     = xfcc.ErrMissing
	ErrXFCCMalformed   = xfcc.ErrMalformed
	ErrXFCCMissingCert = xfcc.ErrMissingCert
)
