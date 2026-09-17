// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"fmt"

	"github.com/hexxlock/talon/internal/identityjwt"
	"github.com/hexxlock/talon/internal/session"
)

// SignerAssertionMinter is the production AssertionMinter: it mints the
// Talon-vouched clientless-access assertion (jess ADR 0050) by re-signing the
// accessor's verified identity with Talon's IAP identity-token signer, scoped
// to the jess clientless audience and stamped channel=clientless.
//
// jess (server-side) verifies this assertion against Talon's published IAP
// JWKS (the same JWKS jess already fetches for CAEP) for aud=<Audience>,
// binding the brokered DB session's WORM recording + JIT decision to the
// assertion's `sub` — the REAL Falcon-ID subject, never the access-broker.
//
// HONEST SCOPE: ADR 0050 §"Trust chain" also specifies a `tgt` (target-bound)
// claim on the assertion for anti-confused-deputy. The current
// identityjwt.Signer claim set (IdentityClaims) does not carry a per-target
// claim, so this minter binds identity + channel + audience (sub/sid/
// sso_chain/email/tenant/channel) and relies on jess re-applying the JIT +
// sensitivity gate per (sub, target). Adding the explicit `tgt` claim is a
// signer-side change (new claim field + jess verify) tracked with the jess P2
// issuance work — see the deliverable's done-vs-remaining.
type SignerAssertionMinter struct {
	// Signer is Talon's IAP identity-token signer (holds the private key). The
	// access-broker process must be wired with the same signer Talon uses so
	// jess's JWKS verify succeeds. REQUIRED.
	Signer *identityjwt.Signer
	// Audience is the jess clientless audience the assertion is scoped to
	// (ADR 0050: aud = "https://jess.<...>/clientless"). REQUIRED — the
	// per-audience pin is what stops a leaked general Talon IAP token being
	// replayed at jess.
	Audience string
}

// Mint implements AssertionMinter. It projects the verified dial-request
// identity into a session.Blob and signs it with channel=clientless scoped to
// the jess clientless audience.
func (m SignerAssertionMinter) Mint(_ context.Context, req DBDialRequest) (string, error) {
	if m.Signer == nil {
		return "", fmt.Errorf("accessbroker: SignerAssertionMinter has no signer")
	}
	if m.Audience == "" {
		return "", fmt.Errorf("accessbroker: SignerAssertionMinter has no audience (per-audience pin required, ADR 0050)")
	}
	if req.Subject == "" {
		// The handler stamps the verified subject onto the request before Open;
		// an empty subject means an unauthenticated path reached the backend —
		// fail closed rather than mint an unbound assertion.
		return "", fmt.Errorf("accessbroker: refusing to mint an assertion with no subject (fail-closed)")
	}
	blob := &session.Blob{
		Sub:        req.Subject,
		Email:      req.Email,
		TenantID:   req.TenantID,
		SSOChainID: req.SSOChainID,
		SID:        req.SessionID,
	}
	return m.Signer.SignWithChannel(blob, m.Audience, requiredChannel)
}

// compile-time guard.
var _ AssertionMinter = SignerAssertionMinter{}
