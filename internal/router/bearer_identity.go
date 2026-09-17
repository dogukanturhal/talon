// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"github.com/hexxlock/talon/internal/session"
	"github.com/hexxlock/talon/internal/svctoken"
)

// blobFromSvctokenClaims projects a verified END-USER Bearer token onto
// the session.Blob shape the policy evaluator consumes, so a human on a
// CLI is authorised through exactly the same code path as the same human
// in a browser: policy.RoleFilter over groups/roles, then SpiceDB
// CheckPermission keyed on Sub.
//
// Only ever called for tokens where Claims.IsMachine() is false.
//
// SESSION-LIFECYCLE FIELDS ARE DELIBERATELY LEFT ZERO
// ===================================================
// SrcIP, DeviceClaims, LastTouched and LastWebAuthnAt describe a STORED
// session. A Bearer token has none of them, which is exactly why
// evaluatePerHost (absolute TTL / idle / IP-rebind / device claims) is
// not run on this path — those gates are meaningless without a session
// to age. Filling the fields with plausible-looking substitutes (the
// request's current IP, "now") would fabricate posture evidence and let
// a stateless token satisfy a gate it never actually passed, so they
// stay empty and the gates stay skipped.
//
// V is likewise left zero: it is the stored-blob schema version used by
// the session store's decoder, and this blob is never persisted.
func blobFromSvctokenClaims(c *svctoken.Claims) *session.Blob {
	b := &session.Blob{
		Sub:      c.Subject,
		Email:    c.Email,
		Groups:   c.Groups,
		Roles:    c.Roles,
		TenantID: c.TenantID,
		Iss:      c.Issuer,
		AMR:      c.AMR,
		ACR:      c.ACR,
	}
	// Guard the zero time: time.Time{}.Unix() is a large negative number,
	// which would read as a 1754-era session to anything that later
	// compares these against wall-clock.
	if !c.IssuedAt.IsZero() {
		b.IAT = c.IssuedAt.Unix()
	}
	if !c.ExpiresAt.IsZero() {
		b.Exp = c.ExpiresAt.Unix()
	}
	return b
}
