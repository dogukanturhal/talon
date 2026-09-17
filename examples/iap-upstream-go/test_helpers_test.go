// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/hexxlock/talon/internal/identityjwt"
	"github.com/hexxlock/talon/internal/session"
)

func mustBlob(t *testing.T) *session.Blob {
	t.Helper()
	return &session.Blob{
		Sub:        "u-1",
		Email:      "user@hexxlock.test",
		Groups:     []string{"viewer"},
		TenantID:   "tenant-1",
		SSOChainID: "chain-1",
		SID:        "sid-1",
	}
}

func mustBlobWithGroups(t *testing.T, groups ...string) *session.Blob {
	t.Helper()
	b := mustBlob(t)
	b.Groups = groups
	return b
}

func mustSign(t *testing.T, r *rig, blob *session.Blob) string {
	t.Helper()
	tok, err := r.signer.Sign(blob, "myservice.ops.hexxlock.test")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Ensure identityjwt is referenced from the helpers file so the test
// binary compiles cleanly when integration_test.go is trimmed.
var _ = identityjwt.HeaderName
