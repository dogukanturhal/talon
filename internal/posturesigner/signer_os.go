// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import "os"

// osReadFile is the production implementation of the readFileOnce variable.
// It wraps os.ReadFile so the rest of the package can reference it without
// importing os directly in signer.go (which makes the mock substitution
// simpler in tests).
//
// The path passed here comes exclusively from a vetted source (Vault
// config + env var loaded at boot), never from a request body — so the
// gosec G304 false-positive does not apply.
func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: path is from vetted Vault config, not user input
}
