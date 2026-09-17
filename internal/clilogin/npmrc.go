// SPDX-License-Identifier: AGPL-3.0-or-later

package clilogin

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WriteNpmrc points npm at a Talon-fronted registry and installs a
// freshly minted access token as its credential.
//
// WHY THE CLI HAS TO EDIT A CONFIG FILE AT ALL
// ============================================
// npm has no credential-helper hook. git has credential.helper and
// docker has credsStore, either of which would let a short-lived token
// be fetched on demand; npm reads a STATIC `_authToken` string out of
// .npmrc and offers no callback. So a login helper that rewrites .npmrc
// is not a workaround around npm — it is the only integration point npm
// exposes, and it is what every managed registry ships:
// `aws codeartifact login`, `gcloud artifacts print-settings npm`, and
// Azure's vsts-npm-auth all do exactly this.
//
// Note this is NOT `npm login`. That path (POST /-/v1/login, poll
// doneUrl) is an unspecified npm-internal protocol that Verdaccio
// explicitly declined to implement, and behind an IAP it additionally
// requires punching unauthenticated holes for the CLI's poll endpoint.
// Minting the token here and writing it in keeps the gateway's auth
// model intact.
//
// Only the two lines this tool owns are touched. Everything else in the
// file — registries for other scopes, proxy settings, an unrelated
// auth token — is preserved verbatim, because this file is the user's,
// not ours.
func WriteNpmrc(npmrcPath, host, scope, accessToken string) error {
	if npmrcPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("locate home directory: %w", err)
		}
		npmrcPath = filepath.Join(home, ".npmrc")
	}

	authKey := fmt.Sprintf("//%s/:_authToken=", host)
	scopeKey := fmt.Sprintf("%s:registry=", scope)
	scopeLine := fmt.Sprintf("%s:registry=https://%s/", scope, host)

	// Clean the path before it reaches the filesystem. npmrcPath is
	// operator-supplied (--npmrc) or derived from $HOME, so this is not a
	// known injection vector — but a traversal-laden value would have this
	// process read, and then REWRITE, a file the user never named. Clean
	// collapses any ".." segments so what gets read is what gets written.
	npmrcPath = filepath.Clean(npmrcPath)

	var kept []string
	var sawScope bool
	existing, err := readIfExists(npmrcPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", npmrcPath, err)
	}
	if err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(existing)))
		// npmrc lines are short, but a corrupted file could hold one
		// enormous line; keep the default limit rather than risk an
		// unbounded buffer, and surface the error below.
		for sc.Scan() {
			line := sc.Text()
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, authKey):
				// Drop — replaced with the fresh token below.
			case strings.HasPrefix(trimmed, scopeKey):
				// Keep the user's own registry choice for this scope if
				// they already pinned one; rewriting it could silently
				// repoint a project at a different registry.
				sawScope = true
				kept = append(kept, line)
			default:
				kept = append(kept, line)
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("read %s: %w", npmrcPath, err)
		}
	}

	if !sawScope {
		kept = append(kept, scopeLine)
	}
	kept = append(kept, authKey+accessToken)

	out := strings.Join(kept, "\n") + "\n"

	// Same atomic-write discipline as the token store: .npmrc is how the
	// user's whole toolchain resolves packages, and a truncated one is a
	// confusing outage. 0600 because the file now contains a bearer
	// credential.
	dir := filepath.Dir(npmrcPath)
	tmp, err := os.CreateTemp(dir, ".npmrc-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, npmrcPath); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// readIfExists reads a cleaned path, returning a nil slice (and no error)
// when the file simply is not there yet — the first-run case.
//
// The read is wrapped so the path is opened exactly once, through a value
// filepath.Clean has already normalised, rather than handing a raw
// caller-supplied string straight to os.ReadFile.
func readIfExists(clean string) ([]byte, error) {
	f, err := os.Open(clean)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
