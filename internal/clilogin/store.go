// SPDX-License-Identifier: AGPL-3.0-or-later

package clilogin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Store persists the developer's refresh token between invocations.
//
// WHY A FILE AND NOT AN OS KEYRING
// ================================
// A keyring would be better and is the eventual target. It is not here
// yet for two honest reasons: every Go keyring binding pulls a cgo/DBus
// dependency chain that this repo does not otherwise carry, and on the
// headless Linux boxes developers also use there is frequently no
// keyring daemon to talk to — so the fallback path would be this file
// anyway, just with more moving parts hiding it.
//
// What this file holds is a REFRESH token, not a client secret. It is
// revocable centrally (Falcon-ID's revocation endpoint), scoped to one
// user, and expires. That is already a large improvement on the
// per-developer client_credentials secret it replaces, which was
// non-expiring and revocable only by deleting a YAML file. Treat 0600 as
// the floor, not the destination.
type Store struct {
	Path string
}

// Tokens is the stored login state.
//
// THE SECRET IS DELIBERATELY NOT PART OF THE JSON
// ===============================================
// RefreshToken carries `json:"-"`: it is written to a SEPARATE file
// alongside the metadata rather than marshalled into it. Two reasons,
// and the second is the one that matters.
//
// First, it keeps the credential out of anything that serialises this
// struct incidentally — a debug dump, a log line, a future status
// command — so the secret can only ever be written by the one function
// that means to write it.
//
// Second, it splits "which IdP did I log into, and when" from "here is
// the bearer credential". Only the latter needs the careful handling,
// and separating them is the same shape as a docker config pointing at a
// credential helper rather than inlining the password.
type Tokens struct {
	Issuer     string    `json:"issuer"`
	ClientID   string    `json:"client_id"`
	Subject    string    `json:"subject,omitempty"`
	ObtainedAt time.Time `json:"obtained_at"`

	// RefreshToken is persisted to the sibling secret file, never to JSON.
	RefreshToken string `json:"-"`
}

// secretPath returns the companion file holding the refresh token.
func (s *Store) secretPath() string {
	return filepath.Join(filepath.Dir(s.Path), "refresh_token")
}

// DefaultStore returns the standard location, honouring XDG_CONFIG_HOME.
func DefaultStore() (*Store, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locate home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return &Store{Path: filepath.Join(dir, "hexxlock", "talon-cli", "tokens.json")}, nil
}

// Save writes the token set atomically with 0600 permissions.
//
// Written to a temp file in the SAME directory and renamed, so a crash
// mid-write cannot leave a truncated file that reads as "logged in" with
// an unusable token. The temp file is created 0600 from the start rather
// than chmod'ed afterwards — the window between create and chmod is
// exactly when another local user could open it.
func (s *Store) Save(t *Tokens) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	blob, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	// Secret first: if this fails there is no metadata left claiming a
	// login that has no usable credential behind it.
	if err := writeFileAtomic(s.secretPath(), []byte(t.RefreshToken)); err != nil {
		return fmt.Errorf("write refresh token: %w", err)
	}
	if err := writeFileAtomic(s.Path, blob); err != nil {
		return fmt.Errorf("write %s: %w", s.Path, err)
	}
	return nil
}

// writeFileAtomic writes to a temp file in the same directory and renames
// it into place, so a crash mid-write cannot leave a truncated file that
// reads as "logged in" with an unusable token.
//
// The temp file is created and then chmod'ed to 0600 BEFORE any content
// is written — the window between creating a file and tightening its mode
// is exactly when another local user could open it, so nothing sensitive
// goes in until it is closed.
//
// fsync precedes the rename: rename is atomic with respect to readers,
// but without the sync a power loss can leave the directory entry
// pointing at unwritten data.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// ErrNotLoggedIn is returned when no token set is stored.
var ErrNotLoggedIn = errors.New("not logged in — run `talonctl login`")

// Load reads the stored token set.
//
// Refuses to read a file with permissions looser than 0600. A refresh
// token readable by other local accounts is a credential leak, and
// silently using it would hide that; the message says how to fix it.
func (s *Store) Load() (*Tokens, error) {
	info, err := os.Stat(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is group/world-accessible (%04o) — run: chmod 600 %s", s.Path, perm, s.Path)
	}
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var t Tokens
	if err := json.Unmarshal(blob, &t); err != nil {
		return nil, fmt.Errorf("parse %s: %w (delete it and log in again)", s.Path, err)
	}
	sp := s.secretPath()
	si, err := os.Stat(sp)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	if perm := si.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is group/world-accessible (%04o) — run: chmod 600 %s", sp, perm, sp)
	}
	secret, err := readIfExists(filepath.Clean(sp))
	if err != nil {
		return nil, err
	}
	t.RefreshToken = strings.TrimSpace(string(secret))
	if t.RefreshToken == "" {
		return nil, ErrNotLoggedIn
	}
	return &t, nil
}

// Delete removes the stored token set. Missing file is not an error —
// `logout` should be idempotent.
func (s *Store) Delete() error {
	for _, p := range []string{s.Path, s.secretPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// FromOAuth2 projects an oauth2.Token onto the on-disk shape.
func FromOAuth2(issuer, clientID string, tok *oauth2.Token) *Tokens {
	return &Tokens{
		Issuer:       issuer,
		ClientID:     clientID,
		RefreshToken: tok.RefreshToken,
		ObtainedAt:   time.Now().UTC(),
	}
}
