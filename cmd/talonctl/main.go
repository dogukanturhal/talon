// SPDX-License-Identifier: AGPL-3.0-or-later

// Command talonctl is the developer-facing CLI for Talon-fronted hosts.
//
// It is the human counterpart to cmd/svctoken-refresher: where that
// sidecar keeps a MACHINE's client_credentials token fresh for ArgoCD /
// Atlantis / CI, this authenticates a PERSON against Falcon-ID in a
// browser (RFC 8252 loopback + PKCE) and mints short-lived, host-scoped
// access tokens from the resulting refresh token.
//
// The practical difference is that tokens minted here carry the
// developer's own identity — sub, groups, roles — so a TalonRoute's
// allowedGroups and its SpiceDB relation actually apply to CLI traffic,
// and offboarding is disabling the Falcon-ID user rather than deleting a
// per-developer YAML file.
//
//	talonctl login
//	talonctl token   --host internal.example.com
//	talonctl npm      --host internal.example.com --scope @hexxlock
//	talonctl logout
//
// See internal/clilogin for why loopback PKCE (not device flow), and why
// the `resource` parameter is not optional.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	"github.com/hexxlock/talon/internal/clilogin"
)

// Build metadata, injected via -ldflags -X at build time. These must
// exist as package-level vars for that to work: `go build -X main.version=…`
// against a variable that is not declared is a SILENT no-op — the linker
// does not error, the flag is simply dropped, and every published binary
// reports "dev". cmd/talon carries the same trio for the same reason.
//
// A credential tool in particular needs this: the first question about a
// misbehaving login is which build produced it, and "dev" answers nothing.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

const usage = `talonctl — sign in to Talon-fronted hosts as your Falcon-ID user

Usage:
  talonctl login [--publish]                        authenticate in a browser (read-only unless --publish)
  talonctl token  --host <host>                     print an access token for one host
  talonctl npm    --host <host> [--scope @hexxlock] write an npm credential to ~/.npmrc
  talonctl logout                                   forget the stored refresh token
  talonctl version                                  print build metadata

Common flags:
  --issuer    OIDC issuer            (default https://id.hexxlock.com)
  --client-id public client id       (default svc-talon-cli)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	os.Exit(main1())
}

// main1 exists so every cleanup path runs before the process exits.
// os.Exit does not run deferred functions, so calling it directly from
// main would skip stop() and leak the signal handler's registration —
// the gocritic exitAfterDefer diagnostic. Returning a code and exiting in
// exactly one place keeps the teardown honest.
func main1() int {
	// Ctrl-C during the browser leg should tear down the loopback
	// listener rather than orphan it holding a port.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "cancelled")
			return 130
		}
		fmt.Fprintf(os.Stderr, "talonctl: %v\n", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, sub string, args []string) error {
	fs := flag.NewFlagSet("talonctl "+sub, flag.ExitOnError)
	issuer := fs.String("issuer", clilogin.DefaultIssuer, "OIDC issuer to authenticate against")
	clientID := fs.String("client-id", clilogin.DefaultClientID, "public (no-secret) OAuth client id")
	host := fs.String("host", "", "Talon-fronted host the token is for, e.g. internal.example.com")
	scope := fs.String("scope", "@hexxlock", "npm package scope to point at the registry")
	npmrc := fs.String("npmrc", "", "path to .npmrc (default ~/.npmrc)")
	// Per-host Talon scopes must be granted at login — a refresh
	// cannot widen scope (RFC 6749 §6), so naming the hosts later is
	// too late. Comma-separated.
	hosts := fs.String("hosts", "", "comma-separated Talon hosts this login grants (default internal.example.com)")
	// Read-only by default. `npm install` is a GET (talon:<host>:read);
	// `npm publish` is a PUT (talon:<host>:write). Most developers only
	// consume, and a consume-only credential cannot damage the registry.
	publish := fs.Bool("publish", false, "also grant publish (write) access — needed only to run `npm publish`")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := clilogin.DefaultStore()
	if err != nil {
		return err
	}

	switch sub {
	case "login":
		return doLogin(ctx, *issuer, *clientID, splitHosts(*hosts), *publish, store)
	case "token":
		tok, err := mint(ctx, *issuer, *clientID, *host, store)
		if err != nil {
			return err
		}
		fmt.Println(tok.AccessToken)
		return nil
	case "npm":
		return doNpm(ctx, *issuer, *clientID, *host, *scope, *npmrc, store)
	case "logout":
		if err := store.Delete(); err != nil {
			return err
		}
		fmt.Println("Signed out. The stored refresh token has been removed from this machine.")
		// Deliberately explicit: deleting the local file does not revoke
		// the token server-side. Saying so prevents a false sense that a
		// lost laptop is handled by having run `logout` on it.
		fmt.Println("Note: this removes the local credential only — it does not revoke the session at the IdP.")
		return nil
	case "version", "--version", "-v":
		fmt.Printf("talonctl %s (commit %s, built %s, %s/%s)\n",
			version, commit, buildDate, runtime.GOOS, runtime.GOARCH)
		return nil
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func doLogin(ctx context.Context, issuer, clientID string, hosts []string, publish bool, store *clilogin.Store) error {
	// The browser leg is human-paced; bound it so a forgotten tab does
	// not leave the process and its listener alive indefinitely.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ep, err := clilogin.Discover(ctx, issuer)
	if err != nil {
		return err
	}
	tok, err := clilogin.Login(ctx, ep, clientID, hosts, publish, nil)
	if err != nil {
		return err
	}
	if err := store.Save(clilogin.FromOAuth2(ep.Issuer, clientID, tok)); err != nil {
		return err
	}
	access := "read-only (install)"
	if publish {
		access = "read + publish"
	}
	fmt.Printf("Signed in as yourself — %s. Refresh token stored at %s (0600).\n", access, store.Path)
	if !publish {
		// Say this now rather than let `npm publish` fail with a bare 403
		// later. Re-running login is the only way to widen the grant: the
		// IdP will not add scope to an existing one on refresh.
		fmt.Println("To publish packages, re-run: talonctl login --publish")
	}
	fmt.Println("Next: talonctl npm --host internal.example.com")
	return nil
}

func mint(ctx context.Context, issuer, clientID, host string, store *clilogin.Store) (*oauth2.Token, error) {
	if host == "" {
		return nil, errors.New("--host is required (e.g. --host internal.example.com)")
	}
	saved, err := store.Load()
	if err != nil {
		return nil, err
	}
	// Prefer what login recorded over the flag defaults: a token set
	// obtained from one issuer/client must be refreshed against the same
	// pair, and silently mixing them yields a confusing invalid_grant.
	if saved.Issuer != "" {
		issuer = saved.Issuer
	}
	if saved.ClientID != "" {
		clientID = saved.ClientID
	}
	ep, err := clilogin.Discover(ctx, issuer)
	if err != nil {
		return nil, err
	}
	tok, err := clilogin.MintForHost(ctx, ep, clientID, saved.RefreshToken, host)
	if err != nil {
		return nil, err
	}
	// Falcon-ID may rotate the refresh token on use (RFC 9700 §4.14.2).
	// Persist the replacement or the next command fails with
	// invalid_grant on a token that has already been consumed.
	if tok.RefreshToken != "" && tok.RefreshToken != saved.RefreshToken {
		saved.RefreshToken = tok.RefreshToken
		if err := store.Save(saved); err != nil {
			return nil, fmt.Errorf("persist rotated refresh token: %w", err)
		}
	}
	return tok, nil
}

// splitHosts turns the comma-separated --hosts flag into a slice,
// dropping empties so "a,,b" and a trailing comma behave.
func splitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func doNpm(ctx context.Context, issuer, clientID, host, scope, npmrc string, store *clilogin.Store) error {
	tok, err := mint(ctx, issuer, clientID, host, store)
	if err != nil {
		return err
	}
	if err := clilogin.WriteNpmrc(npmrc, host, scope, tok.AccessToken); err != nil {
		return err
	}
	where := npmrc
	if where == "" {
		where = "~/.npmrc"
	}
	fmt.Printf("Wrote npm credential for %s to %s (valid until %s).\n",
		host, where, tok.Expiry.Local().Format(time.Kitchen))
	fmt.Printf("Re-run `talonctl npm --host %s` when npm starts returning 401.\n", host)
	return nil
}
