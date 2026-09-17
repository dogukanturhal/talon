// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clilogin implements the human half of Talon's Bearer-token
// story: an RFC 8252 native-app login that authenticates a DEVELOPER
// against Falcon-ID and yields short-lived, host-scoped access tokens.
//
// WHY THIS EXISTS
// ===============
// cmd/svctoken-refresher is the MACHINE pattern — a sidecar holding a
// client_credentials secret, keeping a Bearer token fresh in a file for
// ArgoCD/Atlantis/CI. There was no human counterpart, so the only way to
// give a developer CLI access to a Talon-fronted host was to mint them a
// personal client_credentials client. That models a person as a service
// account, with three consequences:
//
//   - The token carries no user identity, so a TalonRoute's
//     allowedGroups cannot apply to it (Talon skips policy evaluation
//     for machine identities by design).
//   - Offboarding is not tied to the Falcon-ID user — disabling the
//     person leaves their client working until someone deletes a YAML
//     file.
//   - A non-expiring client_secret sits on every laptop, which the
//     short-lived access token in front of it does nothing to mitigate.
//
// This package fixes the root cause: the developer authenticates AS
// THEMSELVES, in a browser, and the laptop stores only a refresh token.
//
// WHY LOOPBACK PKCE AND NOT DEVICE FLOW
// =====================================
// RFC 8252 §7.3 (still the governing BCP for native apps) specifies the
// loopback redirect for clients on a machine that has a browser, and
// OAuth 2.1 makes PKCE mandatory. The device authorization grant is the
// fallback for INPUT-CONSTRAINED devices, and its user_code leg is
// phishable in a way PKCE is not — which is why AWS CLI v2.22+ moved its
// default to PKCE and put device code behind an explicit flag, and why
// gcloud has always been loopback-only.
//
// Falcon-ID does not advertise a device_authorization_endpoint at all
// today, so the loopback flow is also the only one actually available.
// A headless/SSH fallback is deliberately left for later rather than
// half-built here.
//
// THE `resource` PARAMETER IS LOAD-BEARING
// ========================================
// Talon pins a token's `aud` to the request Host (RFC 8707 resource→aud,
// RFC 8725 §3.1 — see internal/svctoken/scope.go expectedAudienceForHost).
// Falcon-ID only emits that audience when the token request carries
// `resource=`. Without it the token comes back audienced to the generic
// API and Talon rejects it with `audience mismatch` BEFORE the upstream
// is ever reached. Requesting the right scope is NOT sufficient — scope
// and audience are enforced separately. Every mint path here therefore
// sends `resource`, and MintForHost re-checks the returned `aud` rather
// than trusting it.
package clilogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// DefaultIssuer is Falcon-ID. Overridable for dev tenants.
const DefaultIssuer = "https://id.hexxlock.com"

// DefaultClientID is the platform's first-party public client. It holds
// NO secret — that is the point of a native app — so shipping the
// identifier in the binary is expected, not a leak (RFC 6749 §2.2:
// client_id is not confidential).
//
// NOTE THE `svc-` PREFIX. The ServiceClientClaim declares
// `service: talon-cli`, but the provisioner derives the registered
// client_id as "svc-" + service, so the value Falcon-ID actually knows
// is `svc-talon-cli` (verified against iam_oauth_clients after the
// claim first reconciled). Using the bare service name here yields
// `invalid_client` at the authorize step.
const DefaultClientID = "svc-talon-cli"

// baseScopes are requested at login. `offline_access` yields the refresh
// token that makes this a login rather than a one-shot; `groups` and
// `roles` are what Talon's policy evaluator actually gates on, so a
// token minted without them authenticates fine and then fails
// authorisation — confusingly. Request them up front.
var baseScopes = []string{"openid", "profile", "email", "groups", "roles", "offline_access"}

// DefaultHosts are the Talon-fronted hosts a login grants access to when
// the caller does not name any.
var DefaultHosts = []string{"internal.example.com"}

// scopesForLogin returns the full scope set to request at AUTHORIZE time.
//
// READ IS THE DEFAULT; WRITE IS OPT-IN
// ====================================
// Talon derives the required verb from the request
// (svctoken.VerbForRequest): `npm install` is a GET and needs
// talon:<host>:read, while `npm publish` is a PUT and needs
// talon:<host>:write. A token granted only :read therefore cannot
// publish — the gateway rejects it before Verdaccio is reached.
//
// That makes consume-only the natural default and matches how managed
// registries model this: AWS CodeArtifact splits ReadFromRepository
// (consumers) from PublishPackageVersion (a designated publishing
// role), and its guidance is that a shared repository should be
// read-only to everyone except that role, because most teams consume
// packages in their build and never publish. Most developers here want
// `npm install @hexxlock/...` and nothing more; handing them a token
// that can also overwrite a package is privilege they never asked for.
//
// THE SCOPES MUST BE CHOSEN HERE, NOT AT REFRESH
// ==============================================
// RFC 6749 §6 lets a refresh_token request NARROW the granted scope; it
// can never widen it. Asking the token endpoint for
// `talon:<host>:read` when the original authorization did not include it
// yields a token without it — silently, since the response carries the
// originally granted scopes and looks perfectly valid. The failure then
// lands far from its cause: Falcon-ID issues a token with the correct
// audience, the CLI's audience check passes, and Talon rejects it with
// `scope insufficient` at the gateway. Diagnosed live 2026-08-16.
//
// ⚠ Falcon-ID additionally does NOT honour narrowing: asked for only
// :read against a grant containing both, it returns both (verified
// 2026-08-16). So the grant recorded at login IS the effective ceiling
// for every token derived from it, and dropping :write later requires a
// fresh login rather than a narrower refresh.
//
// Note this is exactly the class of bug a mock authorization server
// cannot catch — a fake that echoes back whatever scope it is asked for
// will happily "grant" the widened set.
func scopesForLogin(hosts []string, publish bool) []string {
	out := append([]string(nil), baseScopes...)
	for _, h := range hosts {
		if h == "" {
			continue
		}
		out = append(out, "talon:"+h+":read")
		if publish {
			out = append(out, "talon:"+h+":write")
		}
	}
	return out
}

// Endpoints is the subset of OIDC discovery this flow needs.
type Endpoints struct {
	Issuer        string
	Authorization string
	Token         string
	Revocation    string
}

// Discover fetches the issuer's OIDC discovery document.
//
// Endpoints are discovered rather than hardcoded so a tenant migration
// or an endpoint rename does not require shipping a new binary to every
// laptop.
func Discover(ctx context.Context, issuer string) (*Endpoints, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: %s returned %d", u, resp.StatusCode)
	}
	var doc struct {
		Issuer     string   `json:"issuer"`
		AuthURL    string   `json:"authorization_endpoint"`
		TokenURL   string   `json:"token_endpoint"`
		RevokeURL  string   `json:"revocation_endpoint"`
		PKCEMethod []string `json:"code_challenge_methods_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("discovery: decode: %w", err)
	}
	// Refuse to continue if the AS cannot do S256. Downgrading to `plain`
	// (RFC 7636 §4.2) would defeat the only thing protecting a public
	// client's authorization code, so fail loudly instead.
	if !contains(doc.PKCEMethod, "S256") {
		return nil, fmt.Errorf("issuer %s does not advertise PKCE S256 (got %v)", issuer, doc.PKCEMethod)
	}
	if doc.AuthURL == "" || doc.TokenURL == "" {
		return nil, errors.New("discovery: missing authorization_endpoint or token_endpoint")
	}
	return &Endpoints{
		Issuer:        doc.Issuer,
		Authorization: doc.AuthURL,
		Token:         doc.TokenURL,
		Revocation:    doc.RevokeURL,
	}, nil
}

// Login runs the interactive loopback PKCE flow and returns the token
// set. The caller is responsible for persisting it (see Store).
//
// openBrowser is injectable so tests can drive the flow without a
// desktop; pass nil for the real thing.
// hosts names the Talon-fronted hosts this login should grant access to;
// their per-host scopes are requested here because a later refresh
// cannot add them (see scopesForLogin). Empty means DefaultHosts.
func Login(ctx context.Context, ep *Endpoints, clientID string, hosts []string, publish bool, openBrowser func(string) error) (*oauth2.Token, error) {
	if openBrowser == nil {
		openBrowser = OpenBrowser
	}
	if len(hosts) == 0 {
		hosts = DefaultHosts
	}

	// Bind on port 0 and let the kernel choose. RFC 8252 §7.3 requires
	// the AS to accept ANY port on a registered loopback redirect, which
	// is what makes a fixed registered URI workable here — Falcon-ID
	// implements that port-fuzzy match. Binding explicitly to 127.0.0.1
	// (not :: or 0.0.0.0) keeps the callback unreachable from the
	// network.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener: %w", err)
	}
	defer func() { _ = ln.Close() }()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	verifier := oauth2.GenerateVerifier()
	state, err := randomState()
	if err != nil {
		return nil, err
	}

	cfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    oauth2.Endpoint{AuthURL: ep.Authorization, TokenURL: ep.Token},
		RedirectURL: redirectURI,
		Scopes:      scopesForLogin(hosts, publish),
	}

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// Compare state before ANYTHING else. A mismatch means this
		// callback did not originate from the authorize request we
		// started, so the code is not ours to redeem (RFC 6749 §10.12).
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resultCh <- result{err: errors.New("state mismatch — callback did not match this login attempt")}
			return
		}
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			http.Error(w, "login failed: "+e, http.StatusBadRequest)
			resultCh <- result{err: fmt.Errorf("authorization failed: %s %s", e, desc)}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			resultCh <- result{err: errors.New("callback carried neither code nor error")}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(successPage))
		resultCh <- result{code: code}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.AccessTypeOffline)
	fmt.Printf("Opening browser to sign in as your Falcon-ID user.\nIf it does not open, visit:\n\n  %s\n\n", authURL)
	if err := openBrowser(authURL); err != nil {
		// Not fatal — the URL is printed above and the listener is up.
		fmt.Printf("(could not open a browser automatically: %v)\n", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		tok, err := cfg.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return nil, fmt.Errorf("token exchange: %w", err)
		}
		if tok.RefreshToken == "" {
			// Without this the "login" lasts one access-token lifetime
			// and every later command silently re-opens a browser.
			return nil, errors.New("no refresh_token returned — check the client allows offline_access")
		}
		return tok, nil
	}
}

// MintForHost exchanges the stored refresh token for an access token
// scoped and audienced to ONE Talon host.
//
// Both halves matter and are enforced separately by Talon:
//   - scope  talon:<host>:read|write  → what the token may do
//   - aud    https://<host>           → where it may be presented
//
// The audience only appears when the request carries `resource`, so a
// caller that forgets it gets a token that authenticates against
// Falcon-ID perfectly and is then rejected by Talon. Rather than trust
// that, the returned token's `aud` is verified before it is handed back.
func MintForHost(ctx context.Context, ep *Endpoints, clientID, refreshToken, host string) (*oauth2.Token, error) {
	// No `scope` parameter, deliberately. RFC 6749 §6: omitting it means
	// "identical to the scope originally granted", which is exactly what
	// is wanted — the login already decided whether this credential may
	// publish, and naming :write here would ask for authority the user
	// may have declined. (Falcon-ID ignores narrowing on refresh anyway,
	// so requesting a subset would be misleading rather than effective.)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"resource":      {"https://" + host},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("refresh: decode: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return nil, fmt.Errorf("refresh failed (%d): %s %s", resp.StatusCode, body.Error, body.ErrorDesc)
	}
	if err := verifyAudience(body.AccessToken, host); err != nil {
		return nil, err
	}
	tok := &oauth2.Token{
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Duration(body.ExpiresIn) * time.Second),
	}
	return tok, nil
}

// verifyAudience refuses to hand back a token Talon will reject.
//
// This is a usability guard, not a security control — the CLI does not
// verify the signature (Talon does that, against the IdP's JWKS). The
// point is that a missing `resource` produces a token which fails at the
// gateway with an opaque 401 several steps later; catching it here names
// the actual cause.
func verifyAudience(accessToken, host string) error {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return errors.New("access token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode token claims: %w", err)
	}
	var claims struct {
		Aud any `json:"aud"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fmt.Errorf("parse token claims: %w", err)
	}
	want := "https://" + host
	for _, a := range audienceList(claims.Aud) {
		if a == want {
			return nil
		}
	}
	return fmt.Errorf("token audience %v does not include %q — Talon will reject it with 'audience mismatch'; "+
		"the token request must carry resource=%s", claims.Aud, want, want)
}

// audienceList normalises the `aud` claim, which RFC 7519 §4.1.3 allows
// to be either a single string or an array.
func audienceList(aud any) []string {
	switch v := aud.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// OpenBrowser opens a URL in the user's default browser.
//
// The URL is validated before it reaches the process launcher. It is
// built locally from the discovery document rather than taken from
// input, so this is defence in depth rather than a known hole — but the
// argument does cross a process boundary, and a handler that accepted
// `file://` or a shell-ish string would be a real problem on the
// platforms whose openers are more permissive than xdg-open. Restricting
// to http/https with a host present makes the value passed out of the
// process a URL by construction, not by assumption.
//
// Each branch names its command as a literal so the executable itself is
// never variable; only the validated URL varies.
func OpenBrowser(u string) error {
	if err := validateBrowserURL(u); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

// validateBrowserURL rejects anything that is not an absolute http(s)
// URL with a host.
func validateBrowserURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("refusing to open malformed URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("refusing to open non-http(s) URL scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("refusing to open URL with no host")
	}
	return nil
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

const successPage = `<!doctype html><html><head><meta charset="utf-8">
<title>Signed in</title></head>
<body style="font-family:system-ui,sans-serif;text-align:center;padding-top:4rem">
<h2>Signed in to HexxLock</h2>
<p>You can close this tab and return to your terminal.</p>
</body></html>`
