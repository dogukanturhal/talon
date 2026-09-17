// SPDX-License-Identifier: AGPL-3.0-or-later

// Package security — tier-1 baseline response-header middleware.
//
// Every response Talon writes (auth callbacks, deny pages, /healthz)
// flows through this middleware before the body reaches the client.
// The header set is the minimum baseline OWASP + MDN + Mozilla
// Observatory call out for browser-facing surfaces in 2026.
//
// Headers added (defaults):
//
//	Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
//	X-Content-Type-Options:    nosniff
//	X-Frame-Options:           DENY            (overridden by FCL CSP)
//	Referrer-Policy:           strict-origin-when-cross-origin
//	Cross-Origin-Opener-Policy: same-origin
//	Permissions-Policy:        accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()
//
// Notes
//   - HSTS preload requires `includeSubDomains` AND a 12-month minimum
//     max-age; Talon emits 1y by default. Once a tier-1 host signs up
//     for the preload list (https://hstspreload.org), the directive
//     becomes hard to undo — keep that in mind before flipping the
//     env flag on production for the first time on a new apex.
//   - CSP for proxied upstream bodies is OUT OF SCOPE — the upstream
//     owns content-security policy for its own UI. This middleware
//     only sets CSP on responses *Talon itself authored* (deny pages,
//     auth-flow scaffolding). For Talon-authored HTML, callers can
//     layer their own CSP after this middleware (e.g. the FCL handler
//     in internal/handlers/frontchannel_logout.go does exactly that).
//   - X-XSS-Protection is INTENTIONALLY OMITTED. Modern browsers ignore
//     or have removed it; OWASP guidance is now "do not set". CSP +
//     output encoding cover the same surface.
//   - This package only fixes header GAPS in Talon's own responses;
//     headers proxied through from upstream are preserved by the reverse
//     proxy and not rewritten.
//
// Configuration: see Options. The zero value renders the conservative
// defaults documented above. Operators can dial HSTS down (e.g. shorter
// max-age during initial rollout) without code change.
package security

import (
	"net/http"
	"strings"
)

// Options controls which headers the middleware emits and how. Zero
// value is the tier-1 default; HSTS is enabled at 1y with preload +
// includeSubDomains, all other defaults match the package doc.
type Options struct {
	// DisableHSTS skips the Strict-Transport-Security header entirely.
	// Use only on non-TLS dev/test deployments — production with TLS
	// MUST keep HSTS on.
	DisableHSTS bool

	// HSTSMaxAge overrides the default 31536000 (1y). Anything <12mo
	// disqualifies the host from hstspreload.org submission; set lower
	// values only during initial rollout windows.
	HSTSMaxAge int

	// HSTSNoPreload omits the `preload` directive. Required before
	// first submission to https://hstspreload.org; set this to true
	// initially, flip to false once the host is on the list.
	HSTSNoPreload bool

	// HSTSNoSubdomains omits `includeSubDomains`. Removes the host from
	// preload eligibility; set only when the apex hosts non-HTTPS
	// content on subdomains (unlikely in a Talon deployment).
	HSTSNoSubdomains bool

	// FrameOptions overrides the default `DENY`. Common values:
	// "DENY", "SAMEORIGIN", or "" to omit (use CSP frame-ancestors
	// instead — see the FCL handler for the iframe-allow case).
	FrameOptions string

	// ReferrerPolicy overrides the default
	// `strict-origin-when-cross-origin`. Empty omits.
	ReferrerPolicy string

	// CrossOriginOpenerPolicy overrides default `same-origin`. Empty
	// omits.
	CrossOriginOpenerPolicy string

	// PermissionsPolicy overrides the default opt-out list. Empty
	// omits the header entirely. Operators wanting to ALLOW a feature
	// must specify the full policy string themselves — the package
	// does not provide builder helpers (low value vs. complexity).
	PermissionsPolicy string

	// SkipCOOPHosts is the set of request Hosts that should NOT receive
	// the Cross-Origin-Opener-Policy header at all (effective COOP =
	// unsafe-none for those responses).
	//
	// Use this for upstreams that run popup-based OAuth/OIDC flows whose
	// callback page calls `window.opener.postMessage(...)`. The textbook
	// example is HashiCorp Vault UI: the OIDC popup chain is broken by
	// ANY non-`unsafe-none` COOP value — including `same-origin-allow-
	// popups` — on either the IdP OR the RP, because in many real-world
	// browser/extension combinations (Firefox containers, CanvasBlocker,
	// Brave shields, browsers configured to open popups as tabs) the
	// popup is opened in a context where `window.opener` is severed on
	// the cross-origin → same-origin transition even when the WHATWG
	// spec says it should be preserved (HTML §7.2.7.2 rule 2.2 "unsafe-
	// none → same-origin-allow-popups, same origin as opener: no swap").
	// Documented at https://github.com/hashicorp/vault/issues/18648 +
	// https://web.dev/cross-origin-isolation-guide/ ("COOP breaks OAuth
	// for now"). The community consensus: do not emit COOP for hosts
	// whose UI does popup OAuth.
	//
	// The Spectre/Meltdown isolation benefit lost on listed hosts is
	// bounded:
	//   * Admin-tier UIs behind Talon serve no third-party content
	//   * No SharedArrayBuffer / no high-precision timer surface
	//   * Authenticated-admin-only access (Talon IAP)
	// For these hosts the operator-friction cost (broken sign-in)
	// strictly dominates the COOP risk reduction.
	//
	// Match is on exact Host header (lower-cased on entry); no wildcard
	// support — list the hosts explicitly so the security exception is
	// auditable.
	//
	// Env: TALON_SKIP_COOP_HOSTS=internal.example.com,other.host
	SkipCOOPHosts []string
}

const (
	defaultHSTSMaxAge        = 31536000 // 1y, hstspreload.org minimum
	defaultFrameOptions      = "DENY"
	defaultReferrerPolicy    = "strict-origin-when-cross-origin"
	// same-origin-allow-popups instead of strict same-origin so popup-
	// mode OIDC RPs (Vault UI, etc.) preserve `window.opener` across the
	// cross-origin navigation through Falcon-ID. Strict `same-origin`
	// SEVERS window.opener the moment the popup leaves vault.ops for
	// id.hexxlock.com, so the popup's eventual callback page at
	// vault.ops/ui/.../callback throws
	//   Cannot read properties of null (reading 'postMessage')
	// when it tries to deliver the auth code back to the parent tab.
	//
	// `same-origin-allow-popups` keeps the COOP+COEP top-level
	// isolation benefits (Spectre/Meltdown mitigations,
	// SharedArrayBuffer gating) but explicitly allows popups opened
	// by trusted same-origin parents to retain the opener relationship
	// across cross-origin navigation. The risk delta is bounded:
	//   * iframe embed is still blocked by X-Frame-Options: DENY
	//   * cross-origin fetch is still gated by CORS
	//   * the only postMessage receivers are upstream RPs that already
	//     validate origin
	// Matches the falcon-id middleware default after
	// falcon-id@a0b4851 (same fix on the IdP side).
	defaultCOOP              = "same-origin-allow-popups"
	defaultPermissionsPolicy = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"
)

// Headers returns the middleware. Apply via http.Handler chaining at
// the top of Talon's mux — before routing — so every response (auth,
// deny page, /healthz, /metrics-public) carries the tier-1 baseline.
//
// The middleware is a thin pre-write header set; it does not buffer
// or rewrite the body. Conflict resolution with handlers that set
// their own CSP / X-Frame-Options is "handler wins" — the FCL handler
// explicitly sets `Content-Security-Policy: frame-ancestors ...` after
// this middleware fires, which overrides the default DENY frame
// behaviour. Use http.Header.Set semantics intentionally so the latest
// writer wins on ResponseWriter.WriteHeader.
func Headers(opts Options, next http.Handler) http.Handler {
	hstsValue := hstsHeader(opts)
	// Pre-build the COOP-skip lookup set once at construction so the
	// per-request hot path is a single map lookup, not a slice scan.
	skipCOOP := make(map[string]struct{}, len(opts.SkipCOOPHosts))
	for _, h := range opts.SkipCOOPHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		skipCOOP[h] = struct{}{}
	}
	coopValue := defaultIfEmpty(opts.CrossOriginOpenerPolicy, defaultCOOP)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if hstsValue != "" {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		h.Set("X-Content-Type-Options", "nosniff")
		if v := defaultIfEmpty(opts.FrameOptions, defaultFrameOptions); v != "" {
			h.Set("X-Frame-Options", v)
		}
		if v := defaultIfEmpty(opts.ReferrerPolicy, defaultReferrerPolicy); v != "" {
			h.Set("Referrer-Policy", v)
		}
		if coopValue != "" {
			// Host comparison is case-insensitive per RFC 7230 §5.4.
			// Strip the port suffix (`internal.example.com:443`) so
			// the operator-configured list stays simple.
			host := strings.ToLower(r.Host)
			if i := strings.IndexByte(host, ':'); i >= 0 {
				host = host[:i]
			}
			if _, skip := skipCOOP[host]; !skip {
				h.Set("Cross-Origin-Opener-Policy", coopValue)
			}
		}
		if v := defaultIfEmpty(opts.PermissionsPolicy, defaultPermissionsPolicy); v != "" {
			h.Set("Permissions-Policy", v)
		}
		next.ServeHTTP(w, r)
	})
}

func hstsHeader(opts Options) string {
	if opts.DisableHSTS {
		return ""
	}
	maxAge := opts.HSTSMaxAge
	if maxAge <= 0 {
		maxAge = defaultHSTSMaxAge
	}
	// Build "max-age=N; includeSubDomains; preload"
	out := "max-age=" + itoa(maxAge)
	if !opts.HSTSNoSubdomains {
		out += "; includeSubDomains"
	}
	if !opts.HSTSNoPreload && !opts.HSTSNoSubdomains {
		// preload requires includeSubDomains; without it, preload would
		// be rejected by hstspreload.org submission. Skip preload when
		// includeSubDomains is off so the header stays valid.
		out += "; preload"
	}
	return out
}

func defaultIfEmpty(v, def string) string {
	if v == "" {
		return def
	}
	if v == "-" {
		// Explicit omit. Allows operators to disable a single header
		// without disabling the entire middleware.
		return ""
	}
	return v
}

// itoa avoids strconv import for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
