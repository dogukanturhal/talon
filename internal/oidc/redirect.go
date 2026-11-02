// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oidc — redirect.go ports Falcon-ID's writeOAuthHTMLRedirect to
// Go's net/http for Talon. Every cross-origin 302 in the auth dance must
// emit a fully HTML-scaffolded body to avoid the iOS WebKit "is this a
// download?" heuristic. See ADR 0001 §5.d.
package oidc

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
)

// htmlRedirectTpl is the canonical body shape. Two redundant mechanisms:
// the meta refresh works without JS, the script tag fires immediately when
// JS is enabled. Both serve as signals to WebKit that this is an HTML
// document (not a binary blob to download).
var htmlRedirectTpl = template.Must(template.New("oauth_redirect").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta http-equiv="refresh" content="0;url={{.Target}}">
  <title>Redirecting…</title>
</head>
<body>
  <p>Redirecting to <a href="{{.Target}}">{{.Target}}</a>&hellip;</p>
  <script>window.location.replace({{.TargetJS}});</script>
</body>
</html>
`))

// WriteHTMLRedirect emits a 302 Found with a full <html><head><body>
// document body whose meta-refresh + JS script both navigate to target.
//
// Use this in place of http.Redirect for any redirect that:
//
//  1. crosses an origin boundary (talon ↔ Falcon-ID), AND
//  2. is served by Talon (the iOS bug fires on the response Talon writes,
//     not Falcon-ID's response — Falcon-ID has its own writeOAuthHTMLRedirect).
//
// Same-origin redirects can use http.Redirect; iOS only fires the download
// heuristic on cross-origin chains.
func WriteHTMLRedirect(w http.ResponseWriter, target string) {
	w.Header().Set("Location", target)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Cache-Control:no-store prevents an intermediary or browser cache
	// from serving the meta-refresh page on a back-button navigation that
	// would re-trigger the OIDC dance with stale state cookies.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// nosniff is intentionally KEPT — the body's HTML scaffolding is what
	// satisfies WebKit's heuristic, not the absence of nosniff. See ADR
	// 0001 §5.d for the rule.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusFound)
	_ = renderHTMLRedirect(w, target)
}

func renderHTMLRedirect(w io.Writer, target string) error {
	// Use encoding/json with HTMLEscape ON so that any `<` (specifically
	// `</script`) inside target becomes `<`, which keeps the JS
	// string literal closed and prevents <script> tag breakout.
	var jsBuf bytes.Buffer
	enc := json.NewEncoder(&jsBuf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(target); err != nil {
		return err
	}
	// Encoder appends a newline; strip it so the JS source stays compact.
	jsLit := bytes.TrimRight(jsBuf.Bytes(), "\n")
	return htmlRedirectTpl.Execute(w, struct {
		Target   string
		TargetJS template.JS
	}{
		Target: target,
		// safe to mark as JS: the value is a JSON-encoded string with
		// HTML-special bytes escaped to \uXXXX.
		TargetJS: template.JS(jsLit), //nolint:gosec // sanitised above
	})
}
