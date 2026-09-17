// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the access-broker's minimal in-browser terminal
// front-end (xterm.js) so the broker binary is self-contained — no
// sidecar static-file server, no CDN dependency at runtime (the access
// zone serves unmanaged/contractor devices that may not reach a public
// CDN, and a CDN dependency would be an uncontrolled supply-chain edge
// for a security plane). The HTML loads xterm.js from a pinned,
// SRI-checked CDN URL by default; operators who need a fully air-gapped
// build can vendor the xterm assets next to index.html and they will be
// embedded too (any *.js / *.css here is served from the same handler).
package web

import (
	"embed"
	"io/fs"
)

// index.html is the Phase 2 xterm.js SSH terminal; rdp.html is the Phase 3
// HTML5-canvas remote-desktop client; db.html is the Phase 4 SQL console and
// k8s.html the Phase 4 kubectl exec/logs terminal (ADR 0044). All are served
// from the same FileServer mounted on the broker binary.
//
//go:embed index.html rdp.html db.html k8s.html
var assets embed.FS

// FS returns the embedded static asset filesystem rooted at this
// package's directory (so "index.html", "db.html", "k8s.html" resolve
// directly). index.html is the Phase 2 SSH terminal; db.html is the Phase 4
// SQL console; k8s.html is the Phase 4 kubectl exec/logs terminal. Mount it
// with http.FileServer(http.FS(web.FS())).
func FS() fs.FS { return assets }
