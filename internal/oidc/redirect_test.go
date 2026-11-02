// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/talon/internal/oidc"
)

// TestWriteHTMLRedirect_FullScaffolding asserts the response body has the
// full <html><head><body> structure required to defeat iOS WebKit's
// download heuristic. ADR 0001 §5.d codifies the contract; regression
// here = browsers will treat a Talon redirect as a downloadable file.
func TestWriteHTMLRedirect_FullScaffolding(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	target := "https://id.example.com/oauth/authorize?client_id=svc-talon&state=abc"
	oidc.WriteHTMLRedirect(rr, target)

	if rr.Code != 302 {
		t.Fatalf("status: want 302, got %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != target {
		t.Errorf("Location: want %q, got %q", target, got)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type: want text/html…, got %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff must remain present (body scaffolding satisfies WebKit), got %q", got)
	}

	body := rr.Body.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"<html",
		"<head>",
		`<meta http-equiv="refresh"`,
		"<body>",
		"window.location.replace",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing required marker %q\nfull body:\n%s", want, body)
		}
	}

	// The forbidden Pomerium-shape: bare anchor with no document scaffolding.
	if strings.HasPrefix(strings.TrimSpace(body), "<a ") && !strings.Contains(body, "<!DOCTYPE") {
		t.Fatal("body matches the iOS-failing Pomerium shape (bare <a>)")
	}

	if rr.Body.Len() < 200 {
		t.Errorf("body too short (%d bytes); a full HTML doc is typically 400-800 bytes", rr.Body.Len())
	}
}

// TestWriteHTMLRedirect_HTMLEscaping asserts that hostile-looking targets
// are HTML-escaped (defence-in-depth — open-redirect prevention is
// elsewhere, but the body must not allow XSS into the document).
func TestWriteHTMLRedirect_HTMLEscaping(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	oidc.WriteHTMLRedirect(rr, `https://id.example.com/x?foo="><script>alert(1)</script>`)
	body := rr.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("body contains unescaped <script> tag — XSS regression")
	}
}
