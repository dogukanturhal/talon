// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dogukanturhal/talon/internal/config"
	"golang.org/x/oauth2"
)

func TestLastUserCookie_Attributes(t *testing.T) {
	r := &RP{cfg: &config.Config{CookieDomain: ".internal.example.com"}}
	w := httptest.NewRecorder()
	r.setLastUserCookie(w, "alice+x@example.com")
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	c := cs[0]
	if c.Name != LastUserCookieName || !c.HttpOnly || !c.Secure || c.Domain != "" || c.Path != "/" || c.MaxAge <= 0 {
		t.Errorf("bad cookie attrs: %+v", c)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	// Round-trips through lastUserHint.
	req := httptest.NewRequest(http.MethodGet, "/auth/start", nil)
	req.AddCookie(c)
	if got := lastUserHint(req); got != "alice+x@example.com" {
		t.Errorf("hint = %q", got)
	}
}

func TestLastUserCookie_RejectsInvalid(t *testing.T) {
	r := &RP{cfg: &config.Config{CookieDomain: ".internal.example.com"}}
	for _, bad := range []string{"", "a\nb", strings.Repeat("a", 300)} {
		w := httptest.NewRecorder()
		r.setLastUserCookie(w, bad)
		if n := len(w.Result().Cookies()); n != 0 {
			t.Errorf("set cookie for invalid %q", bad)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/start", nil)
	req.AddCookie(&http.Cookie{Name: LastUserCookieName, Value: "%0Aevil"})
	if got := lastUserHint(req); got != "" {
		t.Errorf("control chars must be rejected, got %q", got)
	}
	if got := lastUserHint(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Errorf("no cookie -> empty hint, got %q", got)
	}
}

func TestClearLastUserCookie(t *testing.T) {
	r := &RP{cfg: &config.Config{CookieDomain: ".internal.example.com"}}
	w := httptest.NewRecorder()
	r.clearLastUserCookie(w)
	cs := w.Result().Cookies()
	if len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatalf("expected deletion cookie, got %+v", cs)
	}
}

// Both authorize paths carry login_hint: the inline URL and the PAR params.
func TestLoginHint_InlineAuthURL(t *testing.T) {
	oa := &oauth2.Config{ClientID: "c", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/oauth/authorize"}}
	u := oa.AuthCodeURL("st", oauth2.SetAuthURLParam("login_hint", "alice@example.com"))
	parsed, _ := url.Parse(u)
	if parsed.Query().Get("login_hint") != "alice@example.com" {
		t.Errorf("inline url missing login_hint: %s", u)
	}
}
