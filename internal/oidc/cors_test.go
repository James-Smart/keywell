package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/testenv"
)

const (
	spaOrigin   = "https://spa.example.org"
	spaRedirect = spaOrigin + "/callback"
	evilOrigin  = "https://evil.example"
)

// spaApp registers a browser app: a public client whose redirect URI is on
// spaOrigin.
func spaApp(t *testing.T, env *testenv.Env) *model.Application {
	t.Helper()
	return env.CreateApp(t, model.Application{
		Name: "Tool Booking", Slug: "booking", ClientID: "booking-spa",
		ClientType: model.ClientTypePublic, RedirectURIs: []string{spaRedirect},
	}, "")
}

// corsRequest sends a request to path with an Origin header; for OPTIONS
// it is a preflight asking for POST with an Authorization header.
func corsRequest(t *testing.T, env *testenv.Env, method, path, origin string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.TS.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	} else if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := env.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func varyOrigin(resp *http.Response) bool {
	for _, v := range resp.Header.Values("Vary") {
		for f := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "Origin") {
				return true
			}
		}
	}
	return false
}

// assertCORS checks resp allows origin, never with credentials, and says
// it varies by Origin.
func assertCORS(t *testing.T, resp *http.Response, origin string) {
	t.Helper()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin %q, want %q", got, origin)
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("Access-Control-Allow-Credentials sent")
	}
	if !varyOrigin(resp) {
		t.Errorf("Vary %q, want Origin", resp.Header.Values("Vary"))
	}
}

// assertNoCORS checks resp carries no CORS permission.
func assertNoCORS(t *testing.T, resp *http.Response) {
	t.Helper()
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers", "Access-Control-Allow-Credentials"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("%s: %q, want none", h, v)
		}
	}
}

// A browser app at the origin of a registered redirect URI may call the
// token, userinfo and revocation endpoints: preflights are answered, and
// responses name its origin.
func TestCORSForRegisteredOrigins(t *testing.T) {
	env := testenv.New(t)
	spaApp(t, env)
	wikiApp(t, env) // a confidential app's origin counts too
	for _, path := range []string{"/oauth/token", "/oauth/userinfo", "/oauth/revoke"} {
		for _, origin := range []string{spaOrigin, "https://wiki.example.org"} {
			resp := corsRequest(t, env, http.MethodOptions, path, origin, nil)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("OPTIONS %s from %s: status %d, want 204", path, origin, resp.StatusCode)
			}
			assertCORS(t, resp, origin)
			for h, want := range map[string]string{
				"Access-Control-Allow-Methods": "GET, POST",
				"Access-Control-Allow-Headers": "Authorization, Content-Type",
				"Access-Control-Max-Age":       "600",
			} {
				if got := resp.Header.Get(h); got != want {
					t.Errorf("OPTIONS %s: %s %q, want %q", path, h, got, want)
				}
			}

			method := http.MethodPost
			if path == "/oauth/userinfo" {
				method = http.MethodGet
			}
			assertCORS(t, corsRequest(t, env, method, path, origin, url.Values{"grant_type": {"x"}, "token": {"x"}}), origin)
		}
	}
}

// Any other origin gets no CORS permission, though a preflight is still
// answered.
func TestCORSRefusesOtherOrigins(t *testing.T) {
	env := testenv.New(t)
	spaApp(t, env)
	for _, path := range []string{"/oauth/token", "/oauth/userinfo", "/oauth/revoke"} {
		for _, origin := range []string{evilOrigin, "http://spa.example.org", "https://spa.example.org:8443", "null"} {
			resp := corsRequest(t, env, http.MethodOptions, path, origin, nil)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("OPTIONS %s from %s: status %d, want 204", path, origin, resp.StatusCode)
			}
			assertNoCORS(t, resp)
			resp = corsRequest(t, env, http.MethodPost, path, origin, url.Values{"grant_type": {"x"}})
			assertNoCORS(t, resp)
			if !varyOrigin(resp) {
				t.Errorf("POST %s from %s: no Vary: Origin", path, origin)
			}
		}
	}
}

// The endpoints used only by servers or by top-level navigation never
// grant CORS, even to a registered origin.
func TestCORSNotOnServerAndNavigationEndpoints(t *testing.T) {
	env := testenv.New(t)
	spaApp(t, env)
	assertNoCORS(t, corsRequest(t, env, http.MethodPost, "/oauth/introspect", spaOrigin, url.Values{"token": {"x"}}))
	assertNoCORS(t, corsRequest(t, env, http.MethodOptions, "/oauth/introspect", spaOrigin, nil))
	assertNoCORS(t, corsRequest(t, env, http.MethodGet, "/oauth/authorize?client_id=booking-spa", spaOrigin, nil))
	assertNoCORS(t, corsRequest(t, env, http.MethodGet, "/oauth/logout", spaOrigin, nil))
}

// Discovery and the signing keys are public: any origin may read them.
func TestCORSDiscoveryAndJWKSOpenToAll(t *testing.T) {
	env := testenv.New(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		resp := corsRequest(t, env, http.MethodGet, path, evilOrigin, nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("GET %s: status %d, Access-Control-Allow-Origin %q; want 200 and *",
				path, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("GET %s: Access-Control-Allow-Credentials sent", path)
		}
	}
}

// A browser app completes sign-in: its code exchange, sent with its Origin,
// returns tokens it is allowed to read.
func TestCORSBrowserAppExchangesCode(t *testing.T) {
	env := testenv.New(t)
	app := spaApp(t, env)
	c, _ := signedIn(t, env)
	code, verifier, _ := env.Authorize(t, c, app, true)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {spaRedirect},
		"code_verifier": {verifier}, "client_id": {app.ClientID}}
	req, err := http.NewRequest(http.MethodPost, env.TS.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", spaOrigin)
	resp, err := env.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("exchange: status %d body %v", resp.StatusCode, body)
	}
	assertCORS(t, resp, spaOrigin)
}

// Origins are compared as browsers send them: lower case, without the
// default port. An application registered later is allowed within a minute.
func TestCORSOriginsNormalisedAndRefreshed(t *testing.T) {
	env := testenv.New(t)
	spaApp(t, env)
	assertCORS(t, corsRequest(t, env, http.MethodOptions, "/oauth/token", spaOrigin, nil), spaOrigin)

	env.CreateApp(t, model.Application{Name: "Laser", Slug: "laser", ClientID: "laser",
		ClientType: model.ClientTypePublic, RedirectURIs: []string{"HTTPS://Laser.Example.org:443/cb"}}, "")
	env.Clock.Advance(61 * time.Second)
	const laser = "https://laser.example.org"
	resp := corsRequest(t, env, http.MethodOptions, "/oauth/token", laser, nil)
	assertCORS(t, resp, laser)
	if !slices.Contains(strings.Split(resp.Header.Get("Access-Control-Allow-Methods"), ", "), http.MethodPost) {
		t.Errorf("Access-Control-Allow-Methods %q, want POST", resp.Header.Get("Access-Control-Allow-Methods"))
	}
}
