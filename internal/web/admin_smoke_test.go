package web_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/James-Smart/keywell/internal/testenv"
)

// adminCreate posts a create form with the admin's client and fails unless
// it answers with status want. It returns the page.
func adminCreate(t *testing.T, env *testenv.Env, c *http.Client, path string, form url.Values, want int) string {
	t.Helper()
	resp, body := env.Submit(t, c, path, form)
	assertStatus(t, resp, want)
	return body
}

// TestSmokeAdminOnboarding is the one-minute onboarding: an admin, using
// only the admin pages, adds a group, an app and a member, and the member
// signs in to the app.
func TestSmokeAdminOnboarding(t *testing.T) {
	const callback = "https://tools.example.org/callback"
	env := testenv.New(t)
	ctx := gooidc.ClientContext(context.Background(), env.TS.Client())
	admin, _ := env.AdminClient(t)

	adminCreate(t, env, admin, "/admin/groups", groupValues("Laser", false, false), http.StatusSeeOther)
	laser, err := env.Store.GetGroupByName(ctx, "Laser")
	if err != nil {
		t.Fatal(err)
	}

	form := appValues("Tool Booking", "confidential")
	form.Set("redirect_uris", callback)
	form.Set("allowed_groups", laser.ID)
	form.Set("show_tile", "on")
	form.Set("launch_url", "https://tools.example.org/")
	form.Set("description", "Book the laser cutter")
	secret := shownSecret(t, adminCreate(t, env, admin, "/admin/apps", form, http.StatusOK))
	app := storedApp(t, env, "tool-booking")

	adminCreate(t, env, admin, "/admin/members", url.Values{
		"name": {"Sam Okafor"}, "email": {"sam@example.org"}, "username": {""},
		"groups": {laser.ID}, "metadata": {"{}"}, "setup": {"invite"},
	}, http.StatusSeeOther)
	msg, ok := env.Mailer.Last()
	link := resetLinkRE.FindString(msg.Text)
	if !ok || msg.To != "sam@example.org" || link == "" {
		t.Fatalf("invitation email %+v (sent %v), want a /reset/ link to sam@example.org", msg, ok)
	}

	// Sam follows the link and chooses a password, which also signs them in.
	sam := env.Client(t)
	resp, _ := env.Page(t, sam, link)
	assertStatus(t, resp, http.StatusOK)
	adminCreate(t, env, sam, link, url.Values{"password": {testPW}, "confirm": {testPW}}, http.StatusSeeOther)
	resp, body := env.Page(t, sam, "/")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "Tool Booking", `href="https://tools.example.org/"`)

	provider, err := gooidc.NewProvider(ctx, env.TS.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	rp := oauth2.Config{ClientID: app.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(),
		RedirectURL: callback, Scopes: []string{gooidc.ScopeOpenID, "profile", "email", "groups"}}
	resp, _ = get(t, sam, rp.AuthCodeURL("st-admin", gooidc.Nonce("n-admin")))
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), callback+"?") {
		t.Fatalf("authorize: status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	tok, err := rp.Exchange(ctx, loc.Query().Get("code"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&gooidc.Config{ClientID: app.ClientID}).Verify(ctx, rawID)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims.Email != "sam@example.org" || !slices.Contains(claims.Groups, "Laser") {
		t.Fatalf("ID token email %q groups %v, want sam and Laser", claims.Email, claims.Groups)
	}
}

// TestSmokeMachineToMachine checks that a service account made on the
// admin pages can sign in to an app by itself and call the admin API.
func TestSmokeMachineToMachine(t *testing.T) {
	ctx := context.Background()
	env := testenv.New(t)
	admin, _ := env.AdminClient(t)

	adminCreate(t, env, admin, "/admin/groups", groupValues("Laser", false, false), http.StatusSeeOther)
	laser, err := env.Store.GetGroupByName(ctx, "Laser")
	if err != nil {
		t.Fatal(err)
	}

	sa := serviceAccountValues("Door controller", "door")
	sa["groups"] = []string{laser.ID}
	adminCreate(t, env, admin, "/admin/service-accounts", sa, http.StatusSeeOther)
	door, err := env.Store.GetUserByUsername(ctx, "door")
	if err != nil {
		t.Fatal(err)
	}
	body := adminCreate(t, env, admin, "/admin/service-accounts/"+door.ID+"/tokens",
		url.Values{"label": {"Door"}, "scope": {"read"}}, http.StatusOK)
	m := tokenRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token shown:\n%s", body)
	}
	apiToken := m[1]

	form := appValues("Doors", "confidential")
	form.Set("machine", "on")
	form.Set("service_account_id", door.ID)
	secret := shownSecret(t, adminCreate(t, env, admin, "/admin/apps", form, http.StatusOK))
	app := storedApp(t, env, "doors")

	out, resp := env.PostAsClient(t, "/oauth/token", app, secret, url.Values{"grant_type": {"client_credentials"}})
	access, _ := out["access_token"].(string)
	if resp.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("client_credentials: status %d %v", resp.StatusCode, out)
	}
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("access token %q is not a JWT", access)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Username string   `json:"preferred_username"`
		Groups   []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Username != "door" || !slices.Contains(claims.Groups, "Laser") {
		t.Fatalf("access token claims %+v, want door in Laser", claims)
	}

	me, resp := env.API(t, apiToken, http.MethodGet, "/api/v1/me", nil)
	account, _ := me["service_account"].(map[string]any)
	if resp.StatusCode != http.StatusOK || account["username"] != "door" {
		t.Fatalf("GET /api/v1/me: status %d %v, want username door", resp.StatusCode, me)
	}
}

var jargonRE = regexp.MustCompile(`(?i)\b(provider|flow|stage|binding)s?\b`)

// Code an admin pastes verbatim, such as MediaWiki's providerURL, may use
// the words.
var codeRE = regexp.MustCompile(`(?is)<(pre|code)\b[^>]*>.*?</(pre|code)>`)

// TestAdminCopyAvoidsJargon reads every admin page for the words the
// admin pages promise never to use.
func TestAdminCopyAvoidsJargon(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	c, _ := env.AdminClient(t)
	check := func(name, body string) {
		t.Helper()
		if m := jargonRE.FindString(codeRE.ReplaceAllString(body, "")); m != "" {
			t.Errorf("%s uses %q", name, m)
		}
	}

	adminCreate(t, env, c, "/admin/groups", groupValues("Laser", false, false), http.StatusSeeOther)
	laser, err := env.Store.GetGroupByName(ctx, "Laser")
	if err != nil {
		t.Fatal(err)
	}
	adminCreate(t, env, c, "/admin/members", url.Values{"name": {"Sam Okafor"}, "email": {"sam@example.org"},
		"groups": {laser.ID}, "metadata": {"{}"}, "setup": {"invite"}}, http.StatusSeeOther)
	sam, err := env.Store.GetUserByEmail(ctx, "sam@example.org")
	if err != nil {
		t.Fatal(err)
	}
	adminCreate(t, env, c, "/admin/service-accounts", serviceAccountValues("Door controller", "door"), http.StatusSeeOther)
	door, err := env.Store.GetUserByUsername(ctx, "door")
	if err != nil {
		t.Fatal(err)
	}
	check("token page", adminCreate(t, env, c, "/admin/service-accounts/"+door.ID+"/tokens",
		url.Values{"label": {"Door"}, "scope": {"admin"}}, http.StatusOK))
	form := appValues("Doors", "confidential")
	form.Set("machine", "on")
	form.Set("service_account_id", door.ID)
	form.Set("show_tile", "on")
	form.Set("launch_url", "https://doors.example.org/")
	check("app secret page", adminCreate(t, env, c, "/admin/apps", form, http.StatusOK))
	app := storedApp(t, env, "doors")

	for _, p := range []string{
		"/admin/members", "/admin/members/new", "/admin/members/" + sam.ID,
		"/admin/groups", "/admin/groups/new", "/admin/groups/" + laser.ID,
		"/admin/apps", "/admin/apps/new", "/admin/apps/" + app.ID,
		"/admin/service-accounts", "/admin/service-accounts/new", "/admin/service-accounts/" + door.ID,
		"/admin/settings", "/admin/audit?category=all",
	} {
		resp, body := env.Page(t, c, p)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d", p, resp.StatusCode)
			continue
		}
		check(p, body)
	}
}
