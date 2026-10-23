package web_test

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/testenv"
)

// appValues is the application form with the fields a new app needs.
func appValues(name, clientType string) url.Values {
	return url.Values{
		"name":          {name},
		"client_type":   {clientType},
		"redirect_uris": {"https://wiki.example.org/cb"},
		"subject_mode":  {"id"},
	}
}

var secretRE = regexp.MustCompile(`<code class="secret">([A-Za-z0-9_-]{43})</code>`)

// shownSecret returns the one 43-character client secret a secret page shows.
func shownSecret(t *testing.T, body string) string {
	t.Helper()
	m := secretRE.FindAllStringSubmatch(body, -1)
	if len(m) != 1 {
		t.Fatalf("secret page shows %d secrets, want 1:\n%s", len(m), body)
	}
	return m[0][1]
}

// createApp stores a with a client ID made from its slug, as the service
// would, so several apps can exist.
func createApp(t *testing.T, env *testenv.Env, a model.Application, secret string) *model.Application {
	t.Helper()
	a.ClientID = "client-" + a.Slug
	return env.CreateApp(t, a, secret)
}

func storedApp(t *testing.T, env *testenv.Env, slug string) *model.Application {
	t.Helper()
	app, err := env.Store.GetApplicationBySlug(context.Background(), slug)
	if err != nil {
		t.Fatalf("get app %s: %v", slug, err)
	}
	return app
}

func TestAppsList(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, false)
	createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}, AllowedGroupIDs: []string{laser.ID}}, "s3cret")
	createApp(t, env, model.Application{Name: "Phone app", Slug: "phone", ClientType: model.ClientTypePublic,
		RedirectURIs: []string{"https://phone.example.org/cb"}}, "")

	resp, body := env.Page(t, c, "/admin/apps")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, `href="/admin/apps/new"`, "Add application")
	wiki := rowWith(body, ">Wiki</a>")
	assertContains(t, wiki, "Keeps a secret", `<span class="chip">Laser</span>`, ">W<")
	assertLacks(t, wiki, "Everyone", "Machine to machine")
	phone := rowWith(body, ">Phone app</a>")
	assertContains(t, phone, "No secret (browser or phone app)", "Everyone", ">P<")
}

func TestAppsListMachineChip(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	sa := createServiceAccount(t, env, "door@example.org")
	createApp(t, env, model.Application{Name: "Doors", Slug: "doors", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://doors.example.org/cb"}, ServiceAccountID: sa.ID}, "s3cret")
	_, body := env.Page(t, c, "/admin/apps")
	assertContains(t, rowWith(body, ">Doors</a>"), "Machine to machine")
}

func TestNewAppForm(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	env.CreateGroup(t, "Laser", false, false)

	resp, body := env.Page(t, c, "/admin/apps/new")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "Name", "Short name (used in links; leave blank to make one from the name)",
		"Does the app keep a secret?", "Yes: it runs on a server, like MediaWiki", "No: it runs in the browser or on a phone",
		"Sign-in return addresses, one per line", "Addresses to return to after signing out (optional)",
		"Leave all unticked to let every active member in.", `name="allowed_groups"`, "Laser",
		"How the app recognises people", "Latch ID (recommended)", "A permanent ID that never changes, even if their email does.",
		"Email address", "Changes when their email changes.", "Username", "People without a username get their Latch ID.",
		"Authentik ID (Authentik's default)", "Authentik UUID", "Authentik number",
		"Changing this changes how the app recognises people, so existing accounts in the app may stop matching.",
		"Show on members' home page", "Link to open the app", "Description", "Icon address (https)",
		"Allow this app to sign in by itself (machine to machine)", "/admin/service-accounts/new",
		"Token lifetimes (advanced)", `placeholder="1h"`, `placeholder="30d"`)
	assertContains(t, body, `name="client_type" value="confidential" checked`)
	assertLacks(t, body, "Setup details", "Regenerate secret", "Delete application", `class="lifetimes" open`)
}

func TestCreateConfidentialAppShowsSecretOnce(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)

	resp, body := env.Submit(t, c, "/admin/apps", appValues("Wiki", "confidential"))
	assertStatus(t, resp, http.StatusOK)
	app := storedApp(t, env, "wiki")
	secret := shownSecret(t, body)
	if secrets.HashToken(secret) != app.ClientSecretHash {
		t.Error("the secret shown does not match the stored hash")
	}
	assertContains(t, body, "Copy the client secret now",
		"You won&#39;t be able to see it again. If you lose it, regenerate it from the app&#39;s page.",
		app.ClientID, `href="/admin/apps/`+app.ID+`"`)
	events := auditEvents(t, env, "app.create")
	if len(events) != 1 || events[0].ActorID != admin.ID {
		t.Fatalf("app.create events %+v, want one by the admin", events)
	}
	if strings.Contains(fmt.Sprint(events[0].Detail), secret) {
		t.Error("the secret is in the audit log")
	}

	resp, body = env.Page(t, c, "/admin/apps/"+app.ID)
	assertStatus(t, resp, http.StatusOK)
	assertLacks(t, body, secret)
	assertContains(t, body, app.ClientID)
}

func TestCreatePublicApp(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	resp, _ := env.Submit(t, c, "/admin/apps", appValues("Phone app", "public"))
	app := storedApp(t, env, "phone-app")
	assertRedirect(t, resp, "/admin/apps/"+app.ID+"?notice=saved")
	if app.ClientType != model.ClientTypePublic || app.ClientSecretHash != "" {
		t.Errorf("stored %+v, want public with no secret", app)
	}
}

func TestAppFormErrors(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)

	messy := "https://a/cb\r\n\r\n  https://a/cb  \r\n/relative"
	v := appValues("Wiki", "confidential")
	v.Set("redirect_uris", messy)
	resp, body := env.Submit(t, c, "/admin/apps", v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, html.EscapeString("Line 4 isn't a full web address"), messy, `aria-invalid="true"`)
	assertLacks(t, body, "Copy the client secret now")

	v = appValues("Wiki", "confidential")
	v.Set("access_token_ttl", "soon")
	resp, body = env.Submit(t, c, "/admin/apps", v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Use a time like 1h or 30d.", `value="soon"`, `class="lifetimes" open`)

	v.Set("access_token_ttl", "25h")
	resp, body = env.Submit(t, c, "/admin/apps", v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "between 1m and 24h", `value="25h"`)

	v = appValues("Wiki", "confidential")
	v.Set("machine", "on")
	resp, body = env.Submit(t, c, "/admin/apps", v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Choose a service account.")

	// None of these saved anything.
	apps, err := env.Store.ListApplications(context.Background())
	if err != nil || len(apps) != 0 {
		t.Errorf("stored apps %v, err %v, want none", apps, err)
	}
}

func TestEditApp(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, false)
	sa := createServiceAccount(t, env, "door@example.org")
	app := createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}}, "s3cret")
	path := "/admin/apps/" + app.ID

	v := appValues("Wiki", "confidential")
	v.Set("slug", "wiki")
	v.Set("allowed_groups", laser.ID)
	v.Set("subject_mode", "email")
	v.Set("access_token_ttl", "2h")
	v.Set("refresh_token_ttl", "7d")
	v.Set("show_tile", "on")
	v.Set("launch_url", "https://wiki.example.org/")
	v.Set("description", "The club wiki")
	v.Set("machine", "on")
	v.Set("service_account_id", sa.ID)
	v.Set("post_logout_redirect_uris", "https://wiki.example.org/bye")
	resp, _ := env.Submit(t, c, path, v)
	assertRedirect(t, resp, path+"?notice=saved")
	got := storedApp(t, env, "wiki")
	if got.AccessTokenTTL != 2*time.Hour || got.RefreshTokenTTL != 7*24*time.Hour || got.IDTokenTTL != 0 ||
		got.SubjectMode != model.SubjectModeEmail || len(got.AllowedGroupIDs) != 1 || got.AllowedGroupIDs[0] != laser.ID ||
		!got.ShowTile || got.LaunchURL != "https://wiki.example.org/" || got.Description != "The club wiki" ||
		got.ServiceAccountID != sa.ID || len(got.PostLogoutRedirectURIs) != 1 {
		t.Errorf("stored %+v", got)
	}
	if events := auditEvents(t, env, "app.update"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("app.update events %+v, want one by the admin", events)
	}

	resp, body := env.Page(t, c, path+"?notice=saved")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, `value="2h"`, `value="7d"`, "Changes saved.", `value="The club wiki"`,
		`value="`+sa.ID+`" selected`, `<option value="email" selected>`, `name="machine" checked`)

	// Blank lifetimes mean the default again, and machine off clears the account.
	v.Set("access_token_ttl", "")
	v.Set("refresh_token_ttl", "")
	v.Del("machine")
	v.Del("show_tile")
	resp, _ = env.Submit(t, c, path, v)
	assertRedirect(t, resp, path+"?notice=saved")
	got = storedApp(t, env, "wiki")
	if got.AccessTokenTTL != 0 || got.RefreshTokenTTL != 0 || got.ServiceAccountID != "" || got.ShowTile {
		t.Errorf("stored %+v, want default lifetimes, no service account, no tile", got)
	}
	if got.ClientSecretHash != secrets.HashToken("s3cret") {
		t.Error("saving changed the secret")
	}

	// A refused save keeps what was typed and changes nothing.
	v.Set("name", "")
	v.Set("description", "typed but refused")
	resp, body = env.Submit(t, c, path, v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "typed but refused")
	if storedApp(t, env, "wiki").Description != "The club wiki" {
		t.Error("a refused save changed the app")
	}
}

func TestSubjectModeWarning(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	warning := "Switch to Latch ID once the app no longer needs Authentik's identifiers."
	app := createApp(t, env, model.Application{Name: "Old wiki", Slug: "old", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}, SubjectMode: model.SubjectModeAuthentikUID}, "s3cret")
	_, body := env.Page(t, c, "/admin/apps/"+app.ID)
	assertContains(t, body, warning, "This uses the identifier Authentik gave this app, so people's existing accounts in it keep working.")

	app = createApp(t, env, model.Application{Name: "New wiki", Slug: "new", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}, SubjectMode: model.SubjectModeID}, "s3cret")
	_, body = env.Page(t, c, "/admin/apps/"+app.ID)
	assertLacks(t, body, warning)
}

func TestSetupDetails(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	sa := createServiceAccount(t, env, "door@example.org")
	app := createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb", "https://wiki.example.org/cb2"}, ServiceAccountID: sa.ID}, "s3cret")
	issuer := env.Cfg.Issuer()

	_, body := env.Page(t, c, "/admin/apps/"+app.ID)
	assertContains(t, body, "Setup details", issuer, "/.well-known/openid-configuration", app.ClientID,
		"https://wiki.example.org/cb2", "LocalSettings.php", "'clientID' => '"+app.ClientID+"'",
		"'providerURL' => '"+issuer+"'", "(the secret you copied when you made this app)",
		"client_secret_basic", "client_secret_post", "grant_type=client_credentials", issuer+"/oauth/token",
		"Regenerate secret", "The old secret stops working straight away.", "Delete application")
	assertLacks(t, body, "s3cret", "No secret; use PKCE")

	pub := createApp(t, env, model.Application{Name: "Phone", Slug: "phone", ClientType: model.ClientTypePublic,
		RedirectURIs: []string{"https://phone.example.org/cb"}}, "")
	_, body = env.Page(t, c, "/admin/apps/"+pub.ID)
	assertContains(t, body, "Setup details", "No secret; use PKCE with S256", pub.ClientID, "/.well-known/openid-configuration")
	assertLacks(t, body, "LocalSettings.php", "Regenerate secret", "client_credentials")

	// Outside code samples, the page avoids the engineering words.
	prose := strings.ToLower(regexp.MustCompile(`(?s)<pre.*?</pre>`).ReplaceAllString(body, ""))
	for _, word := range []string{"provider", "flow", "stage", "binding"} {
		if strings.Contains(prose, word) {
			t.Errorf("public app page uses %q", word)
		}
	}
}

func TestRegenerateSecret(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	app := createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}}, "oldsecret")
	introspect := url.Values{"token": {"x"}}

	if _, resp := env.PostAsClient(t, "/oauth/introspect", app, "oldsecret", introspect); resp.StatusCode != http.StatusOK {
		t.Fatalf("old secret before: status %d, want 200", resp.StatusCode)
	}
	resp, body := env.Submit(t, c, "/admin/apps/"+app.ID+"/rotate-secret", nil)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "Copy the client secret now", app.ClientID)
	fresh := shownSecret(t, body)
	app = storedApp(t, env, "wiki")
	if _, resp := env.PostAsClient(t, "/oauth/introspect", app, "oldsecret", introspect); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old secret after: status %d, want 401", resp.StatusCode)
	}
	if _, resp := env.PostAsClient(t, "/oauth/introspect", app, fresh, introspect); resp.StatusCode != http.StatusOK {
		t.Errorf("new secret: status %d, want 200", resp.StatusCode)
	}
	if events := auditEvents(t, env, "app.secret.rotate"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("rotate events %+v, want one by the admin", events)
	}
	_, body = env.Page(t, c, "/admin/apps/"+app.ID)
	assertLacks(t, body, fresh)

	// A public app has no secret to regenerate.
	pub := createApp(t, env, model.Application{Name: "Phone", Slug: "phone", ClientType: model.ClientTypePublic,
		RedirectURIs: []string{"https://phone.example.org/cb"}}, "")
	resp, body = env.Submit(t, c, "/admin/apps/"+pub.ID+"/rotate-secret", nil)
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, html.EscapeString("This app doesn't use a secret."))
	assertLacks(t, body, "Copy the client secret now")
}

func TestSwitchToConfidentialShowsSecret(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	app := createApp(t, env, model.Application{Name: "Phone", Slug: "phone", ClientType: model.ClientTypePublic,
		RedirectURIs: []string{"https://phone.example.org/cb"}}, "")

	v := appValues("Phone", "confidential")
	v.Set("slug", "phone")
	v.Set("redirect_uris", "https://phone.example.org/cb")
	resp, body := env.Submit(t, c, "/admin/apps/"+app.ID, v)
	assertStatus(t, resp, http.StatusOK)
	secret := shownSecret(t, body)
	got := storedApp(t, env, "phone")
	if got.ClientType != model.ClientTypeConfidential || got.ClientSecretHash != secrets.HashToken(secret) {
		t.Errorf("stored %+v, want confidential with the shown secret", got)
	}
	assertContains(t, body, "Copy the client secret now", `href="/admin/apps/`+app.ID+`"`)
}

func TestDeleteAppConfirm(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	app := createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/cb"}}, "s3cret")
	path := "/admin/apps/" + app.ID + "/delete"

	resp, body := env.Submit(t, c, path, url.Values{"confirm": {"Wik"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Type the name exactly to confirm.", "The application wasn&#39;t deleted. See Delete application below.")
	if _, err := env.Store.GetApplication(context.Background(), app.ID); err != nil {
		t.Fatalf("app gone after wrong name: %v", err)
	}

	resp, _ = env.Submit(t, c, path, url.Values{"confirm": {"Wiki"}})
	assertRedirect(t, resp, "/admin/apps?notice=deleted")
	if _, err := env.Store.GetApplication(context.Background(), app.ID); err == nil {
		t.Error("app still exists")
	}
	if events := auditEvents(t, env, "app.delete"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("app.delete events %+v, want one by the admin", events)
	}
	resp, _ = env.Page(t, c, "/admin/apps/"+app.ID)
	assertStatus(t, resp, http.StatusNotFound)
	resp, _ = env.Submit(t, c, "/admin/apps/"+app.ID+"/rotate-secret", nil)
	assertStatus(t, resp, http.StatusNotFound)
}
