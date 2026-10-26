package web_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"keywell/internal/model"
	"keywell/internal/store"
	"keywell/internal/testenv"
)

// seedServiceAccount stores an active service account called name, in the
// named groups (made when missing).
func seedServiceAccount(t *testing.T, env *testenv.Env, name, username string, groups ...string) *model.User {
	t.Helper()
	ctx := context.Background()
	u := &model.User{Name: name, Username: username, Type: model.UserTypeService, IsActive: true}
	if err := env.Store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		grp, err := env.Store.GetGroupByName(ctx, g)
		if err != nil {
			grp = env.CreateGroup(t, g, false, false)
		}
		if err := env.Store.AddMember(ctx, u.ID, grp.ID); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

// seedToken stores a read token for the account, made by creator.
func seedToken(t *testing.T, env *testenv.Env, sa *model.User, label, creator string) *model.APIToken {
	t.Helper()
	tok := &model.APIToken{ServiceAccountID: sa.ID, Label: label, TokenHash: "hash-" + label,
		Scope: model.APITokenScopeRead, CreatedByUserID: creator}
	if err := env.Store.CreateAPIToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func serviceAccountValues(name, username string) url.Values {
	return url.Values{"name": {name}, "username": {username}, "description": {""}, "metadata": {"{}"}}
}

func storedTokens(t *testing.T, env *testenv.Env, sa *model.User) []model.APIToken {
	t.Helper()
	toks, err := env.Store.ListAPITokens(context.Background(), sa.ID)
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

func TestServiceAccountsList(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	door := seedServiceAccount(t, env, "Door controller", "door", "Laser")
	seedToken(t, env, door, "one", admin.ID)
	seedToken(t, env, door, "two", admin.ID)
	addMember(t, env, "Alex Rivera", "alex@example.org")

	resp, body := env.Page(t, c, "/admin/service-accounts")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body,
		"<h1>Service accounts</h1>",
		"Service accounts are for scripts and devices, like a door controller. They can't use the sign-in pages; they use API tokens, or sign in to apps by themselves.",
		`href="/admin/service-accounts/new"`, ">Add service account</a>",
		`<a href="/admin/service-accounts" aria-current="page">`)
	for _, col := range []string{"Name", "Username", "Groups", "Tokens", "Last used"} {
		assertContains(t, between(body, "<thead>", "</thead>"), ">"+col+"</th>")
	}
	row := rowWith(body, "Door controller")
	assertContains(t, row, `href="/admin/service-accounts/`+door.ID+`"`, "door", `<span class="chip">Laser</span>`, "<td>2</td>", "Never")
	if strings.Contains(body, "Alex Rivera") {
		t.Error("the service accounts list shows a member")
	}
}

func TestCreateServiceAccount(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)

	resp, body := env.Page(t, c, "/admin/service-accounts/new")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "Add service account", ">Name</label>", ">Username</label>", ">Description</label>", `name="metadata"`)

	laser := env.CreateGroup(t, "Laser", false, false)
	form := serviceAccountValues("Door controller", "door")
	form.Set("description", "Front door")
	form["groups"] = []string{laser.ID}
	resp, _ = env.Submit(t, c, "/admin/service-accounts", form)
	u, err := env.Store.GetUserByUsername(context.Background(), "door")
	if err != nil {
		t.Fatal(err)
	}
	assertRedirect(t, resp, "/admin/service-accounts/"+u.ID+"?notice=saved")
	if u.Type != model.UserTypeService || u.Name != "Door controller" || u.Description != "Front door" {
		t.Errorf("stored %+v", u)
	}
	if ev := auditEvents(t, env, "service_account.create"); len(ev) != 1 || ev[0].ActorID != admin.ID {
		t.Errorf("audit events %+v", ev)
	}

	resp, body = env.Submit(t, c, "/admin/service-accounts", serviceAccountValues("Other", ""))
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Enter a username.", `value="Other"`)

	// Saving changes the account; a bad save keeps what was typed.
	resp, _ = env.Submit(t, c, "/admin/service-accounts/"+u.ID, serviceAccountValues("Gate controller", "gate"))
	assertRedirect(t, resp, "/admin/service-accounts/"+u.ID+"?notice=saved")
	if got, _ := env.Store.GetUser(context.Background(), u.ID); got.Name != "Gate controller" || got.Username != "gate" {
		t.Errorf("saved %+v", got)
	}
	resp, body = env.Submit(t, c, "/admin/service-accounts/"+u.ID, serviceAccountValues("Typed name", ""))
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Enter a username.", `value="Typed name"`)
}

// A refused add or save says so at the top.
func TestServiceAccountFormsSayNothingSaved(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	sa := seedServiceAccount(t, env, "Door controller", "door")
	badMeta := serviceAccountValues("Gate controller", "gate")
	badMeta.Set("metadata", "[1]")
	assertNotSaved(t, env, c, "/admin/service-accounts", serviceAccountValues("Other", ""))
	assertNotSaved(t, env, c, "/admin/service-accounts", badMeta)
	assertNotSaved(t, env, c, "/admin/service-accounts/"+sa.ID, serviceAccountValues("Door controller", ""))
	assertNotSaved(t, env, c, "/admin/service-accounts/"+sa.ID, badMeta)
}

var tokenRE = regexp.MustCompile(`<code class="secret">(keywell_[A-Za-z0-9_-]+)</code>`)

func TestCreateTokenShowsOnce(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	sa := seedServiceAccount(t, env, "Door controller", "door")

	resp, body := env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/tokens",
		url.Values{"label": {"Door"}, "scope": {"read"}, "expires_days": {"30"}})
	assertStatus(t, resp, http.StatusOK)
	m := tokenRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token shown:\n%s", body)
	}
	raw := m[1]
	assertContains(t, body, "Copy the API token now", "Token",
		`curl -H &#34;Authorization: Bearer `+raw+`&#34; `+env.TS.URL+`/api/v1/me`)

	toks := storedTokens(t, env, sa)
	if len(toks) != 1 || toks[0].Label != "Door" || toks[0].Scope != model.APITokenScopeRead || toks[0].CreatedByUserID != admin.ID {
		t.Fatalf("stored %+v", toks)
	}
	want := env.Clock.Now().Add(30 * 24 * time.Hour)
	if toks[0].ExpiresAt == nil || toks[0].ExpiresAt.Sub(want).Abs() > time.Minute {
		t.Errorf("expires %v, want about %v", toks[0].ExpiresAt, want)
	}

	resp, body = env.Page(t, c, "/admin/service-accounts/"+sa.ID)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "Door", "Read only", "Revoke")
	assertLacks(t, body, raw)

	// Bad input keeps the page and makes no token.
	resp, body = env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/tokens", url.Values{"label": {""}, "scope": {"read"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Enter a label so you can tell tokens apart.")
	if n := len(storedTokens(t, env, sa)); n != 1 {
		t.Errorf("%d tokens", n)
	}

	// No expiry means never; the default scope is read.
	resp, _ = env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/tokens", url.Values{"label": {"Forever"}, "expires_days": {""}})
	assertStatus(t, resp, http.StatusOK)
	for _, tk := range storedTokens(t, env, sa) {
		if tk.Label == "Forever" && (tk.ExpiresAt != nil || tk.Scope != model.APITokenScopeRead) {
			t.Errorf("stored %+v", tk)
		}
	}
}

func TestRevokeTokenUI(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	sa := seedServiceAccount(t, env, "Door controller", "door")
	tok := seedToken(t, env, sa, "Door", "")

	resp, _ := env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/tokens/"+tok.ID+"/revoke", nil)
	assertRedirect(t, resp, "/admin/service-accounts/"+sa.ID+"?notice=token_revoked")
	if n := len(storedTokens(t, env, sa)); n != 0 {
		t.Errorf("%d tokens left", n)
	}
	resp, _ = env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/tokens/"+tok.ID+"/revoke", nil)
	assertStatus(t, resp, http.StatusNotFound)
}

func TestServiceAccountShowsApps(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	sa := seedServiceAccount(t, env, "Door controller", "door")
	other := seedServiceAccount(t, env, "Printer", "printer")
	createApp(t, env, model.Application{Name: "Door opener", Slug: "door-opener", ClientType: model.ClientTypeConfidential, ServiceAccountID: sa.ID}, "s")
	createApp(t, env, model.Application{Name: "Print queue", Slug: "print-queue", ClientType: model.ClientTypeConfidential, ServiceAccountID: other.ID}, "s")
	seedToken(t, env, sa, "Door", admin.ID)

	_, body := env.Page(t, c, "/admin/service-accounts/"+sa.ID)
	section := between(body, "Apps that sign in as this account", "</section>")
	assertContains(t, section, "Door opener")
	assertLacks(t, section, "Print queue")
	assertContains(t, body, "Never", admin.Email)
}

func TestDeleteServiceAccount(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	sa := seedServiceAccount(t, env, "Door controller", "door")
	seedToken(t, env, sa, "Door", "")
	app := createApp(t, env, model.Application{Name: "Door opener", Slug: "door-opener", ClientType: model.ClientTypeConfidential, ServiceAccountID: sa.ID}, "s")

	_, body := env.Page(t, c, "/admin/service-accounts/"+sa.ID)
	assertContains(t, body, "1 API token will stop working", "Door opener")

	resp, body := env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/delete", url.Values{"confirm": {"wrong"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Type the name exactly to confirm.")
	if _, err := env.Store.GetUser(context.Background(), sa.ID); err != nil {
		t.Fatal(err)
	}

	resp, _ = env.Submit(t, c, "/admin/service-accounts/"+sa.ID+"/delete", url.Values{"confirm": {"Door controller"}})
	assertRedirect(t, resp, "/admin/service-accounts?notice=deleted")
	if _, err := env.Store.GetUser(context.Background(), sa.ID); err != store.ErrNotFound {
		t.Errorf("account: %v", err)
	}
	if n := len(storedTokens(t, env, sa)); n != 0 {
		t.Errorf("%d tokens left", n)
	}
	got, err := env.Store.GetApplication(context.Background(), app.ID)
	if err != nil || got.ServiceAccountID != "" {
		t.Errorf("app %+v, %v", got, err)
	}
}

func TestServiceAccountPagesRejectMembers(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	resp, _ := env.Page(t, c, "/admin/service-accounts/"+admin.ID)
	assertStatus(t, resp, http.StatusNotFound)
	for _, path := range []string{"", "/tokens", "/delete", "/tokens/x/revoke"} {
		resp, _ := env.Submit(t, c, "/admin/service-accounts/"+admin.ID+path,
			url.Values{"label": {"x"}, "scope": {"read"}, "confirm": {"x"}, "name": {"x"}, "username": {"x"}})
		assertStatus(t, resp, http.StatusNotFound)
	}
}
