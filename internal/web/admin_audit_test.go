package web_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"keywell/internal/model"
	"keywell/internal/testenv"
)

// addEvent stores an audit event at the given time.
func addEvent(t *testing.T, env *testenv.Env, at time.Time, e model.AuditEvent) {
	t.Helper()
	e.At = at
	if err := env.Store.InsertAuditEvent(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
}

func TestAuditDefaultsToChangesLast30Days(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	now := env.Clock.Now()
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", TargetType: "user", TargetID: admin.ID, Summary: "Updated Zed Recent"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorSystem, Action: "oidc.token.issued", Summary: "Issued token for Tokenapp"})
	addEvent(t, env, now.AddDate(0, 0, -40), model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.create", TargetType: "user", TargetID: admin.ID, Summary: "Created Old Member"})

	resp, body := env.Page(t, c, "/admin/audit")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, "<h1>Audit log</h1>", "Updated Zed Recent", `<a href="/admin/audit" aria-current="page">`)
	assertLacks(t, body, "Tokenapp", "Old Member")
}

func TestAuditCategoriesAndRange(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	now := env.Clock.Now()
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", Summary: "Updated Zed Recent"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "login.success", Summary: "Signed in as Sam"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorSystem, Action: "oidc.token.issued", Summary: "Issued token for Tokenapp"})
	addEvent(t, env, now.AddDate(0, 0, -40), model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.create", Summary: "Created Old Member"})

	_, body := env.Page(t, c, "/admin/audit?category=signins")
	assertContains(t, body, "Signed in as Sam")
	assertLacks(t, body, "Zed Recent", "Tokenapp")

	_, body = env.Page(t, c, "/admin/audit?category=tokens")
	assertContains(t, body, "Tokenapp")
	assertLacks(t, body, "Zed Recent", "Signed in as Sam")

	from := now.AddDate(0, 0, -60).Format("2006-01-02")
	_, body = env.Page(t, c, "/admin/audit?category=all&from="+from)
	assertContains(t, body, "Old Member", "Zed Recent", "Signed in as Sam", "Tokenapp", `value="`+from+`"`)

	// The to date is inclusive: today's events show with to=today, and not
	// with to=yesterday. A bad date falls back to the default.
	_, body = env.Page(t, c, "/admin/audit?to="+now.Format("2006-01-02"))
	assertContains(t, body, "Zed Recent")
	_, body = env.Page(t, c, "/admin/audit?to="+now.AddDate(0, 0, -1).Format("2006-01-02"))
	assertLacks(t, body, "Zed Recent")
	_, body = env.Page(t, c, "/admin/audit?from=nonsense&to=2026-13-45")
	assertContains(t, body, "Zed Recent")
	assertLacks(t, body, "Old Member")

	// The summary search.
	_, body = env.Page(t, c, "/admin/audit?category=all&q=sam")
	assertContains(t, body, "Signed in as Sam")
	assertLacks(t, body, "Zed Recent")
}

func TestAuditCollapsedFailures(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	// Four failures within one clock hour, in the past.
	base := env.Clock.Now().Add(-2 * time.Hour).Truncate(time.Hour)
	for i := range 4 {
		addEvent(t, env, base.Add(time.Duration(i)*time.Minute), model.AuditEvent{ActorType: model.ActorSystem, Action: "login.failure",
			TargetType: "user", TargetID: alex.ID, Summary: "Failed sign-in for Alex"})
	}
	_, body := env.Page(t, c, "/admin/audit?category=signins")
	assertContains(t, rowWith(body, "Failed sign-in for Alex"), "(4 times)")
	if n := strings.Count(body, "Failed sign-in for Alex"); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

func TestAuditNamesAndLinks(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	renameUser(t, env, admin, "Ada Admin")
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	nameless := env.CreateUser(t, "nameless@example.org", "")
	renameUser(t, env, nameless, "")
	sa := createServiceAccount(t, env, "door@example.org")
	group := env.CreateGroup(t, "Laser", false, false)
	app := env.CreateApp(t, model.Application{Name: "Wiki", Slug: "wiki", ClientID: "wiki"}, "s3cret")
	now := env.Clock.Now()
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", TargetType: "user", TargetID: alex.ID, Summary: "Edit one"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: "gone-user", Action: "user.update", TargetType: "user", TargetID: "gone-target", Summary: "Edit two"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorSystem, Action: "user.update", TargetType: "user", TargetID: nameless.ID, Summary: "Edit three"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorServiceAccount, ActorID: sa.ID, Action: "group.update", TargetType: "group", TargetID: group.ID, Summary: "Edit four"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorImporter, Action: "app.update", TargetType: "application", TargetID: app.ID, Summary: "Edit five"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", TargetType: "user", TargetID: sa.ID, Summary: "Edit six"})

	_, body := env.Page(t, c, "/admin/audit")
	assertContains(t, rowWith(body, "Edit one"), "Ada Admin", `?actor=`+admin.ID, "Alex Rivera", `href="/admin/members/`+alex.ID+`"`,
		`?action=user.update&amp;category=all`, "user.update")
	row := rowWith(body, "Edit two")
	assertContains(t, row, "Deleted account")
	assertLacks(t, row, "/admin/members/")
	assertContains(t, rowWith(body, "Edit three"), "Keywell", "nameless@example.org", `href="/admin/members/`+nameless.ID+`"`)
	assertContains(t, rowWith(body, "Edit four"), "Door controller", `href="/admin/groups/`+group.ID+`"`)
	assertContains(t, rowWith(body, "Edit five"), "Importer", "Wiki", `href="/admin/apps/`+app.ID+`"`)
	assertContains(t, rowWith(body, "Edit six"), "Door controller", `href="/admin/service-accounts/`+sa.ID+`"`)
}

// A target that no longer exists is named from what its event kept (a
// delete keeps the name or email), without a link. An API token, which has
// no page, is named by its label.
func TestAuditNamesDeletedTargets(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	now := env.Clock.Now()
	ev := func(action, targetType, summary string, detail map[string]any) {
		addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: action,
			TargetType: targetType, TargetID: "gone-" + summary, Summary: summary, Detail: detail})
	}
	ev("user.delete", "user", "Gone one", map[string]any{"email": "kim@example.org", "name": "Kim Ito"})
	ev("user.delete", "user", "Gone two", map[string]any{"email": "nameless@example.org", "name": ""})
	ev("group.delete", "group", "Gone three", map[string]any{"name": "Old laser"})
	ev("app.delete", "application", "Gone four", map[string]any{"name": "Old wiki", "slug": "old-wiki"})
	ev("service_account.delete", "service_account", "Gone five", map[string]any{"name": "Old door", "username": "olddoor"})
	ev("api_token.revoke", "api_token", "Gone six", map[string]any{"label": "Deploy"})
	ev("user.update", "user", "Gone seven", map[string]any{"changed": map[string]any{}})

	_, body := env.Page(t, c, "/admin/audit")
	for summary, name := range map[string]string{
		"Gone one": "Kim Ito", "Gone two": "nameless@example.org", "Gone three": "Old laser",
		"Gone four": "Old wiki", "Gone five": "Old door", "Gone six": "Deploy",
	} {
		about := between(rowWith(body, summary), "</small></td>", "</tr>")
		if !strings.Contains(about, "<td>"+name+"</td>") {
			t.Errorf("%s: About cell %q, want %q without a link", summary, about, name)
		}
	}
	if about := between(rowWith(body, "Gone seven"), "</small></td>", "</tr>"); !strings.Contains(about, "<td></td>") {
		t.Errorf("Gone seven: About cell %q, want empty", about)
	}
}

func TestAuditFilterByTarget(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	priya := addMember(t, env, "Priya Nair", "priya@example.org")
	now := env.Clock.Now()
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "login.success", TargetType: "user", TargetID: alex.ID, Summary: "About Alex"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", TargetType: "user", TargetID: priya.ID, Summary: "About Priya"})

	_, body := env.Page(t, c, "/admin/audit?target="+alex.ID+"&category=all")
	assertContains(t, body, "About Alex", "Alex Rivera", `href="/admin/audit"`)
	assertLacks(t, body, "About Priya")

	_, body = env.Page(t, c, "/admin/audit?actor="+admin.ID+"&category=all")
	assertContains(t, body, "About Alex", "About Priya")

	_, body = env.Page(t, c, "/admin/members/"+alex.ID)
	assertContains(t, body, "View activity", "/admin/audit?target="+alex.ID)
}

func TestAuditFilterByAction(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	now := env.Clock.Now()
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "group.member.add", Summary: "Added to Laser"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "group.member.remove", Summary: "Removed from Laser"})
	addEvent(t, env, now, model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "group.update", Summary: "Edited Laser"})

	_, body := env.Page(t, c, "/admin/audit?action=group.member.")
	assertContains(t, rowWith(body, "Added to Laser"), `?action=group.member.add&amp;category=all`)
	assertContains(t, rowWith(body, "Removed from Laser"), `?action=group.member.remove&amp;category=all`)
	assertLacks(t, body, "Edited Laser")
}

func TestAuditPaginatesAndRecordPagesLinkHere(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	now := env.Clock.Now()
	for i := range 55 {
		addEvent(t, env, now.Add(-time.Duration(i)*time.Second), model.AuditEvent{ActorType: model.ActorUser, ActorID: admin.ID, Action: "user.update", Summary: "Bulk edit"})
	}
	_, body := env.Page(t, c, "/admin/audit")
	if n := tableRows(body); n != 50 {
		t.Errorf("%d rows, want 50", n)
	}
	assertContains(t, body, "page=2")

	g := env.CreateGroup(t, "Laser", false, false)
	app := env.CreateApp(t, model.Application{Name: "Wiki", Slug: "wiki", ClientID: "wiki"}, "s3cret")
	sa := createServiceAccount(t, env, "door@example.org")
	for _, p := range []struct{ path, id string }{
		{"/admin/groups/" + g.ID, g.ID}, {"/admin/apps/" + app.ID, app.ID}, {"/admin/service-accounts/" + sa.ID, sa.ID},
	} {
		_, body = env.Page(t, c, p.path)
		assertContains(t, body, "View activity", "/admin/audit?target="+p.id)
	}
}
