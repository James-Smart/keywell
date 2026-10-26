package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"latch/internal/config"
	"latch/internal/importer"
	"latch/internal/mail"
	"latch/internal/store"
	"latch/internal/testenv"
)

func TestSettingsImportStatus(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	_, body := env.Page(t, c, "/admin/settings")
	for _, want := range []string{"Import from Authentik", "Nothing has been imported from Authentik yet."} {
		if !strings.Contains(body, want) {
			t.Errorf("no-run page missing %q", want)
		}
	}

	rep := importer.Report{
		Source:  "db.internal:5432/authentik",
		Members: importer.Counts{Added: 6, Skipped: 1},
		Groups:  importer.Counts{Added: 4, Updated: 1, Skipped: 2},
		Apps:    importer.Counts{Added: 3, Skipped: 3},
		Items: []importer.Item{
			{Kind: "member", Name: "nomail", Skipped: true, Reason: "Has no email address, so Latch can't sign them in."},
			{Kind: "app", Name: "Grafana", Reason: "Signs in with SAML, which Latch can't do <yet>."},
		},
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 14, 5, 0, 0, time.UTC)
	if err := env.Store.InsertImportRun(context.Background(), &store.ImportRun{
		StartedAt: at, FinishedAt: at.Add(time.Minute), Source: rep.Source, Report: string(raw),
	}); err != nil {
		t.Fatal(err)
	}
	_, body = env.Page(t, c, "/admin/settings")
	for _, want := range []string{
		"3 Oct 2026", "db.internal:5432/authentik",
		"Members: 6 added, 0 updated, 1 skipped",
		"Groups: 4 added, 1 updated, 2 skipped",
		"Apps: 3 added, 0 updated, 3 skipped",
		"<details>", "What was skipped or needs a look (2)",
		"member nomail", "Has no email address, so Latch can&#39;t sign them in.",
		"app Grafana", "which Latch can&#39;t do &lt;yet&gt;.",
		">skipped<", ">warning<",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "Nothing has been imported") {
		t.Error("empty-state sentence shown after a run")
	}
}

// adminLinks are the admin sidebar's links, in order.
var adminLinks = []string{
	`href="/admin/members"`,
	`href="/admin/groups"`,
	`href="/admin/apps"`,
	`href="/admin/service-accounts"`,
	`href="/admin/settings"`,
	`href="/admin/audit"`,
}

// notSavedAlert is the top alert of an add or edit form refused with
// messages beside its fields.
const notSavedAlert = `<p class="alert alert-error" role="alert">Nothing was saved. Check the highlighted fields below.</p>`

// assertNotSaved posts form to path and checks the answer is a 422 that
// says so at the top.
func assertNotSaved(t *testing.T, env *testenv.Env, c *http.Client, path string, form url.Values) {
	t.Helper()
	resp, body := env.Submit(t, c, path, form)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	if !strings.Contains(body, notSavedAlert) {
		t.Errorf("POST %s %v: no top alert saying nothing was saved", path, form)
	}
}

// between returns the part of body from the first start up to and
// including the next end, or "" when either is missing.
func between(body, start, end string) string {
	i := strings.Index(body, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(body[i:], end)
	if j < 0 {
		return ""
	}
	return body[i : i+j+len(end)]
}

// rowWith returns the table row (<tr>…</tr>) of body that contains text,
// or "" when no row does.
func rowWith(body, text string) string {
	i := strings.Index(body, text)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(body[:i], "<tr")
	end := strings.Index(body[i:], "</tr>")
	if start < 0 || end < 0 {
		return ""
	}
	return body[start : i+end+len("</tr>")]
}

func TestAdminRequiresAdmin(t *testing.T) {
	env := testenv.New(t)

	resp, _ := env.Page(t, env.Client(t), "/admin")
	assertRedirect(t, resp, "/login?next=%2Fadmin")

	env.CreateUser(t, "member@example.org", testPW, "Members")
	member := env.Client(t)
	env.Login(t, member, "member@example.org", testPW)
	for _, path := range []string{"/admin", "/admin/settings"} {
		resp, body := env.Page(t, member, path)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("member GET %s: status %d, want 403", path, resp.StatusCode)
		}
		for _, want := range []string{"Admins only",
			html.EscapeString("You need to be in an admin group to use these pages. Ask an existing admin if you think you should be.")} {
			if !strings.Contains(body, want) {
				t.Errorf("member GET %s: body missing %q", path, want)
			}
		}
		if strings.Contains(body, "admin-nav") {
			t.Errorf("member GET %s: the refusal shows the admin sidebar", path)
		}
	}
	resp, _ = env.Submit(t, member, "/admin/settings/rotate-keys", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member POST rotate-keys: status %d, want 403", resp.StatusCode)
	}

	admin, _ := env.AdminClient(t)
	resp, _ = env.Page(t, admin, "/admin")
	assertRedirect(t, resp, "/admin/members")
}

// An admin whose admin group requires the second step is sent to it
// before any admin page, even with the right password.
func TestAdminRequiresSecondStep(t *testing.T) {
	env := testenv.New(t)
	env.CreateGroup(t, "Admin", true, true)
	u := env.CreateUser(t, "admin@example.org", testPW, "Admin")
	env.EnrolTOTP(t, u)
	c := env.Client(t)
	env.Login(t, c, "admin@example.org", testPW)

	resp, _ := env.Page(t, c, "/admin/settings")
	assertRedirect(t, resp, "/login/totp?next=%2Fadmin%2Fsettings")
}

// Ruling 15: a member who signed in when no group of theirs required two-step
// sign in, and is then made an admin by a group that does, sets it up before
// the next admin page.
func TestAdminPromotedMidSessionMustEnrol(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	u := env.CreateUser(t, "member@example.org", testPW, "Members")
	c := env.Client(t)
	env.Login(t, c, "member@example.org", testPW)
	if resp, _ := env.Page(t, c, "/admin/members"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("before promotion: status %d, want 403", resp.StatusCode)
	}

	admins := env.CreateGroup(t, "Admin", true, true)
	if err := env.Store.AddMember(ctx, u.ID, admins.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ := env.Page(t, c, "/admin/members?q=alex")
	assertRedirect(t, resp, "/account/totp?required=1&next=%2Fadmin%2Fmembers%3Fq%3Dalex")
	resp, _ = env.Submit(t, c, "/admin/members/"+u.ID+"/sign-out", nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/account/totp?required=1") {
		t.Errorf("POST: status %d to %q, want 303 to enrolment", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The enrolment page itself works for this session.
	resp, body := env.Page(t, c, "/account/totp?required=1&next=%2Fadmin%2Fmembers")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, `name="next" value="/admin/members"`)

	// Once enrolled, the admin pages open.
	stored, err := env.Store.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	env.EnrolTOTP(t, stored)
	resp, _ = env.Page(t, c, "/admin/members")
	assertStatus(t, resp, http.StatusOK)
}

// Ruling 15: an admin whose admin group starts requiring two-step sign in
// sets it up before the next admin page.
func TestAdminGroupStartsRequiringSecondStep(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	c, _ := env.AdminClient(t)
	resp, _ := env.Page(t, c, "/admin/settings")
	assertStatus(t, resp, http.StatusOK)

	g, err := env.Store.GetGroupByName(ctx, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	g.RequireTOTP = true
	if err := env.Store.UpdateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	resp, _ = env.Page(t, c, "/admin/settings")
	assertRedirect(t, resp, "/account/totp?required=1&next=%2Fadmin%2Fsettings")

	// Another group requiring it counts too, once its member is an admin.
	g.RequireTOTP = false
	if err := env.Store.UpdateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	resp, _ = env.Page(t, c, "/admin/settings")
	assertStatus(t, resp, http.StatusOK)
	laser := env.CreateGroup(t, "Laser", false, true)
	admin, err := env.Store.GetUserByEmail(ctx, testenv.AdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Store.AddMember(ctx, admin.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ = env.Page(t, c, "/admin/settings")
	assertRedirect(t, resp, "/account/totp?required=1&next=%2Fadmin%2Fsettings")
}

// The admin check is made afresh on every request: an admin taken out of
// their admin group mid-session is refused on the next one.
func TestAdminRemovedMidSessionRefused(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	c, admin := env.AdminClient(t)
	resp, _ := env.Page(t, c, "/admin/members")
	assertStatus(t, resp, http.StatusOK)

	g, err := env.Store.GetGroupByName(ctx, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Store.RemoveMember(ctx, admin.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	resp, body := env.Page(t, c, "/admin/members")
	assertStatus(t, resp, http.StatusForbidden)
	assertContains(t, body, "Admins only")
	resp, _ = env.Submit(t, c, "/admin/settings/rotate-keys", nil)
	assertStatus(t, resp, http.StatusForbidden)
}

func TestAdminFrame(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	resp, body := env.Page(t, c, "/admin/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	nav := between(body, `<nav class="admin-nav" aria-label="Admin">`, "</nav>")
	if nav == "" {
		t.Fatalf("no admin sidebar in:\n%s", body)
	}
	last := -1
	for _, link := range adminLinks {
		i := strings.Index(nav, link)
		if i < 0 {
			t.Fatalf("sidebar missing %s", link)
		}
		if i < last {
			t.Errorf("sidebar link %s out of order", link)
		}
		last = i
	}
	for _, label := range []string{"Members", "Groups", "Applications", "Service accounts", "Settings", "Audit log"} {
		if !strings.Contains(nav, ">"+label+"</a>") {
			t.Errorf("sidebar missing %q", label)
		}
	}
	if !strings.Contains(nav, `<a href="/admin/settings" aria-current="page">`) {
		t.Errorf("Settings is not marked as the current page:\n%s", nav)
	}
	if n := strings.Count(body, `aria-current="page"`); n != 1 {
		t.Errorf("%d links marked current, want 1", n)
	}
	if !strings.Contains(body, `<main class="admin">`) || !strings.Contains(body, `<div class="admin-main">`) {
		t.Errorf("body lacks the admin layout")
	}

	header := between(body, "<header", "</header>")
	for _, want := range []string{">Admin<", testenv.AdminEmail, `class="account-menu"`, `href="/"`, "Member home",
		`href="/account"`, "Your account", `<form method="post" action="/logout">`, "Sign out"} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing %q:\n%s", want, header)
		}
	}
	if strings.Contains(header, "Admin pages") {
		t.Errorf("admin pages link to themselves:\n%s", header)
	}
}

// The member pages keep their own frame: no admin sidebar or label.
func TestMemberPagesHaveNoAdminFrame(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	_, body := env.Page(t, c, "/")
	for _, unwanted := range []string{"admin-nav", `class="admin"`, "Member home"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("member home has %q", unwanted)
		}
	}
}

func TestSettingsPage(t *testing.T) {
	env := testenv.New(t, testenv.WithConfig(func(c *config.Config) {
		c.Branding.Name = "Northside Hackspace"
		c.Branding.PrimaryColor = "#a1b2c3"
		c.Branding.SupportText = "Need help? Ask on the forum."
	}))
	c, _ := env.AdminClient(t)
	resp, body := env.Page(t, c, "/admin/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		"<title>Settings · Admin · Northside Hackspace</title>",
		"Northside Hackspace", `style="background-color: #a1b2c3"></span>#a1b2c3`, "Need help? Ask on the forum.",
		"To change these, edit the branding section of Latch's config file (latch.yaml) and restart Latch.",
		"Email isn't set up yet.",
		`action="/admin/settings/test-email"`, "Send a test email to " + testenv.AdminEmail,
		`action="/admin/settings/rotate-keys"`, "Make a new signing key",
		"Apps pick up the new key automatically. Older keys are retired 90 days after they're replaced.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	kid := env.Keys.ActiveKID()
	if row := rowWith(body, kid); !strings.Contains(row, "In use") {
		t.Errorf("active key %s not shown in use: %q", kid, row)
	}

	// With email set up, its settings are shown but never the password.
	env = testenv.New(t, testenv.WithConfig(func(c *config.Config) {
		c.SMTP.Host = "smtp.northside.example"
		c.SMTP.Port = 465
		c.SMTP.Username = "latch"
		c.SMTP.Password = "smtp-password-do-not-show"
		c.SMTP.From = "Northside <noreply@northside.example>"
		c.SMTP.TLS = "tls"
	}))
	c, _ = env.AdminClient(t)
	_, body = env.Page(t, c, "/admin/settings")
	for _, want := range []string{"smtp.northside.example", "465", html.EscapeString("Northside <noreply@northside.example>"), "TLS"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, unwanted := range []string{"smtp-password-do-not-show", "Email isn't set up yet."} {
		if strings.Contains(body, unwanted) {
			t.Errorf("body has %q", unwanted)
		}
	}
}

func TestSettingsTestEmail(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	resp, _ := env.Submit(t, c, "/admin/settings/test-email", nil)
	assertRedirect(t, resp, "/admin/settings?notice=test_email_sent")
	msg, ok := env.Mailer.Last()
	if !ok || msg.To != admin.Email {
		t.Fatalf("last email %+v (sent %v), want one to %s", msg, ok, admin.Email)
	}
	_, body := env.Page(t, c, resp.Header.Get("Location"))
	if !strings.Contains(body, "Test email sent. Check your inbox.") {
		t.Errorf("notice not shown after sending")
	}
	if events := auditEvents(t, env, "settings.smtp_test"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("smtp test events %+v, want one by the admin", events)
	}

	// A failed send shows the mailer's error, so the admin can fix it.
	env = testenv.New(t, testenv.WithMailer(func(*mail.Memory) mail.Mailer { return failingMailer{} }))
	c, _ = env.AdminClient(t)
	resp, body = env.Submit(t, c, "/admin/settings/test-email", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("failed send: status %d, want 502", resp.StatusCode)
	}
	for _, want := range []string{
		html.EscapeString("The test email couldn't be sent: 550 5.1.1 <admin@example.org>: mailbox unavailable"),
		`class="alert alert-error"`,
		"admin-nav", // still the settings page
		`action="/admin/settings/rotate-keys"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("failed send: body missing %q", want)
		}
	}
}

func TestSettingsRotateKeys(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	old := env.Keys.ActiveKID()

	resp, _ := env.Submit(t, c, "/admin/settings/rotate-keys", nil)
	assertRedirect(t, resp, "/admin/settings?notice=key_rotated")
	kid := env.Keys.ActiveKID()
	if kid == old || kid == "" {
		t.Fatalf("active key %q after rotating from %q", kid, old)
	}
	if events := auditEvents(t, env, "oidc.key.rotate"); len(events) != 1 || events[0].ActorID != admin.ID || events[0].TargetID != kid {
		t.Errorf("rotation events %+v, want one by the admin for %s", events, kid)
	}

	_, jwks := env.Page(t, c, "/.well-known/jwks.json")
	var set struct{ Keys []struct{ Kid string } }
	if err := json.Unmarshal([]byte(jwks), &set); err != nil {
		t.Fatalf("decode JWKS %q: %v", jwks, err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2: %s", len(set.Keys), jwks)
	}

	_, body := env.Page(t, c, "/admin/settings?notice=key_rotated")
	if !strings.Contains(body, "New signing key in use. Apps pick it up automatically.") {
		t.Errorf("notice not shown after rotating")
	}
	if row := rowWith(body, kid); !strings.Contains(row, "In use") {
		t.Errorf("new key not in use: %q", row)
	}
	if row := rowWith(body, old); !strings.Contains(row, "Still published") {
		t.Errorf("replaced key not shown as still published: %q", row)
	}

	// A retired key shows the date it was retired.
	if _, err := env.Keys.RetireOlderThan(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	keys, err := env.Store.ListSigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var retired string
	for _, k := range keys {
		if k.KID == old && k.RetiredAt != nil {
			retired = "Retired " + k.RetiredAt.UTC().Format("2 Jan 2006")
		}
	}
	if retired == "" {
		t.Fatalf("key %s not retired", old)
	}
	_, body = env.Page(t, c, "/admin/settings")
	if row := rowWith(body, old); !strings.Contains(row, retired) {
		t.Errorf("retired key row %q, want %q", row, retired)
	}
}

// A notice is only ever a message from the table, never request text.
func TestAdminNoticesComeFromTable(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)

	_, body := env.Page(t, c, "/admin/settings?notice=saved")
	if !strings.Contains(body, `<p class="alert alert-notice" role="status">Changes saved.</p>`) {
		t.Errorf("?notice=saved does not show its message")
	}

	_, body = env.Page(t, c, "/admin/settings?notice=%3Cb%3Ehi%3C%2Fb%3E")
	for _, unwanted := range []string{"<b>hi</b>", "&lt;b&gt;hi", `class="alert`, `role="status"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("unknown notice: body has %q", unwanted)
		}
	}
}

func TestHomeLinksAdminsToAdminPages(t *testing.T) {
	env := testenv.New(t)
	admin, _ := env.AdminClient(t)
	_, body := env.Page(t, admin, "/")
	if !strings.Contains(body, `<a href="/admin">Admin pages</a>`) {
		t.Errorf("admin's home has no link to the admin pages")
	}

	env.CreateUser(t, "member@example.org", testPW, "Members")
	member := env.Client(t)
	env.Login(t, member, "member@example.org", testPW)
	_, body = env.Page(t, member, "/")
	if strings.Contains(body, `href="/admin"`) || strings.Contains(body, "Admin pages") {
		t.Errorf("a plain member's home links to the admin pages")
	}
}

func TestRequestBodyLimit(t *testing.T) {
	env := testenv.New(t)
	big := bytes.Repeat([]byte("a"), 2<<20)
	send := func(path string) (*http.Response, string) {
		t.Helper()
		form := append([]byte("email=a%40example.org&password="), big...)
		resp, err := env.Client(t).Post(env.TS.URL+path, "application/x-www-form-urlencoded", bytes.NewReader(form))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return resp, b.String()
	}

	resp, body := send("/login")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /login with 2 MiB: status %d, want 413", resp.StatusCode)
	}
	if !strings.Contains(body, "Too much data") {
		t.Errorf("413 page has no title:\n%s", body)
	}
	if n := len(auditEvents(t, env, "login.failure")); n != 0 {
		t.Errorf("the oversized sign-in was checked: %d login failures", n)
	}

	// The API limits its own bodies, answering in JSON, not with the page.
	resp, body = send("/api/v1/me")
	if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get("Content-Type") != "application/json" ||
		!strings.Contains(body, `"too_large"`) || strings.Contains(body, "Too much data") {
		t.Errorf("POST /api/ with 2 MiB: status %d, Content-Type %q, want the API's JSON 413:\n%s",
			resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	// A body within the limit still reaches the handler.
	resp, err := env.Client(t).PostForm(env.TS.URL+"/login", url.Values{"email": {"a@example.org"}, "password": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("small sign-in: status %d, want 200", resp.StatusCode)
	}
}
