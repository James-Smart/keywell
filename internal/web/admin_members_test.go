package web_test

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"keywell/internal/mail"
	"keywell/internal/model"
	"keywell/internal/store"
	"keywell/internal/testenv"
)

// addMember stores an active member called name, with email and testPW as
// their password, in the named groups (made when missing).
func addMember(t *testing.T, env *testenv.Env, name, email string, groups ...string) *model.User {
	t.Helper()
	u := env.CreateUser(t, email, testPW, groups...)
	renameUser(t, env, u, name)
	return u
}

// seedMembers stores the members the list tests look for: Alex Rivera,
// active and in Laser; Priya Nair, invited; and Chris Dubois, disabled.
func seedMembers(t *testing.T, env *testenv.Env) (alex, priya, chris *model.User) {
	t.Helper()
	alex = addMember(t, env, "Alex Rivera", "alex@example.org", "Laser")
	priya = env.CreateUser(t, "priya@example.org", "")
	renameUser(t, env, priya, "Priya Nair")
	issueLink(t, env, priya, model.ResetPurposeInvite)
	chris = addMember(t, env, "Chris Dubois", "chris@example.org")
	chris.IsActive = false
	if err := env.Store.UpdateUser(context.Background(), chris); err != nil {
		t.Fatal(err)
	}
	return alex, priya, chris
}

// memberValues is the member form with name and email, the groups ticked,
// no username and empty metadata.
func memberValues(name, email string, groupIDs ...string) url.Values {
	return url.Values{"name": {name}, "email": {email}, "username": {""}, "metadata": {"{}"}, "groups": groupIDs}
}

// memberByEmail returns the user with email, failing the test when there
// is none.
func memberByEmail(t *testing.T, env *testenv.Env, email string) *model.User {
	t.Helper()
	u, err := env.Store.GetUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("get %s: %v", email, err)
	}
	return u
}

// memberCount is how many members are stored.
func memberCount(t *testing.T, env *testenv.Env) int {
	t.Helper()
	page, err := env.Store.ListUsers(context.Background(), store.UserFilter{Type: model.UserTypeMember})
	if err != nil {
		t.Fatal(err)
	}
	return page.Total
}

// groupNamesOf returns the names of the groups u is in, in order.
func groupNamesOf(t *testing.T, env *testenv.Env, u *model.User) []string {
	t.Helper()
	groups, err := env.Store.ListGroupsForUser(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return names
}

// tableRows counts the rows in body's table body.
func tableRows(body string) int {
	return strings.Count(between(body, "<tbody>", "</tbody>"), "<tr")
}

var hrefRE = regexp.MustCompile(`href="([^"]*)"`)

// pageLink returns the link of body's pagination to page n, decoded,
// failing the test when there is none.
func pageLink(t *testing.T, body string, n int) *url.URL {
	t.Helper()
	nav := between(body, `<nav class="pagination"`, "</nav>")
	for _, m := range hrefRE.FindAllStringSubmatch(nav, -1) {
		u, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatalf("page link %q: %v", m[1], err)
		}
		if u.Query().Get("page") == fmt.Sprint(n) {
			return u
		}
	}
	t.Fatalf("no link to page %d in %q", n, nav)
	return nil
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

func assertContains(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func assertLacks(t *testing.T, body string, unwanted ...string) {
	t.Helper()
	for _, s := range unwanted {
		if strings.Contains(body, s) {
			t.Errorf("body has %q", s)
		}
	}
}

func TestMembersList(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	alex, priya, chris := seedMembers(t, env)
	createServiceAccount(t, env, "door@example.org")

	resp, body := env.Page(t, c, "/admin/members")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body,
		"<h1>Members</h1>",
		`href="/admin/members/new"`, ">Add member</a>",
		`placeholder="Search name, email or username"`,
		`<option value="" selected>All</option>`,
		`<option value="active">Active</option>`,
		`<option value="invited">Invited</option>`,
		`<option value="needs_password">Needs password</option>`,
		`<option value="disabled">Disabled</option>`,
		`<option value="no_2fa">No two-step sign in</option>`,
		`<option value="admins">Admins</option>`,
		`<a href="/admin/members" aria-current="page">`,
	)
	for _, col := range []string{"Name", "Email", "Groups", "Status", "Last login"} {
		assertContains(t, between(body, "<thead>", "</thead>"), ">"+col+"</th>")
	}

	row := rowWith(body, "Alex Rivera")
	assertContains(t, row, `href="/admin/members/`+alex.ID+`"`, "alex@example.org", `<span class="chip">Laser</span>`,
		`<span class="status status-active">Active</span>`, "Never")
	row = rowWith(body, "Priya Nair")
	assertContains(t, row, `href="/admin/members/`+priya.ID+`"`, "priya@example.org",
		`<span class="status status-invited">Invited, not set up</span>`)
	row = rowWith(body, "Chris Dubois")
	assertContains(t, row, `href="/admin/members/`+chris.ID+`"`, "chris@example.org",
		`<span class="status status-disabled">Disabled</span>`)
	// The admin signed in just now. (Their address is also in the header.)
	assertContains(t, rowWith(body, `href="/admin/members/`+admin.ID+`"`), "Today", `<span class="chip">Admin</span>`)
	if strings.Contains(body, "Door") || strings.Contains(body, "door@example.org") {
		t.Error("the members list shows a service account")
	}
	if n := tableRows(body); n != 4 {
		t.Errorf("%d rows, want 4", n)
	}

	// The list is for admins only.
	member := env.Client(t)
	env.Login(t, member, "alex@example.org", testPW)
	resp, _ = env.Page(t, member, "/admin/members")
	assertStatus(t, resp, http.StatusForbidden)
}

func TestMembersListSearchFilterPage(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	c, admin := env.AdminClient(t)
	seedMembers(t, env)
	adminLink := `href="/admin/members/` + admin.ID + `"`

	_, body := env.Page(t, c, "/admin/members?q=priya")
	assertContains(t, body, "Priya Nair", `value="priya"`)
	assertLacks(t, body, "Alex Rivera", "Chris Dubois", adminLink)

	_, body = env.Page(t, c, "/admin/members?status=disabled")
	assertContains(t, body, "Chris Dubois", `<option value="disabled" selected>Disabled</option>`)
	assertLacks(t, body, "Alex Rivera", "Priya Nair", adminLink)

	_, body = env.Page(t, c, "/admin/members?q=nobody-matches-this")
	assertContains(t, body, "No members match.")
	if n := tableRows(body); n != 0 {
		t.Errorf("no match: %d rows", n)
	}

	// An unknown filter lists everyone.
	_, body = env.Page(t, c, "/admin/members?status=bogus")
	assertContains(t, body, "Alex Rivera", "Priya Nair", "Chris Dubois", `<option value="" selected>All</option>`)

	// 60 more active members: with Alex and the admin, 62.
	for i := 1; i <= 60; i++ {
		u := &model.User{Name: fmt.Sprintf("Member %02d", i), Email: fmt.Sprintf("member%02d@example.org", i),
			IsActive: true, PasswordHash: "not checked by these tests"}
		if err := env.Store.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	_, first := env.Page(t, c, "/admin/members?status=active")
	if n := tableRows(first); n != 50 {
		t.Fatalf("page 1: %d rows, want 50", n)
	}
	assertContains(t, first, "Showing 1–50 of 62", "Alex Rivera", "Member 48")
	assertLacks(t, first, "Member 49")
	next := pageLink(t, first, 2)
	if next.Path != "/admin/members" || next.Query().Get("status") != "active" {
		t.Errorf("next page link %q does not keep the filter", next)
	}

	_, second := env.Page(t, c, next.String())
	if n := tableRows(second); n != 12 {
		t.Errorf("page 2: %d rows, want 12", n)
	}
	assertContains(t, second, "Showing 51–62 of 62", "Member 49", "Member 60")
	assertLacks(t, second, "Alex Rivera", "Member 48")
	if prev := pageLink(t, second, 1); prev.Query().Get("status") != "active" {
		t.Errorf("previous page link %q does not keep the filter", prev)
	}

	// A page that is not a number is the first page.
	_, abc := env.Page(t, c, "/admin/members?status=active&page=abc")
	if got, want := between(abc, "<tbody>", "</tbody>"), between(first, "<tbody>", "</tbody>"); got != want || got == "" {
		t.Errorf("page=abc is not the first page")
	}

	// Page links keep the search too.
	_, body = env.Page(t, c, "/admin/members?q=Member&status=active")
	assertContains(t, body, "Showing 1–50 of 60")
	if q := pageLink(t, body, 2).Query(); q.Get("q") != "Member" || q.Get("status") != "active" {
		t.Errorf("next page link %v does not keep the search and filter", q)
	}
}

func TestAddMemberInvite(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, false)

	resp, body := env.Page(t, c, "/admin/members/new")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body,
		"<h1>Add member</h1>",
		`<form method="post" action="/admin/members"`,
		">Full name</label>", `name="name"`,
		">Email (used to sign in)</label>", `name="email"`,
		">Username (optional, for the wiki)</label>", `name="username"`,
		`name="groups" value="`+laser.ID+`">`, "Laser",
		"Metadata (custom JSON, passed to apps)", ">{}</textarea>",
		"How will they set their password?",
		`name="setup" value="invite" checked>`, "Email them an invitation (recommended)",
		`name="setup" value="password">`, "Set a password now",
		`name="password"`,
	)
	if d := between(between(body, "<main", "</main>"), "<details", ">"); d == "" || strings.Contains(d, "open") {
		t.Errorf("metadata disclosure %q, want closed", d)
	}
	// The password field is hidden while an invitation is chosen, and a
	// hidden field the browser finds invalid blocks the form silently.
	assertLacks(t, body, "minlength")

	resp, _ = env.Submit(t, c, "/admin/members", url.Values{
		"name": {"Sam Okafor"}, "email": {"sam@example.org"}, "username": {""},
		"groups": {laser.ID}, "metadata": {"{}"}, "setup": {"invite"},
	})
	sam := memberByEmail(t, env, "sam@example.org")
	assertRedirect(t, resp, "/admin/members/"+sam.ID+"?notice=invited")
	msg, ok := env.Mailer.Last()
	if !ok || msg.To != "sam@example.org" || !strings.Contains(msg.Text, "/reset/") {
		t.Fatalf("last email %+v (sent %v), want an invitation to sam@example.org", msg, ok)
	}
	if sam.Name != "Sam Okafor" || sam.Type != model.UserTypeMember || !sam.IsActive || sam.HasPassword() {
		t.Errorf("stored member %+v", sam)
	}
	if got := groupNamesOf(t, env, sam); len(got) != 1 || got[0] != "Laser" {
		t.Errorf("groups %v, want [Laser]", got)
	}
	if events := auditEvents(t, env, "user.create"); len(events) != 1 || events[0].ActorID != admin.ID || events[0].TargetID != sam.ID {
		t.Errorf("user.create events %+v, want one by the admin", events)
	}

	_, body = env.Page(t, c, resp.Header.Get("Location"))
	assertContains(t, body, html.EscapeString("Member added. We've emailed them an invitation."), "Invited, not set up")
}

// Ruling 17: the add form never sends both an invitation and a password.
// A password typed before choosing the invitation is dropped, and the
// invitation goes out.
func TestAddMemberInviteDropsTypedPassword(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	form := memberValues("Sam Okafor", "sam@example.org")
	form.Set("setup", "invite")
	form.Set("password", "correct horse battery")
	resp, _ := env.Submit(t, c, "/admin/members", form)
	sam := memberByEmail(t, env, "sam@example.org")
	assertRedirect(t, resp, "/admin/members/"+sam.ID+"?notice=invited")
	if sam.HasPassword() {
		t.Error("the typed password was set")
	}
	if n := len(env.Mailer.Sent); n != 1 {
		t.Errorf("sent %d emails, want the invitation", n)
	}
}

func TestAddMemberSetPassword(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	form := memberValues("Sam Okafor", "sam@example.org")
	form.Set("setup", "password")
	form.Set("password", "correct horse battery")
	resp, _ := env.Submit(t, c, "/admin/members", form)
	sam := memberByEmail(t, env, "sam@example.org")
	assertRedirect(t, resp, "/admin/members/"+sam.ID+"?notice=added")
	if n := len(env.Mailer.Sent); n != 0 {
		t.Errorf("sent %d emails", n)
	}
	env.Login(t, env.Client(t), "sam@example.org", "correct horse battery")

	_, body := env.Page(t, c, resp.Header.Get("Location"))
	assertContains(t, body, "Member added.", `<span class="status status-active">Active</span>`)
}

func TestAddMemberErrorsKeepInput(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, false)
	env.CreateUser(t, "alex@example.org", testPW)
	before := memberCount(t, env)

	// Review Focus 1: an email that differs only in case is taken.
	form := memberValues("Alex Two", "ALEX@example.org", laser.ID)
	form.Set("setup", "invite")
	resp, body := env.Submit(t, c, "/admin/members", form)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body,
		"Another member already uses that email address.",
		`value="Alex Two"`, `value="ALEX@example.org"`,
		`aria-invalid="true" aria-describedby="email-error"`, `id="email-error"`,
		`name="groups" value="`+laser.ID+`" checked>`,
		"<h1>Add member</h1>",
	)

	// Review Focus 2: metadata that is JSON but not an object.
	form = memberValues("Sam Okafor", "sam@example.org")
	form.Set("metadata", "[1,2]")
	resp, body = env.Submit(t, c, "/admin/members", form)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Metadata must be a JSON object", ">[1,2]</textarea>", `value="Sam Okafor"`)
	if d := between(between(body, "<main", "</main>"), "<details", ">"); !strings.Contains(d, "open") {
		t.Errorf("metadata disclosure %q, want open to show the message", d)
	}

	// Setting a password now needs one, and a refused one is not shown again.
	form = memberValues("Sam Okafor", "sam@example.org")
	form.Set("setup", "password")
	resp, body = env.Submit(t, c, "/admin/members", form)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Enter a password, or choose to email them an invitation.", `name="setup" value="password" checked>`)
	form.Set("password", "short")
	resp, body = env.Submit(t, c, "/admin/members", form)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Use at least 10 characters.")
	assertLacks(t, body, `value="short"`)

	if n := memberCount(t, env); n != before {
		t.Errorf("%d members after refused adds, want %d", n, before)
	}
	if n := len(env.Mailer.Sent); n != 0 {
		t.Errorf("sent %d emails", n)
	}
}

// A refused add or save says so at the top: the messages beside the fields
// may be far down the page. Both the service's checks and the page's own
// (metadata that isn't an object) do.
func TestMemberFormsSayNothingSaved(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	badMeta := func(f url.Values) url.Values { f.Set("metadata", "[1]"); return f }
	assertNotSaved(t, env, c, "/admin/members", memberValues("Sam Okafor", "not an email"))
	assertNotSaved(t, env, c, "/admin/members", badMeta(memberValues("Sam Okafor", "sam@example.org")))
	setPassword := memberValues("Sam Okafor", "sam@example.org")
	setPassword.Set("setup", "password")
	assertNotSaved(t, env, c, "/admin/members", setPassword)
	assertNotSaved(t, env, c, "/admin/members/"+alex.ID, memberValues("Alex Rivera", "not an email"))
	assertNotSaved(t, env, c, "/admin/members/"+alex.ID, badMeta(memberValues("Alex Rivera", "alex@example.org")))
}

func TestAddMemberInviteEmailFails(t *testing.T) {
	env := testenv.New(t, testenv.WithMailer(func(*mail.Memory) mail.Mailer { return failingMailer{} }))
	c, _ := env.AdminClient(t)
	form := memberValues("Sam Okafor", "sam@example.org")
	form.Set("setup", "invite")
	resp, _ := env.Submit(t, c, "/admin/members", form)
	sam := memberByEmail(t, env, "sam@example.org")
	assertRedirect(t, resp, "/admin/members/"+sam.ID+"?notice=added_no_email")

	_, body := env.Page(t, c, resp.Header.Get("Location"))
	assertContains(t, body,
		html.EscapeString("Member added, but the invitation email couldn't be sent. Check the email settings on the Settings page, then use Send invite email."),
		">Send invite email</button>",
		// Ruling 16: no invitation went out, so they still need a password.
		`<span class="status status-needs_password">Needs password</span>`)
	assertLacks(t, body, "Invited, not set up")
	if n := liveResetTokens(t, env, sam.ID); n != 0 {
		t.Errorf("%d live links after a failed invitation, want 0", n)
	}
	if events := auditEvents(t, env, "user.invite"); len(events) != 1 || events[0].Detail["email_sent"] != false {
		t.Errorf("user.invite events %+v, want one failed attempt", events)
	}

	// Sending was the whole action, so failing again is an error.
	resp, body = env.Submit(t, c, "/admin/members/"+sam.ID+"/send-email", nil)
	assertStatus(t, resp, http.StatusBadGateway)
	assertContains(t, body,
		`class="alert alert-error"`,
		html.EscapeString("The email couldn't be sent. Check the email settings on the Settings page, then try again."),
		`value="Sam Okafor"`, "Needs password")
	assertLacks(t, body, "mailbox unavailable")
	if n := liveResetTokens(t, env, sam.ID); n != 0 {
		t.Errorf("%d live links after a failed send, want 0", n)
	}

	// A failed reset email for a member with a password leaves no link either.
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	resp, _ = env.Submit(t, c, "/admin/members/"+alex.ID+"/send-email", nil)
	assertStatus(t, resp, http.StatusBadGateway)
	if n := liveResetTokens(t, env, alex.ID); n != 0 {
		t.Errorf("%d live reset links after a failed send, want 0", n)
	}
}

func TestEditMember(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	c, admin := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, true)
	wood := env.CreateGroup(t, "Woodshop", false, false)
	alex := &model.User{Name: "Alex Rivera", Email: "alex@example.org", Username: "arivera", IsActive: true,
		Metadata: map[string]any{"member_number": 42}, AuthentikUUID: "8f2a3c1e-6b7d-4e5f-9a0b-1c2d3e4f5a6b"}
	if err := env.Store.CreateUser(ctx, alex); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.AddMember(ctx, alex.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	base := "/admin/members/" + alex.ID

	resp, body := env.Page(t, c, base)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body,
		"<h1>Alex Rivera</h1>",
		`<form method="post" action="`+base+`"`,
		`value="Alex Rivera"`, `value="alex@example.org"`, `value="arivera"`,
		`name="groups" value="`+laser.ID+`" checked>`,
		`name="groups" value="`+wood.ID+`">`,
		html.EscapeString("{\n  \"member_number\": 42\n}")+"</textarea>",
		">Save changes</button>",
		"Imported from Authentik",
		"Needs password",
		"Required by Laser; they'll set it up next time they sign in",
		`<a href="/admin/members" aria-current="page">`,
	)
	if twoStep := between(body, "Two-step sign in</dt>", "</dd>"); !strings.Contains(twoStep, "Off") {
		t.Errorf("two-step sign in %q, want Off", twoStep)
	}
	if created := between(body, "Created</dt>", "</dd>"); !strings.Contains(created, alex.CreatedAt.UTC().Format("2 Jan 2006")) {
		t.Errorf("created %q", created)
	}
	if login := between(body, "Last login</dt>", "</dd>"); !strings.Contains(login, "Never") {
		t.Errorf("last login %q, want Never", login)
	}

	// Only imported members say so.
	_, body = env.Page(t, c, "/admin/members/"+admin.ID)
	assertLacks(t, body, "Imported from Authentik")

	// Enrolled: on since the day they set it up, and no longer "required".
	env.EnrolTOTP(t, alex)
	_, body = env.Page(t, c, base)
	if twoStep := between(body, "Two-step sign in</dt>", "</dd>"); !strings.Contains(twoStep, "On since "+alex.TOTPConfirmedAt.UTC().Format("2 Jan 2006")) {
		t.Errorf("two-step sign in %q, want On since the enrolment date", twoStep)
	}
	assertLacks(t, body, "Required by")

	resp, _ = env.Submit(t, c, base, url.Values{"name": {"Alex R. Rivera"}, "email": {"alex@example.org"},
		"username": {"arivera"}, "metadata": {`{"member_number": 42}`}})
	assertRedirect(t, resp, base+"?notice=saved")
	got := getUser(t, env, alex.ID)
	if got.Name != "Alex R. Rivera" || got.Username != "arivera" || fmt.Sprint(got.Metadata) != "map[member_number:42]" {
		t.Errorf("saved member %+v", got)
	}
	if groups := groupNamesOf(t, env, alex); len(groups) != 0 {
		t.Errorf("groups %v after saving with none ticked", groups)
	}
	_, body = env.Page(t, c, resp.Header.Get("Location"))
	assertContains(t, body, "Changes saved.", `value="Alex R. Rivera"`)

	// A refused save keeps what was typed and changes nothing.
	resp, body = env.Submit(t, c, base, url.Values{"name": {"Alex Again"}, "email": {"alex@example.org"},
		"username": {"has space"}, "groups": {wood.ID}, "metadata": {"null"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Metadata must be a JSON object", ">null</textarea>", `value="Alex Again"`,
		`name="groups" value="`+wood.ID+`" checked>`)
	if got := getUser(t, env, alex.ID); got.Name != "Alex R. Rivera" {
		t.Errorf("refused save changed the name to %q", got.Name)
	}
	resp, body = env.Submit(t, c, base, url.Values{"name": {"Alex Again"}, "email": {"alex@example.org"},
		"username": {"has space"}, "metadata": {"{}"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, html.EscapeString("Usernames can't contain spaces."), `value="has space"`)
	if got := getUser(t, env, alex.ID); got.Name != "Alex R. Rivera" || got.Username != "arivera" {
		t.Errorf("refused save changed the member to %+v", got)
	}
}

func TestMemberActions(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	priya := env.CreateUser(t, "priya@example.org", "")
	renameUser(t, env, priya, "Priya Nair")
	base := "/admin/members/" + alex.ID

	// The email offered fits whether they have a password.
	_, body := env.Page(t, c, "/admin/members/"+priya.ID)
	assertContains(t, body, ">Send invite email</button>", "Set password manually", ">Sign out everywhere</button>",
		"Disable account", "Delete member", "Type their email address to confirm")
	assertLacks(t, body, "Send password reset email", "Clear two-step sign in", "Enable account")
	_, body = env.Page(t, c, base)
	assertContains(t, body, ">Send password reset email</button>",
		`name="password" type="password" autocomplete="new-password" required minlength="10"`)
	assertLacks(t, body, "Send invite email")

	resp, _ := env.Submit(t, c, "/admin/members/"+priya.ID+"/send-email", nil)
	assertRedirect(t, resp, "/admin/members/"+priya.ID+"?notice=invite_sent")
	if msg, _ := env.Mailer.Last(); msg.To != priya.Email || !strings.HasPrefix(msg.Subject, "Set up your") {
		t.Errorf("invite email %+v", msg)
	}
	resp, _ = env.Submit(t, c, base+"/send-email", nil)
	assertRedirect(t, resp, base+"?notice=reset_sent")
	if msg, _ := env.Mailer.Last(); msg.To != alex.Email || !strings.HasPrefix(msg.Subject, "Reset your") {
		t.Errorf("reset email %+v", msg)
	}

	// Setting a password.
	alexClient := env.Client(t)
	env.Login(t, alexClient, alex.Email, testPW)
	sid := jarSession(t, env, alexClient)
	resp, body = env.Submit(t, c, base+"/password", url.Values{"password": {"short"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	// The message is beside the field, far down a phone's page, so the top
	// says what failed too.
	assertContains(t, body, "Use at least 10 characters.", `id="password-error"`,
		`<p class="alert alert-error" role="alert">`+html.EscapeString("The password wasn't set. See Set password manually below.")+"</p>")
	assertLacks(t, body, `value="short"`)
	if d := between(body, `<details class="reveal"`, ">"); !strings.Contains(d, "open") {
		t.Errorf("set password disclosure %q, want open to show the message", d)
	}
	resp, _ = env.Submit(t, c, base+"/password", url.Values{"password": {newPW}})
	assertRedirect(t, resp, base+"?notice=password_set")
	assertSessionGone(t, env, sid)
	env.Login(t, env.Client(t), alex.Email, newPW)

	// Clearing two-step sign in, offered only when they have it.
	env.EnrolTOTP(t, alex)
	_, body = env.Page(t, c, base)
	assertContains(t, body, "Clear two-step sign in", `action="`+base+`/clear-totp"`)
	resp, _ = env.Submit(t, c, base+"/clear-totp", nil)
	assertRedirect(t, resp, base+"?notice=totp_cleared")
	if got := getUser(t, env, alex.ID); got.TOTPConfirmedAt != nil || got.TOTPSecretEnc != nil {
		t.Errorf("two-step sign in still set: %v", got.TOTPConfirmedAt)
	}

	// Disabling signs them out; enabling lets them back.
	alexClient = env.Client(t)
	env.Login(t, alexClient, alex.Email, newPW)
	sid = jarSession(t, env, alexClient)
	resp, _ = env.Submit(t, c, base+"/disable", nil)
	assertRedirect(t, resp, base+"?notice=disabled")
	assertSessionGone(t, env, sid)
	if getUser(t, env, alex.ID).IsActive {
		t.Error("still active after disabling")
	}
	_, body = env.Page(t, c, base)
	assertContains(t, body, ">Enable account</button>", `<span class="status status-disabled">Disabled</span>`)
	assertLacks(t, body, `action="`+base+`/disable"`)
	resp, _ = env.Submit(t, c, base+"/enable", nil)
	assertRedirect(t, resp, base+"?notice=enabled")
	if !getUser(t, env, alex.ID).IsActive {
		t.Error("not active after enabling")
	}

	// Signing out everywhere.
	alexClient = env.Client(t)
	env.Login(t, alexClient, alex.Email, newPW)
	sid = jarSession(t, env, alexClient)
	resp, _ = env.Submit(t, c, base+"/sign-out", nil)
	assertRedirect(t, resp, base+"?notice=signed_out")
	assertSessionGone(t, env, sid)

	for _, action := range []string{"user.invite", "user.password.reset_sent", "user.password.set", "user.totp.clear",
		"user.disable", "user.enable", "user.sessions.revoke"} {
		if events := auditEvents(t, env, action); len(events) != 1 || events[0].ActorID != admin.ID {
			t.Errorf("%s events %+v, want one by the admin", action, events)
		}
	}
}

func TestDeleteMemberConfirm(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	base := "/admin/members/" + alex.ID

	notDeleted := `<p class="alert alert-error" role="alert">` +
		html.EscapeString("The member wasn't deleted. See Delete member below.") + "</p>"
	resp, body := env.Submit(t, c, base+"/delete", url.Values{"confirm": {"wrong@example.org"}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Type the email address exactly to confirm.", `value="Alex Rivera"`, notDeleted)
	if d := between(body, `<details class="confirm" open`, "Delete member"); d == "" {
		t.Error("the delete confirmation is not open to show the message")
	}
	getUser(t, env, alex.ID)

	resp, body = env.Submit(t, c, base+"/delete", url.Values{"confirm": {""}})
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, notDeleted)
	getUser(t, env, alex.ID)

	resp, _ = env.Submit(t, c, base+"/delete", url.Values{"confirm": {" ALEX@example.org "}})
	assertRedirect(t, resp, "/admin/members?notice=deleted")
	if _, err := env.Store.GetUser(context.Background(), alex.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("member still stored: %v", err)
	}
	if events := auditEvents(t, env, "user.delete"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("user.delete events %+v, want one by the admin", events)
	}
	_, body = env.Page(t, c, resp.Header.Get("Location"))
	assertContains(t, body, `role="status">Deleted.</p>`)
	assertLacks(t, body, "Alex Rivera")

	resp, _ = env.Page(t, c, base)
	assertStatus(t, resp, http.StatusNotFound)
}

// Review Focus 3: an admin cannot disable or delete their own account, or
// take away their own admin access.
func TestAdminCannotLockThemselvesOut(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	base := "/admin/members/" + admin.ID

	// Ruling 7: setting their own password here would also end this very
	// session, so the page leaves it out as well; signing out stays.
	_, body := env.Page(t, c, base)
	assertContains(t, body, "This is your account.", "Change your own password from", `action="`+base+`/sign-out"`)
	assertLacks(t, body, `action="`+base+`/disable"`, `action="`+base+`/delete"`, `action="`+base+`/password"`,
		"Disable account", "Delete member", "Set password manually")
	alex := addMember(t, env, "Alex Rivera", "alex@example.org")
	_, body = env.Page(t, c, "/admin/members/"+alex.ID)
	assertContains(t, body, `action="/admin/members/`+alex.ID+`/disable"`, `action="/admin/members/`+alex.ID+`/delete"`,
		`action="/admin/members/`+alex.ID+`/password"`)
	assertLacks(t, body, "This is your account.")

	// A refusal's own message is the alert, not the action's summary.
	resp, body := env.Submit(t, c, base+"/disable", nil)
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, `<p class="alert alert-error" role="alert">`+html.EscapeString("You can't disable your own account.")+"</p>")
	assertLacks(t, body, html.EscapeString("The account wasn't disabled."))
	resp, body = env.Submit(t, c, base+"/delete", url.Values{"confirm": {admin.Email}})
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, html.EscapeString("You can't delete your own account."))
	resp, body = env.Submit(t, c, base, memberValues("Admin", admin.Email))
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, html.EscapeString("You can't remove your own admin access"))

	got := getUser(t, env, admin.ID)
	if !got.IsActive || got.Name != admin.Name {
		t.Errorf("admin changed to %+v", got)
	}
	if groups := groupNamesOf(t, env, admin); len(groups) != 1 || groups[0] != "Admin" {
		t.Errorf("admin's groups %v, want [Admin]", groups)
	}
	resp, _ = env.Page(t, c, "/admin/members")
	assertStatus(t, resp, http.StatusOK)
}

func TestMemberPagesRejectServiceAccounts(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	svc := createServiceAccount(t, env, "door@example.org")
	base := "/admin/members/" + svc.ID

	for _, path := range []string{base, "/admin/members/no-such-member"} {
		resp, body := env.Page(t, c, path)
		assertStatus(t, resp, http.StatusNotFound)
		assertContains(t, body, "Not found")
	}
	bad := memberValues("Door", "door@example.org")
	bad.Set("metadata", "[1]")
	for _, post := range []struct {
		path string
		form url.Values
	}{
		{base, memberValues("Door", "door@example.org")},
		{base, bad},
		{base + "/send-email", nil},
		{base + "/password", url.Values{"password": {newPW}}},
		{base + "/password", url.Values{"password": {"short"}}},
		{base + "/clear-totp", nil},
		{base + "/disable", nil},
		{base + "/enable", nil},
		{base + "/sign-out", nil},
		{base + "/delete", url.Values{"confirm": {"door@example.org"}}},
		{base + "/delete", url.Values{"confirm": {"wrong"}}},
	} {
		resp, _ := env.Submit(t, c, post.path, post.form)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s %v: status %d, want 404", post.path, post.form, resp.StatusCode)
		}
	}
	got := getUser(t, env, svc.ID)
	if got.Name != "Door controller" || !got.IsActive || !got.HasPassword() {
		t.Errorf("service account changed to %+v", got)
	}
	if n := len(env.Mailer.Sent); n != 0 {
		t.Errorf("sent %d emails", n)
	}
}
