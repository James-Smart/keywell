package web_test

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/testenv"
)

// alexSmith creates alex@example.org, named Alex Smith, with username
// "alex", and returns a client signed in as them.
func alexSmith(t *testing.T, env *testenv.Env) (*http.Client, *model.User) {
	t.Helper()
	alex := env.CreateUser(t, "alex@example.org", testPW)
	alex.Name, alex.Username = "Alex Smith", "alex"
	if err := env.Store.UpdateUser(context.Background(), alex); err != nil {
		t.Fatal(err)
	}
	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	return c, alex
}

func TestAccountPageShowsDetails(t *testing.T) {
	env := testenv.New(t)
	c, _ := alexSmith(t, env)
	resp, body := env.Page(t, c, "/account")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	main := between(body, "<main", "</main>")
	for _, want := range []string{
		"<h1>Your account</h1>",
		`<form method="post" action="/account/name"`, `name="name"`, `value="Alex Smith"`,
		"alex@example.org", "You sign in with this. Ask an admin to change it.",
		"Username", ">alex<",
		`href="/account/password"`,
		`href="/account/totp"`, "Off",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestAccountPageTwoStepOnAndNoUsername(t *testing.T) {
	env := testenv.New(t)
	sam := env.CreateUser(t, "sam@example.org", testPW)
	secret := env.EnrolTOTP(t, sam)
	c := env.Client(t)
	signInWithCode(t, env, c, "sam@example.org", secret)
	_, body := env.Page(t, c, "/account")
	main := between(body, "<main", "</main>")
	if !strings.Contains(main, ">On<") {
		t.Errorf("two-step not shown as on:\n%s", main)
	}
	if strings.Contains(main, "Username") {
		t.Errorf("username section shown for a member without one")
	}
}

func TestAccountPageRequiresLogin(t *testing.T) {
	env := testenv.New(t)
	resp, _ := env.Page(t, env.Client(t), "/account")
	assertRedirect(t, resp, "/login?next=%2Faccount")
}

func TestSaveOwnName(t *testing.T) {
	env := testenv.New(t)
	c, alex := alexSmith(t, env)
	resp, _ := env.Submit(t, c, "/account/name", url.Values{"name": {" Alex Jones "}})
	assertRedirect(t, resp, "/account?notice=name_saved")

	_, body := env.Page(t, c, "/account?notice=name_saved")
	for _, want := range []string{"Name saved.", `value="Alex Jones"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page after saving missing %q", want)
		}
	}
	if got := getUser(t, env, alex.ID).Name; got != "Alex Jones" {
		t.Errorf("stored name %q", got)
	}
	evs := auditEvents(t, env, audit.UserUpdate)
	wantChanged := map[string]any{"name": map[string]any{"from": "Alex Smith", "to": "Alex Jones"}}
	if len(evs) != 1 || evs[0].ActorID != alex.ID || evs[0].TargetID != alex.ID ||
		!reflect.DeepEqual(evs[0].Detail["changed"], wantChanged) {
		t.Errorf("audit events %+v", evs)
	}
}

func TestSaveOwnNameInvalid(t *testing.T) {
	env := testenv.New(t)
	c, alex := alexSmith(t, env)
	resp, body := env.Submit(t, c, "/account/name", url.Values{"name": {strings.Repeat("x", 201)}})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422", resp.StatusCode)
	}
	for _, want := range []string{"Use at most 200 characters.", `aria-invalid="true"`, `value="` + strings.Repeat("x", 201) + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if got := getUser(t, env, alex.ID).Name; got != "Alex Smith" {
		t.Errorf("stored name %q", got)
	}
	if evs := auditEvents(t, env, audit.UserUpdate); len(evs) != 0 {
		t.Errorf("audit events %+v", evs)
	}
}

func TestSaveOwnNameRequiresLogin(t *testing.T) {
	env := testenv.New(t)
	resp, _ := env.Submit(t, env.Client(t), "/account/name", url.Values{"name": {"Mallory"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Errorf("status %d, Location %q; want a redirect to sign in", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAccountMenuForMembers(t *testing.T) {
	env := testenv.New(t)
	c, _ := alexSmith(t, env)
	for _, path := range []string{"/", "/account", "/account/password", "/account/totp"} {
		_, body := env.Page(t, c, path)
		header := between(body, "<header", "</header>")
		for _, want := range []string{
			`class="account-menu"`, ">AS<", "Alex Smith", "alex@example.org",
			`href="/account"`, "Your account", `action="/logout"`, "Sign out",
		} {
			if !strings.Contains(header, want) {
				t.Errorf("%s: header missing %q", path, want)
			}
		}
		if strings.Contains(header, "Admin pages") {
			t.Errorf("%s: admin link shown to a member", path)
		}
		if !strings.Contains(body, `<script src="/static/latch.js" defer></script>`) {
			t.Errorf("%s: menu script not loaded", path)
		}
	}

	// The home page keeps only the greeting and tiles.
	_, body := env.Page(t, c, "/")
	main := between(body, "<main", "</main>")
	for _, unwanted := range []string{"Your account", `href="/account/password"`, `action="/logout"`} {
		if strings.Contains(main, unwanted) {
			t.Errorf("home page body has %q", unwanted)
		}
	}

	resp, js := env.Page(t, c, "/static/latch.js")
	if resp.StatusCode != http.StatusOK || !strings.Contains(js, "account-menu") {
		t.Errorf("latch.js: status %d", resp.StatusCode)
	}
}

func TestAccountMenuForAdmins(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	for _, path := range []string{"/", "/account"} {
		_, body := env.Page(t, c, path)
		header := between(body, "<header", "</header>")
		if !strings.Contains(header, `href="/admin"`) || !strings.Contains(header, "Admin pages") {
			t.Errorf("%s: header lacks the admin link:\n%s", path, header)
		}
	}
}

// Without a complete session there is nobody to show a menu for.
func TestNoAccountMenuWithoutCompleteSession(t *testing.T) {
	env := testenv.New(t)
	_, body := env.Page(t, env.Client(t), "/login")
	if strings.Contains(body, "account-menu") || strings.Contains(body, "latch.js") {
		t.Errorf("sign-in page has the account menu")
	}

	env.CreateGroup(t, "Trustees", false, true)
	env.CreateUser(t, "sam@example.org", testPW, "Trustees")
	c := env.Client(t)
	env.Login(t, c, "sam@example.org", testPW)
	_, body = env.Page(t, c, "/account/totp")
	if strings.Contains(body, "account-menu") {
		t.Errorf("enrolment page for an incomplete session has the account menu")
	}
	if !strings.Contains(body, `href="/logout"`) {
		t.Errorf("enrolment page lost its sign out link")
	}
}

func TestAccountSubpagesLinkBack(t *testing.T) {
	env := testenv.New(t)
	c, _ := alexSmith(t, env)
	for _, path := range []string{"/account/password", "/account/totp"} {
		_, body := env.Page(t, c, path)
		main := between(body, "<main", "</main>")
		if !strings.Contains(main, `<a href="/account">Back to your account</a>`) {
			t.Errorf("%s: no link back to the account page", path)
		}
	}
}
