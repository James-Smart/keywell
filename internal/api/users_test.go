package api_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/mail"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/store"
	"github.com/James-Smart/keywell/internal/testenv"
)

const apiUsers = "/api/v1/users"

// items returns the "items" of a list response as objects.
func items(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["items"].([]any)
	if !ok {
		t.Fatalf("items is not an array: %v", body)
	}
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i], _ = v.(map[string]any)
	}
	return out
}

// emails returns the "email" of each item.
func emails(t *testing.T, body map[string]any) []string {
	t.Helper()
	var out []string
	for _, it := range items(t, body) {
		out = append(out, it["email"].(string))
	}
	return out
}

// fieldsOf returns the "fields" of an invalid response.
func fieldsOf(body map[string]any) map[string]any {
	f, _ := body["fields"].(map[string]any)
	return f
}

// groupsOf returns the "groups" of a user response.
func groupsOf(body map[string]any) []string {
	var out []string
	raw, _ := body["groups"].([]any)
	for _, g := range raw {
		out = append(out, g.(string))
	}
	return out
}

func mustUser(t *testing.T, env *testenv.Env, username string) *model.User {
	t.Helper()
	u, err := env.Store.GetUserByUsername(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustMember(t *testing.T, env *testenv.Env, email string) *model.User {
	t.Helper()
	u, err := env.Store.GetUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAPIUsersList(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	env.CreateUser(t, "priya@example.org", "pw", "Laser")
	env.CreateUser(t, "alex@example.org", "pw")
	off := env.CreateUser(t, "sam@example.org", "pw")
	off.IsActive = false
	if err := env.Store.UpdateUser(context.Background(), off); err != nil {
		t.Fatal(err)
	}

	body, resp := env.API(t, raw, http.MethodGet, apiUsers, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %v", resp.StatusCode, body)
	}
	assertJSONHeaders(t, resp)
	if body["page"] != float64(1) || body["per_page"] != float64(50) || body["total"] != float64(3) {
		t.Errorf("envelope %v", body)
	}
	if got := emails(t, body); len(got) != 3 {
		t.Errorf("emails %v, want 3 members and no service account", got)
	}
	for _, it := range items(t, body) {
		if it["username"] == "door" {
			t.Errorf("service account listed: %v", it)
		}
	}

	for _, c := range []struct{ query, want string }{
		{"?q=priya", "priya@example.org"},
		{"?status=disabled", "sam@example.org"},
		{"?group=Laser", "priya@example.org"},
	} {
		body, resp := env.API(t, raw, http.MethodGet, apiUsers+c.query, nil)
		if got := emails(t, body); resp.StatusCode != 200 || len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: %d %v, want [%s]", c.query, resp.StatusCode, got, c.want)
		}
	}
	laser, _ := env.Store.GetGroupByName(context.Background(), "Laser")
	body, _ = env.API(t, raw, http.MethodGet, apiUsers+"?group="+laser.ID, nil)
	if got := emails(t, body); len(got) != 1 {
		t.Errorf("group by ID: %v", got)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiUsers+"?group=Nope", nil)
	assertError(t, body, resp, 422, "invalid")

	body, _ = env.API(t, raw, http.MethodGet, apiUsers+"?per_page=500", nil)
	if body["per_page"] != float64(200) {
		t.Errorf("per_page %v, want 200", body["per_page"])
	}
	body, _ = env.API(t, raw, http.MethodGet, apiUsers+"?per_page=2&page=2", nil)
	if len(items(t, body)) != 1 || body["total"] != float64(3) || body["page"] != float64(2) {
		t.Errorf("page 2: %v", body)
	}
}

func TestAPICreateUser(t *testing.T) {
	env := testenv.New(t)
	raw, acct := env.APIToken(t, "door", model.APITokenScopeAdmin)
	env.CreateGroup(t, "Laser", false, false)
	toks, err := env.Store.ListAPITokens(context.Background(), acct.ID)
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens: %v %v", toks, err)
	}
	tokenID := toks[0].ID

	body, resp := env.API(t, raw, http.MethodPost, apiUsers, map[string]any{
		"name": "Priya", "email": "priya@example.org", "groups": []string{"Laser"}, "invite": true})
	if resp.StatusCode != 201 {
		t.Fatalf("status %d: %v", resp.StatusCode, body)
	}
	assertJSONHeaders(t, resp)
	if body["status"] != "invited" || body["email"] != "priya@example.org" || body["is_active"] != true {
		t.Errorf("body %v", body)
	}
	if g := groupsOf(body); len(g) != 1 || g[0] != "Laser" {
		t.Errorf("groups %v", g)
	}
	if _, ok := body["invite_error"]; ok {
		t.Errorf("invite_error present: %v", body)
	}
	env.WaitMail(t)
	if len(env.Mailer.Sent) != 1 {
		t.Errorf("%d emails sent, want 1", len(env.Mailer.Sent))
	}

	page, err := env.Store.ListAuditEvents(context.Background(), store.AuditFilter{Actions: []string{"user.create"}})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("audit: %v %v", page.Rows, err)
	}
	ev := page.Rows[0]
	if ev.ActorType != model.ActorServiceAccount || ev.Detail["token_id"] != tokenID {
		t.Errorf("audit actor %q detail %v, want service_account and token_id %s", ev.ActorType, ev.Detail, tokenID)
	}

	// With a password and no invite: active.
	body, resp = env.API(t, raw, http.MethodPost, apiUsers, map[string]any{
		"name": "Sam", "email": "sam@example.org", "username": "sam", "password": "correct horse battery"})
	if resp.StatusCode != 201 || body["status"] != "active" || body["username"] != "sam" {
		t.Errorf("with password: %d %v", resp.StatusCode, body)
	}
}

func TestAPICreateUserErrors(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	env.CreateUser(t, "alex@example.org", "pw")

	body, resp := env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"name": "Alex 2", "email": "ALEX@example.org"})
	assertError(t, body, resp, 422, "invalid")
	if f := fieldsOf(body); f["email"] != "Another member already uses that email address." {
		t.Errorf("fields %v", f)
	}

	body, resp = env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"emial": "x"})
	assertError(t, body, resp, 400, "invalid_json")
	body, resp = env.API(t, raw, http.MethodPost, apiUsers, strings.NewReader("nope"))
	assertError(t, body, resp, 400, "invalid_json")

	body, resp = env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"name": "M", "email": "m@example.org", "metadata": []int{1}})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["metadata"]; !ok {
		t.Errorf("no fields.metadata: %v", body)
	}
	if _, err := env.Store.GetUserByEmail(context.Background(), "m@example.org"); err == nil {
		t.Error("member saved despite bad metadata")
	}

	body, resp = env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"name": "G", "email": "g@example.org", "groups": []string{"Nope"}})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["groups"]; !ok {
		t.Errorf("no fields.groups: %v", body)
	}

	// Ruling 17: an invitation and a password together is refused, not
	// half done.
	body, resp = env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"name": "B", "email": "b@example.org",
		"invite": true, "password": "correct horse battery"})
	assertError(t, body, resp, 422, "invalid")
	if got := fieldsOf(body)["password"]; got != "Choose an invitation or a password, not both." {
		t.Errorf("fields.password %q (body %v)", got, body)
	}
	if _, err := env.Store.GetUserByEmail(context.Background(), "b@example.org"); err == nil {
		t.Error("member saved with both an invitation and a password")
	}
	if n := len(env.Mailer.Sent); n != 0 {
		t.Errorf("sent %d emails", n)
	}
}

type failingMailer struct{}

func (failingMailer) Send(context.Context, mail.Message) error {
	return errors.New("smtp refused priya@example.org")
}

// Ruling 11: a failed email is logged with the address redacted, and the
// response carries a plain message, not the SMTP text.
func TestAPIEmailFailures(t *testing.T) {
	var logs strings.Builder
	env := testenv.New(t,
		testenv.WithMailer(func(*mail.Memory) mail.Mailer { return failingMailer{} }),
		testenv.WithLog(slog.New(slog.NewTextHandler(&logs, nil))))
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)

	body, resp := env.API(t, raw, http.MethodPost, apiUsers, map[string]any{"name": "Priya", "email": "priya@example.org", "invite": true})
	if resp.StatusCode != 201 {
		t.Fatalf("status %d: %v", resp.StatusCode, body)
	}
	msg, _ := body["invite_error"].(string)
	if msg == "" || strings.Contains(msg, "smtp") || strings.Contains(msg, "priya@example.org") {
		t.Errorf("invite_error %q", msg)
	}
	// Ruling 16: no invitation went out, so they aren't shown as invited.
	if body["status"] != "needs_password" {
		t.Errorf("status %v, want needs_password", body["status"])
	}
	if !strings.Contains(logs.String(), "smtp refused") || strings.Contains(logs.String(), "priya@example.org") {
		t.Errorf("log should hold the cause without the address:\n%s", logs.String())
	}

	u := mustMember(t, env, "priya@example.org")
	body, resp = env.API(t, raw, http.MethodPost, apiUsers+"/"+u.ID+"/reset-email", nil)
	assertError(t, body, resp, 502, "email_failed")
	if strings.Count(logs.String(), "smtp refused") != 2 || strings.Contains(logs.String(), "priya@example.org") {
		t.Errorf("reset failure not logged redacted:\n%s", logs.String())
	}
}

func TestAPIGetPatchDeleteUser(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	alex := env.CreateUser(t, "alex@example.org", "pw", "Laser")
	path := apiUsers + "/" + alex.ID

	body, resp := env.API(t, raw, http.MethodGet, path, nil)
	if resp.StatusCode != 200 || body["id"] != alex.ID || body["status"] != "active" {
		t.Fatalf("get by ID: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiUsers+"/email:ALEX@example.org", nil)
	if resp.StatusCode != 200 || body["id"] != alex.ID {
		t.Errorf("get by email: %d %v", resp.StatusCode, body)
	}

	body, resp = env.API(t, raw, http.MethodPatch, path, map[string]any{"name": "New", "username": nil})
	if resp.StatusCode != 200 || body["name"] != "New" || body["email"] != "alex@example.org" {
		t.Fatalf("patch name: %d %v", resp.StatusCode, body)
	}
	if g := groupsOf(body); len(g) != 1 || g[0] != "Laser" {
		t.Errorf("groups after patch %v", g)
	}
	body, _ = env.API(t, raw, http.MethodPatch, path, map[string]any{"username": "alex"})
	if body["username"] != "alex" {
		t.Errorf("username %v", body["username"])
	}
	body, _ = env.API(t, raw, http.MethodPatch, path, map[string]any{"username": ""})
	if body["username"] != "" {
		t.Errorf("username not cleared: %v", body["username"])
	}
	body, resp = env.API(t, raw, http.MethodPatch, path, map[string]any{"metadata": "x"})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["metadata"]; !ok {
		t.Errorf("no fields.metadata: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPatch, path, map[string]any{"metadata": map[string]any{"desk": 4}, "groups": nil})
	if resp.StatusCode != 200 || body["metadata"].(map[string]any)["desk"] != float64(4) || len(groupsOf(body)) != 1 {
		t.Errorf("metadata patch: %d %v", resp.StatusCode, body)
	}

	// Disabling signs the member out.
	now := env.Clock.Now()
	sess := &model.Session{ID: "sess-1", UserID: alex.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := env.Store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	body, resp = env.API(t, raw, http.MethodPatch, path, map[string]any{"is_active": false})
	if resp.StatusCode != 200 || body["status"] != "disabled" || body["is_active"] != false {
		t.Fatalf("disable: %d %v", resp.StatusCode, body)
	}
	if _, err := env.Store.GetSession(context.Background(), "sess-1"); err == nil {
		t.Error("session survived disabling")
	}

	_, resp = env.API(t, raw, http.MethodDelete, path, nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	body, resp = env.API(t, raw, http.MethodGet, path, nil)
	assertError(t, body, resp, 404, "not_found")
}

func TestAPIUserActions(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	alex := env.CreateUser(t, "alex@example.org", "pw")
	path := apiUsers + "/" + alex.ID

	body, resp := env.API(t, raw, http.MethodPost, path+"/reset-email", nil)
	if resp.StatusCode != 200 || body["sent"] != "reset" {
		t.Errorf("reset-email: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPost, path+"/password", map[string]any{"password": "short"})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["password"]; !ok {
		t.Errorf("no fields.password: %v", body)
	}
	_, resp = env.API(t, raw, http.MethodPost, path+"/password", map[string]any{"password": "correct horse battery"})
	if resp.StatusCode != 204 {
		t.Errorf("password: %d", resp.StatusCode)
	}
	_, resp = env.API(t, raw, http.MethodPost, path+"/totp/clear", nil)
	if resp.StatusCode != 204 {
		t.Errorf("totp/clear: %d", resp.StatusCode)
	}
	_, resp = env.API(t, raw, http.MethodPost, path+"/sessions/revoke", nil)
	if resp.StatusCode != 204 {
		t.Errorf("sessions/revoke: %d", resp.StatusCode)
	}

	invited := env.CreateUser(t, "new@example.org", "")
	body, _ = env.API(t, raw, http.MethodPost, apiUsers+"/"+invited.ID+"/reset-email", nil)
	if body["sent"] != "invite" {
		t.Errorf("no-password member: %v", body)
	}
}

func TestAPIUserGroups(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	alex := env.CreateUser(t, "alex@example.org", "pw", "Members")
	env.CreateGroup(t, "Laser", false, false)
	env.CreateGroup(t, "Woodshop", false, false)
	path := apiUsers + "/" + alex.ID + "/groups"

	body, resp := env.API(t, raw, http.MethodPut, path, map[string]any{"groups": []string{"Members", "Laser"}})
	if resp.StatusCode != 200 || strings.Join(groupsOf(body), ",") != "Laser,Members" {
		t.Errorf("put: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPost, path+"/Woodshop", nil)
	if resp.StatusCode != 200 || strings.Join(groupsOf(body), ",") != "Laser,Members,Woodshop" {
		t.Errorf("add: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodDelete, path+"/Laser", nil)
	if resp.StatusCode != 200 || strings.Join(groupsOf(body), ",") != "Members,Woodshop" {
		t.Errorf("remove: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPost, path+"/Nope", nil)
	assertError(t, body, resp, 404, "not_found")
	body, resp = env.API(t, raw, http.MethodPut, path, map[string]any{"groups": []string{"Nope"}})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["groups"]; !ok {
		t.Errorf("no fields.groups: %v", body)
	}
	body, _ = env.API(t, raw, http.MethodGet, apiUsers+"/"+alex.ID, nil)
	if strings.Join(groupsOf(body), ",") != "Members,Woodshop" {
		t.Errorf("failed PUT changed groups: %v", body)
	}
}

func TestAPIUserJSONHasNoSecrets(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	alex := env.CreateUser(t, "alex@example.org", "pw")
	env.EnrolTOTP(t, alex)

	want := strings.Fields("id email username name status is_active is_admin groups metadata totp_enrolled imported_from_authentik last_login_at created_at updated_at")
	slices.Sort(want)
	check := func(what string, body map[string]any) {
		t.Helper()
		if got := keys(body); !slices.Equal(got, want) {
			t.Errorf("%s keys %v, want %v", what, got, want)
		}
		for k := range body {
			for _, bad := range []string{"hash", "secret", "password"} {
				if strings.Contains(k, bad) {
					t.Errorf("%s has key %q", what, k)
				}
			}
		}
	}
	body, _ := env.API(t, raw, http.MethodGet, apiUsers+"/"+alex.ID, nil)
	check("get", body)
	if body["totp_enrolled"] != true {
		t.Errorf("totp_enrolled %v", body["totp_enrolled"])
	}
	list, _ := env.API(t, raw, http.MethodGet, apiUsers, nil)
	check("list item", items(t, list)[0])
}

func TestAPIUsersRejectServiceAccounts(t *testing.T) {
	env := testenv.New(t)
	raw, acct := env.APIToken(t, "door", model.APITokenScopeAdmin)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, apiUsers + "/" + acct.ID},
		{http.MethodPatch, apiUsers + "/" + acct.ID},
		{http.MethodDelete, apiUsers + "/" + acct.ID},
		{http.MethodPost, apiUsers + "/" + acct.ID + "/sessions/revoke"},
	} {
		var in any
		if c.method == http.MethodPatch {
			in = map[string]any{"name": "x"}
		}
		body, resp := env.API(t, raw, c.method, c.path, in)
		assertError(t, body, resp, 404, "not_found")
	}
}
