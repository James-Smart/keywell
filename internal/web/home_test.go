package web_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"latch/internal/model"
	"latch/internal/testenv"
)

// tileApp creates an app shown as a tile on the home page, open to members
// of groups (to everyone when there are none).
func tileApp(t *testing.T, env *testenv.Env, name, launchURL, iconURL string, groups ...*model.Group) *model.Application {
	t.Helper()
	ids := []string{}
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	return env.CreateApp(t, model.Application{
		Name:            name,
		Slug:            slug,
		ClientID:        slug,
		LaunchURL:       launchURL,
		IconURL:         iconURL,
		Description:     "All about " + name,
		ShowTile:        true,
		AllowedGroupIDs: ids,
	}, "")
}

// renameUser sets u's display name.
func renameUser(t *testing.T, env *testenv.Env, u *model.User, name string) {
	t.Helper()
	u.Name = name
	if err := env.Store.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func TestHomeShowsTilesForUserGroups(t *testing.T) {
	env := testenv.New(t)
	members := env.CreateGroup(t, "Members", false, false)
	staff := env.CreateGroup(t, "Staff", false, false)
	alex := env.CreateUser(t, "alex@example.org", testPW, "Members")
	renameUser(t, env, alex, "Alex Smith")
	tileApp(t, env, "wiki", "https://wiki.example.org", "")
	tileApp(t, env, "Tool Booking", "https://tools.example.org/book", "https://tools.example.org/icon.png", members)
	tileApp(t, env, "Accounts", "https://accounts.example.org", "", staff)

	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	resp, body := get(t, c, env.TS.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		"Hi Alex",
		// Open to everyone: no icon, so the upper-cased first letter.
		"wiki", `href="https://wiki.example.org"`, ">W</span>", "All about wiki",
		// Open to Members, with an icon.
		"Tool Booking", `href="https://tools.example.org/book"`, `src="https://tools.example.org/icon.png"`, "All about Tool Booking",
		"Change password", `href="/account/password"`,
		"Two-step sign in", `href="/account/totp"`,
		`action="/logout"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"Accounts", "accounts.example.org", // Staff only
		"Hi Alex Smith", // first word only
		"No apps yet",
		"target=", // apps open in the same tab
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("body has %q", unwanted)
		}
	}
}

func TestHomeEmptyState(t *testing.T) {
	env := testenv.New(t)
	staff := env.CreateGroup(t, "Staff", false, false)
	sam := env.CreateUser(t, "sam@example.org", testPW)
	renameUser(t, env, sam, "")
	tileApp(t, env, "Accounts", "https://accounts.example.org", "", staff)
	env.CreateApp(t, model.Application{Name: "Hidden", Slug: "hidden", ClientID: "hidden",
		LaunchURL: "https://hidden.example.org", ShowTile: false}, "")

	c := env.Client(t)
	env.Login(t, c, "sam@example.org", testPW)
	resp, body := get(t, c, env.TS.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		"Hi sam", // no name: the email address before the @
		"No apps yet. Ask an admin to give you access.",
		`href="/account/password"`,
		`action="/logout"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, unwanted := range []string{"Accounts", "Hidden", `class="tiles"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("body has %q", unwanted)
		}
	}
}

func TestHomeRequiresLogin(t *testing.T) {
	env := testenv.New(t)
	resp, _ := get(t, env.Client(t), env.TS.URL+"/")
	assertRedirect(t, resp, "/login?next=%2F")
}

// logBuffer collects log output written from server goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHomeSkipsTilesWithoutHTTPLaunchURL(t *testing.T) {
	var logs logBuffer
	env := testenv.New(t, testenv.WithLog(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	env.CreateUser(t, "alex@example.org", testPW)
	tileApp(t, env, "Safe", "https://safe.example.org", "")
	script := tileApp(t, env, "Sneaky", "javascript:alert(1)", "")
	shouty := tileApp(t, env, "Shouty", "JavaScript:alert(2)", "")
	noScheme := tileApp(t, env, "Relative", "//elsewhere.example.org/app", "")

	c := env.Client(t)
	env.Login(t, c, "alex@example.org", testPW)
	for range 2 {
		resp, body := get(t, c, env.TS.URL+"/")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if !strings.Contains(body, `href="https://safe.example.org"`) {
			t.Error("body missing the Safe tile")
		}
		for _, unwanted := range []string{"Sneaky", "Shouty", "Relative", "alert(", "elsewhere.example.org", "ZgotmplZ"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("body has %q", unwanted)
			}
		}
	}
	// Each skipped tile is logged once, however often the page is shown.
	got := logs.String()
	for _, app := range []*model.Application{script, shouty, noScheme} {
		if n := strings.Count(got, app.ID); n != 1 {
			t.Errorf("app %s logged %d times, want 1; log:\n%s", app.Name, n, got)
		}
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("no warning logged:\n%s", got)
	}
}
