package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"keywell/internal/authentik"
	"keywell/internal/model"
	"keywell/internal/oidc"
	"keywell/internal/secrets"
	"keywell/internal/store"
)

// app returns the Keywell app with this slug.
func (e *env) app(slug string) *model.Application {
	e.t.Helper()
	a, err := e.st.GetApplicationBySlug(context.Background(), slug)
	if err != nil {
		e.t.Fatalf("app %s: %v", slug, err)
	}
	return a
}

// groupIDs returns the Keywell IDs of the groups with these names, sorted as
// the store returns an app's allowed groups.
func (e *env) groupIDs(names ...string) []string {
	e.t.Helper()
	ids := []string{}
	for _, n := range names {
		ids = append(ids, e.group(n).ID)
	}
	slices.Sort(ids)
	return ids
}

// appItems returns the report's app items, in order.
func appItems(rep *Report) []Item {
	var out []Item
	for _, it := range rep.Items {
		if it.Kind == "app" {
			out = append(out, it)
		}
	}
	return out
}

// providerPK returns the PK of the snapshot's provider with this name.
func providerPK(s *Snap, name string) int64 {
	for _, p := range s.Providers {
		if p.Name == name {
			return p.PK
		}
	}
	panic("no provider " + name)
}

// appUUID returns the UUID of the snapshot's application with this name.
func appUUID(s *Snap, name string) string {
	for _, a := range s.Applications {
		if a.Name == name {
			return a.UUID
		}
	}
	panic("no application " + name)
}

// noAdminLine is the Blocking line for an app called Lab that can only be
// limited to admins when Keywell has no admin group (Ruling P).
const noAdminLine = `Keywell has no admin group, so "Lab" can't be limited to admins. Give a group admin access before importing.`

const profileWarning = `Authentik sent group names to it with "profile". Keywell sends them only when an app asks ` +
	`for "groups", so add groups to its scopes if it uses them.`

func TestImportApps(t *testing.T) {
	e := newEnv(t)
	s := DevStack()
	rep := e.run(s)

	if rep.Apps != (Counts{Added: 3, Skipped: 3}) {
		t.Errorf("Apps = %+v", rep.Apps)
	}
	want := []Item{
		{Kind: "app", Name: "Wiki", Reason: `Return address https://.*\.example\.org/cb is a pattern. Add the real addresses on the app's page.`},
		{Kind: "app", Name: "Wiki", Reason: "Its icon is stored in Authentik. Upload it on the app's page."},
		{Kind: "app", Name: "Wiki", Reason: `Authentik sent extra details through "Wiki extra claims", which Keywell doesn't send.`},
		{Kind: "app", Name: "Wiki", Reason: profileWarning},
		{Kind: "app", Name: "Door Booking", Reason: "Its short name changed from Door_Booking to door-booking."},
		{Kind: "app", Name: "Door Booking", Reason: "Authentik kept sign-ins for 140d; Keywell's limit is 90d, so it uses that."},
		{Kind: "app", Name: "Door Booking", Reason: profileWarning},
		{Kind: "app", Name: "Tool Booking", Reason: "Authentik's access tokens lasted 36h; Keywell's limit is 1d, so it uses that."},
		{Kind: "app", Name: "Tool Booking", Reason: profileWarning},
		{Kind: "app", Name: "Tool Booking", Reason: "Authentik limited who could use it with a policy. " +
			"Only admins can use it until you choose its groups on the app's page."},
		{Kind: "app", Name: "Tool Booking", Reason: "Authentik let it sign in by itself. " +
			"To allow that in Keywell, choose a service account on the app's page."},
		{Kind: "app", Name: "Grafana", Skipped: true,
			Reason: "Signs in with something other than OpenID Connect, which is all Keywell supports."},
		{Kind: "app", Name: "Printer", Skipped: true, Reason: "Has nothing to sign in with in Authentik."},
		{Kind: "app", Name: "orphan", Skipped: true, Reason: "Isn't used by any application in Authentik."},
	}
	if got := appItems(rep); !reflect.DeepEqual(got, want) {
		t.Errorf("app items:\n got %s\nwant %s", itemLines(got), itemLines(want))
	}

	wiki := e.app("wiki")
	if wiki.Name != "Wiki" || wiki.ClientType != model.ClientTypeConfidential || wiki.ClientID != "wiki-client-id" ||
		wiki.ClientSecretHash != secrets.HashToken("wiki-client-secret-0123456789") ||
		wiki.SubjectMode != model.SubjectModeAuthentikUID {
		t.Errorf("wiki = %+v", wiki)
	}
	if !slices.Equal(wiki.RedirectURIs, []string{"https://wiki.example.org/index.php/Special:PluggableAuthLogin"}) ||
		!slices.Equal(wiki.PostLogoutRedirectURIs, []string{"https://wiki.example.org/"}) {
		t.Errorf("wiki addresses %q, after signing out %q", wiki.RedirectURIs, wiki.PostLogoutRedirectURIs)
	}
	if wiki.AccessTokenTTL != 2*time.Hour || wiki.IDTokenTTL != 2*time.Hour || wiki.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("wiki lifetimes %v, %v, %v", wiki.AccessTokenTTL, wiki.IDTokenTTL, wiki.RefreshTokenTTL)
	}
	if wiki.LaunchURL != "https://wiki.example.org/" || !wiki.ShowTile || wiki.IconURL != "" ||
		wiki.Description != "The makerspace wiki" {
		t.Errorf("wiki launch %q, tile %v, icon %q, description %q", wiki.LaunchURL, wiki.ShowTile, wiki.IconURL,
			wiki.Description)
	}
	if !slices.Equal(wiki.AllowedGroupIDs, e.groupIDs("Members")) {
		t.Errorf("wiki allowed groups %v, want Members", wiki.AllowedGroupIDs)
	}
	if wiki.AuthentikProviderPK == nil || *wiki.AuthentikProviderPK != providerPK(s, "wiki") || wiki.ServiceAccountID != "" {
		t.Errorf("wiki provider %v, service account %q", wiki.AuthentikProviderPK, wiki.ServiceAccountID)
	}

	door := e.app("door-booking")
	if door.Name != "Door Booking" || door.ClientType != model.ClientTypePublic || door.ClientID != "door-app-client-id" ||
		door.ClientSecretHash != "" || door.SubjectMode != model.SubjectModeEmail {
		t.Errorf("door = %+v", door)
	}
	if door.AccessTokenTTL != 5*time.Minute || door.IDTokenTTL != 5*time.Minute ||
		door.RefreshTokenTTL != e.d.Cfg.Tokens.RefreshAbsolute {
		t.Errorf("door lifetimes %v, %v, %v", door.AccessTokenTTL, door.IDTokenTTL, door.RefreshTokenTTL)
	}
	if door.IconURL != "https://door.example.org/icon.png" || door.LaunchURL != "https://door.example.org/" ||
		!door.ShowTile || len(door.AllowedGroupIDs) != 0 {
		t.Errorf("door icon %q, launch %q, tile %v, allowed groups %v", door.IconURL, door.LaunchURL, door.ShowTile,
			door.AllowedGroupIDs)
	}

	tools := e.app("tools")
	if tools.SubjectMode != model.SubjectModeAuthentikUUID || tools.AccessTokenTTL != 24*time.Hour ||
		tools.IDTokenTTL != 24*time.Hour || tools.RefreshTokenTTL != 720*time.Hour ||
		tools.ClientSecretHash != secrets.HashToken("tools-client-secret-0123456789") || tools.ServiceAccountID != "" {
		t.Errorf("tools = %+v", tools)
	}
	if !slices.Equal(tools.AllowedGroupIDs, e.groupIDs("Trustees", "authentik Admins")) {
		t.Errorf("tools allowed groups %v, want the admin groups", tools.AllowedGroupIDs)
	}

	if n := e.rows()["applications"]; n != 3 {
		t.Errorf("%d apps, want 3", n)
	}

	// The report follows the copy rule and holds no secrets.
	for _, it := range rep.Items {
		for _, word := range []string{"provider", "flow", "stage", "binding"} {
			if strings.Contains(strings.ToLower(it.Reason), word) {
				t.Errorf("item says %q: %s", word, it.Reason)
			}
		}
	}
	if b, err := json.Marshal(rep); err != nil || strings.Contains(string(b), "client-secret") {
		t.Errorf("report holds a client secret: %s, %v", b, err)
	}
}

func itemLines(items []Item) string {
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "\n  %+v", it)
	}
	return b.String()
}

// Review Focus 3: access rules Keywell can't express never open an app wider
// than Authentik did (Ruling 6).
func TestImportAppAccess(t *testing.T) {
	const tail = " Only admins can use it until you choose its groups on the app's page."
	type world struct {
		s    *Snap
		app  string
		a, b string // group UUIDs
		ann  int64
	}
	everyone := []string{"ann", "bob", "cat", "dan", "tess"}
	cases := []struct {
		name     string
		mode     string // the engine mode; "" is "any"
		noAdmins bool   // Trustees is not an admin group, and there is no other
		bind     func(w *world)
		allowed  []string // names of the allowed Keywell groups; none is open to every active member
		warning  string
		blocked  bool // the import is blocked (Ruling P)
		// Who could use the app in Authentik; nil when a policy decides.
		authentik []string
	}{{
		name:      "none",
		bind:      func(w *world) {},
		authentik: everyone,
	}, {
		name: "only disabled ones",
		bind: func(w *world) {
			w.s.Bind(w.app, w.a, Disabled())
			w.s.BindUser(w.app, w.ann, Disabled())
			w.s.BindPolicy(w.app, WeekdaysPolicy, Disabled(), Negated())
		},
		authentik: everyone,
	}, {
		name:      "one group",
		bind:      func(w *world) { w.s.Bind(w.app, w.a) },
		allowed:   []string{"A"},
		authentik: []string{"ann", "cat"},
	}, {
		name:      "one group, mode all",
		mode:      "all",
		bind:      func(w *world) { w.s.Bind(w.app, w.a) },
		allowed:   []string{"A"},
		authentik: []string{"ann", "cat"},
	}, {
		name:      "two groups, mode any",
		bind:      func(w *world) { w.s.Bind(w.app, w.a); w.s.Bind(w.app, w.b) },
		allowed:   []string{"A", "B"},
		authentik: []string{"ann", "bob", "cat"},
	}, {
		name:      "one group and a disabled policy",
		bind:      func(w *world) { w.s.Bind(w.app, w.a); w.s.BindPolicy(w.app, WeekdaysPolicy, Disabled()) },
		allowed:   []string{"A"},
		authentik: []string{"ann", "cat"},
	}, {
		name:      "two groups, mode all",
		mode:      "all",
		bind:      func(w *world) { w.s.Bind(w.app, w.a); w.s.Bind(w.app, w.b) },
		allowed:   []string{"Trustees"},
		warning:   "Authentik limited who could use it with several groups that all had to match." + tail,
		authentik: []string{"cat"},
	}, {
		name:      "negated group",
		bind:      func(w *world) { w.s.Bind(w.app, w.a, Negated()) },
		allowed:   []string{"Trustees"},
		warning:   "Authentik limited who could use it with a rule that left people out." + tail,
		authentik: []string{"bob", "dan", "tess"},
	}, {
		name:      "user binding",
		bind:      func(w *world) { w.s.BindUser(w.app, w.ann) },
		allowed:   []string{"Trustees"},
		warning:   "Authentik limited who could use it with a named person." + tail,
		authentik: []string{"ann"},
	}, {
		name:    "policy",
		bind:    func(w *world) { w.s.BindPolicy(w.app, WeekdaysPolicy) },
		allowed: []string{"Trustees"},
		warning: "Authentik limited who could use it with a policy." + tail,
	}, {
		name: "policy, named person and negated group",
		bind: func(w *world) {
			w.s.Bind(w.app, w.a, Negated())
			w.s.BindUser(w.app, w.ann)
			w.s.BindPolicy(w.app, WeekdaysPolicy)
		},
		allowed: []string{"Trustees"},
		warning: "Authentik limited who could use it with a policy." + tail,
	}, {
		name:      "named person and negated group",
		bind:      func(w *world) { w.s.Bind(w.app, w.a, Negated()); w.s.BindUser(w.app, w.ann) },
		allowed:   []string{"Trustees"},
		warning:   "Authentik limited who could use it with a named person." + tail,
		authentik: []string{"ann", "bob", "dan", "tess"},
	}, {
		name:      "negated group and two groups, mode all",
		mode:      "all",
		bind:      func(w *world) { w.s.Bind(w.app, w.a); w.s.Bind(w.app, w.b, Negated()) },
		allowed:   []string{"Trustees"},
		warning:   "Authentik limited who could use it with a rule that left people out." + tail,
		authentik: []string{"ann"},
	}, {
		name:    "a group Keywell doesn't have",
		bind:    func(w *world) { w.s.Bind(w.app, w.a); w.s.Bind(w.app, "10000000-0000-4000-8000-999999999999") },
		allowed: []string{"Trustees"},
		warning: "Authentik limited who could use it with a group Keywell doesn't have." + tail,
	}, {
		name:     "no admin group for a policy",
		noAdmins: true,
		bind:     func(w *world) { w.s.BindPolicy(w.app, WeekdaysPolicy) },
		blocked:  true,
	}, {
		name:      "no admin group for one group",
		noAdmins:  true,
		bind:      func(w *world) { w.s.Bind(w.app, w.a) },
		allowed:   []string{"A"},
		authentik: []string{"ann", "cat"},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewSnap()
			a, b := s.Group("A"), s.Group("B")
			var trustees string
			if tc.noAdmins {
				trustees = s.Group("Trustees")
			} else {
				trustees = s.Group("Trustees", Superuser())
			}
			ann := s.User("ann", "ann@x.org")
			s.Join(ann, a)
			s.Join(s.User("bob", "bob@x.org"), b)
			s.Join(s.User("cat", "cat@x.org"), a, b)
			s.User("dan", "dan@x.org")
			s.Join(s.User("tess", "tess@x.org"), trustees)
			app := s.App("Lab", "lab")
			if tc.mode != "" {
				s.A(app).EngineMode = tc.mode
			}
			s.Use(app, s.Provider(labProvider()))
			tc.bind(&world{s: s, app: app, a: a, b: b, ann: ann})

			e := newEnv(t)
			if tc.blocked {
				rep, err := e.try(s)
				if !errors.Is(err, ErrBlocked) || !slices.Equal(blockingOf(rep), []string{noAdminLine}) {
					t.Errorf("Run = %v, blocking %q; want ErrBlocked with %q", err, blockingOf(rep), noAdminLine)
				}
				if _, err := e.st.GetApplicationBySlug(ctx, "lab"); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("blocked app is in Keywell: %v", err)
				}
				return
			}
			rep := e.run(s)
			var want []Item
			if tc.warning != "" {
				want = []Item{{Kind: "app", Name: "Lab", Reason: tc.warning}}
			}
			if got := appItems(rep); !reflect.DeepEqual(got, want) {
				t.Errorf("app items:\n got %s\nwant %s", itemLines(got), itemLines(want))
			}
			lab := e.app("lab")
			if got, want := lab.AllowedGroupIDs, e.groupIDs(tc.allowed...); !slices.Equal(got, want) {
				t.Errorf("allowed groups %v, want %v (%v)", got, want, tc.allowed)
			}

			// Nobody can use it in Keywell who couldn't in Authentik, admins
			// excepted, as Ruling 6 allows.
			for _, name := range everyone {
				u := e.user(name + "@x.org")
				groups, err := e.st.ListGroupsForUser(ctx, u.ID)
				if err != nil {
					t.Fatal(err)
				}
				admin := slices.ContainsFunc(groups, func(g model.Group) bool { return g.IsAdmin })
				if oidc.UserAllowed(u, groups, lab) && !admin && !slices.Contains(tc.authentik, name) {
					t.Errorf("%s can use it in Keywell but not in Authentik", name)
				}
			}
		})
	}
}

// The mapping rules the brief gives without a fixture row.
func TestImportAppMapping(t *testing.T) {
	type src struct {
		a *authentik.Application
		p *authentik.OAuth2Provider
	}
	cases := []struct {
		name    string
		edit    func(s src)
		skipped bool
		items   []string // the app's warnings, or why it was skipped
		check   func(t *testing.T, app *model.Application)
	}{{
		name: "user_id",
		edit: func(s src) { s.p.SubMode = "user_id" },
		check: func(t *testing.T, app *model.Application) {
			if app.SubjectMode != model.SubjectModeAuthentikPK {
				t.Errorf("subject mode %s", app.SubjectMode)
			}
		},
	}, {
		name: "user_username",
		edit: func(s src) { s.p.SubMode = "user_username" },
		check: func(t *testing.T, app *model.Application) {
			if app.SubjectMode != model.SubjectModeUsername {
				t.Errorf("subject mode %s", app.SubjectMode)
			}
		},
	}, {
		name:  "user_upn",
		edit:  func(s src) { s.p.SubMode = "user_upn" },
		items: []string{"Identified people by UPN in Authentik. Keywell uses their email address instead."},
		check: func(t *testing.T, app *model.Application) {
			if app.SubjectMode != model.SubjectModeEmail {
				t.Errorf("subject mode %s", app.SubjectMode)
			}
		},
	}, {
		name:    "a subject mode Keywell doesn't know",
		edit:    func(s src) { s.p.SubMode = "user_shoe_size" },
		skipped: true,
		items:   []string{"Identifies people in a way Keywell doesn't support."},
	}, {
		name: "lifetimes Keywell can't read",
		edit: func(s src) { s.p.AccessTokenValidity, s.p.RefreshTokenValidity = "soon", "" },
		items: []string{
			"Keywell couldn't read how long Authentik's access tokens lasted, so it uses the default.",
			"Keywell couldn't read how long Authentik kept sign-ins, so it uses the default.",
		},
		check: func(t *testing.T, app *model.Application) {
			if app.AccessTokenTTL != 0 || app.IDTokenTTL != 0 || app.RefreshTokenTTL != 0 {
				t.Errorf("lifetimes %v, %v, %v; want the defaults", app.AccessTokenTTL, app.IDTokenTTL, app.RefreshTokenTTL)
			}
		},
	}, {
		name: "lifetimes under a minute",
		edit: func(s src) { s.p.AccessTokenValidity, s.p.RefreshTokenValidity = "seconds=30", "seconds=0" },
		items: []string{
			"Authentik's access tokens lasted 30s; Keywell's minimum is 1m, so it uses that.",
			"Authentik kept sign-ins for 0s; Keywell's minimum is 1m, so it uses that.",
		},
		check: func(t *testing.T, app *model.Application) {
			if app.AccessTokenTTL != time.Minute || app.IDTokenTTL != time.Minute || app.RefreshTokenTTL != time.Minute {
				t.Errorf("lifetimes %v, %v, %v", app.AccessTokenTTL, app.IDTokenTTL, app.RefreshTokenTTL)
			}
		},
	}, {
		name: "blank://blank launch link",
		edit: func(s src) { s.a.LaunchURL = "blank://blank" },
		check: func(t *testing.T, app *model.Application) {
			if app.LaunchURL != "" || app.ShowTile {
				t.Errorf("launch %q, tile %v", app.LaunchURL, app.ShowTile)
			}
		},
	}, {
		name:  "a launch link that isn't a web address",
		edit:  func(s src) { s.a.LaunchURL = "/start" },
		items: []string{"Its link to open the app isn't a web address Keywell can use, so it was left off."},
		check: func(t *testing.T, app *model.Application) {
			if app.LaunchURL != "" || app.ShowTile {
				t.Errorf("launch %q, tile %v", app.LaunchURL, app.ShowTile)
			}
		},
	}, {
		// The report never quotes a user name and password.
		name:  "a launch link with a password",
		edit:  func(s src) { s.a.LaunchURL = "https://bot:hunter2@lab.example.org/" },
		items: []string{"Its link to open the app isn't a web address Keywell can use, so it was left off."},
		check: func(t *testing.T, app *model.Application) {
			if app.LaunchURL != "" || app.ShowTile {
				t.Errorf("launch %q, tile %v", app.LaunchURL, app.ShowTile)
			}
		},
	}, {
		name: "a pattern with a password",
		edit: func(s src) {
			s.p.RedirectURIs = append(s.p.RedirectURIs,
				authentik.RedirectURI{URL: `https://bot:hunter2@lab\.example\.org/.*`, MatchingMode: "regex",
					Type: "authorization"})
		},
		items: []string{`Return address https://lab\.example\.org/.* is a pattern. Add the real addresses on the app's page.`},
	}, {
		name: "hidden",
		edit: func(s src) { s.a.LaunchURL, s.a.Hide = "https://lab.example.org/", true },
		check: func(t *testing.T, app *model.Application) {
			if app.LaunchURL != "https://lab.example.org/" || app.ShowTile {
				t.Errorf("launch %q, tile %v", app.LaunchURL, app.ShowTile)
			}
		},
	}, {
		name: "a sign-out pattern",
		edit: func(s src) {
			s.p.RedirectURIs = append(s.p.RedirectURIs,
				authentik.RedirectURI{URL: `https://lab\.example\.org/.*`, MatchingMode: "regex", Type: "logout"})
		},
		items: []string{`Sign-out return address https://lab\.example\.org/.* is a pattern. Add the real addresses on the app's page.`},
		check: func(t *testing.T, app *model.Application) {
			if len(app.PostLogoutRedirectURIs) != 0 || !slices.Equal(app.RedirectURIs, []string{"https://lab.example.org/cb"}) {
				t.Errorf("addresses %q, after signing out %q", app.RedirectURIs, app.PostLogoutRedirectURIs)
			}
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSnap()
			app := s.App("Lab", "lab")
			pk := s.Provider(labProvider())
			s.Use(app, pk)
			tc.edit(src{a: s.A(app), p: s.P(pk)})
			e := newEnv(t)
			rep := e.run(s)

			var want []Item
			for _, reason := range tc.items {
				want = append(want, Item{Kind: "app", Name: "Lab", Skipped: tc.skipped, Reason: reason})
			}
			if got := appItems(rep); !reflect.DeepEqual(got, want) {
				t.Errorf("app items:\n got %s\nwant %s", itemLines(got), itemLines(want))
			}
			saved, err := e.st.LastImportRun(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(saved.Report, "hunter2") {
				t.Errorf("the saved report quotes a password:\n%s", saved.Report)
			}
			if tc.skipped {
				if n := e.rows()["applications"]; n != 0 {
					t.Errorf("%d apps, want none", n)
				}
				return
			}
			if tc.check != nil {
				tc.check(t, e.app("lab"))
			}
		})
	}
}

// An app whose client ID another Keywell app has is skipped, and the import
// carries on; a Keywell app whose Authentik app is gone is left as it is.
func TestImportAppConflicts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := NewSnap()
	groupA := s.Group("A")
	s.Join(s.User("ann", "ann@x.org"), groupA)
	lab := s.App("Lab", "lab")
	labPK := s.Provider(labProvider())
	s.Use(lab, labPK)
	other := labProvider()
	other.Name, other.ClientID = "one", "one-client-id"
	one := s.App("One", "one")
	onePK := s.Provider(other)
	s.Use(one, onePK)

	// Keywell's app for One still has the client ID Lab now uses.
	was := &model.Application{Name: "One", Slug: "one", ClientID: "lab-client-id", AuthentikProviderPK: &onePK}
	gonePK := int64(99)
	gone := &model.Application{Name: "Old Wiki", Slug: "old-wiki", ClientID: "old-wiki", AuthentikProviderPK: &gonePK}
	for _, a := range []*model.Application{was, gone} {
		if err := e.st.CreateApplication(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	goneBefore := e.app("old-wiki")

	rep := e.run(s)
	want := []Item{
		{Kind: "app", Name: "Lab", Skipped: true, Reason: "Another app in Keywell already uses its client ID."},
		{Kind: "app", Name: "Old Wiki", Reason: "Is no longer in Authentik. Keywell has left it as it is."},
	}
	if got := appItems(rep); !reflect.DeepEqual(got, want) {
		t.Errorf("app items:\n got %s\nwant %s", itemLines(got), itemLines(want))
	}
	if rep.Apps != (Counts{Updated: 1, Skipped: 1}) {
		t.Errorf("Apps = %+v", rep.Apps)
	}
	if a := e.app("one"); a.ID != was.ID || a.ClientID != "one-client-id" {
		t.Errorf("one = %+v", a)
	}
	if a := e.app("old-wiki"); !reflect.DeepEqual(a, goneBefore) {
		t.Errorf("old wiki changed:\n%+v\n%+v", goneBefore, a)
	}

	// With One's client ID changed, the next run adds Lab.
	rep = e.run(s)
	if rep.Apps != (Counts{Added: 1, Updated: 1}) {
		t.Errorf("second run: Apps = %+v", rep.Apps)
	}
	labBefore := e.app("lab")
	if labBefore.ClientID != "lab-client-id" || labBefore.AuthentikProviderPK == nil || *labBefore.AuthentikProviderPK != labPK {
		t.Errorf("lab = %+v", labBefore)
	}

	// Lab, imported open, now takes a hand-made app's client ID and is
	// limited to group A in Authentik. It is skipped, but who can use it
	// follows Authentik (Ruling N).
	spare := &model.Application{Name: "Spare", Slug: "spare", ClientID: "spare-client-id"}
	if err := e.st.CreateApplication(ctx, spare); err != nil {
		t.Fatal(err)
	}
	s.P(labPK).ClientID = "spare-client-id"
	s.Bind(lab, groupA)
	rep = e.run(s)
	want = []Item{{Kind: "app", Name: "Lab", Skipped: true,
		Reason: "Another app in Keywell already uses its client ID. Who can use it still follows Authentik."}}
	var got []Item
	for _, it := range appItems(rep) {
		if it.Name == "Lab" {
			got = append(got, it)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("third run Lab items:\n got %s\nwant %s", itemLines(got), itemLines(want))
	}
	a := e.app("lab")
	if !slices.Equal(a.AllowedGroupIDs, e.groupIDs("A")) {
		t.Errorf("skipped lab allows %v, want only A", a.AllowedGroupIDs)
	}
	a.AllowedGroupIDs, a.UpdatedAt = labBefore.AllowedGroupIDs, labBefore.UpdatedAt
	if !reflect.DeepEqual(a, labBefore) {
		t.Errorf("skipped lab changed beyond its groups:\n%+v\n%+v", labBefore, a)
	}
}

// Ruling P: every skip of an app an earlier import made still sets who can
// use it from Authentik, here a skip for an unknown subject mode, and the
// reason says when that is admins only.
func TestImportSkipFollowsAccess(t *testing.T) {
	cases := []struct {
		name    string
		bind    func(s *Snap, lab, a string)
		allowed []string
		reason  string
	}{{
		name:    "a group",
		bind:    func(s *Snap, lab, a string) { s.Bind(lab, a) },
		allowed: []string{"A"},
		reason:  "Identifies people in a way Keywell doesn't support. Who can use it still follows Authentik.",
	}, {
		name:    "admins only",
		bind:    func(s *Snap, lab, a string) { s.BindPolicy(lab, WeekdaysPolicy) },
		allowed: []string{"Trustees"},
		reason: "Identifies people in a way Keywell doesn't support. " +
			"Only admins can use it until you choose its groups on the app's page.",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSnap()
			a := s.Group("A")
			s.Join(s.User("ann", "ann@x.org"), a)
			s.Join(s.User("tess", "tess@x.org"), s.Group("Trustees", Superuser()))
			lab := s.App("Lab", "lab")
			pk := s.Provider(labProvider())
			s.Use(lab, pk)
			e := newEnv(t)
			e.run(s)
			before := e.app("lab")
			if len(before.AllowedGroupIDs) != 0 {
				t.Fatalf("first run: lab allows %v, want everyone", before.AllowedGroupIDs)
			}

			// Authentik limits Lab, and identifies people in a way Keywell
			// doesn't know.
			tc.bind(s, lab, a)
			s.P(pk).SubMode = "user_shoe_size"
			rep := e.run(s)
			want := []Item{{Kind: "app", Name: "Lab", Skipped: true, Reason: tc.reason}}
			if got := appItems(rep); !reflect.DeepEqual(got, want) {
				t.Errorf("app items:\n got %s\nwant %s", itemLines(got), itemLines(want))
			}
			after := e.app("lab")
			if !slices.Equal(after.AllowedGroupIDs, e.groupIDs(tc.allowed...)) {
				t.Errorf("skipped lab allows %v, want %v", after.AllowedGroupIDs, tc.allowed)
			}
			after.AllowedGroupIDs, after.UpdatedAt = before.AllowedGroupIDs, before.UpdatedAt
			if !reflect.DeepEqual(after, before) {
				t.Errorf("skipped lab changed beyond its groups:\n%+v\n%+v", before, after)
			}
		})
	}
}

// Ruling P: an app that can only be limited to admins blocks the import
// when Keywell has no admin group, because no groups means open to all.
func TestImportBlocksAppWithoutAdminGroup(t *testing.T) {
	s := NewSnap()
	s.Join(s.User("ann", "ann@x.org"), s.Group("A"))
	lab := s.App("Lab", "lab")
	s.Use(lab, s.Provider(labProvider()))
	e := newEnv(t)
	e.run(s) // Lab is open to everyone, and Keywell has no admin group
	s.BindPolicy(lab, WeekdaysPolicy)

	for _, dry := range []bool{true, false} {
		before := e.dump()
		rep, err := e.try(s, func(o *Options) { o.DryRun = dry })
		if !errors.Is(err, ErrBlocked) || !slices.Equal(blockingOf(rep), []string{noAdminLine}) {
			t.Errorf("dry=%v: Run = %v, blocking %q; want ErrBlocked with %q", dry, err, blockingOf(rep), noAdminLine)
		}
		if after := e.dump(); after != before {
			t.Errorf("dry=%v: database changed:\n%s\n---\n%s", dry, before, after)
		}
	}
}

// labProvider is an OAuth2 provider that imports with no warnings.
func labProvider() authentik.OAuth2Provider {
	return authentik.OAuth2Provider{Name: "lab", ClientType: "confidential", ClientID: "lab-client-id",
		ClientSecret: "lab-client-secret", SubMode: "hashed_user_id", AccessTokenValidity: "hours=1",
		RefreshTokenValidity: "days=30", GrantTypes: []string{"authorization_code"},
		RedirectURIs: []authentik.RedirectURI{{URL: "https://lab.example.org/cb", MatchingMode: "strict",
			Type: "authorization"}}}
}

func TestImportAppsUpdate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	// An app made in Keywell by hand, with Door Booking's client ID.
	door := &model.Application{Name: "Door", Slug: "door", ClientID: "door-app-client-id",
		ClientType: model.ClientTypePublic}
	if err := e.st.CreateApplication(ctx, door); err != nil {
		t.Fatal(err)
	}

	s := DevStack()
	rep := e.run(s)
	if rep.Apps != (Counts{Added: 2, Updated: 1, Skipped: 3}) {
		t.Errorf("first run: Apps = %+v", rep.Apps)
	}
	if d := e.app("door-booking"); d.ID != door.ID || d.Name != "Door Booking" || d.AuthentikProviderPK == nil ||
		*d.AuthentikProviderPK != providerPK(s, "door-app") {
		t.Errorf("door = %+v, want the Keywell app %s linked to provider %d", d, door.ID, providerPK(s, "door-app"))
	}

	// Choices made in Keywell: a service account for Tool Booking and an
	// uploaded icon for Wiki, whose icon Authentik keeps to itself.
	sa := &model.User{Name: "Tools bot", Type: model.UserTypeService, Username: "tools-bot", IsActive: true}
	if err := e.st.CreateUser(ctx, sa); err != nil {
		t.Fatal(err)
	}
	tools := e.app("tools")
	tools.ServiceAccountID = sa.ID
	if err := e.st.UpdateApplication(ctx, tools); err != nil {
		t.Fatal(err)
	}
	wiki := e.app("wiki")
	wiki.IconURL = "/icons/x.png"
	if err := e.st.UpdateApplication(ctx, wiki); err != nil {
		t.Fatal(err)
	}
	before := map[string]*model.Application{}
	for _, slug := range []string{"wiki", "door-booking", "tools"} {
		before[slug] = e.app(slug)
	}
	rows := e.rows()

	rep = e.run(s)
	if rep.Apps != (Counts{Updated: 3, Skipped: 3}) {
		t.Errorf("second run: Apps = %+v", rep.Apps)
	}
	if got := e.rows(); !reflect.DeepEqual(got, rows) {
		t.Errorf("rows changed: %v -> %v", rows, got)
	}
	for slug, was := range before {
		if now := e.app(slug); !reflect.DeepEqual(now, was) {
			t.Errorf("%s changed:\n%+v\n%+v", slug, was, now)
		}
	}
	for _, reason := range append(itemsFor(rep, "Wiki"), itemsFor(rep, "Tool Booking")...) {
		if strings.Contains(reason, "icon") || strings.Contains(reason, "service account") {
			t.Errorf("warning for something Keywell already has: %s", reason)
		}
	}

	// An app that breaks the app pages' rules is skipped and left as it was,
	// except that who can use it follows Authentik (Ruling N): here
	// Authentik narrows Wiki from Members to Laser.
	p := s.P(providerPK(s, "wiki"))
	for i := range 20 {
		p.RedirectURIs = append(p.RedirectURIs, authentik.RedirectURI{URL: fmt.Sprintf("https://wiki.example.org/cb%d", i),
			MatchingMode: "strict", Type: "authorization"})
	}
	wikiUUID := appUUID(s, "Wiki")
	s.A(wikiUUID).Description = strings.Repeat("d", 501)
	for i := range s.Bindings {
		if s.Bindings[i].TargetUUID == wikiUUID {
			s.Bindings[i].GroupUUID = e.group("Laser").AuthentikUUID
		}
	}
	wantWiki := []Item{{Kind: "app", Name: "Wiki", Skipped: true,
		Reason: "Use at most 500 characters. Add at most 20 addresses. Who can use it still follows Authentik."}}
	wikiItems := func(rep *Report) []Item {
		var out []Item
		for _, it := range appItems(rep) {
			if it.Name == "Wiki" {
				out = append(out, it)
			}
		}
		return out
	}

	rep = e.run(s)
	if got := wikiItems(rep); !reflect.DeepEqual(got, wantWiki) {
		t.Errorf("Wiki items:\n got %s\nwant %s", itemLines(got), itemLines(wantWiki))
	}
	if rep.Apps != (Counts{Updated: 2, Skipped: 4}) {
		t.Errorf("third run: Apps = %+v", rep.Apps)
	}
	narrowed := e.app("wiki")
	if !slices.Equal(narrowed.AllowedGroupIDs, e.groupIDs("Laser")) {
		t.Errorf("skipped wiki allows %v, want only Laser", narrowed.AllowedGroupIDs)
	}
	sameApart := *narrowed
	sameApart.AllowedGroupIDs, sameApart.UpdatedAt = before["wiki"].AllowedGroupIDs, before["wiki"].UpdatedAt
	if !reflect.DeepEqual(&sameApart, before["wiki"]) {
		t.Errorf("skipped wiki changed beyond its groups:\n%+v\n%+v", before["wiki"], narrowed)
	}

	// When the groups already match, nothing is written, and the reason
	// still says so.
	rep = e.run(s)
	if got := wikiItems(rep); !reflect.DeepEqual(got, wantWiki) {
		t.Errorf("fourth run Wiki items:\n got %s\nwant %s", itemLines(got), itemLines(wantWiki))
	}
	if now := e.app("wiki"); !reflect.DeepEqual(now, narrowed) {
		t.Errorf("fourth run wrote wiki:\n%+v\n%+v", narrowed, now)
	}
}
