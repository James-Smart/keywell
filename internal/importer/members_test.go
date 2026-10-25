package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"latch/internal/authentik"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
	"latch/internal/store/storetest"
)

// testNow is the time test runs report until a test moves env.now.
var testNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const testSource = "db.internal:5432/authentik"

// env is a migrated database and the Deps of an import into it.
type env struct {
	t   *testing.T
	st  *store.Store
	db  *sql.DB
	d   Deps
	now time.Time // what Deps.Now returns
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, db := storetest.OpenTestDB(t)
	e := &env{t: t, st: st, db: db, now: testNow}
	e.d = Deps{Store: st, Now: func() time.Time { return e.now }}
	return e
}

// run imports snap for real and fails the test on any error.
func (e *env) run(snap *Snap, opts ...func(*Options)) *Report {
	e.t.Helper()
	rep, err := e.try(snap, opts...)
	if err != nil {
		e.t.Fatalf("Run: %v (blocking: %q)", err, blockingOf(rep))
	}
	return rep
}

// try imports snap for real, or as a dry run with dryRun.
func (e *env) try(snap *Snap, opts ...func(*Options)) (*Report, error) {
	o := Options{Source: testSource}
	for _, f := range opts {
		f(&o)
	}
	return Run(context.Background(), e.d, snap.Snapshot, o)
}

func dryRun(o *Options) { o.DryRun = true }

func blockingOf(r *Report) []string {
	if r == nil {
		return nil
	}
	return r.Blocking
}

// user returns the Latch user with this email (any case).
func (e *env) user(email string) *model.User {
	e.t.Helper()
	u, err := e.st.GetUserByEmail(context.Background(), email)
	if err != nil {
		e.t.Fatalf("user %s: %v", email, err)
	}
	return u
}

// group returns the Latch group with this name.
func (e *env) group(name string) *model.Group {
	e.t.Helper()
	g, err := e.st.GetGroupByName(context.Background(), name)
	if err != nil {
		e.t.Fatalf("group %s: %v", name, err)
	}
	return g
}

// groupsOf returns the names of the Latch groups the member with this email
// is in, sorted.
func (e *env) groupsOf(email string) []string {
	e.t.Helper()
	gs, err := e.st.ListGroupsForUser(context.Background(), e.user(email).ID)
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, g := range gs {
		names = append(names, g.Name)
	}
	slices.Sort(names)
	return names
}

// rows returns the row count of each of the tables the brief names.
func (e *env) rows() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	for _, table := range []string{"users", "groups", "memberships", "applications"} {
		var n int
		if err := e.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			e.t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

// dump returns every row of every table, so two dumps are equal only when
// nothing was added, changed or removed.
func (e *env) dump() string {
	e.t.Helper()
	tables, err := e.db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			e.t.Fatal(err)
		}
		names = append(names, n)
	}
	tables.Close()
	var b strings.Builder
	for _, name := range names {
		rows, err := e.db.Query(`SELECT * FROM "` + name + `" ORDER BY rowid`)
		if err != nil {
			// WITHOUT ROWID tables have no rowid; none exist today.
			e.t.Fatalf("dump %s: %v", name, err)
		}
		cols, _ := rows.Columns()
		fmt.Fprintf(&b, "%s %v\n", name, cols)
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			for _, v := range vals {
				if bs, ok := v.([]byte); ok {
					v = string(bs)
				}
				fmt.Fprintf(&b, "%v|", v)
			}
			b.WriteString("\n")
		}
		rows.Close()
	}
	return b.String()
}

// mkLatchMember adds a member to Latch directly, as the member pages would.
func (e *env) mkLatchMember(name, email, username string) *model.User {
	e.t.Helper()
	u := &model.User{Name: name, Email: email, Username: username, IsActive: true}
	if err := e.st.CreateUser(context.Background(), u); err != nil {
		e.t.Fatal(err)
	}
	return u
}

// mkLatchGroup adds a group to Latch directly.
func (e *env) mkLatchGroup(g *model.Group) *model.Group {
	e.t.Helper()
	if err := e.st.CreateGroup(context.Background(), g); err != nil {
		e.t.Fatal(err)
	}
	return g
}

// mkLatchAdmin makes what latch init makes: an Admin group with no
// Authentik ID and an admin in it.
func (e *env) mkLatchAdmin(email string) *model.User {
	e.t.Helper()
	admin := e.mkLatchGroup(&model.Group{Name: "Admin", IsAdmin: true, RequireTOTP: true})
	u := e.mkLatchMember("Ada Admin", email, "ada")
	if err := e.st.AddMember(context.Background(), u.ID, admin.ID); err != nil {
		e.t.Fatal(err)
	}
	return u
}

func TestImportMembers(t *testing.T) {
	e := newEnv(t)
	s := NewSnap()
	joined := time.Date(2019, 3, 4, 5, 6, 7, 0, time.UTC)
	lastLogin := time.Date(2026, 9, 30, 18, 15, 0, 0, time.UTC)
	alex := s.User("alex", "Alex.Smith@Example.org", WithName("Alex Smith"), WithJoined(joined),
		WithLastLogin(lastLogin), WithAttrs(map[string]any{
			"member_number": 42, "goauthentik.io/user/sources": []any{}, "door_pin": "1234",
		}))
	s.User("door-bot", "", WithType("service_account"))
	jo := s.User("jo", "jo@example.org", WithPassword("!unusable"))
	s.User("ak-outpost-1", "", WithType("internal_service_account"))
	s.User("nomail", "", WithName("No Mail"))
	s.User("AnonymousUser", "", WithPassword("!"))
	pat := s.User("pat", "pat@example.org", WithName("Pat Inactive"), Inactive())

	rep := e.run(s, func(o *Options) { o.DropKeys = []string{"door_pin"} })

	if rep.Members != (Counts{Added: 3, Skipped: 1}) {
		t.Errorf("Members = %+v", rep.Members)
	}
	if rep.LeftOut != 3 {
		t.Errorf("LeftOut = %d, want 3", rep.LeftOut)
	}
	wantItems := []Item{{Kind: "member", Name: "nomail", Skipped: true,
		Reason: "Has no email address, which Latch needs to sign them in."}}
	if !reflect.DeepEqual(rep.Items, wantItems) {
		t.Errorf("Items = %+v", rep.Items)
	}
	if want := []KeyCount{{"member_number", 1}}; !reflect.DeepEqual(rep.MemberKeys, want) {
		t.Errorf("MemberKeys = %+v", rep.MemberKeys)
	}

	a := e.user("alex.smith@example.org")
	if a.Email != "Alex.Smith@Example.org" || a.Name != "Alex Smith" || a.Username != "alex" || !a.IsActive ||
		a.Type != model.UserTypeMember {
		t.Errorf("alex = %+v", a)
	}
	if want := map[string]any{"member_number": float64(42)}; !reflect.DeepEqual(a.Metadata, want) {
		t.Errorf("alex metadata = %v", a.Metadata)
	}
	if a.AuthentikPK == nil || *a.AuthentikPK != alex || a.AuthentikUUID != UserUUID(alex) ||
		a.AuthentikUID != authentik.HashedUserID(alex, TestInstallID) {
		t.Errorf("alex authentik IDs = %v %q %q", a.AuthentikPK, a.AuthentikUUID, a.AuthentikUID)
	}
	if !a.CreatedAt.Equal(joined) || a.LastLoginAt == nil || !a.LastLoginAt.Equal(lastLogin) {
		t.Errorf("alex created %v, last login %v", a.CreatedAt, a.LastLoginAt)
	}
	// Ruling B: a member Latch adds starts with Authentik's hash when Latch
	// can check it, and with none otherwise.
	if a.LegacyPasswordHash != UsableHash || a.PasswordHash != "" {
		t.Errorf("alex hashes: legacy %q, native %q", a.LegacyPasswordHash, a.PasswordHash)
	}
	j := e.user("jo@example.org")
	if j.Name != "jo" || j.LegacyPasswordHash != "" || j.LastLoginAt != nil || *j.AuthentikPK != jo {
		t.Errorf("jo = %+v", j)
	}
	if p := e.user("pat@example.org"); p.IsActive || *p.AuthentikPK != pat {
		t.Errorf("pat = %+v", p)
	}
	if n := e.rows()["users"]; n != 3 {
		t.Errorf("%d users, want 3", n)
	}
	for _, name := range []string{"door-bot", "ak-outpost-1", "AnonymousUser", "nomail"} {
		if _, err := e.st.GetUserByUsername(context.Background(), name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s was imported: %v", name, err)
		}
	}
}

// Ruling D: imported members pass the member pages' rules.
func TestImportMemberProblems(t *testing.T) {
	e := newEnv(t)
	s := NewSnap()
	long := strings.Repeat("n", 201)
	s.User("bad", "not an email")
	s.User("jo smith", "jo@example.org")
	s.User("tall", "tall@example.org", WithName(long))
	s.User("big", "big@example.org", WithAttrs(map[string]any{"notes": strings.Repeat("x", 8200)}))
	rep := e.run(s)

	want := []Item{
		{Kind: "member", Name: "not an email", Skipped: true, Reason: "Has an email address Latch can't use."},
		{Kind: "member", Name: "jo@example.org", Reason: "Has a username Latch can't use, so it was left off."},
		{Kind: "member", Name: "tall@example.org",
			Reason: "Has a name longer than Latch allows. Latch kept it, but shorten it before editing them on their page."},
		{Kind: "member", Name: "big@example.org",
			Reason: "Has more than 8 KB of metadata. Latch kept it, but shorten it before editing them on their page."},
	}
	if !reflect.DeepEqual(rep.Items, want) {
		t.Errorf("Items:\n got %+v\nwant %+v", rep.Items, want)
	}
	if rep.Members != (Counts{Added: 3, Skipped: 1}) {
		t.Errorf("Members = %+v", rep.Members)
	}
	if u := e.user("jo@example.org"); u.Username != "" || u.Name != "jo smith" {
		t.Errorf("jo: username %q, name %q", u.Username, u.Name)
	}
	if u := e.user("tall@example.org"); u.Name != long {
		t.Errorf("long name not kept: %d characters", len(u.Name))
	}
	if u := e.user("big@example.org"); len(u.Metadata["notes"].(string)) != 8200 {
		t.Errorf("big metadata not kept")
	}
}

func TestImportGroupsAndMemberships(t *testing.T) {
	e := newEnv(t)
	woodshopLatch := e.mkLatchGroup(&model.Group{Name: "Woodshop", Description: "Made in Latch"})

	s := NewSnap()
	members := s.Group("Members", GroupAttrs(map[string]any{"door": "yes", "goauthentik.io/internal": true}))
	laser := s.Group("Laser", GroupAttrs(map[string]any{"induction": "2024", "door": "no"}))
	advanced := s.Group("Laser Advanced")
	woodshop := s.Group("Woodshop")
	trainers := s.Group("Trainers")
	cycleA, cycleB := s.Group("Cycle A"), s.Group("Cycle B")
	trustees := s.Group("Trustees", Superuser())
	s.Group("Empty")
	bound := s.Group("Bound")
	disabled := s.Group("Disabled access")
	negated := s.Group("Negated access")
	onlyNomail := s.Group("Only nomail")
	s.Parent(laser, members)
	s.Parent(advanced, laser)
	s.Parent(trainers, laser)
	s.Parent(trainers, woodshop)
	s.Parent(cycleA, cycleB)
	s.Parent(cycleB, cycleA)
	wiki := s.App("Wiki", "wiki")
	s.Bind(wiki, bound)
	s.Bind(wiki, disabled, Disabled())
	s.Bind(wiki, negated, Negated())

	alex := s.User("alex", "alex@example.org")
	sam := s.User("sam", "sam@example.org")
	kim := s.User("kim", "kim@example.org")
	tess := s.User("tess", "tess@example.org")
	nomail := s.User("nomail", "")
	s.Join(alex, advanced)
	s.Join(sam, trainers)
	s.Join(kim, cycleA)
	s.Join(tess, trustees)
	s.Join(nomail, onlyNomail)

	rep := e.run(s)

	// A member of a grandchild group is in its parent and grandparent too.
	if got, want := e.groupsOf("alex@example.org"), []string{"Laser", "Laser Advanced", "Members"}; !slices.Equal(got, want) {
		t.Errorf("alex in %v, want %v", got, want)
	}
	// A group with two parents gets both.
	if got, want := e.groupsOf("sam@example.org"), []string{"Laser", "Members", "Trainers", "Woodshop"}; !slices.Equal(got, want) {
		t.Errorf("sam in %v, want %v", got, want)
	}
	// A parent cycle ends.
	if got, want := e.groupsOf("kim@example.org"), []string{"Cycle A", "Cycle B"}; !slices.Equal(got, want) {
		t.Errorf("kim in %v, want %v", got, want)
	}
	if g := e.group("Trustees"); !g.IsAdmin || !g.RequireTOTP || g.AuthentikUUID != trustees {
		t.Errorf("Trustees = %+v", g)
	}
	if g := e.group("Laser"); g.IsAdmin || g.RequireTOTP || g.AuthentikUUID != laser ||
		!reflect.DeepEqual(g.Metadata, map[string]any{"induction": "2024", "door": "no"}) {
		t.Errorf("Laser = %+v", g)
	}
	if g := e.group("Members"); !reflect.DeepEqual(g.Metadata, map[string]any{"door": "yes"}) {
		t.Errorf("Members metadata = %v", g.Metadata)
	}
	// A Latch group with the same name and no Authentik ID is adopted.
	if g := e.group("Woodshop"); g.ID != woodshopLatch.ID || g.AuthentikUUID != woodshop || g.Description != "Made in Latch" {
		t.Errorf("Woodshop = %+v, want adopted %s", g, woodshopLatch.ID)
	}
	if _, err := e.st.GetGroupByName(context.Background(), "Bound"); err != nil {
		t.Errorf("Bound, which an app uses, was not imported: %v", err)
	}

	reason := "Has no members and no app uses it."
	var skipped []Item
	for _, it := range rep.Items {
		if it.Kind == "group" {
			skipped = append(skipped, it)
		}
	}
	want := []Item{
		{Kind: "group", Name: "Empty", Skipped: true, Reason: reason},
		{Kind: "group", Name: "Disabled access", Skipped: true, Reason: reason},
		{Kind: "group", Name: "Negated access", Skipped: true, Reason: reason},
		{Kind: "group", Name: "Only nomail", Skipped: true, Reason: reason},
	}
	if !reflect.DeepEqual(skipped, want) {
		t.Errorf("group items:\n got %+v\nwant %+v", skipped, want)
	}
	for _, name := range []string{"Empty", "Disabled access", "Negated access", "Only nomail"} {
		if _, err := e.st.GetGroupByName(context.Background(), name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s was imported: %v", name, err)
		}
	}
	if rep.Groups != (Counts{Added: 8, Updated: 1, Skipped: 4}) {
		t.Errorf("Groups = %+v", rep.Groups)
	}
	if want := []KeyCount{{"door", 2}, {"induction", 1}}; !reflect.DeepEqual(rep.GroupKeys, want) {
		t.Errorf("GroupKeys = %+v", rep.GroupKeys)
	}
}

// The dev stack fixture's counts, as the report text test shows them.
func TestImportDevStack(t *testing.T) {
	e := newEnv(t)
	rep := e.run(DevStack())
	if rep.Members != (Counts{Added: 6, Skipped: 1}) || rep.Groups != (Counts{Added: 4, Skipped: 2}) || rep.LeftOut != 3 {
		t.Errorf("members %+v, groups %+v, left out %d", rep.Members, rep.Groups, rep.LeftOut)
	}
	if want := []KeyCount{{"member_number", 1}}; !reflect.DeepEqual(rep.MemberKeys, want) {
		t.Errorf("MemberKeys = %+v", rep.MemberKeys)
	}
	if want := []KeyCount{{"door", 1}, {"induction", 1}}; !reflect.DeepEqual(rep.GroupKeys, want) {
		t.Errorf("GroupKeys = %+v", rep.GroupKeys)
	}
	if got, want := e.groupsOf("akadmin@example.org"), []string{"authentik Admins"}; !slices.Equal(got, want) {
		t.Errorf("akadmin in %v", got)
	}
	if got, want := e.groupsOf("sam@example.org"), []string{"Members", "Trustees"}; !slices.Equal(got, want) {
		t.Errorf("sam in %v", got)
	}
	var skipped []string
	for _, it := range rep.Items {
		skipped = append(skipped, it.Kind+" "+it.Name)
	}
	if want := []string{"member nomail", "group authentik Read-only", "group authentik Agent-Users"}; !slices.Equal(skipped, want) {
		t.Errorf("items %v, want %v", skipped, want)
	}
}

// idempotentSnap is a small snapshot with members, groups, memberships and
// an app that uses a group.
func idempotentSnap() (s *Snap, alex int64, woodshop, laser string) {
	s = NewSnap()
	members := s.Group("Members")
	laser = s.Group("Laser")
	woodshop = s.Group("Woodshop")
	s.Parent(laser, members)
	s.Bind(s.App("Wiki", "wiki"), s.Group("Readers"))
	alex = s.User("alex", "alex@example.org", WithName("Alex"))
	sam := s.User("sam", "sam@example.org")
	s.User("nomail", "")
	s.Join(alex, laser, woodshop)
	s.Join(sam, woodshop)
	return s, alex, woodshop, laser
}

func TestImportIsIdempotent(t *testing.T) {
	e := newEnv(t)
	s, alex, woodshop, laser := idempotentSnap()
	first := e.run(s)
	if first.Members.Added != 2 || first.Groups.Added != 4 {
		t.Fatalf("first run: members %+v, groups %+v", first.Members, first.Groups)
	}
	before := e.rows()

	second := e.run(s)
	if second.Members != (Counts{Updated: 2, Skipped: 1}) || second.Groups != (Counts{Updated: 4}) {
		t.Errorf("second run: members %+v, groups %+v", second.Members, second.Groups)
	}
	if after := e.rows(); !reflect.DeepEqual(after, before) {
		t.Errorf("rows changed: %v -> %v", before, after)
	}

	// Dropping a membership removes only that membership.
	memberships := func() []string {
		rows, err := e.db.Query(`SELECT u.email, g.name FROM memberships m JOIN users u ON u.id = m.user_id
			JOIN groups g ON g.id = m.group_id ORDER BY u.email, g.name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var u, g string
			if err := rows.Scan(&u, &g); err != nil {
				t.Fatal(err)
			}
			out = append(out, u+" in "+g)
		}
		return out
	}
	was := memberships()
	s.Leave(alex, woodshop)
	e.run(s)
	want := slices.DeleteFunc(slices.Clone(was), func(m string) bool { return m == "alex@example.org in Woodshop" })
	if got := memberships(); !slices.Equal(got, want) || len(want) != len(was)-1 {
		t.Errorf("memberships after leaving:\n got %v\nwant %v", got, want)
	}

	// A renamed group is renamed in Latch, not added again.
	id := e.group("Laser").ID
	s.G(laser).Name = "Laser Cutter"
	rep := e.run(s)
	if g := e.group("Laser Cutter"); g.ID != id {
		t.Errorf("renamed group has ID %s, want %s", g.ID, id)
	}
	if rep.Groups.Added != 0 || e.rows()["groups"] != before["groups"] {
		t.Errorf("rename added a group: %+v, %v", rep.Groups, e.rows())
	}
}

// Review Focus 1 and 2.
func TestImportKeepsLatchOnlyState(t *testing.T) {
	e := newEnv(t)
	ada := e.mkLatchAdmin("ada@example.org")

	s := NewSnap()
	laser := s.Group("Laser")
	trustees := s.Group("Trustees", Superuser())
	adaPK := s.User("ada", "ADA@EXAMPLE.ORG", WithName("Ada Lovelace"))
	gone := s.User("gone", "gone@example.org")
	s.Join(adaPK, laser)
	s.Join(gone, trustees)

	rep := e.run(s)
	if rep.Members != (Counts{Added: 1, Updated: 1}) {
		t.Errorf("Members = %+v", rep.Members)
	}
	a := e.user("ada@example.org")
	if a.ID != ada.ID || a.Email != "ADA@EXAMPLE.ORG" || a.AuthentikUUID != UserUUID(adaPK) {
		t.Errorf("ada = %+v, want matched to %s", a, ada.ID)
	}
	if got, want := e.groupsOf("ada@example.org"), []string{"Admin", "Laser"}; !slices.Equal(got, want) {
		t.Errorf("ada in %v, want %v", got, want)
	}

	// The next snapshot no longer marks Trustees is_superuser, and gone has
	// left Authentik.
	s.G(trustees).IsSuperuser = false
	s.Users = slices.DeleteFunc(s.Users, func(u authentik.User) bool { return u.PK == gone })
	s.Leave(gone, trustees)
	goneBefore := e.user("gone@example.org")
	rep = e.run(s)

	g := e.group("Trustees")
	if !g.IsAdmin || g.RequireTOTP {
		t.Errorf("Trustees: is_admin %v, require_totp %v; want admin kept and second step off", g.IsAdmin, g.RequireTOTP)
	}
	if goneAfter := e.user("gone@example.org"); !reflect.DeepEqual(goneAfter, goneBefore) {
		t.Errorf("gone changed:\n%+v\n%+v", goneBefore, goneAfter)
	}
	if got := e.groupsOf("gone@example.org"); !slices.Equal(got, []string{"Trustees"}) {
		t.Errorf("gone in %v, want left in Trustees", got)
	}
	if got, want := e.groupsOf("ada@example.org"), []string{"Admin", "Laser"}; !slices.Equal(got, want) {
		t.Errorf("ada in %v after second run", got)
	}
	want := []Item{
		{Kind: "member", Name: "gone@example.org", Reason: "Is no longer in Authentik. Latch has left them as they are."},
		{Kind: "group", Name: "Trustees",
			Reason: "Isn't an admin group in Authentik any more. Latch leaves admin access on; untick it on the group's page if that's right."},
	}
	if !reflect.DeepEqual(rep.Items, want) {
		t.Errorf("Items:\n got %+v\nwant %+v", rep.Items, want)
	}
}

func TestImportDisablesAndSignsOut(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := NewSnap()
	pat := s.User("pat", "pat@example.org")
	s.User("alex", "alex@example.org")
	e.run(s)

	app := &model.Application{Name: "Wiki", Slug: "wiki", ClientID: "wiki"}
	if err := e.st.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signIn := func(email string) (sessionID, tokenHash string) {
		u := e.user(email)
		sessionID, tokenHash = secrets.NewID(), secrets.HashToken(secrets.NewID())
		if err := e.st.CreateSession(ctx, &model.Session{ID: sessionID, UserID: u.ID, CreatedAt: now,
			LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := e.st.CreateRefreshToken(ctx, &model.RefreshToken{TokenHash: tokenHash, FamilyID: secrets.NewID(),
			ApplicationID: app.ID, UserID: u.ID, AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		return sessionID, tokenHash
	}
	patSession, patToken := signIn("pat@example.org")
	alexSession, alexToken := signIn("alex@example.org")

	s.U(pat).IsActive = false
	e.run(s)

	if e.user("pat@example.org").IsActive {
		t.Error("pat is still active")
	}
	if _, err := e.st.GetSession(ctx, patSession); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("pat's session: %v", err)
	}
	if tok, err := e.st.GetRefreshToken(ctx, patToken); err != nil || tok.RevokedAt == nil {
		t.Errorf("pat's refresh token not revoked: %+v, %v", tok, err)
	}
	if _, err := e.st.GetSession(ctx, alexSession); err != nil {
		t.Errorf("alex's session: %v", err)
	}
	if tok, err := e.st.GetRefreshToken(ctx, alexToken); err != nil || tok.RevokedAt != nil {
		t.Errorf("alex's refresh token: %+v, %v", tok, err)
	}
}

// A member whose Authentik account was deleted and made again is matched by
// email and linked to the new account (Ruling F).
func TestImportRelinksRecreatedAccount(t *testing.T) {
	e := newEnv(t)
	s := NewSnap()
	old := s.User("sam", "sam@example.org")
	e.run(s)
	id := e.user("sam@example.org").ID

	// The account is deleted and made again, with a new PK and UUID.
	s.Users = slices.DeleteFunc(s.Users, func(u authentik.User) bool { return u.PK == old })
	recreated := *s.U(s.User("sam", "Sam@example.org"))
	rep := e.run(s)

	u := e.user("sam@example.org")
	if u.ID != id || u.AuthentikUUID != recreated.UUID || *u.AuthentikPK != recreated.PK ||
		u.AuthentikUID != authentik.HashedUserID(recreated.PK, TestInstallID) || u.Email != "Sam@example.org" {
		t.Errorf("sam = %+v", u)
	}
	want := []Item{{Kind: "member", Name: "Sam@example.org", Reason: "Was linked to an Authentik account that no longer " +
		"exists. Latch now links them to this one, so apps that identify people by their Authentik ID will see a new ID."}}
	if !reflect.DeepEqual(rep.Items, want) {
		t.Errorf("Items = %+v", rep.Items)
	}
	if rep.Members != (Counts{Updated: 1}) {
		t.Errorf("Members = %+v", rep.Members)
	}
}

// Review Focus 4: conflicts stop the import with nothing written, also
// without a dry run, and the report names both records.
func TestImportBlocksConflicts(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *env) *Snap
		want  []string     // each appears in one Blocking line
		check func(e *env) // more checks after the run; may be nil
	}{{
		name: "emails differ only in case",
		setup: func(e *env) *Snap {
			s := NewSnap()
			s.User("ann", "a@x.org")
			s.User("andy", "A@X.org")
			return s
		},
		want: []string{"ann (a@x.org)", "andy (A@X.org)"},
	}, {
		name: "email of another Latch account",
		setup: func(e *env) *Snap {
			s := NewSnap()
			s.User("bob", "bob@x.org")
			e.run(s)
			e.mkLatchMember("Taken", "taken@x.org", "tk")
			s.Users[0].Email = "Taken@x.org"
			return s
		},
		want: []string{"bob (Taken@x.org)", "Latch member bob@x.org", "Latch member taken@x.org"},
	}, {
		name: "username of another Latch account",
		setup: func(e *env) *Snap {
			e.mkLatchMember("Other", "other@x.org", "alex")
			s := NewSnap()
			s.User("alex", "alex@x.org")
			return s
		},
		want: []string{"alex (alex@x.org)", "Latch member other@x.org"},
	}, {
		name: "username of a Latch service account",
		setup: func(e *env) *Snap {
			sa := &model.User{Name: "Door", Type: model.UserTypeService, Username: "door", IsActive: true}
			if err := e.st.CreateUser(context.Background(), sa); err != nil {
				e.t.Fatal(err)
			}
			s := NewSnap()
			s.User("door", "door@x.org")
			return s
		},
		want: []string{"door (door@x.org)", "Latch service account door"},
	}, {
		name: "group name linked to another Authentik group",
		setup: func(e *env) *Snap {
			e.mkLatchGroup(&model.Group{Name: "Laser", AuthentikUUID: "99999999-0000-4000-8000-000000000001"})
			s := NewSnap()
			s.Join(s.User("alex", "alex@x.org"), s.Group("Laser"))
			return s
		},
		want: []string{"Authentik group Laser", "Latch group Laser"},
	}, {
		name: "email of a Latch member linked to another account still in Authentik",
		setup: func(e *env) *Snap {
			s := NewSnap()
			sam := s.User("sam", "sam@x.org")
			e.run(s)
			s.U(sam).Email = "samuel@x.org"
			s.User("newsam", "SAM@x.org")
			return s
		},
		want: []string{"newsam (SAM@x.org)", "Latch member sam@x.org", "sam (samuel@x.org)"},
	}, {
		name: "renamed group takes the name of another Latch group",
		setup: func(e *env) *Snap {
			s := NewSnap()
			laser := s.Group("Laser")
			s.Join(s.User("alex", "alex@x.org"), laser)
			e.run(s)
			e.mkLatchGroup(&model.Group{Name: "Lasers"})
			s.G(laser).Name = "Lasers"
			return s
		},
		want: []string{"Authentik group Lasers", "Latch group Laser,", "Lasers"},
	}, {
		name: "two Authentik groups with one name",
		setup: func(e *env) *Snap {
			s := NewSnap()
			alex := s.User("alex", "alex@x.org")
			s.Join(alex, s.Group("Laser"), s.Group("Laser"))
			return s
		},
		want: []string{"two groups called Laser"},
	}, {
		// Ruling J: adopting Latch's own admin group would let the import
		// remove Latch's admins from it.
		name: "group named like Latch's admin group",
		setup: func(e *env) *Snap {
			s := NewSnap()
			s.Join(s.User("sam", "sam@x.org"), s.Group("Admin"))
			return s
		},
		want: []string{`Authentik's group "Admin" has the same name as Latch's admin group. ` +
			"Rename one of them before importing."},
		check: func(e *env) {
			if got := e.groupsOf("ada@example.org"); !slices.Equal(got, []string{"Admin"}) {
				e.t.Errorf("the Latch admin is in %v, want Admin", got)
			}
		},
	}}
	for _, tc := range cases {
		for _, dry := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/dry=%v", tc.name, dry), func(t *testing.T) {
				e := newEnv(t)
				e.mkLatchAdmin("ada@example.org")
				s := tc.setup(e)
				before := e.dump()
				rep, err := e.try(s, func(o *Options) { o.DryRun = dry })
				if !errors.Is(err, ErrBlocked) {
					t.Fatalf("err = %v, want ErrBlocked", err)
				}
				if rep == nil || len(rep.Blocking) == 0 || rep.DryRun != dry {
					t.Fatalf("report = %+v", rep)
				}
				if !slices.ContainsFunc(rep.Blocking, func(line string) bool {
					for _, w := range tc.want {
						if !strings.Contains(line, w) {
							return false
						}
					}
					return true
				}) {
					t.Errorf("no blocking line names %q:\n%s", tc.want, strings.Join(rep.Blocking, "\n"))
				}
				for _, line := range rep.Blocking {
					for _, word := range []string{"provider", "flow", "stage", "binding"} {
						if strings.Contains(strings.ToLower(line), word) {
							t.Errorf("blocking line says %q: %s", word, line)
						}
					}
				}
				if after := e.dump(); after != before {
					t.Errorf("database changed:\n%s\n---\n%s", before, after)
				}
				if tc.check != nil {
					tc.check(e)
				}
				var text strings.Builder
				if err := rep.WriteText(&text); err != nil || !strings.HasPrefix(text.String(),
					"Nothing was imported from "+testSource+". Fix these first:\n  ") {
					t.Errorf("text = %q, %v", text.String(), err)
				}
			})
		}
	}
}

// Ruling 9: usernames that differ only in case are a warning, not a block.
func TestImportWarnsOnUsernameCase(t *testing.T) {
	e := newEnv(t)
	s := NewSnap()
	s.User("alex", "alex@x.org")
	s.User("Alex", "alex.two@x.org")
	rep := e.run(s)
	if rep.Members.Added != 2 || len(rep.Blocking) != 0 {
		t.Errorf("members %+v, blocking %v", rep.Members, rep.Blocking)
	}
	want := []Item{{Kind: "member", Name: "alex.two@x.org", Reason: "Has the username Alex, which differs only in " +
		"capitals from the username alex of member alex@x.org. Latch keeps both, but apps that ignore capitals may mix them up."}}
	if !reflect.DeepEqual(rep.Items, want) {
		t.Errorf("Items = %+v", rep.Items)
	}
}

// changedSnap is a second snapshot for e's database after idempotentSnap
// was imported: something of every kind changes.
func changedSnap(s *Snap, alex int64, woodshop, laser string) {
	s.U(alex).Email = "Alex@Example.org"
	s.U(alex).Name = "Alex Smith"
	s.U(alex).IsActive = false
	s.G(laser).Name = "Laser Cutter"
	s.G(woodshop).IsSuperuser = true
	s.Leave(alex, woodshop)
	s.Join(s.User("new", "new@example.org"), laser)
	s.Join(s.User("ada", "Ada@Example.org"), woodshop)
}

// Review Focus 5: a dry run gives the real run's report and writes nothing.
func TestDryRunWritesNothing(t *testing.T) {
	e := newEnv(t)
	e.mkLatchAdmin("ada@example.org")
	s, alex, woodshop, laser := idempotentSnap()
	e.run(s)
	changedSnap(s, alex, woodshop, laser)
	e.now = testNow.Add(time.Hour)

	before := e.dump()
	dry, err := e.try(s, dryRun)
	if err != nil {
		t.Fatal(err)
	}
	if after := e.dump(); after != before {
		t.Errorf("dry run changed the database:\n%s\n---\n%s", before, after)
	}
	if !dry.DryRun {
		t.Error("dry run report has DryRun false")
	}
	real := e.run(s)
	if real.DryRun {
		t.Error("real run report has DryRun true")
	}
	dry.DryRun = false
	if !reflect.DeepEqual(dry, real) {
		t.Errorf("reports differ:\n dry %+v\nreal %+v", dry, real)
	}
	if real.Members != (Counts{Added: 1, Updated: 3, Skipped: 1}) {
		t.Errorf("Members = %+v", real.Members)
	}

	run, err := e.st.LastImportRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var stored Report
	if err := json.Unmarshal([]byte(run.Report), &stored); err != nil {
		t.Fatal(err)
	}
	if run.Source != testSource || !run.StartedAt.Equal(e.now) || !run.FinishedAt.Equal(e.now) ||
		stored.Summary() != real.Summary() || !reflect.DeepEqual(stored.Items, real.Items) {
		t.Errorf("stored run = %+v\n%s", run, run.Report)
	}
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM import_runs`).Scan(&n); err != nil || n != 2 {
		t.Errorf("%d import runs, want 2 (the dry run stores none): %v", n, err)
	}
}

// Review Focus 5: a failure partway leaves the database as it was.
func TestFailurePartwayLeavesNothing(t *testing.T) {
	e := newEnv(t)
	e.mkLatchAdmin("ada@example.org")
	s, alex, woodshop, laser := idempotentSnap()
	e.run(s)
	changedSnap(s, alex, woodshop, laser)

	boom := errors.New("boom")
	testHookAfterMembers = func() error { return boom }
	t.Cleanup(func() { testHookAfterMembers = nil })

	before := e.dump()
	rep, err := e.try(s)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %+v, %v; want boom", rep, err)
	}
	if after := e.dump(); after != before {
		t.Errorf("database changed:\n%s\n---\n%s", before, after)
	}
}
