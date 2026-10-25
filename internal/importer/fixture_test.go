package importer

// Snapshot builders for the importer's tests. They are exported so that
// package importer_test files in this directory can use them too.

import (
	"fmt"
	"slices"
	"time"

	"latch/internal/authentik"
)

// TestInstallID is the Authentik install ID of every snapshot NewSnap builds.
const TestInstallID = "6f1c2a9e-3b7d-4e1a-9c55-0d8e2f4b7a13"

// UsableHash is a password hash password.CheckStored accepts.
const UsableHash = "pbkdf2_sha256$870000$vK9mZ2pQxL3n$k/YNzDxY8WuRK/+6PjMgYNCGxD4pyHdDwQFRbvUuXCo="

// Snap is an Authentik snapshot under construction. Its methods add rows
// with realistic defaults; tests change the rows between runs through U
// and G, or edit the slices directly.
type Snap struct {
	*authentik.Snapshot
	nextPK    int64
	nextGroup int
	nextApp   int
}

// NewSnap returns an empty snapshot with TestInstallID.
func NewSnap() *Snap { return &Snap{Snapshot: &authentik.Snapshot{InstallID: TestInstallID}} }

// UserUUID is the UUID Snap gives the user with this PK.
func UserUUID(pk int64) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", pk) }

// UserOpt changes a user that Snap.User adds.
type UserOpt func(*authentik.User)

// WithName sets the user's name, which is otherwise empty.
func WithName(name string) UserOpt { return func(u *authentik.User) { u.Name = name } }

// Inactive makes the user inactive.
func Inactive() UserOpt { return func(u *authentik.User) { u.IsActive = false } }

// WithType sets the user's Authentik type, which is otherwise "internal".
func WithType(typ string) UserOpt { return func(u *authentik.User) { u.Type = typ } }

// WithAttrs sets the user's attributes.
func WithAttrs(attrs map[string]any) UserOpt { return func(u *authentik.User) { u.Attributes = attrs } }

// WithPassword sets the user's password hash, which is otherwise UsableHash.
func WithPassword(hash string) UserOpt { return func(u *authentik.User) { u.Password = hash } }

// WithLastLogin sets when the user last signed in to Authentik.
func WithLastLogin(t time.Time) UserOpt { return func(u *authentik.User) { u.LastLogin = &t } }

// WithJoined sets when the user's Authentik account was made.
func WithJoined(t time.Time) UserOpt { return func(u *authentik.User) { u.DateJoined = t } }

// WithUUID sets the user's UUID, which is otherwise UserUUID(pk).
func WithUUID(uuid string) UserOpt { return func(u *authentik.User) { u.UUID = uuid } }

// User adds an active internal user with the next PK, a usable password and
// no name or attributes, and returns the PK.
func (s *Snap) User(username, email string, opts ...UserOpt) int64 {
	s.nextPK++
	u := authentik.User{
		PK:         s.nextPK,
		UUID:       UserUUID(s.nextPK),
		Username:   username,
		Email:      email,
		Password:   UsableHash,
		IsActive:   true,
		Type:       "internal",
		Attributes: map[string]any{},
		DateJoined: time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC).AddDate(0, 0, int(s.nextPK)),
	}
	for _, o := range opts {
		o(&u)
	}
	s.Users = append(s.Users, u)
	return u.PK
}

// U returns the user with this PK, for changing between runs.
func (s *Snap) U(pk int64) *authentik.User {
	for i := range s.Users {
		if s.Users[i].PK == pk {
			return &s.Users[i]
		}
	}
	panic(fmt.Sprintf("no user with pk %d", pk))
}

// GroupOpt changes a group that Snap.Group adds.
type GroupOpt func(*authentik.Group)

// Superuser marks the group is_superuser.
func Superuser() GroupOpt { return func(g *authentik.Group) { g.IsSuperuser = true } }

// GroupAttrs sets the group's attributes.
func GroupAttrs(attrs map[string]any) GroupOpt {
	return func(g *authentik.Group) { g.Attributes = attrs }
}

// Group adds a group and returns its UUID.
func (s *Snap) Group(name string, opts ...GroupOpt) string {
	s.nextGroup++
	g := authentik.Group{
		UUID:       fmt.Sprintf("10000000-0000-4000-8000-%012d", s.nextGroup),
		Name:       name,
		Attributes: map[string]any{},
	}
	for _, o := range opts {
		o(&g)
	}
	s.Groups = append(s.Groups, g)
	return g.UUID
}

// G returns the group with this UUID, for changing between runs.
func (s *Snap) G(uuid string) *authentik.Group {
	for i := range s.Groups {
		if s.Groups[i].UUID == uuid {
			return &s.Groups[i]
		}
	}
	panic("no group " + uuid)
}

// Parent makes parent a parent of child.
func (s *Snap) Parent(child, parent string) {
	s.Parents = append(s.Parents, authentik.Parentage{ChildUUID: child, ParentUUID: parent})
}

// Join makes the user a direct member of the groups.
func (s *Snap) Join(pk int64, groups ...string) {
	for _, g := range groups {
		s.Memberships = append(s.Memberships, authentik.Membership{UserPK: pk, GroupUUID: g})
	}
}

// Leave removes the user's direct membership of the group.
func (s *Snap) Leave(pk int64, group string) {
	s.Memberships = slices.DeleteFunc(s.Memberships, func(m authentik.Membership) bool {
		return m.UserPK == pk && m.GroupUUID == group
	})
}

// App adds an application with no provider that anyone may use, and
// returns its UUID.
func (s *Snap) App(name, slug string) string {
	s.nextApp++
	a := authentik.Application{
		UUID:       fmt.Sprintf("20000000-0000-4000-8000-%012d", s.nextApp),
		Name:       name,
		Slug:       slug,
		EngineMode: "any",
	}
	s.Applications = append(s.Applications, a)
	return a.UUID
}

// BindingOpt changes a binding that Snap.Bind adds.
type BindingOpt func(*authentik.Binding)

// Disabled makes the binding disabled.
func Disabled() BindingOpt { return func(b *authentik.Binding) { b.Enabled = false } }

// Negated makes the binding negated.
func Negated() BindingOpt { return func(b *authentik.Binding) { b.Negate = true } }

// Bind adds an enabled group binding of group to the application target.
func (s *Snap) Bind(target, group string, opts ...BindingOpt) {
	b := authentik.Binding{TargetUUID: target, GroupUUID: group, Enabled: true}
	for _, o := range opts {
		o(&b)
	}
	s.Bindings = append(s.Bindings, b)
}

// DevStack is the dev stack fixture (see the plan's "Dev stack fixture")
// as far as members, groups and access rules go: Authentik's own accounts
// and groups, the seeded members and groups, and the group bindings of
// Wiki and Tool Booking. Applications carry only their names; providers,
// TOTP devices and recovery codes are not filled in.
func DevStack() *Snap {
	s := NewSnap()
	s.User("AnonymousUser", "", WithPassword("!"))
	akadmin := s.User("akadmin", "akadmin@example.org", WithName("authentik Default Admin"))
	s.User("ak-outpost-0f8a3e3c", "", WithType("internal_service_account"), WithPassword(""))

	admins := s.Group("authentik Admins", Superuser())
	s.Group("authentik Read-only")
	s.Group("authentik Agent-Users")
	members := s.Group("Members", GroupAttrs(map[string]any{"door": "yes", "goauthentik.io/internal": true}))
	laser := s.Group("Laser", GroupAttrs(map[string]any{"induction": "2024"}))
	trustees := s.Group("Trustees", Superuser())
	s.Parent(laser, members)
	s.Parent(trustees, members)
	s.Join(akadmin, admins)

	alex := s.User("alex", "Alex.Smith@Example.org", WithName("Alex Smith"),
		WithAttrs(map[string]any{"member_number": 42, "goauthentik.io/user/sources": []any{}}))
	sam := s.User("sam", "sam@example.org", WithName("Sam Jones"))
	jo := s.User("jo", "jo@example.org", WithPassword("!unusable"))
	pat := s.User("pat", "pat@example.org", WithName("Pat Inactive"), Inactive())
	s.User("kim", "kim@example.org", WithName("Kim External"), WithType("external"))
	nomail := s.User("nomail", "", WithName("No Mail"))
	s.User("door-bot", "", WithName("door-bot"), WithType("service_account"), WithPassword(""))
	s.Join(alex, laser)
	s.Join(sam, trustees)
	s.Join(jo, members)
	s.Join(pat, members)
	s.Join(nomail, members)

	wiki := s.App("Wiki", "wiki")
	s.App("Door Booking", "Door_Booking")
	tools := s.App("Tool Booking", "tools")
	s.App("Grafana", "grafana")
	s.App("Printer", "printer")
	s.Bind(wiki, members)
	s.Bind(tools, laser)
	s.Bindings = append(s.Bindings, authentik.Binding{TargetUUID: tools,
		PolicyUUID: "30000000-0000-4000-8000-000000000001", Enabled: true})
	return s
}
