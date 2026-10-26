package admin_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/secrets"
	"github.com/James-Smart/keywell/internal/store"
	"github.com/James-Smart/keywell/internal/store/storetest"
)

// fakeNotifier records SendReset calls and, when err is set, fails them.
type fakeNotifier struct {
	mu    sync.Mutex
	calls []notification
	err   error
}

// notification is one SendReset call.
type notification struct {
	UserID  string
	Purpose model.ResetPurpose
}

func (n *fakeNotifier) SendReset(_ context.Context, u *model.User, purpose model.ResetPurpose) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, notification{UserID: u.ID, Purpose: purpose})
	return n.err
}

// Calls returns the SendReset calls made so far.
func (n *fakeNotifier) Calls() []notification {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]notification(nil), n.calls...)
}

// Fail makes every later SendReset return err (nil to succeed again).
func (n *fakeNotifier) Fail(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.err = err
}

// testClock is a settable time source for Deps.Now.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *testClock { return &testClock{t: t} }

// Now returns the clock's current time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setup is what newService builds the Service from; options edit it.
type setup struct {
	deps     admin.Deps
	notifier *fakeNotifier
}

// option adjusts newService's setup before the Service is made.
type option func(*setup)

// withNow gives the Service now as its clock (Deps.Now).
func withNow(now func() time.Time) option { return func(s *setup) { s.deps.Now = now } }

// withNotifyError makes the fake notifier fail every SendReset with err.
func withNotifyError(err error) option { return func(s *setup) { s.notifier.err = err } }

// withDeps edits the Deps directly, e.g. to set Mailer or Keys.
func withDeps(f func(*admin.Deps)) option { return func(s *setup) { f(&s.deps) } }

// newService returns a Service over a fresh test database, with the default
// config (minimum password length 10), a discarding audit log and a fake
// notifier.
func newService(t *testing.T, opts ...option) (*admin.Service, *store.Store, *fakeNotifier) {
	t.Helper()
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	st, _ := storetest.OpenTestDB(t)
	s := &setup{notifier: &fakeNotifier{}}
	s.deps = admin.Deps{
		Cfg:      cfg,
		Store:    st,
		Audit:    audit.New(st, slog.New(slog.DiscardHandler)),
		Notifier: s.notifier,
	}
	for _, opt := range opts {
		opt(s)
	}
	return admin.New(s.deps), st, s.notifier
}

// mkGroup stores a group.
func mkGroup(t *testing.T, st *store.Store, name string, isAdmin bool) *model.Group {
	t.Helper()
	g := &model.Group{Name: name, IsAdmin: isAdmin}
	if err := st.CreateGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	return g
}

// mkMember stores an active member with no password in groups.
func mkMember(t *testing.T, st *store.Store, name, email string, groups ...*model.Group) *model.User {
	t.Helper()
	u := &model.User{Name: name, Email: email, Type: model.UserTypeMember, IsActive: true}
	return storeUser(t, st, u, groups...)
}

// storeUser stores u and adds it to groups.
func storeUser(t *testing.T, st *store.Store, u *model.User, groups ...*model.Group) *model.User {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if err := st.AddMember(ctx, u.ID, g.ID); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

// mkServiceAccount stores a service account.
func mkServiceAccount(t *testing.T, st *store.Store, name, username string) *model.User {
	t.Helper()
	return storeUser(t, st, &model.User{Name: name, Username: username, Type: model.UserTypeService, IsActive: true})
}

// mkAdmin stores the group "Admin" (an admin group) and Ada, a member of it.
func mkAdmin(t *testing.T, st *store.Store) (*model.User, *model.Group) {
	t.Helper()
	g := mkGroup(t, st, "Admin", true)
	return mkMember(t, st, "Ada Admin", "ada@example.org", g), g
}

// actorFor is u acting in the admin pages.
func actorFor(u *model.User) admin.Actor { return admin.Actor{Type: model.ActorUser, ID: u.ID} }

// events returns the audit events with exactly this action, newest first.
func events(t *testing.T, st *store.Store, action string) []store.AuditRow {
	t.Helper()
	page, err := st.ListAuditEvents(context.Background(), store.AuditFilter{Actions: []string{action}, PerPage: 500})
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditRow
	for _, r := range page.Rows {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// oneEvent returns the only audit event with this action.
func oneEvent(t *testing.T, st *store.Store, action string) store.AuditRow {
	t.Helper()
	evs := events(t, st, action)
	if len(evs) != 1 {
		t.Fatalf("%s: %d events, want 1: %+v", action, len(evs), evs)
	}
	return evs[0]
}

// countEvents returns how many audit events there are of any action.
func countEvents(t *testing.T, st *store.Store) int {
	t.Helper()
	page, err := st.ListAuditEvents(context.Background(), store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return page.Total
}

// fields returns the field messages of err, failing unless it is a
// *admin.ValidationError.
func fields(t *testing.T, err error) map[string]string {
	t.Helper()
	var ve *admin.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *admin.ValidationError, got %T %v", err, err)
	}
	return ve.Fields
}

// refusal returns the message of err, failing unless it is a *admin.RefusedError.
func refusal(t *testing.T, err error) string {
	t.Helper()
	var re *admin.RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("want *admin.RefusedError, got %T %v", err, err)
	}
	return re.Message
}

// addSession gives the user a live session and returns its ID.
func addSession(t *testing.T, st *store.Store, userID string) string {
	t.Helper()
	now := time.Now().UTC()
	sess := &model.Session{ID: secrets.NewID(), UserID: userID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess.ID
}

// addRefreshToken gives the user a live refresh token for a new app and
// returns its hash.
func addRefreshToken(t *testing.T, st *store.Store, userID string) string {
	t.Helper()
	ctx := context.Background()
	app := &model.Application{Name: "App", Slug: "app-" + secrets.NewID(), ClientID: secrets.NewID(), ClientType: model.ClientTypePublic}
	if err := st.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tok := &model.RefreshToken{TokenHash: secrets.NewID(), FamilyID: secrets.NewID(), ApplicationID: app.ID, UserID: userID,
		AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)}
	if err := st.CreateRefreshToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	return tok.TokenHash
}

// assertSignedOut checks the session is gone and the refresh token revoked.
func assertSignedOut(t *testing.T, st *store.Store, sessionID, refreshHash string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.GetSession(ctx, sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session still there: %v", err)
	}
	tok, err := st.GetRefreshToken(ctx, refreshHash)
	if err != nil {
		t.Fatal(err)
	}
	if tok.RevokedAt == nil {
		t.Error("refresh token not revoked")
	}
}

// groupNames returns the names of the user's groups, ordered by name.
func groupNames(t *testing.T, st *store.Store, userID string) []string {
	t.Helper()
	gs, err := st.ListGroupsForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, g := range gs {
		names = append(names, g.Name)
	}
	return names
}

// ptr returns a pointer to v, for patches.
func ptr[T any](v T) *T { return &v }

const metadataObjectMsg = `Metadata must be a JSON object, like {"member_number": 42}.`

func TestParseMetadata(t *testing.T) {
	for _, raw := range []string{"", "  \n "} {
		m, verr := admin.ParseMetadata(raw)
		if verr != nil || m == nil || len(m) != 0 {
			t.Errorf("ParseMetadata(%q) = %v, %v; want {}", raw, m, verr)
		}
	}
	m, verr := admin.ParseMetadata(` {"a": 1, "b": {"c": [true, "x"]}} `)
	want := map[string]any{"a": float64(1), "b": map[string]any{"c": []any{true, "x"}}}
	if verr != nil || !reflect.DeepEqual(m, want) {
		t.Errorf("object: %v, %v", m, verr)
	}
	// Review Focus 2: valid JSON that is not an object, and text that is
	// not JSON, get the field message.
	for _, raw := range []string{`[1,2]`, `"x"`, `null`, `42`, `{bad`, `{"a":1} {"b":2}`, `true`} {
		m, verr := admin.ParseMetadata(raw)
		if verr == nil {
			t.Errorf("ParseMetadata(%q) = %v, want an error", raw, m)
			continue
		}
		if got := verr.Fields["metadata"]; got != metadataObjectMsg {
			t.Errorf("ParseMetadata(%q) message %q", raw, got)
		}
	}
	long := `{"notes": "` + strings.Repeat("x", 8200) + `"}`
	if _, verr := admin.ParseMetadata(long); verr == nil || verr.Fields["metadata"] != "Metadata is too long. Keep it under 8 KB." {
		t.Errorf("long metadata: %v", verr)
	}
	// The limit is on the stored (compact) form, so indentation does not count.
	padded := "{\n" + strings.Repeat(" ", 9000) + `"a": 1}`
	if _, verr := admin.ParseMetadata(padded); verr != nil {
		t.Errorf("indented metadata refused: %v", verr.Fields)
	}
}

// MemberProblems applies the member pages' checks, with their messages, to
// values that did not come from a form, such as an imported member.
func TestMemberProblems(t *testing.T) {
	if got := admin.MemberProblems(" Alex Rivera ", " alex@example.org ", "alex",
		map[string]any{"member_number": 42}); len(got) != 0 {
		t.Errorf("valid member: %v", got)
	}
	if got := admin.MemberProblems("Alex", "alex@example.org", "", nil); len(got) != 0 {
		t.Errorf("no username and nil metadata: %v", got)
	}
	got := admin.MemberProblems(strings.Repeat("n", 201), "not an email", "alex rivera",
		map[string]any{"notes": strings.Repeat("x", 8200)})
	want := map[string]string{
		"name":     "Use at most 200 characters.",
		"email":    "Enter an email address, like alex@example.org.",
		"username": "Usernames can't contain spaces.",
		"metadata": "Metadata is too long. Keep it under 8 KB.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MemberProblems = %v, want %v", got, want)
	}
	if got := admin.MemberProblems("", "a@b@c", strings.Repeat("u", 151), nil); got["name"] != "Enter a name." ||
		got["email"] != want["email"] || got["username"] != "Use at most 150 characters." {
		t.Errorf("empty name, two @, long username: %v", got)
	}
}

func TestTokenActorInAudit(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	sa := mkServiceAccount(t, st, "Door", "door")
	a := admin.Actor{Type: model.ActorServiceAccount, ID: sa.ID, TokenID: "tok-1"}
	u, err := svc.CreateMember(ctx, a, admin.NewMember{Name: "Alex Rivera", Email: "alex@example.org", Invite: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{audit.UserCreate, audit.UserInvite} {
		ev := oneEvent(t, st, action)
		if ev.ActorType != model.ActorServiceAccount || ev.ActorID != sa.ID || ev.TargetID != u.ID {
			t.Errorf("%s: actor %s/%s target %s", action, ev.ActorType, ev.ActorID, ev.TargetID)
		}
		if ev.Detail["token_id"] != "tok-1" {
			t.Errorf("%s: detail %v", action, ev.Detail)
		}
	}

	// Without a token ID, nothing is added.
	ada, _ := mkAdmin(t, st)
	if _, err := svc.UpdateMember(ctx, actorFor(ada), u.ID, admin.MemberPatch{Name: ptr("Alex R")}); err != nil {
		t.Fatal(err)
	}
	ev := oneEvent(t, st, audit.UserUpdate)
	if ev.ActorType != model.ActorUser || ev.ActorID != ada.ID {
		t.Errorf("update actor %s/%s", ev.ActorType, ev.ActorID)
	}
	if _, ok := ev.Detail["token_id"]; ok {
		t.Errorf("update has token_id: %v", ev.Detail)
	}
}

func TestErrorTypes(t *testing.T) {
	cause := errors.New("smtp down")
	var err error = &admin.EmailError{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("EmailError does not unwrap to its cause")
	}
	if !strings.Contains(err.Error(), "smtp down") {
		t.Errorf("EmailError text %q", err.Error())
	}
	if got := (&admin.RefusedError{Message: "No."}).Error(); got != "No." {
		t.Errorf("RefusedError text %q", got)
	}
	ve := &admin.ValidationError{Fields: map[string]string{"name": "Enter a name.", "email": "x"}}
	if got := ve.Error(); !strings.Contains(got, "email") || !strings.Contains(got, "name") {
		t.Errorf("ValidationError text %q", got)
	}
}
