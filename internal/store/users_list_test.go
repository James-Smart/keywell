package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/model"
)

// mkMember creates a member with the given name, email and username.
func mkMember(t *testing.T, s *Store, name, email, username string, mod func(*model.User)) *model.User {
	t.Helper()
	u := &model.User{Name: name, Email: email, Username: username, IsActive: true}
	if mod != nil {
		mod(u)
	}
	if err := s.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// statusFixture creates one user of each derived status, plus a service
// account, keyed by status ("service" for the account).
func statusFixture(t *testing.T, s *Store) map[model.UserStatus]*model.User {
	t.Helper()
	now := time.Now()
	hash := func(u *model.User) { u.PasswordHash = "$argon2id$x" }
	active := mkMember(t, s, "A Active", "active@example.org", "", hash)
	invited := mkMember(t, s, "B Invited", "invited@example.org", "", nil)
	mkReset(t, s, "inv", invited.ID, model.ResetPurposeInvite, now.Add(24*time.Hour))
	needs := mkMember(t, s, "C Needs", "needs@example.org", "", nil)
	mkReset(t, s, "old", needs.ID, model.ResetPurposeInvite, now.Add(-24*time.Hour))
	disabled := mkMember(t, s, "D Disabled", "disabled@example.org", "", func(u *model.User) {
		hash(u)
		u.IsActive = false
	})
	svc := mkService(t, s, "svc")
	return map[model.UserStatus]*model.User{
		model.UserStatusActive: active, model.UserStatusInvited: invited,
		model.UserStatusNeedsPassword: needs, model.UserStatusDisabled: disabled, "service": svc,
	}
}

func TestListUsersStatus(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	fx := statusFixture(t, s)
	page, err := s.ListUsers(ctx, UserFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || len(page.Rows) != 5 {
		t.Fatalf("total %d rows %d", page.Total, len(page.Rows))
	}
	want := map[string]model.UserStatus{
		fx[model.UserStatusActive].ID:        model.UserStatusActive,
		fx[model.UserStatusInvited].ID:       model.UserStatusInvited,
		fx[model.UserStatusNeedsPassword].ID: model.UserStatusNeedsPassword,
		fx[model.UserStatusDisabled].ID:      model.UserStatusDisabled,
		fx["service"].ID:                     model.UserStatusActive,
	}
	for _, r := range page.Rows {
		if r.Status != want[r.ID] {
			t.Errorf("%s: status %q, want %q", r.Name, r.Status, want[r.ID])
		}
	}
}

func TestGetUserStatusMatchesList(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	statusFixture(t, s)
	page, err := s.ListUsers(ctx, UserFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Rows {
		u, err := s.GetUser(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.GetUserStatus(ctx, u)
		if err != nil || got != r.Status {
			t.Errorf("%s: GetUserStatus %q, %v; list says %q", r.Name, got, err, r.Status)
		}
	}
}

func names(p UserPage) []string {
	var out []string
	for _, r := range p.Rows {
		out = append(out, r.Name)
	}
	return out
}

func TestListUsersFilters(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	fx := statusFixture(t, s)

	list := func(f UserFilter) UserPage {
		t.Helper()
		p, err := s.ListUsers(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := list(UserFilter{Type: model.UserTypeMember}); p.Total != 4 {
		t.Errorf("members: %v", names(p))
	}
	if p := list(UserFilter{Type: model.UserTypeService}); p.Total != 1 || p.Rows[0].ID != fx["service"].ID {
		t.Errorf("service: %v", names(p))
	}
	for _, st := range []model.UserStatus{model.UserStatusActive, model.UserStatusInvited, model.UserStatusNeedsPassword, model.UserStatusDisabled} {
		p := list(UserFilter{Type: model.UserTypeMember, Status: string(st)})
		if p.Total != 1 || p.Rows[0].ID != fx[st].ID {
			t.Errorf("status %s: %v", st, names(p))
		}
	}

	// no_2fa leaves out an enrolled member.
	at := time.Now()
	if err := s.SetTOTP(ctx, fx[model.UserStatusActive].ID, []byte("s"), &at); err != nil {
		t.Fatal(err)
	}
	p := list(UserFilter{Type: model.UserTypeMember, Status: "no_2fa"})
	if p.Total != 3 {
		t.Errorf("no_2fa: %v", names(p))
	}
	for _, r := range p.Rows {
		if r.ID == fx[model.UserStatusActive].ID {
			t.Errorf("no_2fa includes the enrolled member")
		}
	}

	// admins and group
	admin := &model.Group{Name: "Admin", IsAdmin: true}
	plain := &model.Group{Name: "Plain"}
	for _, g := range []*model.Group{admin, plain} {
		if err := s.CreateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddMember(ctx, fx[model.UserStatusInvited].ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, fx[model.UserStatusNeedsPassword].ID, plain.ID); err != nil {
		t.Fatal(err)
	}
	if p := list(UserFilter{Status: "admins"}); p.Total != 1 || p.Rows[0].ID != fx[model.UserStatusInvited].ID {
		t.Errorf("admins: %v", names(p))
	}
	if p := list(UserFilter{GroupID: plain.ID}); p.Total != 1 || p.Rows[0].ID != fx[model.UserStatusNeedsPassword].ID {
		t.Errorf("group: %v", names(p))
	}
}

func TestListUsersQuery(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	mkMember(t, s, "Alex Rivera", "x1@example.org", "u1", nil)
	mkMember(t, s, "Other", "alex@example.org", "u2", nil)
	mkMember(t, s, "Third", "x3@example.org", "alexr", nil)
	mkMember(t, s, "Nobody", "nobody@example.org", "nobody", nil)
	mkMember(t, s, "50% Club", "c1@example.org", "c1", nil)
	mkMember(t, s, "500 Club", "c2@example.org", "c2", nil)
	mkMember(t, s, "a_b", "u3@example.org", "u3", nil)
	mkMember(t, s, "axb", "u4@example.org", "u4", nil)

	q := func(query string) UserPage {
		t.Helper()
		p, err := s.ListUsers(ctx, UserFilter{Query: query})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := q("ALEX"); p.Total != 3 {
		t.Errorf("ALEX: %v", names(p))
	}
	if p := q("50%"); p.Total != 1 || p.Rows[0].Name != "50% Club" {
		t.Errorf("50%%: %v", names(p))
	}
	if p := q("a_b"); p.Total != 1 || p.Rows[0].Name != "a_b" {
		t.Errorf("a_b: %v", names(p))
	}
	if p := q(`\`); p.Total != 0 {
		t.Errorf("backslash: %v", names(p))
	}
}

func TestListUsersPaging(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for i := 0; i < 120; i++ {
		name := fmt.Sprintf("member %03d", i)
		if i == 77 {
			name = "AAA first" // sorts by NOCASE name, not byte value
		}
		if i == 78 {
			name = "bbb second"
		}
		mkMember(t, s, name, fmt.Sprintf("m%d@example.org", i), "", nil)
	}
	p, err := s.ListUsers(ctx, UserFilter{Type: model.UserTypeMember})
	if err != nil || len(p.Rows) != 50 || p.Total != 120 || p.PerPage != 50 || p.Page != 1 {
		t.Fatalf("page 1: %d rows, total %d, per %d, %v", len(p.Rows), p.Total, p.PerPage, err)
	}
	if p.Rows[0].Name != "AAA first" || p.Rows[1].Name != "bbb second" {
		t.Errorf("order: %v", names(p)[:3])
	}
	if p, _ = s.ListUsers(ctx, UserFilter{Page: 3}); len(p.Rows) != 20 {
		t.Errorf("page 3: %d rows", len(p.Rows))
	}
	if p, _ = s.ListUsers(ctx, UserFilter{Page: 9}); len(p.Rows) != 0 || p.Total != 120 {
		t.Errorf("page 9: %d rows, total %d", len(p.Rows), p.Total)
	}
	if p, _ = s.ListUsers(ctx, UserFilter{PerPage: 1000}); p.PerPage != 500 || len(p.Rows) != 120 {
		t.Errorf("per page cap: %d, %d rows", p.PerPage, len(p.Rows))
	}
}

func TestListUsersGroupsAndTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	m := mkMember(t, s, "Member", "m@example.org", "", nil)
	plain := mkMember(t, s, "Plain", "p@example.org", "", nil)
	zeta, alpha := mkGroup(t, s, "Zeta"), mkGroup(t, s, "Alpha")
	adm := &model.Group{Name: "Mid", IsAdmin: true}
	if err := s.CreateGroup(ctx, adm); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*model.Group{zeta, alpha, adm} {
		if err := s.AddMember(ctx, m.ID, g.ID); err != nil {
			t.Fatal(err)
		}
	}
	svc := mkService(t, s, "svc")
	yesterday := time.Now().Add(-24 * time.Hour).UTC()
	hourAgo := time.Now().Add(-time.Hour).UTC()
	for i, at := range []time.Time{yesterday, hourAgo} {
		tok := &model.APIToken{ServiceAccountID: svc.ID, Label: "t", TokenHash: fmt.Sprintf("h%d", i), Scope: model.APITokenScopeRead}
		if err := s.CreateAPIToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if err := s.TouchAPIToken(ctx, tok.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.ListUsers(ctx, UserFilter{})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]UserRow{}
	for _, r := range p.Rows {
		rows[r.ID] = r
	}
	r := rows[m.ID]
	if len(r.Groups) != 3 || r.Groups[0].Name != "Alpha" || r.Groups[1].Name != "Mid" || r.Groups[2].Name != "Zeta" || !r.IsAdmin {
		t.Errorf("member groups %+v admin %v", r.Groups, r.IsAdmin)
	}
	if r := rows[plain.ID]; len(r.Groups) != 0 || r.IsAdmin {
		t.Errorf("plain: %+v", r)
	}
	r = rows[svc.ID]
	if r.TokenCount != 2 || r.TokenLastUsed == nil || !r.TokenLastUsed.Equal(hourAgo) {
		t.Errorf("service tokens %d, last used %v", r.TokenCount, r.TokenLastUsed)
	}
}
