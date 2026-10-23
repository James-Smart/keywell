package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"latch/internal/model"
)

func TestUpdateGroup(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := mkGroup(t, s, "Staff")
	other := mkGroup(t, s, "Other")
	g.Name, g.Description, g.RequireTOTP = "Crew", "The crew", true
	g.Metadata = map[string]any{"k": "v"}
	if err := s.UpdateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Crew" || got.Description != "The crew" || !got.RequireTOTP || got.IsAdmin ||
		!reflect.DeepEqual(got.Metadata, map[string]any{"k": "v"}) {
		t.Fatalf("not persisted: %+v", got)
	}
	g.IsAdmin = true
	if err := s.UpdateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetGroup(ctx, g.ID); !got.IsAdmin {
		t.Fatal("is_admin not persisted")
	}
	g.Name = other.Name
	if err := s.UpdateGroup(ctx, g); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename onto existing: %v", err)
	}
	if err := s.UpdateGroup(ctx, &model.Group{ID: "nope", Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestLastAdminGroupGuards(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	admin := &model.Group{Name: "Admin", IsAdmin: true}
	if err := s.CreateGroup(ctx, admin); err != nil {
		t.Fatal(err)
	}
	edit := *admin
	edit.IsAdmin, edit.Description = false, "changed"
	if err := s.UpdateGroup(ctx, &edit); !errors.Is(err, ErrLastAdminGroup) {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetGroup(ctx, admin.ID)
	if !got.IsAdmin || got.Description != "" {
		t.Fatalf("row changed: %+v", got)
	}
	// Keeping is_admin while editing other fields is fine.
	keep := *admin
	keep.Description = "ok"
	if err := s.UpdateGroup(ctx, &keep); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, admin.ID); !errors.Is(err, ErrLastAdminGroup) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetGroup(ctx, admin.ID); err != nil {
		t.Fatal("group gone")
	}

	second := &model.Group{Name: "Admin2", IsAdmin: true}
	if err := s.CreateGroup(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateGroup(ctx, &edit); err != nil {
		t.Fatalf("update with second admin: %v", err)
	}
	if err := s.DeleteGroup(ctx, second.ID); !errors.Is(err, ErrLastAdminGroup) {
		t.Fatalf("second is now the last: %v", err)
	}
	plain := mkGroup(t, s, "Plain")
	if err := s.DeleteGroup(ctx, plain.ID); err != nil {
		t.Fatalf("non-admin delete: %v", err)
	}
	// Make admin an admin group again so deleting it has another to rely on.
	edit.IsAdmin = true
	if err := s.UpdateGroup(ctx, &edit); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, admin.ID); err != nil {
		t.Fatalf("delete with another admin: %v", err)
	}
	if err := s.DeleteGroup(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestDeleteGroupCascades(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := mkGroup(t, s, "G")
	other := mkGroup(t, s, "H")
	u := mkUser(t, s, "u@example.org")
	if err := s.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	a := &model.Application{Name: "A", Slug: "a", ClientID: "a", AllowedGroupIDs: []string{g.ID, other.ID}}
	if err := s.CreateApplication(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM memberships WHERE group_id = ?`,
		`SELECT COUNT(*) FROM application_groups WHERE group_id = ?`,
	} {
		var n int
		if err := s.db.QueryRow(q, g.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: n=%d err=%v", q, n, err)
		}
	}
	if got, _ := s.GetApplication(ctx, a.ID); !reflect.DeepEqual(got.AllowedGroupIDs, []string{other.ID}) {
		t.Fatalf("app groups: %v, want only %s", got.AllowedGroupIDs, other.ID)
	}
}

// Ruling 14: a group that is the only one an application lets in is not
// deleted, as the application would then let in every member. The check
// and the delete are one statement.
func TestDeleteGroupSoleAppGroupGuard(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := mkGroup(t, s, "G")
	a := &model.Application{Name: "A", Slug: "a", ClientID: "a", AllowedGroupIDs: []string{g.ID}}
	if err := s.CreateApplication(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, g.ID); !errors.Is(err, ErrSoleAppGroup) {
		t.Fatalf("delete: %v, want ErrSoleAppGroup", err)
	}
	if _, err := s.GetGroup(ctx, g.ID); err != nil {
		t.Fatalf("group gone: %v", err)
	}
	if got, _ := s.GetApplication(ctx, a.ID); !reflect.DeepEqual(got.AllowedGroupIDs, []string{g.ID}) {
		t.Fatalf("app groups: %v", got.AllowedGroupIDs)
	}

	// The last admin group is still told apart.
	admin := &model.Group{Name: "Admin", IsAdmin: true}
	if err := s.CreateGroup(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, admin.ID); !errors.Is(err, ErrLastAdminGroup) {
		t.Fatalf("last admin group: %v", err)
	}

	// With another group allowed in, it can go.
	a.AllowedGroupIDs = []string{g.ID, admin.ID}
	if err := s.UpdateApplication(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("delete alongside another group: %v", err)
	}
}

func TestListGroupsWithCounts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	b, a, empty := mkGroup(t, s, "B"), mkGroup(t, s, "A"), mkGroup(t, s, "Empty")
	m := mkUser(t, s, "m@example.org")
	svc := &model.User{Name: "svc", Type: model.UserTypeService, IsActive: true}
	if err := s.CreateUser(ctx, svc); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{m.ID, a.ID}, {svc.ID, a.ID}, {m.ID, b.ID}} {
		if err := s.AddMember(ctx, p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListGroupsWithCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	counts := map[string]int{}
	for _, r := range rows {
		got = append(got, r.Name)
		counts[r.Name] = r.MemberCount
	}
	if !reflect.DeepEqual(got, []string{"A", "B", "Empty"}) {
		t.Fatalf("order: %v", got)
	}
	if counts["A"] != 2 || counts["B"] != 1 || counts[empty.Name] != 0 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestReplaceUserGroups(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	a, b, c := mkGroup(t, s, "A"), mkGroup(t, s, "B"), mkGroup(t, s, "C")
	u := mkUser(t, s, "u@example.org")
	names := func() []string {
		gs, err := s.ListGroupsForUser(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, g := range gs {
			out = append(out, g.Name)
		}
		return out
	}
	if err := s.ReplaceUserGroups(ctx, u.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if got := names(); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("got %v", got)
	}
	if err := s.ReplaceUserGroups(ctx, u.ID, []string{b.ID, c.ID, c.ID}); err != nil {
		t.Fatal(err)
	}
	if got := names(); !reflect.DeepEqual(got, []string{"B", "C"}) {
		t.Fatalf("got %v", got)
	}
	if err := s.ReplaceUserGroups(ctx, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if err := s.ReplaceUserGroups(ctx, u.ID, []string{b.ID, "no-such-id"}); err == nil {
		t.Fatal("unknown group accepted")
	}
	if got := names(); len(got) != 0 {
		t.Fatalf("memberships changed on failure: %v", got)
	}
}
