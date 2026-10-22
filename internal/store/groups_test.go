package store

import (
	"context"
	"errors"
	"testing"

	"latch/internal/model"
)

func TestGroupsAndMembership(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "A", Email: "a@example.org"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	zed := &model.Group{Name: "zed", IsAdmin: true, Metadata: map[string]any{"x": 1}}
	alpha := &model.Group{Name: "alpha", Description: "first", RequireTOTP: true}
	for _, g := range []*model.Group{zed, alpha} {
		if err := s.CreateGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
		if g.ID == "" || g.CreatedAt.IsZero() {
			t.Fatalf("not filled: %+v", g)
		}
	}
	if err := s.CreateGroup(ctx, &model.Group{Name: "zed"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	for i := 0; i < 2; i++ {
		for _, g := range []*model.Group{zed, alpha} {
			if err := s.AddMember(ctx, u.ID, g.ID); err != nil {
				t.Fatalf("add member (round %d): %v", i, err)
			}
		}
	}
	gs, err := s.ListGroupsForUser(ctx, u.ID)
	if err != nil || len(gs) != 2 || gs[0].Name != "alpha" || gs[1].Name != "zed" {
		t.Fatalf("groups %+v err %v", gs, err)
	}
	if !gs[0].RequireTOTP || gs[0].IsAdmin || !gs[1].IsAdmin || gs[0].Description != "first" {
		t.Fatalf("flags wrong: %+v", gs)
	}
	all, err := s.ListGroups(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list %+v err %v", all, err)
	}
	if err := s.RemoveMember(ctx, u.ID, zed.ID); err != nil {
		t.Fatal(err)
	}
	if gs, _ = s.ListGroupsForUser(ctx, u.ID); len(gs) != 1 || gs[0].Name != "alpha" {
		t.Fatalf("after remove %+v", gs)
	}
	got, err := s.GetGroupByName(ctx, "zed")
	if err != nil || got.ID != zed.ID || !jsonEqual(got.Metadata, map[string]any{"x": 1}) {
		t.Fatalf("by name %+v err %v", got, err)
	}
	if got, err = s.GetGroup(ctx, alpha.ID); err != nil || got.Name != "alpha" {
		t.Fatalf("get %+v err %v", got, err)
	}
	if _, err := s.GetGroupByName(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetGroup(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDeleteUserCascadesMembership(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := &model.User{Name: "A", Email: "a@example.org"}
	g := &model.Group{Name: "g"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM memberships`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("memberships remain: %d %v", n, err)
	}
}
