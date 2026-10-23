package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"latch/internal/admin"
	"latch/internal/audit"
	"latch/internal/store"
)

const msgLastAdminGroup = "This is the only admin group. Make another group an admin group first."

// errOf drops the first of two results, for checking an error inline.
func errOf[T any](_ T, err error) error { return err }

func TestCreateAndUpdateGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	a := actorFor(ada)

	if got := fields(t, errOf(svc.CreateGroup(ctx, a, admin.GroupInput{Name: "  "})))["name"]; got != "Enter a group name." {
		t.Errorf("empty name message %q", got)
	}
	if got := fields(t, errOf(svc.CreateGroup(ctx, a, admin.GroupInput{Name: "Admin"})))["name"]; got != "There's already a group with that name." {
		t.Errorf("taken name message %q", got)
	}
	if got := fields(t, errOf(svc.CreateGroup(ctx, a, admin.GroupInput{Name: strings.Repeat("g", 101)})))["name"]; got != "Use at most 100 characters." {
		t.Errorf("long name message %q", got)
	}
	if got := fields(t, errOf(svc.CreateGroup(ctx, a, admin.GroupInput{Name: "X", Description: strings.Repeat("d", 501)})))["description"]; got != "Use at most 500 characters." {
		t.Errorf("description message %q", got)
	}
	if got := fields(t, errOf(svc.CreateGroup(ctx, a, admin.GroupInput{Name: "X", Metadata: map[string]any{"n": strings.Repeat("x", 9000)}})))["metadata"]; got == "" {
		t.Error("long metadata accepted")
	}
	if n := countEvents(t, st); n != 0 {
		t.Fatalf("%d events after failures", n)
	}

	g, err := svc.CreateGroup(ctx, a, admin.GroupInput{Name: " Laser ", Description: "Cutters", RequireTOTP: true,
		Metadata: map[string]any{"room": "B"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Laser" || got.Description != "Cutters" || !got.RequireTOTP || got.IsAdmin || got.Metadata["room"] != "B" {
		t.Errorf("stored %+v", got)
	}
	if ev := oneEvent(t, st, audit.GroupCreate); ev.TargetType != "group" || ev.TargetID != g.ID || ev.ActorID != ada.ID {
		t.Errorf("create event %+v", ev)
	}

	up, err := svc.UpdateGroup(ctx, a, g.ID, admin.GroupPatch{Name: ptr("Laser Room"), IsAdmin: ptr(true),
		Metadata: ptr(map[string]any{"room": "C"})})
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "Laser Room" || !up.IsAdmin || !up.RequireTOTP || up.Description != "Cutters" {
		t.Errorf("updated %+v", up)
	}
	changed, _ := oneEvent(t, st, audit.GroupUpdate).Detail["changed"].(map[string]any)
	for _, f := range []string{"name", "is_admin", "metadata"} {
		if _, ok := changed[f]; !ok {
			t.Errorf("changed lacks %s: %v", f, changed)
		}
	}
	if m, _ := changed["metadata"].(map[string]any); len(changed) != 3 || len(m) != 0 {
		t.Errorf("changed = %v", changed)
	}

	// A taken name on update changes and records nothing.
	before := countEvents(t, st)
	_, err = svc.UpdateGroup(ctx, a, g.ID, admin.GroupPatch{Name: ptr("Admin")})
	if fields(t, err)["name"] != "There's already a group with that name." {
		t.Errorf("fields %v", fields(t, err))
	}
	// So does a patch that changes nothing.
	if _, err := svc.UpdateGroup(ctx, a, g.ID, admin.GroupPatch{Name: ptr("Laser Room")}); err != nil {
		t.Fatal(err)
	}
	if countEvents(t, st) != before {
		t.Error("events recorded for no change")
	}
	if _, err := svc.UpdateGroup(ctx, a, "nope", admin.GroupPatch{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown group: %v", err)
	}
}

func TestLastAdminGroupRefused(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, g := mkAdmin(t, st)
	a := actorFor(ada)

	_, err := svc.UpdateGroup(ctx, a, g.ID, admin.GroupPatch{IsAdmin: ptr(false)})
	if refusal(t, err) != msgLastAdminGroup {
		t.Errorf("update refusal %q", refusal(t, err))
	}
	if refusal(t, svc.DeleteGroup(ctx, a, g.ID)) != msgLastAdminGroup {
		t.Error("delete refusal differs")
	}
	got, err := st.GetGroup(ctx, g.ID)
	if err != nil || !got.IsAdmin {
		t.Errorf("group changed: %+v %v", got, err)
	}
	if n := countEvents(t, st); n != 0 {
		t.Errorf("%d events recorded", n)
	}

	// With a second admin group both are allowed.
	mkGroup(t, st, "Other admins", true)
	if _, err := svc.UpdateGroup(ctx, a, g.ID, admin.GroupPatch{IsAdmin: ptr(false)}); err != nil {
		t.Errorf("update: %v", err)
	}
}

func TestDeleteGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	laser := mkGroup(t, st, "Laser", false)
	if err := svc.DeleteGroup(ctx, actorFor(ada), laser.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetGroup(ctx, laser.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("group still there: %v", err)
	}
	ev := oneEvent(t, st, audit.GroupDelete)
	if ev.TargetID != laser.ID || ev.Detail["name"] != "Laser" {
		t.Errorf("event %+v", ev)
	}
	if err := svc.DeleteGroup(ctx, actorFor(ada), laser.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestAddRemoveGroupMember(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, admins := mkAdmin(t, st)
	a := actorFor(ada)
	laser := mkGroup(t, st, "Laser", false)
	alex := mkMember(t, st, "Alex", "alex@example.org")
	door := mkServiceAccount(t, st, "Door", "door")

	for _, u := range []string{alex.ID, door.ID} {
		if err := svc.AddToGroup(ctx, a, u, laser.ID); err != nil {
			t.Fatal(err)
		}
	}
	evs := events(t, st, audit.GroupMemberAdd)
	if len(evs) != 2 || evs[0].Detail["group_id"] != laser.ID || evs[0].Detail["group_name"] != "Laser" {
		t.Fatalf("add events %+v", evs)
	}
	// Repeating does nothing and records nothing.
	if err := svc.AddToGroup(ctx, a, alex.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	if len(events(t, st, audit.GroupMemberAdd)) != 2 {
		t.Error("repeated add recorded an event")
	}
	if err := svc.AddToGroup(ctx, a, "nope", laser.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if err := svc.AddToGroup(ctx, a, alex.ID, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown group: %v", err)
	}

	if err := svc.RemoveFromGroup(ctx, a, alex.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	if ev := oneEvent(t, st, audit.GroupMemberRemove); ev.TargetID != alex.ID || ev.Detail["group_id"] != laser.ID {
		t.Errorf("remove event %+v", ev)
	}
	if got := groupNames(t, st, alex.ID); len(got) != 0 {
		t.Errorf("alex in %v", got)
	}
	// Removing a non-member does nothing and records nothing.
	if err := svc.RemoveFromGroup(ctx, a, alex.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	if len(events(t, st, audit.GroupMemberRemove)) != 1 {
		t.Error("repeated remove recorded an event")
	}

	// Your own last admin group.
	if got := refusal(t, svc.RemoveFromGroup(ctx, a, ada.ID, admins.ID)); got != "You can't remove your own admin access. Ask another admin to do it." {
		t.Errorf("refusal %q", got)
	}
	if got := groupNames(t, st, ada.ID); len(got) != 1 {
		t.Errorf("ada in %v", got)
	}
	// Leaving a non-admin group, or removing another admin, is fine.
	if err := svc.AddToGroup(ctx, a, ada.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveFromGroup(ctx, a, ada.ID, laser.ID); err != nil {
		t.Errorf("leave non-admin group: %v", err)
	}
	bob := mkMember(t, st, "Bob", "bob@example.org", admins)
	if err := svc.RemoveFromGroup(ctx, a, bob.ID, admins.ID); err != nil {
		t.Errorf("remove other admin: %v", err)
	}
}

func TestResolveGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	laser := mkGroup(t, st, "Laser", false)
	for _, ref := range []string{laser.ID, "name:Laser"} {
		g, err := svc.ResolveGroup(ctx, ref)
		if err != nil || g.ID != laser.ID {
			t.Errorf("%q: %+v %v", ref, g, err)
		}
	}
	for _, ref := range []string{"name:nope", "nope", "Laser"} {
		if _, err := svc.ResolveGroup(ctx, ref); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%q: %v", ref, err)
		}
	}
}
