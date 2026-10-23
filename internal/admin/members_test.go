package admin_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"latch/internal/admin"
	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/store"
)

func TestCreateMemberInvite(t *testing.T) {
	ctx := context.Background()
	svc, st, n := newService(t)
	ada, _ := mkAdmin(t, st)
	laser := mkGroup(t, st, "Laser", false)

	u, err := svc.CreateMember(ctx, actorFor(ada), admin.NewMember{
		Name: " Alex Rivera ", Email: " alex@example.org ", Username: "alex", GroupIDs: []string{laser.ID}, Invite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsActive || got.Type != model.UserTypeMember || got.Name != "Alex Rivera" || got.Email != "alex@example.org" ||
		got.Username != "alex" || got.HasPassword() {
		t.Errorf("stored %+v", got)
	}
	if got.Metadata == nil || len(got.Metadata) != 0 {
		t.Errorf("metadata %v, want {}", got.Metadata)
	}
	if names := groupNames(t, st, u.ID); !reflect.DeepEqual(names, []string{"Laser"}) {
		t.Errorf("groups %v", names)
	}
	if calls := n.Calls(); !reflect.DeepEqual(calls, []notification{{u.ID, model.ResetPurposeInvite}}) {
		t.Errorf("notifier calls %+v", calls)
	}
	for _, action := range []string{audit.UserCreate, audit.UserInvite} {
		ev := oneEvent(t, st, action)
		if ev.ActorType != model.ActorUser || ev.ActorID != ada.ID || ev.TargetType != "user" || ev.TargetID != u.ID ||
			!strings.Contains(ev.Summary, "Alex Rivera") {
			t.Errorf("%s: %+v", action, ev)
		}
	}
	if ev := oneEvent(t, st, audit.UserCreate); !reflect.DeepEqual(ev.Detail["groups"], []any{"Laser"}) ||
		ev.Detail["email"] != "alex@example.org" {
		t.Errorf("create detail %v", ev.Detail)
	}
	// Each group joined is also an event of its own, as when groups change
	// later, so ?action=group.member. finds every grant.
	if ev := oneEvent(t, st, audit.GroupMemberAdd); ev.TargetID != u.ID || ev.ActorID != ada.ID ||
		ev.Detail["group_id"] != laser.ID || ev.Detail["group_name"] != "Laser" || ev.Summary != "Added Alex Rivera to Laser" {
		t.Errorf("group.member.add on create: %+v", ev)
	}
}

// Joining an admin group on create says so in the summary.
func TestCreateMemberInAdminGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, admins := mkAdmin(t, st)
	laser := mkGroup(t, st, "Laser", false)
	u, err := svc.CreateMember(ctx, actorFor(ada), admin.NewMember{Name: "Sam Lee", Email: "sam@example.org",
		GroupIDs: []string{admins.ID, laser.ID}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, ev := range events(t, st, audit.GroupMemberAdd) {
		if ev.TargetID != u.ID {
			t.Errorf("event about %s, want %s", ev.TargetID, u.ID)
		}
		got[ev.Detail["group_name"].(string)] = ev.Summary
	}
	want := map[string]string{"Admin": "Added Sam Lee to admin group Admin", "Laser": "Added Sam Lee to Laser"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("summaries %v, want %v", got, want)
	}
}

func TestCreateMemberWithPassword(t *testing.T) {
	ctx := context.Background()
	svc, st, n := newService(t)
	ada, _ := mkAdmin(t, st)
	u, err := svc.CreateMember(ctx, actorFor(ada), admin.NewMember{
		Name: "Sam Lee", Email: "sam@example.org", Password: "correct horse battery",
		Metadata: map[string]any{"member_number": 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetUser(ctx, u.ID)
	if ok, err := password.Verify("correct horse battery", got.PasswordHash); !ok || err != nil {
		t.Errorf("password does not verify: %v", err)
	}
	if got.Metadata["member_number"] != float64(42) {
		t.Errorf("metadata %v", got.Metadata)
	}
	if calls := n.Calls(); len(calls) != 0 {
		t.Errorf("notifier called: %+v", calls)
	}
	if status, err := st.GetUserStatus(ctx, got); err != nil || status != model.UserStatusActive {
		t.Errorf("status %q, %v", status, err)
	}
	if evs := events(t, st, audit.UserInvite); len(evs) != 0 {
		t.Errorf("invite recorded: %+v", evs)
	}
	// Without a password or invitation, they need a password.
	u2, err := svc.CreateMember(ctx, actorFor(ada), admin.NewMember{Name: "Kim Ito", Email: "kim@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := st.GetUserStatus(ctx, u2); status != model.UserStatusNeedsPassword {
		t.Errorf("no-password status %q", status)
	}
}

func TestCreateMemberValidation(t *testing.T) {
	ctx := context.Background()
	svc, st, n := newService(t)
	ada, _ := mkAdmin(t, st)
	existing := mkMember(t, st, "Alex Rivera", "alex@example.org")
	existing.Username = "alex"
	if err := st.UpdateUser(ctx, existing); err != nil {
		t.Fatal(err)
	}
	valid := admin.NewMember{Name: "Sam Lee", Email: "sam@example.org"}
	cases := []struct {
		name  string
		edit  func(*admin.NewMember)
		field string
		msg   string
	}{
		{"empty name", func(m *admin.NewMember) { m.Name = "" }, "name", "Enter a name."},
		{"blank name", func(m *admin.NewMember) { m.Name = "   " }, "name", "Enter a name."},
		{"long name", func(m *admin.NewMember) { m.Name = strings.Repeat("n", 201) }, "name", "Use at most 200 characters."},
		{"no at", func(m *admin.NewMember) { m.Email = "alex" }, "email", "Enter an email address, like alex@example.org."},
		{"empty email", func(m *admin.NewMember) { m.Email = "" }, "email", "Enter an email address, like alex@example.org."},
		{"two ats", func(m *admin.NewMember) { m.Email = "a@b@example.org" }, "email", "Enter an email address, like alex@example.org."},
		{"nothing before at", func(m *admin.NewMember) { m.Email = "@example.org" }, "email", "Enter an email address, like alex@example.org."},
		{"nothing after at", func(m *admin.NewMember) { m.Email = "sam@" }, "email", "Enter an email address, like alex@example.org."},
		{"space in email", func(m *admin.NewMember) { m.Email = "sam lee@example.org" }, "email", "Enter an email address, like alex@example.org."},
		{"long email", func(m *admin.NewMember) { m.Email = strings.Repeat("s", 243) + "@example.org" }, "email",
			"Enter an email address, like alex@example.org."},
		// Review Focus 1: the same address in another case.
		{"email taken in another case", func(m *admin.NewMember) { m.Email = "ALEX@example.org" }, "email",
			"Another member already uses that email address."},
		{"username taken", func(m *admin.NewMember) { m.Username = "alex" }, "username", "That username is taken."},
		{"space in username", func(m *admin.NewMember) { m.Username = "sam lee" }, "username", "Usernames can't contain spaces."},
		{"long username", func(m *admin.NewMember) { m.Username = strings.Repeat("u", 151) }, "username", "Use at most 150 characters."},
		{"short password", func(m *admin.NewMember) { m.Password = "short" }, "password", "Use at least 10 characters."},
		{"common password", func(m *admin.NewMember) { m.Password = "password123" }, "password",
			"That password is too common. Pick something less guessable."},
		{"long metadata", func(m *admin.NewMember) { m.Metadata = map[string]any{"notes": strings.Repeat("x", 9000)} }, "metadata",
			"Metadata is too long. Keep it under 8 KB."},
		{"unknown group", func(m *admin.NewMember) { m.GroupIDs = []string{"nope"} }, "groups", "That group no longer exists."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := valid
			c.edit(&in)
			before := countEvents(t, st)
			u, err := svc.CreateMember(ctx, actorFor(ada), in)
			if u != nil {
				t.Errorf("returned a user: %+v", u)
			}
			if got := fields(t, err)[c.field]; got != c.msg {
				t.Errorf("Fields[%q] = %q, want %q (all: %v)", c.field, got, c.msg, fields(t, err))
			}
			page, err := st.ListUsers(ctx, store.UserFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != 2 {
				t.Errorf("%d users stored, want 2", page.Total)
			}
			if after := countEvents(t, st); after != before {
				t.Errorf("recorded %d events", after-before)
			}
		})
	}
	// The password is checked only when it will be used.
	in := valid
	in.Invite, in.Password = true, "short"
	if _, err := svc.CreateMember(ctx, actorFor(ada), in); err != nil {
		t.Errorf("invite with an unused short password: %v", err)
	}
	if len(n.Calls()) != 1 {
		t.Errorf("notifier calls %+v", n.Calls())
	}
}

func TestCreateMemberInviteEmailFails(t *testing.T) {
	ctx := context.Background()
	smtpDown := errors.New("smtp down")
	svc, st, _ := newService(t, withNotifyError(smtpDown))
	ada, _ := mkAdmin(t, st)
	u, err := svc.CreateMember(ctx, actorFor(ada), admin.NewMember{Name: "Alex Rivera", Email: "alex@example.org", Invite: true})
	if u == nil {
		t.Fatal("no user returned")
	}
	var ee *admin.EmailError
	if !errors.As(err, &ee) || !errors.Is(err, smtpDown) {
		t.Fatalf("err %T %v, want *admin.EmailError wrapping the notifier's error", err, err)
	}
	if _, err := st.GetUser(ctx, u.ID); err != nil {
		t.Fatalf("user not stored: %v", err)
	}
	oneEvent(t, st, audit.UserCreate)
	// Ruling 16: the attempt is recorded, saying the email wasn't sent, and
	// the member still needs a password rather than showing as invited.
	ev := oneEvent(t, st, audit.UserInvite)
	if ev.TargetID != u.ID || ev.ActorID != ada.ID || ev.Detail["email_sent"] != false ||
		ev.Summary != "Tried to email Alex Rivera an invitation, but it wasn't sent" {
		t.Errorf("invite event %+v", ev)
	}
	if status, err := st.GetUserStatus(ctx, u); err != nil || status != model.UserStatusNeedsPassword {
		t.Errorf("status %q, %v, want needs_password", status, err)
	}
}

func TestUpdateMember(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	members := mkGroup(t, st, "Members", false)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org", members)
	alex.Username, alex.Metadata = "alex", map[string]any{"member_number": 42}
	if err := st.UpdateUser(ctx, alex); err != nil {
		t.Fatal(err)
	}

	got, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		Name: ptr("Alex Rivera-Smith"), Email: ptr(" alex.rs@example.org "),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Alex Rivera-Smith" || got.Email != "alex.rs@example.org" {
		t.Errorf("returned %+v", got)
	}
	stored, _ := st.GetUser(ctx, alex.ID)
	if stored.Name != "Alex Rivera-Smith" || stored.Email != "alex.rs@example.org" || stored.Username != "alex" ||
		stored.Metadata["member_number"] != float64(42) || !stored.IsActive {
		t.Errorf("stored %+v", stored)
	}
	if names := groupNames(t, st, alex.ID); !reflect.DeepEqual(names, []string{"Members"}) {
		t.Errorf("groups %v", names)
	}
	ev := oneEvent(t, st, audit.UserUpdate)
	wantChanged := map[string]any{
		"name":  map[string]any{"from": "Alex Rivera", "to": "Alex Rivera-Smith"},
		"email": map[string]any{"from": "alex@example.org", "to": "alex.rs@example.org"},
	}
	if !reflect.DeepEqual(ev.Detail["changed"], wantChanged) || ev.TargetID != alex.ID || ev.ActorID != ada.ID {
		t.Errorf("update event %+v", ev)
	}

	// Metadata changes are recorded without their values.
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		Metadata: ptr(map[string]any{"member_number": 43}),
	}); err != nil {
		t.Fatal(err)
	}
	evs := events(t, st, audit.UserUpdate)
	if len(evs) != 2 || !reflect.DeepEqual(evs[0].Detail["changed"], map[string]any{"metadata": map[string]any{}}) {
		t.Errorf("metadata event %+v", evs)
	}
	if stored, _ := st.GetUser(ctx, alex.ID); stored.Metadata["member_number"] != float64(43) {
		t.Errorf("metadata %v", stored.Metadata)
	}

	// Saving the same values changes nothing and records nothing.
	before := countEvents(t, st)
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		Name: ptr("Alex Rivera-Smith"), Email: ptr("alex.rs@example.org"), Username: ptr("alex"),
		Metadata: ptr(map[string]any{"member_number": 43}), GroupIDs: ptr([]string{members.ID}), IsActive: ptr(true),
	}); err != nil {
		t.Fatal(err)
	}
	if after := countEvents(t, st); after != before {
		t.Errorf("no-op save recorded %d events", after-before)
	}

	// "" clears the username.
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{Username: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := st.GetUser(ctx, alex.ID); stored.Username != "" {
		t.Errorf("username %q, want cleared", stored.Username)
	}
}

func TestUpdateMemberValidation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	sam := mkMember(t, st, "Sam Lee", "sam@example.org")
	sam.Username = "sam"
	if err := st.UpdateUser(ctx, sam); err != nil {
		t.Fatal(err)
	}
	// Each patch also makes a valid change, which must not be saved either.
	changed := ptr("Changed Name")
	cases := []struct {
		name  string
		patch admin.MemberPatch
		field string
		msg   string
	}{
		{"empty name", admin.MemberPatch{Name: ptr(" "), Email: ptr("changed@example.org")}, "name", "Enter a name."},
		{"bad email", admin.MemberPatch{Name: changed, Email: ptr("alex")}, "email", "Enter an email address, like alex@example.org."},
		{"email taken", admin.MemberPatch{Name: changed, Email: ptr("SAM@example.org")}, "email",
			"Another member already uses that email address."},
		{"username taken", admin.MemberPatch{Name: changed, Username: ptr("sam")}, "username", "That username is taken."},
		{"long metadata", admin.MemberPatch{Name: changed, Metadata: ptr(map[string]any{"x": strings.Repeat("x", 9000)})}, "metadata",
			"Metadata is too long. Keep it under 8 KB."},
		{"unknown group", admin.MemberPatch{Name: changed, GroupIDs: ptr([]string{"nope"})}, "groups", "That group no longer exists."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := countEvents(t, st)
			_, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, c.patch)
			if got := fields(t, err)[c.field]; got != c.msg {
				t.Errorf("Fields[%q] = %q, want %q", c.field, got, c.msg)
			}
			if stored, _ := st.GetUser(ctx, alex.ID); stored.Name != "Alex Rivera" || stored.Email != "alex@example.org" {
				t.Errorf("changed: %+v", stored)
			}
			if after := countEvents(t, st); after != before {
				t.Errorf("recorded %d events", after-before)
			}
		})
	}
	// Keeping your own email is not a clash.
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{Email: ptr("ALEX@example.org")}); err != nil {
		t.Errorf("own email in another case: %v", err)
	}
}

func TestUpdateMemberGroups(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	members, laser, woodshop := mkGroup(t, st, "Members", false), mkGroup(t, st, "Laser", false), mkGroup(t, st, "Woodshop", false)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org", members, laser)

	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		GroupIDs: ptr([]string{members.ID, woodshop.ID}),
	}); err != nil {
		t.Fatal(err)
	}
	if names := groupNames(t, st, alex.ID); !reflect.DeepEqual(names, []string{"Members", "Woodshop"}) {
		t.Errorf("groups %v", names)
	}
	rm := oneEvent(t, st, audit.GroupMemberRemove)
	if rm.TargetType != "user" || rm.TargetID != alex.ID || rm.Detail["group_id"] != laser.ID || rm.Detail["group_name"] != "Laser" ||
		rm.Summary != "Removed Alex Rivera from Laser" {
		t.Errorf("remove event %+v", rm)
	}
	add := oneEvent(t, st, audit.GroupMemberAdd)
	if add.TargetType != "user" || add.TargetID != alex.ID || add.Detail["group_id"] != woodshop.ID || add.Detail["group_name"] != "Woodshop" ||
		add.Summary != "Added Alex Rivera to Woodshop" {
		t.Errorf("add event %+v", add)
	}
	if evs := events(t, st, audit.UserUpdate); len(evs) != 0 {
		t.Errorf("group change recorded as user.update: %+v", evs)
	}
	// Duplicate IDs are one membership.
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		GroupIDs: ptr([]string{laser.ID, laser.ID}),
	}); err != nil {
		t.Fatal(err)
	}
	if names := groupNames(t, st, alex.ID); !reflect.DeepEqual(names, []string{"Laser"}) {
		t.Errorf("groups %v", names)
	}
	if n := len(events(t, st, audit.GroupMemberAdd)); n != 2 {
		t.Errorf("%d add events, want 2", n)
	}
}

func TestDisableAndEnable(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	sess, refresh := addSession(t, st, alex.ID), addRefreshToken(t, st, alex.ID)

	got, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{IsActive: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if got.IsActive {
		t.Error("returned user still active")
	}
	stored, _ := st.GetUser(ctx, alex.ID)
	if stored.IsActive {
		t.Error("stored user still active")
	}
	assertSignedOut(t, st, sess, refresh)
	if ev := oneEvent(t, st, audit.UserDisable); ev.TargetID != alex.ID || ev.ActorID != ada.ID {
		t.Errorf("disable event %+v", ev)
	}
	if evs := events(t, st, audit.UserUpdate); len(evs) != 0 {
		t.Errorf("disable also recorded user.update: %+v", evs)
	}

	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{IsActive: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := st.GetUser(ctx, alex.ID); !stored.IsActive {
		t.Error("not enabled")
	}
	if ev := oneEvent(t, st, audit.UserEnable); ev.TargetID != alex.ID {
		t.Errorf("enable event %+v", ev)
	}

	// A patch that disables and edits records both.
	if _, err := svc.UpdateMember(ctx, actorFor(ada), alex.ID, admin.MemberPatch{
		Name: ptr("Alex R"), IsActive: ptr(false),
	}); err != nil {
		t.Fatal(err)
	}
	if n := len(events(t, st, audit.UserDisable)); n != 2 {
		t.Errorf("%d disable events, want 2", n)
	}
	ev := oneEvent(t, st, audit.UserUpdate)
	if _, ok := ev.Detail["changed"].(map[string]any)["name"]; !ok {
		t.Errorf("update event %+v", ev)
	}
}

func TestSelfProtection(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, adminGroup := mkAdmin(t, st)
	laser := mkGroup(t, st, "Laser", false)
	if err := st.AddMember(ctx, ada.ID, laser.ID); err != nil {
		t.Fatal(err)
	}
	self := actorFor(ada)
	const (
		noDisable = "You can't disable your own account."
		noDelete  = "You can't delete your own account."
		noAdmin   = "You can't remove your own admin access. Ask another admin to do it."
	)
	before := countEvents(t, st)

	_, err := svc.UpdateMember(ctx, self, ada.ID, admin.MemberPatch{IsActive: ptr(false), Name: ptr("Ada Changed")})
	if msg := refusal(t, err); msg != noDisable {
		t.Errorf("disable: %q", msg)
	}
	if err := svc.DeleteMember(ctx, self, ada.ID); refusal(t, err) != noDelete {
		t.Errorf("delete: %v", err)
	}
	_, err = svc.UpdateMember(ctx, self, ada.ID, admin.MemberPatch{GroupIDs: ptr([]string{laser.ID}), Name: ptr("Ada Changed")})
	if msg := refusal(t, err); msg != noAdmin {
		t.Errorf("groups: %q", msg)
	}
	_, err = svc.UpdateMember(ctx, self, ada.ID, admin.MemberPatch{GroupIDs: ptr([]string{})})
	if msg := refusal(t, err); msg != noAdmin {
		t.Errorf("no groups: %q", msg)
	}
	stored, err := st.GetUser(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.IsActive || stored.Name != "Ada Admin" {
		t.Errorf("changed: %+v", stored)
	}
	if names := groupNames(t, st, ada.ID); !reflect.DeepEqual(names, []string{"Admin", "Laser"}) {
		t.Errorf("groups %v", names)
	}
	if after := countEvents(t, st); after != before {
		t.Errorf("refusals recorded %d events", after-before)
	}

	// Moving to another admin group keeps admin access, so it is allowed.
	admin2 := mkGroup(t, st, "Admin2", true)
	if _, err := svc.UpdateMember(ctx, self, ada.ID, admin.MemberPatch{GroupIDs: ptr([]string{admin2.ID})}); err != nil {
		t.Errorf("move to another admin group: %v", err)
	}
	if _, err := svc.UpdateMember(ctx, self, ada.ID, admin.MemberPatch{GroupIDs: ptr([]string{adminGroup.ID, laser.ID})}); err != nil {
		t.Fatal(err)
	}

	// A second admin may do each of these to Ada.
	bea := mkMember(t, st, "Bea Admin", "bea@example.org", adminGroup)
	other := actorFor(bea)
	if _, err := svc.UpdateMember(ctx, other, ada.ID, admin.MemberPatch{GroupIDs: ptr([]string{laser.ID})}); err != nil {
		t.Errorf("other admin removes Ada's admin access: %v", err)
	}
	if _, err := svc.UpdateMember(ctx, other, ada.ID, admin.MemberPatch{IsActive: ptr(false)}); err != nil {
		t.Errorf("other admin disables Ada: %v", err)
	}
	if err := svc.DeleteMember(ctx, other, ada.ID); err != nil {
		t.Errorf("other admin deletes Ada: %v", err)
	}
	if _, err := st.GetUser(ctx, ada.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Ada not deleted: %v", err)
	}
}

func TestDeleteMember(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	if err := svc.DeleteMember(ctx, actorFor(ada), alex.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUser(ctx, alex.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("still there: %v", err)
	}
	ev := oneEvent(t, st, audit.UserDelete)
	if ev.TargetType != "user" || ev.TargetID != alex.ID || ev.Detail["email"] != "alex@example.org" || ev.Detail["name"] != "Alex Rivera" {
		t.Errorf("delete event %+v", ev)
	}
	if err := svc.DeleteMember(ctx, actorFor(ada), alex.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestSendPasswordEmail(t *testing.T) {
	ctx := context.Background()
	svc, st, n := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")

	purpose, err := svc.SendPasswordEmail(ctx, actorFor(ada), alex.ID)
	if err != nil || purpose != model.ResetPurposeInvite {
		t.Fatalf("no password: %q, %v", purpose, err)
	}
	if ev := oneEvent(t, st, audit.UserInvite); ev.TargetID != alex.ID || ev.ActorID != ada.ID ||
		ev.Detail["email_sent"] != true || ev.Summary != "Emailed Alex Rivera an invitation" {
		t.Errorf("invite event %+v", ev)
	}

	if err := st.SetPassword(ctx, alex.ID, "$argon2id$placeholder"); err != nil {
		t.Fatal(err)
	}
	purpose, err = svc.SendPasswordEmail(ctx, actorFor(ada), alex.ID)
	if err != nil || purpose != model.ResetPurposeReset {
		t.Fatalf("with password: %q, %v", purpose, err)
	}
	if ev := oneEvent(t, st, audit.UserResetSent); ev.TargetID != alex.ID || ev.ActorID != ada.ID {
		t.Errorf("reset event %+v", ev)
	}
	want := []notification{{alex.ID, model.ResetPurposeInvite}, {alex.ID, model.ResetPurposeReset}}
	if calls := n.Calls(); !reflect.DeepEqual(calls, want) {
		t.Errorf("notifier calls %+v", calls)
	}

	smtpDown := errors.New("smtp down")
	n.Fail(smtpDown)
	_, err = svc.SendPasswordEmail(ctx, actorFor(ada), alex.ID)
	var ee *admin.EmailError
	if !errors.As(err, &ee) || !errors.Is(err, smtpDown) {
		t.Errorf("failing notifier: %T %v", err, err)
	}
	// Ruling 16: the failed attempt is recorded too, saying so.
	var unsent []store.AuditRow
	for _, ev := range events(t, st, audit.UserResetSent) {
		if ev.Detail["email_sent"] == false {
			unsent = append(unsent, ev)
		}
	}
	if len(unsent) != 1 || unsent[0].Summary != "Tried to email Alex Rivera a password reset link, but it wasn't sent" ||
		unsent[0].TargetID != alex.ID {
		t.Errorf("failed attempts recorded %+v, want one", unsent)
	}
	if n := len(events(t, st, audit.UserResetSent)); n != 2 {
		t.Errorf("%d reset events after a sent and a failed send, want 2", n)
	}
	n.Fail(nil)

	stored, _ := st.GetUser(ctx, alex.ID)
	stored.IsActive = false
	if err := st.UpdateUser(ctx, stored); err != nil {
		t.Fatal(err)
	}
	calls := len(n.Calls())
	_, err = svc.SendPasswordEmail(ctx, actorFor(ada), alex.ID)
	if msg := refusal(t, err); msg != "This account is disabled. Enable it first." {
		t.Errorf("disabled: %q", msg)
	}
	if len(n.Calls()) != calls {
		t.Error("notifier called for a disabled account")
	}
}

func TestSetMemberPassword(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := storeUser(t, st, &model.User{Name: "Alex Rivera", Email: "alex@example.org", Type: model.UserTypeMember, IsActive: true,
		LegacyPasswordHash: "pbkdf2_sha256$1000$salt$hash"})
	sess, refresh := addSession(t, st, alex.ID), addRefreshToken(t, st, alex.ID)

	err := svc.SetMemberPassword(ctx, actorFor(ada), alex.ID, "short")
	if got := fields(t, err)["password"]; got != "Use at least 10 characters." {
		t.Errorf("short: %q", got)
	}
	if _, err := st.GetSession(ctx, sess); err != nil {
		t.Errorf("refused password ended the session: %v", err)
	}

	const pw = "correct horse battery"
	if err := svc.SetMemberPassword(ctx, actorFor(ada), alex.ID, pw); err != nil {
		t.Fatal(err)
	}
	stored, _ := st.GetUser(ctx, alex.ID)
	if !strings.HasPrefix(stored.PasswordHash, "$argon2id$") || stored.LegacyPasswordHash != "" {
		t.Errorf("hashes %q / %q", stored.PasswordHash, stored.LegacyPasswordHash)
	}
	if ok, err := password.Verify(pw, stored.PasswordHash); !ok || err != nil {
		t.Errorf("does not verify: %v", err)
	}
	assertSignedOut(t, st, sess, refresh)
	ev := oneEvent(t, st, audit.UserPasswordSet)
	if _, ok := ev.Detail["password"]; ok || ev.TargetID != alex.ID {
		t.Errorf("event %+v", ev)
	}
	for k, v := range ev.Detail {
		if s, ok := v.(string); ok && strings.Contains(s, pw) {
			t.Errorf("detail %q holds the password", k)
		}
	}
}

func TestClearMemberTOTP(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	now := time.Now().UTC()
	if err := st.SetTOTP(ctx, alex.ID, []byte("sealed"), &now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceRecoveryCodes(ctx, alex.ID, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ClearMemberTOTP(ctx, actorFor(ada), alex.ID); err != nil {
		t.Fatal(err)
	}
	stored, _ := st.GetUser(ctx, alex.ID)
	if stored.TOTPEnrolled() || stored.TOTPSecretEnc != nil {
		t.Errorf("still enrolled: %+v", stored)
	}
	if n, err := st.CountUnusedRecoveryCodes(ctx, alex.ID); err != nil || n != 0 {
		t.Errorf("%d recovery codes left, %v", n, err)
	}
	if ev := oneEvent(t, st, audit.UserTOTPClear); ev.TargetID != alex.ID || ev.ActorID != ada.ID {
		t.Errorf("event %+v", ev)
	}
}

func TestSignOutEverywhere(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	sess1, sess2, refresh := addSession(t, st, alex.ID), addSession(t, st, alex.ID), addRefreshToken(t, st, alex.ID)
	adaSess := addSession(t, st, ada.ID)
	if err := svc.SignOutEverywhere(ctx, actorFor(ada), alex.ID); err != nil {
		t.Fatal(err)
	}
	assertSignedOut(t, st, sess1, refresh)
	if _, err := st.GetSession(ctx, sess2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second session still there: %v", err)
	}
	if _, err := st.GetSession(ctx, adaSess); err != nil {
		t.Errorf("someone else's session ended: %v", err)
	}
	if ev := oneEvent(t, st, audit.UserSessionsRevoke); ev.TargetID != alex.ID || ev.ActorID != ada.ID {
		t.Errorf("event %+v", ev)
	}
}

func TestMemberMethodsRejectServiceAccounts(t *testing.T) {
	ctx := context.Background()
	svc, st, n := newService(t)
	ada, _ := mkAdmin(t, st)
	sa := mkServiceAccount(t, st, "Door", "door")
	a := actorFor(ada)
	calls := map[string]func(id string) error{
		"UpdateMember": func(id string) error {
			_, err := svc.UpdateMember(ctx, a, id, admin.MemberPatch{Name: ptr("Changed")})
			return err
		},
		"DeleteMember": func(id string) error { return svc.DeleteMember(ctx, a, id) },
		"SendPasswordEmail": func(id string) error {
			_, err := svc.SendPasswordEmail(ctx, a, id)
			return err
		},
		"SetMemberPassword": func(id string) error { return svc.SetMemberPassword(ctx, a, id, "correct horse battery") },
		"ClearMemberTOTP":   func(id string) error { return svc.ClearMemberTOTP(ctx, a, id) },
		"SignOutEverywhere": func(id string) error { return svc.SignOutEverywhere(ctx, a, id) },
	}
	before := countEvents(t, st)
	for name, call := range calls {
		if err := call(sa.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s(service account): %v", name, err)
		}
		if err := call("no-such-id"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s(unknown): %v", name, err)
		}
	}
	stored, err := st.GetUser(ctx, sa.ID)
	if err != nil || stored.Name != "Door" || stored.HasPassword() {
		t.Errorf("service account changed: %+v, %v", stored, err)
	}
	if after := countEvents(t, st); after != before {
		t.Errorf("recorded %d events", after-before)
	}
	if len(n.Calls()) != 0 {
		t.Errorf("notifier called: %+v", n.Calls())
	}
}

func TestResolveMemberAndGroups(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	alex := mkMember(t, st, "Alex Rivera", "alex@example.org")
	sa := mkServiceAccount(t, st, "Door", "door")
	laser, woodshop := mkGroup(t, st, "Laser", false), mkGroup(t, st, "Woodshop", false)

	for _, ref := range []string{"email:ALEX@example.org", alex.ID} {
		u, err := svc.ResolveMember(ctx, ref)
		if err != nil || u.ID != alex.ID {
			t.Errorf("ResolveMember(%q) = %v, %v", ref, u, err)
		}
	}
	for _, ref := range []string{"email:nobody@x", sa.ID, "nope", ""} {
		if _, err := svc.ResolveMember(ctx, ref); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveMember(%q): %v", ref, err)
		}
	}

	ids, err := svc.ResolveGroups(ctx, []string{"Laser", woodshop.ID})
	if err != nil || !reflect.DeepEqual(ids, []string{laser.ID, woodshop.ID}) {
		t.Errorf("ResolveGroups = %v, %v", ids, err)
	}
	ids, err = svc.ResolveGroups(ctx, nil)
	if err != nil || len(ids) != 0 {
		t.Errorf("ResolveGroups(nil) = %v, %v", ids, err)
	}
	_, err = svc.ResolveGroups(ctx, []string{"Laser", "Nope"})
	if got := fields(t, err)["groups"]; got != `No group called "Nope".` {
		t.Errorf("unknown group: %q", got)
	}
}
