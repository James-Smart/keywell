package web_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"latch/internal/model"
	"latch/internal/testenv"
)

// groupValues is the group form: name, description and metadata, with the
// flags ticked as asked.
func groupValues(name string, isAdmin, requireTOTP bool) url.Values {
	v := url.Values{"name": {name}, "description": {""}, "metadata": {"{}"}}
	if isAdmin {
		v.Set("is_admin", "on")
	}
	if requireTOTP {
		v.Set("require_totp", "on")
	}
	return v
}

func TestGroupsList(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	laser := env.CreateGroup(t, "Laser", false, false)
	env.CreateGroup(t, "Safety", false, true)
	addMember(t, env, "Alex Rivera", "alex@example.org", "Laser")
	addMember(t, env, "Sam Taylor", "sam@example.org", "Laser")

	resp, body := env.Page(t, c, "/admin/groups")
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, body, `href="/admin/groups/new"`, "Add group", `href="/admin/groups/`+laser.ID+`"`, "Name", "Description", "Members")
	if row := rowWith(body, "Laser"); !strings.Contains(row, ">2<") || strings.Contains(row, "chip") {
		t.Errorf("Laser row %q, want 2 members and no chips", row)
	}
	if row := rowWith(body, ">Admin</a>"); !strings.Contains(row, "Admin access") || !strings.Contains(row, ">1<") {
		t.Errorf("Admin row %q, want the Admin access chip and 1 member", row)
	}
	if row := rowWith(body, "Safety"); !strings.Contains(row, "Requires two-step sign in") {
		t.Errorf("Safety row %q, want the two-step chip", row)
	}
}

func TestCreateGroup(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)

	_, body := env.Page(t, c, "/admin/groups/new")
	assertContains(t, body, "Name", "Description", "Members can use the admin pages", "Members must use two-step sign in",
		`name="is_admin"`, `name="require_totp"`, `<details class="metadata"`)
	assertLacks(t, body, "Add someone")

	v := groupValues("Laser", false, true)
	v.Set("description", "Laser cutter users")
	resp, _ := env.Submit(t, c, "/admin/groups", v)
	g, err := env.Store.GetGroupByName(context.Background(), "Laser")
	if err != nil {
		t.Fatal(err)
	}
	assertRedirect(t, resp, "/admin/groups/"+g.ID+"?notice=saved")
	if g.Description != "Laser cutter users" || g.IsAdmin || !g.RequireTOTP {
		t.Errorf("stored %+v", g)
	}
	if events := auditEvents(t, env, "group.create"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("group.create events %+v, want one by the admin", events)
	}

	resp, body = env.Submit(t, c, "/admin/groups", groupValues("Laser", false, false))
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, html.EscapeString("There's already a group with that name."), `value="Laser"`, `aria-invalid="true"`)

	resp, body = env.Submit(t, c, "/admin/groups", groupValues("", false, false))
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, "Enter a group name.")
}

func TestEditGroup(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	g := env.CreateGroup(t, "Laser", false, false)
	base := "/admin/groups/" + g.ID

	v := groupValues("Laser cutters", false, true)
	v.Set("description", "Cutters")
	v.Set("metadata", `{"bay": 3}`)
	resp, _ := env.Submit(t, c, base, v)
	assertRedirect(t, resp, base+"?notice=saved")
	got, _ := env.Store.GetGroup(context.Background(), g.ID)
	if got.Name != "Laser cutters" || got.Description != "Cutters" || !got.RequireTOTP || got.Metadata["bay"] != float64(3) {
		t.Errorf("stored %+v", got)
	}
	_, body := env.Page(t, c, base+"?notice=saved")
	assertContains(t, body, `value="Laser cutters"`, "Changes saved.", `name="require_totp" checked`, `&#34;bay&#34;`)

	v = groupValues("Changed", true, false)
	v.Set("metadata", "null")
	resp, body = env.Submit(t, c, base, v)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
	assertContains(t, body, `value="Changed"`, `<details class="metadata" open`)
	got, _ = env.Store.GetGroup(context.Background(), g.ID)
	if got.Name != "Laser cutters" || got.IsAdmin {
		t.Errorf("a refused save changed %+v", got)
	}

	resp, _ = env.Page(t, c, "/admin/groups/nope")
	assertStatus(t, resp, http.StatusNotFound)
}

func TestGroupMembersSection(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	g := env.CreateGroup(t, "Laser", false, false)
	alex := addMember(t, env, "Alex Rivera", "alex@example.org", "Laser")
	sam := addMember(t, env, "Sam Taylor", "sam@example.org")
	door := createServiceAccount(t, env, "door@example.org")
	if err := env.Store.AddMember(context.Background(), door.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	base := "/admin/groups/" + g.ID

	_, body := env.Page(t, c, base)
	assertContains(t, body, "Alex Rivera", "alex@example.org", "door@example.org", "Add someone", `action="`+base+`/members/`+alex.ID+`/remove"`)
	if row := rowWith(body, "door@example.org"); !strings.Contains(row, "Service account") {
		t.Errorf("service account row %q", row)
	}
	if row := rowWith(body, "alex@example.org"); strings.Contains(row, "Service account") {
		t.Errorf("member row %q", row)
	}
	assertLacks(t, body, "sam@example.org")

	_, body = env.Page(t, c, base+"?q=sam")
	assertContains(t, body, "sam@example.org", `action="`+base+`/members"`, `value="`+sam.ID+`"`)
	assertLacks(t, body, `value="`+alex.ID+`"`)
	_, body = env.Page(t, c, base+"?q=alex")
	assertLacks(t, body, `name="user_id"`)
	assertContains(t, body, "No one else matches.")

	resp, _ := env.Submit(t, c, base+"/members", url.Values{"user_id": {sam.ID}})
	assertRedirect(t, resp, base+"?notice=member_added")
	if names := groupNamesOf(t, env, sam); len(names) != 1 || names[0] != "Laser" {
		t.Errorf("Sam's groups %v", names)
	}
	if events := auditEvents(t, env, "group.member.add"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("group.member.add events %+v", events)
	}
	_, body = env.Page(t, c, base)
	assertContains(t, body, "sam@example.org")

	resp, _ = env.Submit(t, c, base+"/members/"+sam.ID+"/remove", nil)
	assertRedirect(t, resp, base+"?notice=member_removed")
	if names := groupNamesOf(t, env, sam); len(names) != 0 {
		t.Errorf("Sam's groups %v, want none", names)
	}

	resp, _ = env.Submit(t, c, base+"/members", url.Values{"user_id": {"nope"}})
	assertStatus(t, resp, http.StatusNotFound)
}

// Review Focus 3: the only admin group cannot lose admin access or be
// deleted.
func TestLastAdminGroupRefusedInUI(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	g, err := env.Store.GetGroupByName(context.Background(), "Admin")
	if err != nil {
		t.Fatal(err)
	}
	base := "/admin/groups/" + g.ID
	msg := html.EscapeString("This is the only admin group. Make another group an admin group first.")

	resp, body := env.Submit(t, c, base, groupValues("Admin", false, false))
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, `<p class="alert alert-error" role="alert">`+msg+"</p>")

	resp, body = env.Submit(t, c, base+"/delete", url.Values{"confirm": {"Admin"}})
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, `<p class="alert alert-error" role="alert">`+msg+"</p>")

	got, err := env.Store.GetGroup(context.Background(), g.ID)
	if err != nil || !got.IsAdmin {
		t.Errorf("group %+v, %v: want it kept as an admin group", got, err)
	}
}

// Review Focus 3, Ruling 5: with another admin group around, an admin still
// cannot take their own admin access away through the groups pages.
func TestOwnAdminAccessRefusedInGroupsUI(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	ctx := context.Background()
	first, err := env.Store.GetGroupByName(ctx, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	env.CreateGroup(t, "Other admins", true, false)
	base := "/admin/groups/" + first.ID
	own := `<p class="alert alert-error" role="alert">` +
		html.EscapeString("You can't remove your own admin access. Ask another admin to do it.") + "</p>"

	resp, body := env.Submit(t, c, base, groupValues("Admin", false, false))
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, own)

	resp, body = env.Submit(t, c, base+"/delete", url.Values{"confirm": {"Admin"}})
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, own)

	resp, body = env.Submit(t, c, base+"/members/"+admin.ID+"/remove", nil)
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, own)

	got, err := env.Store.GetGroup(ctx, first.ID)
	if err != nil || !got.IsAdmin {
		t.Errorf("group %+v, %v: want it kept as an admin group", got, err)
	}
	if names := groupNamesOf(t, env, admin); len(names) != 1 || names[0] != "Admin" {
		t.Errorf("admin's groups %v, want [Admin]", names)
	}
}

func TestDeleteGroupConfirm(t *testing.T) {
	env := testenv.New(t)
	c, admin := env.AdminClient(t)
	g := env.CreateGroup(t, "Laser", false, false)
	base := "/admin/groups/" + g.ID

	notDeleted := `<p class="alert alert-error" role="alert">` +
		html.EscapeString("The group wasn't deleted. See Delete group below.") + "</p>"
	for _, typed := range []string{"wrong", ""} {
		resp, body := env.Submit(t, c, base+"/delete", url.Values{"confirm": {typed}})
		assertStatus(t, resp, http.StatusUnprocessableEntity)
		assertContains(t, body, "Type the name exactly to confirm.", notDeleted, `value="Laser"`)
		if _, err := env.Store.GetGroup(context.Background(), g.ID); err != nil {
			t.Fatalf("group gone: %v", err)
		}
	}

	resp, _ := env.Submit(t, c, base+"/delete", url.Values{"confirm": {"Laser"}})
	assertRedirect(t, resp, "/admin/groups?notice=deleted")
	if _, err := env.Store.GetGroup(context.Background(), g.ID); err == nil {
		t.Fatal("group still stored")
	}
	if events := auditEvents(t, env, "group.delete"); len(events) != 1 || events[0].ActorID != admin.ID {
		t.Errorf("group.delete events %+v", events)
	}
}

// A refused add or save says so at the top.
func TestGroupFormsSayNothingSaved(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	g := env.CreateGroup(t, "Laser", false, false)
	badMeta := groupValues("Woodshop", false, false)
	badMeta.Set("metadata", "[1]")
	assertNotSaved(t, env, c, "/admin/groups", groupValues("", false, false))
	assertNotSaved(t, env, c, "/admin/groups", badMeta)
	assertNotSaved(t, env, c, "/admin/groups/"+g.ID, groupValues("", false, false))
	assertNotSaved(t, env, c, "/admin/groups/"+g.ID, badMeta)
}

// Ruling 14: the only group an app lets in can't be deleted, as the app
// would then let in every member. The page says which app, at the top,
// and the confirmation says so before the admin tries.
func TestDeleteSoleAppGroupRefusedInUI(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	g := env.CreateGroup(t, "Laser", false, false)
	app := env.CreateApp(t, model.Application{Name: "Laser cutter", Slug: "laser-cutter", ClientID: "cutter",
		ClientType: model.ClientTypePublic, AllowedGroupIDs: []string{g.ID}}, "")
	base := "/admin/groups/" + g.ID

	_, body := env.Page(t, c, base)
	assertContains(t, body, html.EscapeString("If this is the only group allowed into an app, change who can sign in to that app first."))
	assertLacks(t, body, "will no longer open for them")

	resp, body := env.Submit(t, c, base+"/delete", url.Values{"confirm": {"Laser"}})
	assertStatus(t, resp, http.StatusConflict)
	assertContains(t, body, `<p class="alert alert-error" role="alert">`+
		html.EscapeString("Laser is the only group allowed into Laser cutter. Change who can sign in to that app first.")+"</p>")
	if _, err := env.Store.GetGroup(context.Background(), g.ID); err != nil {
		t.Fatalf("group gone: %v", err)
	}
	if got, err := env.Store.GetApplication(context.Background(), app.ID); err != nil ||
		len(got.AllowedGroupIDs) != 1 || got.AllowedGroupIDs[0] != g.ID {
		t.Errorf("app lets in %v (%v), want only Laser", got.AllowedGroupIDs, err)
	}
	if events := auditEvents(t, env, "group.delete"); len(events) != 0 {
		t.Errorf("group.delete events %+v", events)
	}
}
