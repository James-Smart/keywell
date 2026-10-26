package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/testenv"
)

const apiGroups = "/api/v1/groups"

func TestAPIGroups(t *testing.T) {
	env := testenv.New(t)
	raw, acct := env.APIToken(t, "door", model.APITokenScopeAdmin)
	laser := env.CreateGroup(t, "Laser", false, false)
	env.CreateUser(t, "priya@example.org", "pw", "Laser")
	if err := env.Store.AddMember(context.Background(), acct.ID, laser.ID); err != nil {
		t.Fatal(err)
	}

	body, resp := env.API(t, raw, http.MethodGet, apiGroups, nil)
	if resp.StatusCode != 200 || body["total"] != float64(1) || body["per_page"] != float64(50) {
		t.Fatalf("list: %d %v", resp.StatusCode, body)
	}
	if it := items(t, body)[0]; it["name"] != "Laser" || it["member_count"] != float64(2) {
		t.Errorf("item %v", it)
	}
	body, _ = env.API(t, raw, http.MethodGet, apiGroups+"?per_page=500", nil)
	if body["per_page"] != float64(200) {
		t.Errorf("per_page %v", body["per_page"])
	}

	body, resp = env.API(t, raw, http.MethodPost, apiGroups, map[string]any{
		"name": "Woodshop", "description": "Saws", "require_totp": true, "metadata": map[string]any{"room": "B"}})
	if resp.StatusCode != 201 || body["name"] != "Woodshop" || body["require_totp"] != true || body["member_count"] != float64(0) {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPost, apiGroups, map[string]any{"name": "Woodshop"})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["name"]; !ok {
		t.Errorf("no fields.name: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPost, apiGroups, map[string]any{"name": "X", "metadata": []int{1}})
	assertError(t, body, resp, 422, "invalid")

	body, resp = env.API(t, raw, http.MethodGet, apiGroups+"/name:Laser", nil)
	if resp.StatusCode != 200 || body["id"] != laser.ID || body["member_count"] != float64(2) {
		t.Errorf("get by name: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiGroups+"/name:Nope", nil)
	assertError(t, body, resp, 404, "not_found")

	body, resp = env.API(t, raw, http.MethodPatch, apiGroups+"/"+laser.ID, map[string]any{"description": "Cutters"})
	if resp.StatusCode != 200 || body["description"] != "Cutters" || body["name"] != "Laser" {
		t.Errorf("patch: %d %v", resp.StatusCode, body)
	}

	body, resp = env.API(t, raw, http.MethodGet, apiGroups+"/"+laser.ID+"/members", nil)
	if resp.StatusCode != 200 || body["total"] != float64(2) {
		t.Fatalf("members: %d %v", resp.StatusCode, body)
	}
	types := map[string]bool{}
	for _, it := range items(t, body) {
		if got := len(it); got != 5 {
			t.Errorf("member keys %v, want id type name email username", keys(it))
		}
		types[it["type"].(string)] = true
	}
	if !types["member"] || !types["service_account"] {
		t.Errorf("types %v, want a member and a service account", types)
	}

	_, resp = env.API(t, raw, http.MethodDelete, apiGroups+"/"+laser.ID, nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiGroups+"/"+laser.ID, nil)
	assertError(t, body, resp, 404, "not_found")
}

// Review Focus 3: the only admin group can't lose admin access or be deleted.
func TestAPILastAdminGroup(t *testing.T) {
	env := testenv.New(t)
	env.AdminClient(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	admins, err := env.Store.GetGroupByName(context.Background(), "Admin")
	if err != nil {
		t.Fatal(err)
	}
	path := apiGroups + "/" + admins.ID

	for _, c := range []struct {
		method string
		body   any
	}{
		{http.MethodPatch, map[string]any{"is_admin": false}},
		{http.MethodDelete, nil},
	} {
		body, resp := env.API(t, raw, c.method, path, c.body)
		assertError(t, body, resp, 409, "refused")
		if msg, _ := body["message"].(string); msg != "This is the only admin group. Make another group an admin group first." {
			t.Errorf("%s message %q", c.method, msg)
		}
	}
	g, err := env.Store.GetGroup(context.Background(), admins.ID)
	if err != nil || !g.IsAdmin {
		t.Errorf("admin group changed: %v %v", g, err)
	}
}

// Ruling 14: the only group an app lets in can't be deleted, as the app
// would then let in every member; one of two groups can.
func TestAPIDeleteSoleAppGroup(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	laser := env.CreateGroup(t, "Laser", false, false)
	wood := env.CreateGroup(t, "Woodshop", false, false)
	cutter := env.CreateApp(t, model.Application{Name: "Laser cutter", Slug: "laser-cutter", ClientID: "cutter",
		ClientType: model.ClientTypePublic, AllowedGroupIDs: []string{laser.ID}}, "")
	wiki := env.CreateApp(t, model.Application{Name: "Wiki", Slug: "wiki", ClientID: "wiki",
		ClientType: model.ClientTypePublic, AllowedGroupIDs: []string{laser.ID, wood.ID}}, "")

	body, resp := env.API(t, raw, http.MethodDelete, apiGroups+"/"+laser.ID, nil)
	assertError(t, body, resp, 409, "refused")
	if msg, _ := body["message"].(string); msg != "Laser is the only group allowed into Laser cutter. Change who can sign in to that app first." {
		t.Errorf("message %q", msg)
	}
	if got, err := env.Store.GetApplication(context.Background(), cutter.ID); err != nil || len(got.AllowedGroupIDs) != 1 {
		t.Errorf("Laser cutter lets in %v (%v), want only Laser", got.AllowedGroupIDs, err)
	}

	_, resp = env.API(t, raw, http.MethodDelete, apiGroups+"/"+wood.ID, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete Woodshop: %d", resp.StatusCode)
	}
	if got, err := env.Store.GetApplication(context.Background(), wiki.ID); err != nil ||
		len(got.AllowedGroupIDs) != 1 || got.AllowedGroupIDs[0] != laser.ID {
		t.Errorf("Wiki lets in %v (%v), want only Laser", got.AllowedGroupIDs, err)
	}
}

// A huge ?page= is an empty page, never a server error.
func TestAPIHugePage(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	env.CreateUser(t, "priya@example.org", "pw", "Laser")
	for _, path := range []string{apiGroups, apiUsers} {
		body, resp := env.API(t, raw, http.MethodGet, path+"?page=9223372036854775807", nil)
		if resp.StatusCode != 200 || len(items(t, body)) != 0 || body["total"] != float64(1) {
			t.Errorf("GET %s: %d %v", path, resp.StatusCode, body)
		}
	}
}

func TestAPIReadTokenCanList(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "viewer", model.APITokenScopeRead)
	for _, path := range []string{apiUsers, apiGroups} {
		if body, resp := env.API(t, raw, http.MethodGet, path, nil); resp.StatusCode != 200 {
			t.Errorf("GET %s: %d %v", path, resp.StatusCode, body)
		}
	}
	body, resp := env.API(t, raw, http.MethodPost, apiGroups, map[string]any{"name": "X"})
	assertError(t, body, resp, 403, "forbidden")
}
