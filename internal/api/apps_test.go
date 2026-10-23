package api_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"latch/internal/icons"
	"latch/internal/model"
	"latch/internal/testenv"
)

const apiApps = "/api/v1/apps"

func TestAPIApps(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	env.CreateGroup(t, "Staff", false, false)

	body, resp := env.API(t, raw, http.MethodPost, apiApps, map[string]any{
		"name": "Members wiki", "slug": "members-wiki", "client_type": "confidential",
		"redirect_uris": []string{"https://wiki.example.org/cb"}, "allowed_groups": []string{"Staff"},
		"access_token_ttl": 600, "show_tile": true})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	secret, _ := body["client_secret"].(string)
	if len(secret) != 43 {
		t.Errorf("client_secret %q, want 43 chars", secret)
	}
	id := body["id"].(string)
	if body["access_token_ttl"] != float64(600) || body["id_token_ttl"] != nil || body["service_account_id"] != nil ||
		body["show_tile"] != true || body["client_id"] == "" {
		t.Errorf("create body %v", body)
	}
	if g := stringsOf(body, "allowed_groups"); len(g) != 1 || g[0] != "Staff" {
		t.Errorf("allowed_groups %v", body["allowed_groups"])
	}

	body, resp = env.API(t, raw, http.MethodGet, apiApps+"/"+id, nil)
	if _, has := body["client_secret"]; resp.StatusCode != 200 || has {
		t.Errorf("get: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPatch, apiApps+"/"+id, map[string]any{
		"redirect_uris": []string{"https://wiki.example.org/cb", "https://wiki.example.org/cb2"}, "access_token_ttl": nil})
	if _, has := body["client_secret"]; resp.StatusCode != 200 || has || len(body["redirect_uris"].([]any)) != 2 {
		t.Errorf("patch: %d %v", resp.StatusCode, body)
	}
	if body["access_token_ttl"] != float64(600) {
		t.Errorf("null ttl in a PATCH should leave it alone: %v", body["access_token_ttl"])
	}
	body, resp = env.API(t, raw, http.MethodPatch, apiApps+"/"+id, map[string]any{"access_token_ttl": 0})
	if resp.StatusCode != 200 || body["access_token_ttl"] != nil {
		t.Errorf("ttl 0 should mean the default: %d %v", resp.StatusCode, body)
	}

	body, resp = env.API(t, raw, http.MethodGet, apiApps+"/slug:members-wiki", nil)
	if resp.StatusCode != 200 || body["id"] != id {
		t.Errorf("get by slug: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiApps, nil)
	if resp.StatusCode != 200 || body["total"] != float64(1) || body["per_page"] != float64(50) {
		t.Errorf("list: %d %v", resp.StatusCode, body)
	}
	if _, has := items(t, body)[0]["client_secret"]; has {
		t.Error("list shows a client_secret")
	}

	body, resp = env.API(t, raw, http.MethodPost, apiApps+"/"+id+"/rotate-secret", nil)
	if next, _ := body["client_secret"].(string); resp.StatusCode != 200 || len(next) != 43 || next == secret || len(body) != 1 {
		t.Errorf("rotate: %d %v", resp.StatusCode, body)
	}

	_, resp = env.API(t, raw, http.MethodDelete, apiApps+"/"+id, nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiApps+"/"+id, nil)
	assertError(t, body, resp, 404, "not_found")
}

// stringsOf returns the strings of body[key], which is an array.
func stringsOf(body map[string]any, key string) []string {
	var out []string
	list, _ := body[key].([]any)
	for _, g := range list {
		out = append(out, g.(string))
	}
	return out
}

func TestAPIAppValidation(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{"name": "App", "client_type": "public", "redirect_uris": []string{"https://a.example.org/cb"}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	body, resp := env.API(t, raw, http.MethodPost, apiApps, base(map[string]any{"access_token_ttl": 90000}))
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["access_token_ttl"]; !ok {
		t.Errorf("no fields.access_token_ttl: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPost, apiApps, base(map[string]any{"subject_mode": "guess"}))
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["subject_mode"]; !ok {
		t.Errorf("no fields.subject_mode: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPost, apiApps, base(map[string]any{"allowed_groups": []string{"Nope"}}))
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["allowed_groups"]; !ok {
		t.Errorf("no fields.allowed_groups: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPost, apiApps, base(map[string]any{"access_token_ttl": -5}))
	assertError(t, body, resp, 422, "invalid")
	body, resp = env.API(t, raw, http.MethodPost, apiApps, base(map[string]any{"bogus": 1}))
	assertError(t, body, resp, 400, "invalid_json")
}

// Ruling 8: API changes never leave an app's icon file behind.
func TestAPIAppIconFilesAreRemoved(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	newApp := func(name string) (id, iconURL, file string) {
		body, resp := env.API(t, raw, http.MethodPost, apiApps, map[string]any{
			"name": name, "client_type": "public", "redirect_uris": []string{"https://a.example.org/cb"}})
		if resp.StatusCode != 201 {
			t.Fatalf("create: %d %v", resp.StatusCode, body)
		}
		id = body["id"].(string)
		iconURL, problem, err := icons.Save(env.Cfg.DataDir, id, png)
		if err != nil || problem != "" {
			t.Fatalf("save icon: %q %v", problem, err)
		}
		file, _ = icons.Path(env.Cfg.DataDir, strings.TrimPrefix(iconURL, icons.Prefix))
		if body, resp = env.API(t, raw, http.MethodPatch, apiApps+"/"+id, map[string]any{"icon_url": iconURL}); resp.StatusCode != 200 {
			t.Fatalf("set icon: %d %v", resp.StatusCode, body)
		}
		return id, iconURL, file
	}
	exists := func(file string) bool { _, err := os.Stat(file); return err == nil }

	id, _, file := newApp("One")
	if body, resp := env.API(t, raw, http.MethodPatch, apiApps+"/"+id, map[string]any{"icon_url": "https://cdn.example.org/i.png"}); resp.StatusCode != 200 {
		t.Fatalf("change icon: %d %v", resp.StatusCode, body)
	}
	if exists(file) {
		t.Error("the old icon file is still there after PATCH")
	}

	id, _, file = newApp("Two")
	if body, resp := env.API(t, raw, http.MethodPatch, apiApps+"/"+id, map[string]any{"description": "same icon"}); resp.StatusCode != 200 {
		t.Fatalf("patch: %d %v", resp.StatusCode, body)
	}
	if !exists(file) {
		t.Error("a PATCH that kept the icon removed its file")
	}
	if _, resp := env.API(t, raw, http.MethodDelete, apiApps+"/"+id, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if exists(file) {
		t.Error("the icon file is still there after DELETE")
	}
}

func TestAPICreatedAppSignsIn(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)
	body, resp := env.API(t, raw, http.MethodPost, apiApps, map[string]any{
		"name": "Notes", "client_type": "public", "redirect_uris": []string{"http://127.0.0.1/cb"}})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	if _, has := body["client_secret"]; has {
		t.Error("a public app got a client_secret")
	}
	app, err := env.Store.GetApplicationByClientID(context.Background(), body["client_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	env.CreateUser(t, "priya@example.org", "pw")
	c := env.Client(t)
	env.Login(t, c, "priya@example.org", "pw")
	code, verifier, _ := env.Authorize(t, c, app, true)
	tok, resp := env.Exchange(t, app, "", code, verifier, app.RedirectURIs[0])
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Errorf("exchange: %d %v", resp.StatusCode, tok)
	}
}
