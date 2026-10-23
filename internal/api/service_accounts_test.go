package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/testenv"
)

const apiSAs = "/api/v1/service-accounts"

func TestAPIServiceAccounts(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "admin-bot", model.APITokenScopeAdmin)
	env.CreateUser(t, "priya@example.org", "pw")
	env.CreateGroup(t, "Doors", false, false)

	body, resp := env.API(t, raw, http.MethodPost, apiSAs, map[string]any{
		"name": "Door", "username": "door", "description": "Opens doors", "groups": []string{"Doors"}, "metadata": map[string]any{"a": 1}})
	if resp.StatusCode != 201 || body["username"] != "door" || body["token_count"] != float64(0) || body["last_used_at"] != nil {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	if g := stringsOf(body, "groups"); len(g) != 1 || g[0] != "Doors" {
		t.Errorf("groups %v", body["groups"])
	}
	id := body["id"].(string)

	body, resp = env.API(t, raw, http.MethodGet, apiSAs+"/username:door", nil)
	if resp.StatusCode != 200 || body["id"] != id {
		t.Errorf("get by username: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPatch, apiSAs+"/"+id, map[string]any{"description": "Front door"})
	if resp.StatusCode != 200 || body["description"] != "Front door" || body["name"] != "Door" {
		t.Errorf("patch: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodGet, apiSAs, nil)
	if resp.StatusCode != 200 || body["total"] != float64(2) { // admin-bot and door, not priya
		t.Fatalf("list: %d %v", resp.StatusCode, body)
	}
	for _, it := range items(t, body) {
		if it["username"] == "priya" || it["name"] == "priya" {
			t.Errorf("list has a member: %v", it)
		}
	}
	body, _ = env.API(t, raw, http.MethodGet, apiSAs+"?q=door", nil)
	if body["total"] != float64(1) {
		t.Errorf("q=door: %v", body)
	}
	member := env.CreateUser(t, "x@example.org", "pw")
	body, resp = env.API(t, raw, http.MethodGet, apiSAs+"/"+member.ID, nil)
	assertError(t, body, resp, 404, "not_found")

	doorRaw := mintToken(t, env, raw, id, "door", "admin")
	if _, resp := env.API(t, doorRaw, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != 200 {
		t.Fatalf("door token before delete: %d", resp.StatusCode)
	}
	_, resp = env.API(t, raw, http.MethodDelete, apiSAs+"/"+id, nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	body, resp = env.API(t, doorRaw, http.MethodGet, "/api/v1/me", nil)
	assertError(t, body, resp, 401, "unauthorized")
}

// mintToken makes a token for service account id through the API.
func mintToken(t *testing.T, env *testenv.Env, raw, id, label, scope string) string {
	t.Helper()
	body, resp := env.API(t, raw, http.MethodPost, apiSAs+"/"+id+"/tokens", map[string]any{"label": label, "scope": scope})
	tok, _ := body["token"].(string)
	if resp.StatusCode != 201 || tok == "" {
		t.Fatalf("mint token: %d %v", resp.StatusCode, body)
	}
	return tok
}

func TestAPITokens(t *testing.T) {
	env := testenv.New(t)
	raw, acct := env.APIToken(t, "admin-bot", model.APITokenScopeAdmin)
	base := apiSAs + "/" + acct.ID + "/tokens"

	body, resp := env.API(t, raw, http.MethodPost, base, map[string]any{"label": "door", "scope": "read"})
	tok, _ := body["token"].(string)
	if resp.StatusCode != 201 || !strings.HasPrefix(tok, "latch_") || body["scope"] != "read" || body["expires_at"] != nil {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}
	tid := body["id"].(string)
	if _, resp := env.API(t, tok, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != 200 {
		t.Errorf("new token on /me: %d", resp.StatusCode)
	}

	body, resp = env.API(t, raw, http.MethodGet, base, nil)
	if resp.StatusCode != 200 || body["total"] != float64(2) || body["per_page"] != float64(50) {
		t.Fatalf("list: %d %v", resp.StatusCode, body)
	}
	for _, it := range items(t, body) {
		if _, has := it["token"]; has {
			t.Errorf("list has a token key: %v", it)
		}
	}

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	body, resp = env.API(t, raw, http.MethodPost, base, map[string]any{"label": "old", "scope": "read", "expires_at": past})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["expires_at"]; !ok {
		t.Errorf("no fields.expires_at: %v", body)
	}
	body, resp = env.API(t, raw, http.MethodPost, base, map[string]any{"label": "x", "scope": "read", "expires_at": "tomorrow"})
	assertError(t, body, resp, 422, "invalid")
	if _, ok := fieldsOf(body)["expires_at"]; !ok {
		t.Errorf("no fields.expires_at for junk: %v", body)
	}
	future := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	body, resp = env.API(t, raw, http.MethodPost, base, map[string]any{"label": "later", "scope": "read", "expires_at": future.Format(time.RFC3339)})
	if resp.StatusCode != 201 || body["expires_at"] != future.Format(time.RFC3339) {
		t.Errorf("future expiry: %d %v", resp.StatusCode, body)
	}
	body, resp = env.API(t, raw, http.MethodPost, base, map[string]any{"label": "x", "scope": "root"})
	assertError(t, body, resp, 422, "invalid")

	_, resp = env.API(t, raw, http.MethodDelete, base+"/"+tid, nil)
	if resp.StatusCode != 204 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	body, resp = env.API(t, tok, http.MethodGet, "/api/v1/me", nil)
	assertError(t, body, resp, 401, "unauthorized")
	body, resp = env.API(t, raw, http.MethodDelete, base+"/"+tid, nil)
	assertError(t, body, resp, 404, "not_found")
}
