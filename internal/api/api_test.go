package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/testenv"
)

const (
	msgUnauthorized = "Send a valid API token in the Authorization header."
	msgReadOnly     = "This token can only read. Use a token with full admin access to make changes."
)

// assertError checks that the response is the API's JSON error shape with
// status and code, and a message.
func assertError(t *testing.T, body map[string]any, resp *http.Response, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status %d, want %d (body %v)", resp.StatusCode, status, body)
	}
	assertJSONHeaders(t, resp)
	if body["error"] != code {
		t.Errorf("error %v, want %q (body %v)", body["error"], code, body)
	}
	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("no message (body %v)", body)
	}
}

// assertJSONHeaders checks the headers every API response has.
func assertJSONHeaders(t *testing.T, resp *http.Response) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
}

// send makes req with c and returns the response body decoded as a JSON
// object, failing the test when it is not one, and the response.
func send(t *testing.T, c *http.Client, req *http.Request) (map[string]any, *http.Response) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%s %s: status %d, body is not a JSON object: %v\n%s", req.Method, req.URL.Path, resp.StatusCode, err, raw)
	}
	return body, resp
}

// keys returns the keys of m, sorted.
func keys(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }

// Review Focus 4: a request without a usable token gets a JSON 401, never
// HTML and never a 500, whatever is wrong with the token.
func TestAPIRequiresToken(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()

	valid, _ := env.APIToken(t, "valid", model.APITokenScopeAdmin)

	// A token that works until it expires.
	_, clockAccount := env.APIToken(t, "clock", model.APITokenScopeRead)
	expiring := "latch_" + secrets.RandomToken(32)
	expiresAt := env.Clock.Now().Add(time.Hour)
	if err := env.Store.CreateAPIToken(ctx, &model.APIToken{ServiceAccountID: clockAccount.ID, Label: "expiring",
		TokenHash: secrets.HashToken(expiring), Scope: model.APITokenScopeRead, ExpiresAt: &expiresAt}); err != nil {
		t.Fatal(err)
	}
	if body, resp := env.API(t, expiring, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("token before it expires: status %d, want 200 (body %v)", resp.StatusCode, body)
	}
	env.Clock.Advance(time.Hour)

	revoked, revokedAccount := env.APIToken(t, "revoked", model.APITokenScopeAdmin)
	tokens, err := env.Store.ListAPITokens(ctx, revokedAccount.ID)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens of revoked: %v, %v", tokens, err)
	}
	if err := env.Store.DeleteAPIToken(ctx, revokedAccount.ID, tokens[0].ID); err != nil {
		t.Fatal(err)
	}

	orphaned, deletedAccount := env.APIToken(t, "deleted", model.APITokenScopeAdmin)
	if err := env.Store.DeleteUser(ctx, deletedAccount.ID); err != nil {
		t.Fatal(err)
	}

	disabled, disabledAccount := env.APIToken(t, "disabled", model.APITokenScopeAdmin)
	disabledAccount.IsActive = false
	if err := env.Store.UpdateUser(ctx, disabledAccount); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, authorization string }{
		{"no header", ""},
		{"junk", "Bearer junk"},
		{"bearer without a token", "Bearer "},
		{"another scheme", "Token " + valid},
		{"expired", "Bearer " + expiring},
		{"revoked", "Bearer " + revoked},
		{"service account deleted", "Bearer " + orphaned},
		{"service account disabled", "Bearer " + disabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req, err := http.NewRequest(method, env.TS.URL+"/api/v1/me", nil)
				if err != nil {
					t.Fatal(err)
				}
				if tc.authorization != "" {
					req.Header.Set("Authorization", tc.authorization)
				}
				body, resp := send(t, env.TS.Client(), req)
				assertError(t, body, resp, http.StatusUnauthorized, "unauthorized")
				if body["message"] != msgUnauthorized {
					t.Errorf("%s: message %q, want %q", method, body["message"], msgUnauthorized)
				}
				if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("%s: WWW-Authenticate %q, want Bearer", method, got)
				}
			}
		})
	}

	// The scheme is not case-sensitive.
	req, err := http.NewRequest(http.MethodGet, env.TS.URL+"/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "bearer "+valid)
	if body, resp := send(t, env.TS.Client(), req); resp.StatusCode != http.StatusOK {
		t.Errorf("lower-case bearer: status %d, want 200 (body %v)", resp.StatusCode, body)
	}
}

// The API never reads the browser session: a signed-in admin's cookie is
// no token.
func TestAPIIgnoresCookies(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, env.TS.URL+"/api/v1/me", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Jar.Cookies(req.URL)) == 0 {
			t.Fatal("the admin client has no session cookie for the API, so this proves nothing")
		}
		body, resp := send(t, c, req)
		assertError(t, body, resp, http.StatusUnauthorized, "unauthorized")
	}
}

func TestAPIMe(t *testing.T) {
	env := testenv.New(t)
	raw, account := env.APIToken(t, "door", model.APITokenScopeRead)
	doors := env.CreateGroup(t, "Doors", false, false)
	if err := env.Store.AddMember(context.Background(), account.ID, doors.ID); err != nil {
		t.Fatal(err)
	}

	body, resp := env.API(t, raw, http.MethodGet, "/api/v1/me", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %v)", resp.StatusCode, body)
	}
	assertJSONHeaders(t, resp)
	if got, want := keys(body), []string{"service_account", "token"}; !slices.Equal(got, want) {
		t.Errorf("keys %v, want %v", got, want)
	}

	sa, _ := body["service_account"].(map[string]any)
	wantSA := []string{"created_at", "description", "groups", "id", "last_used_at", "metadata", "name",
		"token_count", "updated_at", "username"}
	if got := keys(sa); !slices.Equal(got, wantSA) {
		t.Errorf("service_account keys %v, want %v", got, wantSA)
	}
	if sa["username"] != "door" || sa["id"] != account.ID || sa["name"] != "door" {
		t.Errorf("service_account %v, want door (%s)", sa, account.ID)
	}
	if groups, _ := sa["groups"].([]any); len(groups) != 1 || groups[0] != "Doors" {
		t.Errorf("groups %v, want [Doors]", sa["groups"])
	}
	if sa["token_count"] != 1.0 {
		t.Errorf("token_count %v, want 1", sa["token_count"])
	}
	if meta, ok := sa["metadata"].(map[string]any); !ok || len(meta) != 0 {
		t.Errorf("metadata %v, want {}", sa["metadata"])
	}

	tok, _ := body["token"].(map[string]any)
	wantToken := []string{"created_at", "created_by", "expires_at", "id", "label", "last_used_at", "scope"}
	if got := keys(tok); !slices.Equal(got, wantToken) {
		t.Errorf("token keys %v, want %v (never token or token_hash)", got, wantToken)
	}
	if tok["scope"] != "read" {
		t.Errorf("scope %v, want read", tok["scope"])
	}
	if tok["expires_at"] != nil {
		t.Errorf("expires_at %v, want null", tok["expires_at"])
	}
	for _, field := range []string{"created_at", "last_used_at"} {
		s, _ := tok[field].(string)
		if at, err := time.Parse(time.RFC3339, s); err != nil || !strings.HasSuffix(s, "Z") || at.IsZero() {
			t.Errorf("token %s %q, want an RFC 3339 UTC time", field, s)
		}
	}
	if sa["last_used_at"] != tok["last_used_at"] {
		t.Errorf("service account last_used_at %v, want the token's %v", sa["last_used_at"], tok["last_used_at"])
	}
	if out, _ := json.Marshal(body); bytes.Contains(out, []byte("hash")) || bytes.Contains(out, []byte(raw)) {
		t.Errorf("response holds a hash or the raw token: %s", out)
	}
}

// Review Focus 4: a read token on a write gets a JSON 403, before routing.
func TestAPIReadScopeCannotWrite(t *testing.T) {
	env := testenv.New(t)
	read, _ := env.APIToken(t, "reader", model.APITokenScopeRead)
	full, _ := env.APIToken(t, "writer", model.APITokenScopeAdmin)

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		body, resp := env.API(t, read, method, "/api/v1/me", map[string]any{})
		assertError(t, body, resp, http.StatusForbidden, "forbidden")
		if body["message"] != msgReadOnly {
			t.Errorf("%s: message %q, want %q", method, body["message"], msgReadOnly)
		}
	}

	body, resp := env.API(t, full, http.MethodPost, "/api/v1/me", map[string]any{})
	assertError(t, body, resp, http.StatusMethodNotAllowed, "method_not_allowed")
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow %q, want GET, HEAD", got)
	}

	// Reading still works.
	if body, resp := env.API(t, read, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("read token GET /me: status %d, want 200 (body %v)", resp.StatusCode, body)
	}
}

func TestAPIRateLimit(t *testing.T) {
	env := testenv.New(t)
	first, _ := env.APIToken(t, "busy", model.APITokenScopeRead)

	for i := range 600 {
		if body, resp := env.API(t, first, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200 (body %v)", i+1, resp.StatusCode, body)
		}
	}
	body, resp := env.API(t, first, http.MethodGet, "/api/v1/me", nil)
	assertError(t, body, resp, http.StatusTooManyRequests, "rate_limited")
	if got := resp.Header.Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After %q, want 60", got)
	}

	// The limit is per token, even for the same account.
	second, _ := env.APIToken(t, "busy", model.APITokenScopeRead)
	if body, resp := env.API(t, second, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("second token: status %d, want 200 (body %v)", resp.StatusCode, body)
	}

	env.Clock.Advance(61 * time.Second)
	if body, resp := env.API(t, first, http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("first token a minute later: status %d, want 200 (body %v)", resp.StatusCode, body)
	}
}

func TestAPIUnknownRoute(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeRead)

	for _, path := range []string{"/api/v1/nope", "/api/v1/me/", "/api/v2/me", "/api/"} {
		body, resp := env.API(t, raw, http.MethodGet, path, nil)
		assertError(t, body, resp, http.StatusNotFound, "not_found")
	}

	// Without a token the answer is 401: the router comes after the token.
	body, resp := env.API(t, "", http.MethodGet, "/api/v1/nope", nil)
	assertError(t, body, resp, http.StatusUnauthorized, "unauthorized")
}

func TestAPIBodyLimit(t *testing.T) {
	env := testenv.New(t)
	raw, _ := env.APIToken(t, "door", model.APITokenScopeAdmin)

	body, resp := env.API(t, raw, http.MethodPost, "/api/v1/me", bytes.NewReader(make([]byte, 2<<20)))
	assertError(t, body, resp, http.StatusRequestEntityTooLarge, "too_large")
	if resp.Request.ContentLength != 2<<20 {
		t.Fatalf("sent Content-Length %d, want %d", resp.Request.ContentLength, 2<<20)
	}
}

func TestOpenAPIServed(t *testing.T) {
	env := testenv.New(t)

	body, resp := env.API(t, "", http.MethodGet, "/api/v1/openapi.json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %v)", resp.StatusCode, body)
	}
	assertJSONHeaders(t, resp)
	if v, _ := body["openapi"].(string); !strings.HasPrefix(v, "3.") {
		t.Errorf("openapi %q, want 3.x", v)
	}
	if info, _ := body["info"].(map[string]any); info["title"] != "Latch admin API" {
		t.Errorf("info.title %v, want Latch admin API", info["title"])
	}
}
