package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/testenv"
)

const (
	testPW       = "correct horse battery staple"
	wikiRedirect = "https://wiki.example.org/callback"
	cliRedirect  = "http://127.0.0.1/cb"
)

// wikiApp registers the confidential "Members Wiki" application, open to
// the given groups (anyone active when none).
func wikiApp(t *testing.T, env *testenv.Env, allowedGroupIDs ...string) *model.Application {
	t.Helper()
	return env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{wikiRedirect},
		AllowedGroupIDs: allowedGroupIDs,
	}, "wiki-secret")
}

// cliApp registers a public application with a loopback redirect URI.
func cliApp(t *testing.T, env *testenv.Env) *model.Application {
	t.Helper()
	return env.CreateApp(t, model.Application{
		Name: "Laser CLI", Slug: "laser-cli", ClientID: "laser-cli",
		ClientType: model.ClientTypePublic, RedirectURIs: []string{cliRedirect},
	}, "")
}

// authParams is a valid authorization request from app, without PKCE.
func authParams(app *model.Application, redirectURI string) url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {app.ClientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile email groups"},
		"state":         {"st-123"},
		"nonce":         {"n-456"},
	}
}

// signedIn creates a member of Members and returns a client signed in as them.
func signedIn(t *testing.T, env *testenv.Env) (*http.Client, *model.User) {
	t.Helper()
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	c := env.Client(t)
	env.Login(t, c, u.Email, testPW)
	return c, u
}

func get(t *testing.T, c *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// clientRedirect checks that resp is an uncached 302 back to the
// application at redirectURI and returns the parameters it carries.
func clientRedirect(t *testing.T, resp *http.Response, redirectURI string) url.Values {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d (Location %q), want 302 to the application", resp.StatusCode, resp.Header.Get("Location"))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	loc.RawQuery = ""
	if loc.String() != redirectURI {
		t.Fatalf("redirected to %q, want %q", loc, redirectURI)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
	return q
}

// loginRedirect checks that resp is a 303 to the sign-in page naming the
// application with slug, and returns the next parameter.
func loginRedirect(t *testing.T, resp *http.Response, slug string) string {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d (Location %q), want 303 to sign-in", resp.StatusCode, resp.Header.Get("Location"))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if loc.Path != "/login" || q.Get("app") != slug {
		t.Fatalf("redirected to %q, want /login with app=%s", loc, slug)
	}
	next := q.Get("next")
	if !strings.HasPrefix(next, "/oauth/authorize?") {
		t.Fatalf("next %q, want the authorize address", next)
	}
	return next
}

// assertError checks an error redirect to the application.
func assertError(t *testing.T, env *testenv.Env, q url.Values, code string) {
	t.Helper()
	if q.Get("error") != code || q.Get("error_description") == "" {
		t.Errorf("error %q (%q), want %q with a description", q.Get("error"), q.Get("error_description"), code)
	}
	if q.Get("state") != "st-123" || q.Get("iss") != env.TS.URL {
		t.Errorf("state %q iss %q, want st-123 and %s", q.Get("state"), q.Get("iss"), env.TS.URL)
	}
	if q.Has("code") {
		t.Error("error redirect carries a code")
	}
}

// sessionOf returns the session c's cookie names (stored under the
// cookie's hash).
func sessionOf(t *testing.T, env *testenv.Env, c *http.Client) *model.Session {
	t.Helper()
	u, err := url.Parse(env.TS.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			sess, err := env.Store.GetSession(context.Background(), secrets.HashToken(ck.Value))
			if err != nil {
				t.Fatalf("get session: %v", err)
			}
			return sess
		}
	}
	t.Fatal("client has no session cookie")
	return nil
}

func countRows(t *testing.T, env *testenv.Env, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDiscoveryDocument(t *testing.T) {
	env := testenv.New(t)
	hc := env.TS.Client()

	resp := get(t, hc, env.TS.URL+"/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control %q", cc)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if doc["issuer"] != env.TS.URL {
		t.Errorf("issuer %v, want %s", doc["issuer"], env.TS.URL)
	}
	for field, path := range map[string]string{
		"authorization_endpoint": "/oauth/authorize",
		"token_endpoint":         "/oauth/token",
		"userinfo_endpoint":      "/oauth/userinfo",
		"jwks_uri":               "/.well-known/jwks.json",
		"end_session_endpoint":   "/oauth/logout",
		"revocation_endpoint":    "/oauth/revoke",
		"introspection_endpoint": "/oauth/introspect",
	} {
		if doc[field] != env.TS.URL+path {
			t.Errorf("%s = %v, want %s", field, doc[field], env.TS.URL+path)
		}
	}
	for field, want := range map[string][]any{
		"response_types_supported":              {"code"},
		"grant_types_supported":                 {"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               {"public"},
		"id_token_signing_alg_values_supported": {"RS256"},
		"scopes_supported":                      {"openid", "profile", "email", "groups", "offline_access"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      {"S256"},
		"claims_supported": {"sub", "email", "email_verified", "name", "preferred_username",
			"groups", "metadata", "group_metadata", "is_admin", "updated_at"},
	} {
		if !reflect.DeepEqual(doc[field], want) {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
	if doc["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("authorization_response_iss_parameter_supported = %v, want true", doc["authorization_response_iss_parameter_supported"])
	}

	jwksURI, _ := doc["jwks_uri"].(string)
	resp = get(t, hc, jwksURI)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("jwks status %d Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	var set struct {
		Keys []struct{ Kid, Kty, Alg, Use string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(set.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(set.Keys))
	}
	if k := set.Keys[0]; k.Kid != env.Keys.ActiveKID() || k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Errorf("jwks key %+v, want the active RS256 signing key %s", k, env.Keys.ActiveKID())
	}

	// Every advertised endpoint is routed, so clients that read the
	// document find something there.
	for _, ep := range []struct{ method, field string }{
		{http.MethodPost, "token_endpoint"},
		{http.MethodGet, "userinfo_endpoint"},
		{http.MethodPost, "revocation_endpoint"},
		{http.MethodPost, "introspection_endpoint"},
		{http.MethodGet, "end_session_endpoint"},
	} {
		req, err := http.NewRequest(ep.method, doc[ep.field].(string), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := env.Client(t).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d", ep.method, ep.field, resp.StatusCode)
		}
	}
}

func TestAuthorizeUnknownClientIs400Page(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	p := authParams(app, wikiRedirect)
	p.Set("client_id", "nobody")

	resp := env.AuthorizeRaw(t, env.Client(t), p)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("status %d Location %q, want 400 and no redirect", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !strings.Contains(body, "Unknown application") {
		t.Errorf("page does not say the application is unknown:\n%s", body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
}

func TestAuthorizeBadRedirectIs400NoRedirect(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _ := signedIn(t, env)
	for _, redirect := range []string{
		"https://wiki.example.org/callback/", // Review Focus 3
		"https://wiki.example.org:8443/callback",
		"https://evil.example/callback",
		"",
	} {
		resp := env.AuthorizeRaw(t, c, authParams(app, redirect))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("redirect_uri %q: status %d Location %q, want 400 and no redirect",
				redirect, resp.StatusCode, resp.Header.Get("Location"))
			continue
		}
		if !strings.Contains(body, html.EscapeString("That application sent an address we don't recognise.")) {
			t.Errorf("redirect_uri %q: page does not explain the address", redirect)
		}
	}
}

func TestAuthorizeRedirectsToLoginThenIssuesCode(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	c := env.Client(t)
	p := authParams(app, wikiRedirect)

	next := loginRedirect(t, env.AuthorizeRaw(t, c, p), "wiki")
	if next != "/oauth/authorize?"+p.Encode() {
		t.Errorf("next %q, want the authorize request", next)
	}

	env.Login(t, c, u.Email, testPW)
	q := clientRedirect(t, get(t, c, env.TS.URL+next), wikiRedirect)
	if q.Get("state") != "st-123" || q.Get("iss") != env.TS.URL || q.Has("error") {
		t.Errorf("state %q iss %q error %q", q.Get("state"), q.Get("iss"), q.Get("error"))
	}
	code := q.Get("code")
	if code == "" {
		t.Fatal("no code")
	}

	// The code is stored hashed, with the request it answers.
	sess := sessionOf(t, env, c)
	stored, err := env.Store.ConsumeAuthCode(context.Background(), secrets.HashToken(code))
	if err != nil {
		t.Fatalf("consume code: %v", err)
	}
	want := model.AuthCode{
		CodeHash: secrets.HashToken(code), ApplicationID: app.ID, UserID: u.ID, SessionID: sess.ID,
		RedirectURI: wikiRedirect, Scope: "openid profile email groups", Nonce: "n-456",
		AuthTime: sess.CreatedAt, ExpiresAt: env.Clock.Now().Add(60 * time.Second),
	}
	got := *stored
	got.UsedAt = nil
	if !got.AuthTime.Equal(want.AuthTime) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("auth_time %v expires %v, want %v and %v", got.AuthTime, got.ExpiresAt, want.AuthTime, want.ExpiresAt)
	}
	got.AuthTime, got.ExpiresAt, want.AuthTime, want.ExpiresAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if got != want {
		t.Errorf("stored code %+v\nwant %+v", got, want)
	}
}

func TestAuthorizePostForm(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	c := env.Client(t)
	p := authParams(app, wikiRedirect)

	resp, err := c.PostForm(env.TS.URL+"/oauth/authorize", p)
	if err != nil {
		t.Fatal(err)
	}
	if next := loginRedirect(t, resp, "wiki"); next != "/oauth/authorize?"+p.Encode() {
		t.Errorf("next %q, want the posted request as an address", next)
	}

	env.Login(t, c, u.Email, testPW)
	resp, err = c.PostForm(env.TS.URL+"/oauth/authorize", p)
	if err != nil {
		t.Fatal(err)
	}
	if q := clientRedirect(t, resp, wikiRedirect); q.Get("code") == "" || q.Get("state") != "st-123" {
		t.Errorf("code %q state %q", q.Get("code"), q.Get("state"))
	}
}

func TestAuthorizePublicClientRequiresPKCE(t *testing.T) {
	env := testenv.New(t)
	app := cliApp(t, env)
	c, _ := signedIn(t, env)
	const loopback = "http://127.0.0.1:51234/cb" // registered without a port
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	for name, pkce := range map[string]url.Values{
		"no challenge":   {},
		"plain":          {"code_challenge": {challenge}, "code_challenge_method": {"plain"}},
		"method omitted": {"code_challenge": {challenge}},
	} {
		p := authParams(app, loopback)
		for k, v := range pkce {
			p[k] = v
		}
		t.Run(name, func(t *testing.T) {
			assertError(t, env, clientRedirect(t, env.AuthorizeRaw(t, c, p), loopback), "invalid_request")
		})
	}

	code, verifier, _ := env.Authorize(t, c, app, true)
	if code == "" || verifier == "" {
		t.Fatalf("with S256: code %q verifier %q", code, verifier)
	}
}

func TestAuthorizeRequestErrorsRedirect(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _ := signedIn(t, env)
	for _, tc := range []struct {
		name, param, value, code string
	}{
		{"response_type missing", "response_type", "", "invalid_request"},
		{"implicit", "response_type", "token", "unsupported_response_type"},
		{"no openid scope", "scope", "profile email", "invalid_scope"},
		{"plain PKCE", "code_challenge_method", "plain", "invalid_request"},
		{"prompt none with login", "prompt", "none login", "invalid_request"},
		{"negative max_age", "max_age", "-1", "invalid_request"},
		{"max_age not a number", "max_age", "soon", "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := authParams(app, wikiRedirect)
			if tc.param == "code_challenge_method" {
				p.Set("code_challenge", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			}
			if tc.value == "" {
				p.Del(tc.param)
			} else {
				p.Set(tc.param, tc.value)
			}
			assertError(t, env, clientRedirect(t, env.AuthorizeRaw(t, c, p), wikiRedirect), tc.code)
		})
	}
}

func TestAuthorizeConfidentialClientMayUsePKCE(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _ := signedIn(t, env)

	code, verifier, _ := env.Authorize(t, c, app, true)
	stored, err := env.Store.ConsumeAuthCode(context.Background(), secrets.HashToken(code))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if stored.CodeChallenge != base64.RawURLEncoding.EncodeToString(sum[:]) || stored.CodeChallengeMethod != "S256" {
		t.Errorf("stored challenge %q method %q", stored.CodeChallenge, stored.CodeChallengeMethod)
	}
}

func TestAuthorizeGroupDenied(t *testing.T) {
	env := testenv.New(t)
	doors := env.CreateGroup(t, "Doors", false, false)
	app := wikiApp(t, env, doors.ID)
	c, u := signedIn(t, env) // in Members, not Doors

	resp := env.AuthorizeRaw(t, c, authParams(app, wikiRedirect))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		t.Fatalf("status %d Location %q, want the no-access page", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !strings.Contains(body, "You don't have access to Members Wiki.") {
		t.Errorf("page does not name the application:\n%s", body)
	}
	if n := countRows(t, env, `SELECT COUNT(*) FROM auth_codes`); n != 0 {
		t.Errorf("%d codes issued, want none", n)
	}
	if n := countRows(t, env, `SELECT COUNT(*) FROM audit_events WHERE action=? AND actor_id=? AND target_id=?`,
		audit.AuthorizeDenied, u.ID, app.ID); n != 1 {
		t.Errorf("%d %s events, want 1", n, audit.AuthorizeDenied)
	}

	if err := env.Store.AddMember(context.Background(), u.ID, doors.ID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := env.Authorize(t, c, app, false); code == "" {
		t.Error("no code once in an allowed group")
	}
}

func TestAuthorizePromptNoneWithoutSession(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	p := authParams(app, wikiRedirect)
	p.Set("prompt", "none")
	assertError(t, env, clientRedirect(t, env.AuthorizeRaw(t, env.Client(t), p), wikiRedirect), "login_required")
}

// A session still waiting for its second step counts as no session.
func TestAuthorizeIncompleteSessionIsNoSession(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	env.EnrolTOTP(t, u)
	c := env.Client(t)
	env.Login(t, c, u.Email, testPW) // password accepted, code not yet entered

	p := authParams(app, wikiRedirect)
	loginRedirect(t, env.AuthorizeRaw(t, c, p), "wiki")
	p.Set("prompt", "none")
	assertError(t, env, clientRedirect(t, env.AuthorizeRaw(t, c, p), wikiRedirect), "login_required")
}

// A session whose user is not a member (here a member's account turned
// into a service account) gets no code: service accounts cannot use the
// login pages.
func TestAuthorizeServiceAccountSessionIsNoSession(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u := signedIn(t, env)
	u.Type = model.UserTypeService
	if err := env.Store.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	loginRedirect(t, env.AuthorizeRaw(t, c, authParams(app, wikiRedirect)), "wiki")
}

func TestAuthorizeMaxAgeForcesLogin(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u := signedIn(t, env)
	p := authParams(app, wikiRedirect)
	p.Set("max_age", "300")

	if q := clientRedirect(t, env.AuthorizeRaw(t, c, p), wikiRedirect); q.Get("code") == "" {
		t.Fatal("no code for a session within max_age")
	}

	env.Clock.Advance(301 * time.Second)
	stale := url.Values{}
	for k, v := range p {
		stale[k] = v
	}
	stale.Set("prompt", "none")
	assertError(t, env, clientRedirect(t, env.AuthorizeRaw(t, c, stale), wikiRedirect), "login_required")

	next := loginRedirect(t, env.AuthorizeRaw(t, c, p), "wiki")
	// Signing in is the fresh authentication max_age asks for, so the
	// return trip must not ask again.
	nu, err := url.Parse(next)
	if err != nil {
		t.Fatal(err)
	}
	if nu.Query().Has("max_age") || nu.Query().Get("state") != "st-123" {
		t.Errorf("next %q, want the request without max_age", next)
	}
	env.Clock.Advance(time.Hour) // however long signing in takes
	env.Login(t, c, u.Email, testPW)
	if q := clientRedirect(t, get(t, c, env.TS.URL+next), wikiRedirect); q.Get("code") == "" {
		t.Error("no code after signing in again")
	}
}

func TestAuthorizePromptLoginForcesLoginOnce(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u := signedIn(t, env)
	p := authParams(app, wikiRedirect)
	p.Set("prompt", "login")

	next := loginRedirect(t, env.AuthorizeRaw(t, c, p), "wiki")
	nu, err := url.Parse(next)
	if err != nil {
		t.Fatal(err)
	}
	if nu.Query().Has("prompt") {
		t.Errorf("next %q still asks for a sign-in", next)
	}
	env.Login(t, c, u.Email, testPW)
	if q := clientRedirect(t, get(t, c, env.TS.URL+next), wikiRedirect); q.Get("code") == "" {
		t.Error("no code after signing in again")
	}
}
