package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/oidc"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/testenv"
)

// The wiki's registered post-logout redirect URIs.
const (
	signedOutURI = "https://wiki.example.org/signed-out"
	byeURI       = "https://wiki.example.org/bye?from=latch" // already has a query
	loopbackBye  = "http://127.0.0.1/bye"
)

// logoutApp registers the confidential "Members Wiki" application with
// post-logout redirect URIs.
func logoutApp(t *testing.T, env *testenv.Env) *model.Application {
	t.Helper()
	return env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{wikiRedirect},
		PostLogoutRedirectURIs: []string{signedOutURI, byeURI, loopbackBye},
	}, wikiSecret)
}

// idTokenFor signs u in to app with a new browser and returns the browser
// and the ID token the application received.
func idTokenFor(t *testing.T, env *testenv.Env, app *model.Application, u *model.User) (*http.Client, string) {
	t.Helper()
	c := env.Client(t)
	env.Login(t, c, u.Email, testPW)
	code, _, _ := env.Authorize(t, c, app, false)
	body, resp := env.Exchange(t, app, wikiSecret, code, "", app.RedirectURIs[0])
	tokenOK(t, resp, body)
	return c, str(t, body, "id_token")
}

// rpLogout sends an RP-initiated logout request from c with params, in the
// query for GET or as a form for POST, and returns the response unread.
func rpLogout(t *testing.T, env *testenv.Env, c *http.Client, method string, params url.Values) *http.Response {
	t.Helper()
	var (
		resp *http.Response
		err  error
	)
	switch method {
	case http.MethodGet:
		resp, err = c.Get(env.TS.URL + "/oauth/logout?" + params.Encode())
	case http.MethodPost:
		resp, err = c.PostForm(env.TS.URL+"/oauth/logout", params)
	default:
		t.Fatalf("rpLogout: method %s", method)
	}
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// logoutRedirect checks that resp is an uncached 302 to want.
func logoutRedirect(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
		t.Fatalf("status %d Location %q, want 302 to %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
}

// asksFirst checks that resp is an uncached 303 to the sign-out
// confirmation page, carrying nothing from the request.
func asksFirst(t *testing.T, resp *http.Response) {
	t.Helper()
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/logout" {
		t.Fatalf("status %d Location %q, want 303 to /logout", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
}

// signedOutPage checks that resp is the uncached signed-out page, not a
// redirect.
func signedOutPage(t *testing.T, resp *http.Response) {
	t.Helper()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		t.Fatalf("status %d Location %q, want 200 and the signed-out page", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !strings.Contains(body, "You're signed out") {
		t.Errorf("not the signed-out page:\n%s", body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
}

// sessionEnded checks that the session c held with cookie raw is gone, that
// c's cookie is cleared, and that the old cookie no longer signs anyone in.
func sessionEnded(t *testing.T, env *testenv.Env, c *http.Client, raw string) {
	t.Helper()
	if _, err := env.Store.GetSession(context.Background(), secrets.HashToken(raw)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session still stored (err %v)", err)
	}
	u, err := url.Parse(env.TS.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			t.Errorf("browser still holds a %s cookie", session.CookieName)
		}
	}
	old := env.Client(t)
	old.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: raw}})
	resp := get(t, old, env.TS.URL+"/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Errorf("old session cookie: status %d Location %q, want 303 to sign-in",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// cookieOf returns the session cookie c holds, failing the test unless it
// names a stored session.
func cookieOf(t *testing.T, env *testenv.Env, c *http.Client) string {
	t.Helper()
	sessionOf(t, env, c)
	u, err := url.Parse(env.TS.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			return ck.Value
		}
	}
	t.Fatal("client has no session cookie")
	return ""
}

// sessionKept checks that c is still signed in with the session with id.
func sessionKept(t *testing.T, env *testenv.Env, c *http.Client, id string) {
	t.Helper()
	if got := sessionOf(t, env, c).ID; got != id {
		t.Errorf("browser's session changed to %q, want it kept", got)
	}
}

// rpLogouts returns the client_id ("" for none) of each logout event
// recorded for u by RP-initiated logout.
func rpLogouts(t *testing.T, env *testenv.Env, u *model.User) []string {
	t.Helper()
	rows, err := env.DB.Query(`SELECT COALESCE(json_extract(detail, '$.client_id'), '') FROM audit_events
		WHERE action=? AND actor_type='user' AND actor_id=? AND json_extract(detail, '$.via')='rp'`, audit.Logout, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestRPLogoutRedirectsWhenRegistered(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	c, u, tokens := memberTokens(t, env, app, wikiSecret)
	raw := cookieOf(t, env, c)

	logoutRedirect(t, rpLogout(t, env, c, http.MethodGet, url.Values{
		"id_token_hint":            {str(t, tokens, "id_token")},
		"post_logout_redirect_uri": {signedOutURI},
		"client_id":                {app.ClientID},
		"state":                    {"bye now&x=1"},
	}), signedOutURI+"?state=bye+now%26x%3D1")
	sessionEnded(t, env, c, raw)
	if got := rpLogouts(t, env, u); !slices.Equal(got, []string{app.ClientID}) {
		t.Errorf("RP logout events naming %q, want one naming %s", got, app.ClientID)
	}
	// Signing in to the application again starts from the sign-in page.
	loginRedirect(t, env.AuthorizeRaw(t, c, authParams(app, wikiRedirect)), app.Slug)
}

func TestRPLogoutPostWithoutSessionAppendsState(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	signedIn, u, tokens := memberTokens(t, env, app, wikiSecret)
	hint := str(t, tokens, "id_token")
	other := env.Client(t) // never signed in

	logoutRedirect(t, rpLogout(t, env, other, http.MethodPost, url.Values{
		"id_token_hint": {hint}, "post_logout_redirect_uri": {byeURI}, "state": {"s1"},
	}), byeURI+"&state=s1")
	logoutRedirect(t, rpLogout(t, env, other, http.MethodPost, url.Values{
		"id_token_hint": {hint}, "post_logout_redirect_uri": {byeURI},
	}), byeURI)

	// Only the requesting browser's session ends, and it had none.
	sessionOf(t, env, signedIn)
	if got := rpLogouts(t, env, u); len(got) != 0 {
		t.Errorf("logout events without a session: %q", got)
	}
}

func TestRPLogoutUnregisteredURIRendersPage(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	for _, uri := range []string{
		wikiRedirect, // a sign-in redirect URI, not a post-logout one
		signedOutURI + "/",
		"https://evil.example/signed-out",
		"https://wiki.example.org/bye", // registered with a query
		"http://127.0.0.1:8080/bye",    // no loopback port rule here
		"",
	} {
		t.Run(uri, func(t *testing.T) {
			c, hint := idTokenFor(t, env, app, u)
			raw := cookieOf(t, env, c)
			signedOutPage(t, rpLogout(t, env, c, http.MethodGet, url.Values{
				"id_token_hint": {hint}, "post_logout_redirect_uri": {uri}, "state": {"s1"},
			}))
			sessionEnded(t, env, c, raw)
		})
	}
}

func TestRPLogoutClientIDMismatchRendersPage(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	tools := toolsApp(t, env)
	c, u, tokens := memberTokens(t, env, app, wikiSecret)
	raw := cookieOf(t, env, c)

	// The hint is valid and is the member's, so the session ends, but the
	// request names another application, so nobody is sent back.
	signedOutPage(t, rpLogout(t, env, c, http.MethodGet, url.Values{
		"id_token_hint": {str(t, tokens, "id_token")}, "post_logout_redirect_uri": {signedOutURI},
		"client_id": {tools.ClientID}, "state": {"s1"},
	}))
	sessionEnded(t, env, c, raw)
	if got := rpLogouts(t, env, u); !slices.Equal(got, []string{app.ClientID}) {
		t.Errorf("RP logout events naming %q, want one naming %s", got, app.ClientID)
	}
}

func TestRPLogoutWithoutHintAsksFirst(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	c, u := signedIn(t, env)
	sess, raw := sessionOf(t, env, c), cookieOf(t, env, c)
	params := url.Values{"post_logout_redirect_uri": {signedOutURI}, "state": {"s1"}, "client_id": {app.ClientID}}

	// A link or image on any site can make this request, so the member is
	// asked before being signed out.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		asksFirst(t, rpLogout(t, env, c, method, params))
		sessionKept(t, env, c, sess.ID)
	}
	if got := rpLogouts(t, env, u); len(got) != 0 {
		t.Errorf("logout recorded without signing out: %q", got)
	}

	// Confirming there signs the member out.
	if body := readBody(t, get(t, c, env.TS.URL+"/logout")); !strings.Contains(body, `action="/logout"`) {
		t.Fatalf("confirmation page has no sign-out form:\n%s", body)
	}
	resp, err := c.PostForm(env.TS.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sessionEnded(t, env, c, raw)

	// Without a session there is nothing to ask about.
	signedOutPage(t, rpLogout(t, env, c, http.MethodGet, params))
}

func TestRPLogoutIgnoresHintExpiry(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	c, _, tokens := memberTokens(t, env, app, wikiSecret)
	raw := cookieOf(t, env, c)
	env.Clock.Advance(2 * time.Hour) // the ID token lasts an hour

	logoutRedirect(t, rpLogout(t, env, c, http.MethodGet, url.Values{
		"id_token_hint": {str(t, tokens, "id_token")}, "post_logout_redirect_uri": {loopbackBye},
	}), loopbackBye)
	sessionEnded(t, env, c, raw)
}

func TestRPLogoutHintFirstAudienceNamesApp(t *testing.T) {
	expired := func(t *testing.T, env *testenv.Env, u *model.User, app *model.Application, aud []string) string {
		t.Helper()
		hint, err := env.Keys.Sign(map[string]any{
			"iss": env.TS.URL, "sub": oidc.Subject(u, app), "aud": aud,
			"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return hint
	}

	t.Run("the application first", func(t *testing.T) {
		env := testenv.New(t)
		app := logoutApp(t, env)
		c, u := signedIn(t, env)
		logoutRedirect(t, rpLogout(t, env, c, http.MethodGet, url.Values{
			"id_token_hint":            {expired(t, env, u, app, []string{app.ClientID, "other-client"})},
			"post_logout_redirect_uri": {signedOutURI},
		}), signedOutURI)
	})
	t.Run("another application first", func(t *testing.T) {
		env := testenv.New(t)
		app := logoutApp(t, env)
		tools := toolsApp(t, env) // has no post-logout addresses
		c, u := signedIn(t, env)
		raw := cookieOf(t, env, c)
		signedOutPage(t, rpLogout(t, env, c, http.MethodGet, url.Values{
			"id_token_hint":            {expired(t, env, u, app, []string{tools.ClientID, app.ClientID})},
			"post_logout_redirect_uri": {signedOutURI},
		}))
		sessionEnded(t, env, c, raw) // a valid hint for this member, from Tool Booking
		if got := rpLogouts(t, env, u); !slices.Equal(got, []string{tools.ClientID}) {
			t.Errorf("RP logout events naming %q, want one naming %s", got, tools.ClientID)
		}
	})
}

func TestRPLogoutInvalidHintAsksFirst(t *testing.T) {
	// Each case gets a signed-in browser for u at app and its tokens, and
	// returns the hint to send.
	for _, tc := range []struct {
		name string
		hint func(t *testing.T, env *testenv.Env, app *model.Application, u *model.User, tokens map[string]any) string
	}{
		{"not a token", func(*testing.T, *testenv.Env, *model.Application, *model.User, map[string]any) string {
			return "garbage"
		}},
		{"access token", func(t *testing.T, _ *testenv.Env, _ *model.Application, _ *model.User, tokens map[string]any) string {
			return str(t, tokens, "access_token")
		}},
		{"claims altered", func(t *testing.T, _ *testenv.Env, _ *model.Application, _ *model.User, tokens map[string]any) string {
			parts := strings.Split(str(t, tokens, "id_token"), ".")
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatal(err)
			}
			claims["name"] = "Mallory" // a claim logout ignores, so only the signature fails
			if payload, err = json.Marshal(claims); err != nil {
				t.Fatal(err)
			}
			parts[1] = base64.RawURLEncoding.EncodeToString(payload)
			return strings.Join(parts, ".")
		}},
		{"another issuer", func(t *testing.T, env *testenv.Env, app *model.Application, u *model.User, _ map[string]any) string {
			return signHint(t, env, map[string]any{"iss": "https://evil.example", "sub": oidc.Subject(u, app), "aud": app.ClientID})
		}},
		{"unknown application", func(t *testing.T, env *testenv.Env, app *model.Application, u *model.User, _ map[string]any) string {
			return signHint(t, env, map[string]any{"iss": env.TS.URL, "sub": oidc.Subject(u, app), "aud": "nobody"})
		}},
		{"no audience", func(t *testing.T, env *testenv.Env, app *model.Application, u *model.User, _ map[string]any) string {
			return signHint(t, env, map[string]any{"iss": env.TS.URL, "sub": oidc.Subject(u, app)})
		}},
		{"key retired past its grace", func(t *testing.T, env *testenv.Env, _ *model.Application, _ *model.User, tokens map[string]any) string {
			ctx := context.Background()
			var offset atomic.Int64
			env.Keys.SetClock(func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
			if _, err := env.Keys.Rotate(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := env.Keys.RetireOlderThan(ctx, 0); err != nil {
				t.Fatal(err)
			}
			offset.Store(int64(oidc.RetiredKeyGrace + time.Hour))
			return str(t, tokens, "id_token")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testenv.New(t)
			app := logoutApp(t, env)
			c, u, tokens := memberTokens(t, env, app, wikiSecret)
			sess := sessionOf(t, env, c)
			params := url.Values{
				"id_token_hint": {tc.hint(t, env, app, u, tokens)}, "post_logout_redirect_uri": {signedOutURI}, "state": {"s1"},
			}

			asksFirst(t, rpLogout(t, env, c, http.MethodGet, params))
			sessionKept(t, env, c, sess.ID)
			// Without a session: the page, and no trip back to the application.
			signedOutPage(t, rpLogout(t, env, env.Client(t), http.MethodGet, params))
		})
	}
}

// signHint signs claims, with an expiry an hour away, as an ID token.
func signHint(t *testing.T, env *testenv.Env, claims map[string]any) string {
	t.Helper()
	claims["iat"], claims["exp"] = time.Now().Unix(), time.Now().Add(time.Hour).Unix()
	hint, err := env.Keys.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return hint
}

func TestRPLogoutHintForAnotherMemberAsksFirst(t *testing.T) {
	env := testenv.New(t)
	app := logoutApp(t, env)
	alexBrowser, _, tokens := memberTokens(t, env, app, wikiSecret)
	sam := env.CreateUser(t, "sam@example.org", testPW, "Members")
	samBrowser := env.Client(t)
	env.Login(t, samBrowser, sam.Email, testPW)
	samSession := sessionOf(t, env, samBrowser)

	asksFirst(t, rpLogout(t, env, samBrowser, http.MethodGet, url.Values{
		"id_token_hint": {str(t, tokens, "id_token")}, "post_logout_redirect_uri": {signedOutURI},
	}))
	sessionKept(t, env, samBrowser, samSession.ID)
	if got := rpLogouts(t, env, sam); len(got) != 0 {
		t.Errorf("logout recorded for sam without signing out: %q", got)
	}
	sessionOf(t, env, alexBrowser) // alex is still signed in too
}
