package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"keywell/internal/audit"
	"keywell/internal/config"
	"keywell/internal/model"
	"keywell/internal/secrets"
	"keywell/internal/testenv"
)

const (
	wikiSecret  = "wiki-secret"
	toolsSecret = "tools-secret"
	day         = 24 * time.Hour
)

// toolsApp registers a second confidential application, "Tool Booking",
// sharing the wiki's redirect URI so only the client differs.
func toolsApp(t *testing.T, env *testenv.Env) *model.Application {
	t.Helper()
	return env.CreateApp(t, model.Application{
		Name: "Tool Booking", Slug: "tools", ClientID: "tools-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{wikiRedirect},
	}, toolsSecret)
}

// memberTokens signs a new member of Members, alex@example.org, in to app,
// exchanges the code (with PKCE for a public app) and returns the client,
// the member and the successful token response.
func memberTokens(t *testing.T, env *testenv.Env, app *model.Application, secret string) (*http.Client, *model.User, map[string]any) {
	t.Helper()
	return memberTokensAs(t, env, app, secret, "alex@example.org")
}

// memberTokensAs is memberTokens for a member with the given email.
func memberTokensAs(t *testing.T, env *testenv.Env, app *model.Application, secret, email string) (*http.Client, *model.User, map[string]any) {
	t.Helper()
	u := env.CreateUser(t, email, testPW, "Members")
	c := env.Client(t)
	env.Login(t, c, u.Email, testPW)
	code, verifier, _ := env.Authorize(t, c, app, app.ClientType == model.ClientTypePublic)
	body, resp := env.Exchange(t, app, secret, code, verifier, app.RedirectURIs[0])
	tokenOK(t, resp, body)
	return c, u, body
}

// authorizeCode asks for a code with c for params and returns it.
func authorizeCode(t *testing.T, env *testenv.Env, c *http.Client, params url.Values) string {
	t.Helper()
	q := clientRedirect(t, env.AuthorizeRaw(t, c, params), params.Get("redirect_uri"))
	code := q.Get("code")
	if code == "" {
		t.Fatalf("no code: error %q (%s)", q.Get("error"), q.Get("error_description"))
	}
	return code
}

// str returns body[key] as a string, failing the test if it is not one or
// is empty.
func str(t *testing.T, body map[string]any, key string) string {
	t.Helper()
	s, _ := body[key].(string)
	if s == "" {
		t.Fatalf("%s missing from %v", key, body)
	}
	return s
}

// assertNoStore checks that resp is JSON the client must not cache.
func assertNoStore(t *testing.T, resp *http.Response) {
	t.Helper()
	h := resp.Header
	if h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" {
		t.Errorf("Content-Type %q Cache-Control %q Pragma %q, want application/json, no-store, no-cache",
			h.Get("Content-Type"), h.Get("Cache-Control"), h.Get("Pragma"))
	}
}

// tokenOK checks for a successful, uncached token response.
func tokenOK(t *testing.T, resp *http.Response, body map[string]any) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %v; want 200", resp.StatusCode, body)
	}
	assertNoStore(t, resp)
}

// tokenFails checks for an uncached JSON error with status and code; an
// invalid_client error must also challenge for Basic credentials.
func tokenFails(t *testing.T, resp *http.Response, body map[string]any, status int, code string) {
	t.Helper()
	if resp.StatusCode != status || body["error"] != code {
		t.Fatalf("status %d error %v (%v), want %d %s", resp.StatusCode, body["error"], body["error_description"], status, code)
	}
	if d, _ := body["error_description"].(string); d == "" {
		t.Error("no error_description")
	}
	assertNoStore(t, resp)
	if challenge := resp.Header.Get("WWW-Authenticate"); code == "invalid_client" && challenge != `Basic realm="keywell"` {
		t.Errorf("WWW-Authenticate %q, want a Basic challenge", challenge)
	}
}

// doJSON sends req and returns the response, its body closed, and the body
// decoded as a JSON object (nil when empty).
func doJSON(t *testing.T, env *testenv.Env, req *http.Request) (map[string]any, *http.Response) {
	t.Helper()
	resp, err := env.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		return nil, resp
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("status %d, body is not a JSON object: %v\n%s", resp.StatusCode, err, raw)
	}
	return body, resp
}

// userinfo calls the userinfo endpoint with accessToken as a bearer token
// (none when empty).
func userinfo(t *testing.T, env *testenv.Env, accessToken string) (map[string]any, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.TS.URL+"/oauth/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return doJSON(t, env, req)
}

// verifyToken checks that raw is a compact RS256 JWS with header typ, signed by
// one of the server's keys, and returns its claims.
func verifyToken(t *testing.T, env *testenv.Env, raw any, typ string) map[string]any {
	t.Helper()
	s, _ := raw.(string)
	jws, err := jose.ParseSignedCompact(s, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse token %q: %v", s, err)
	}
	h := jws.Signatures[0].Header
	if got := h.ExtraHeaders[jose.HeaderType]; got != typ {
		t.Errorf("header typ %v, want %s", got, typ)
	}
	pub, ok := env.Keys.PublicKey(h.KeyID)
	if !ok {
		t.Fatalf("token signed by unknown key %q", h.KeyID)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// verifyWithJWKS verifies raw against the key with its kid in the published
// key set, as an application checking tokens locally would.
func verifyWithJWKS(t *testing.T, env *testenv.Env, raw string) {
	t.Helper()
	resp := get(t, env.TS.Client(), env.TS.URL+"/.well-known/jwks.json")
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	keys := set.Key(jws.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		t.Fatalf("JWKS has %d keys with kid %q, want 1", len(keys), jws.Signatures[0].Header.KeyID)
	}
	if _, err := jws.Verify(keys[0].Key); err != nil {
		t.Errorf("access token does not verify with the JWKS: %v", err)
	}
}

// wantClaims checks each claim in want against got.
func wantClaims(t *testing.T, what string, got, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s %s = %#v, want %#v", what, k, got[k], v)
		}
	}
}

// atHash is the at_hash of accessToken (OIDC Core §3.1.3.6).
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func storedRefresh(t *testing.T, env *testenv.Env, raw string) *model.RefreshToken {
	t.Helper()
	rt, err := env.Store.GetRefreshToken(context.Background(), secrets.HashToken(raw))
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	return rt
}

func countTokenIssued(t *testing.T, env *testenv.Env, actorType model.ActorType, actorID string, app *model.Application, grant string) int {
	t.Helper()
	return countRows(t, env, `SELECT COUNT(*) FROM audit_events WHERE action=? AND actor_type=? AND actor_id=?
		AND target_type='application' AND target_id=?
		AND json_extract(detail, '$.grant')=? AND json_extract(detail, '$.client_id')=?`,
		audit.TokenIssued, string(actorType), actorID, app.ID, grant, app.ClientID)
}

func TestCodeExchangeConfidentialBasicAuth(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u := signedIn(t, env)
	code, _, _, nonce := env.AuthorizeWithNonce(t, c, app, false)
	authTime := sessionOf(t, env, c).CreatedAt

	body, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
	tokenOK(t, resp, body)
	wantClaims(t, "response", body, map[string]any{
		"token_type": "Bearer", "expires_in": float64(3600), "scope": "openid profile email groups",
	})
	str(t, body, "refresh_token")
	now := float64(env.Clock.Now().Unix())

	access := str(t, body, "access_token")
	verifyWithJWKS(t, env, access)
	at := verifyToken(t, env, access, "at+jwt")
	wantClaims(t, "access token", at, map[string]any{
		"iss": env.TS.URL, "sub": u.ID, "aud": []any{"wiki-client"}, "client_id": "wiki-client",
		"scope": "openid profile email groups", "email": u.Email, "groups": []any{"Members"},
		"iat": now, "exp": now + 3600,
	})
	if jti, _ := at["jti"].(string); len(jti) < 16 {
		t.Errorf("access token jti %q, want a random identifier", jti)
	}

	id := verifyToken(t, env, body["id_token"], "JWT")
	wantClaims(t, "ID token", id, map[string]any{
		"iss": env.TS.URL, "sub": u.ID, "aud": "wiki-client", "nonce": nonce, "at_hash": atHash(access),
		"auth_time": float64(authTime.Unix()), "iat": now, "exp": now + 3600,
		"email": u.Email, "email_verified": true, "name": "alex", "preferred_username": "alex",
		"groups": []any{"Members"},
	})

	if n := countTokenIssued(t, env, model.ActorUser, u.ID, app, "authorization_code"); n != 1 {
		t.Errorf("%d %s events for the exchange, want 1", n, audit.TokenIssued)
	}
}

func TestClientAuthentication(t *testing.T) {
	env := testenv.New(t)
	const awkward = "s3cr:t+/%&= é" // needs form-encoding inside Basic
	env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki client", RedirectURIs: []string{wikiRedirect},
	}, awkward)
	cliApp(t, env)
	basic := func(id, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
	}

	// An unknown code fails with invalid_grant only once the client is
	// authenticated, so invalid_grant here means authentication passed.
	for _, tc := range []struct {
		name          string
		authorization string
		form          url.Values
		status        int
		code          string
	}{
		{"basic", basic("wiki client", awkward), nil, 400, "invalid_grant"},
		{"post", "", url.Values{"client_id": {"wiki client"}, "client_secret": {awkward}}, 400, "invalid_grant"},
		{"basic with matching client_id in form", basic("wiki client", awkward), url.Values{"client_id": {"wiki client"}}, 400, "invalid_grant"},
		{"public client, no secret", "", url.Values{"client_id": {"laser-cli"}}, 400, "invalid_grant"},
		{"public client, basic with empty secret", basic("laser-cli", ""), nil, 400, "invalid_grant"},
		{"wrong secret, basic", basic("wiki client", "nope"), nil, 401, "invalid_client"},
		{"wrong secret, post", "", url.Values{"client_id": {"wiki client"}, "client_secret": {"nope"}}, 401, "invalid_client"},
		{"secret not form-encoded", "Basic " + base64.StdEncoding.EncodeToString([]byte("wiki+client:"+awkward)), nil, 401, "invalid_client"},
		{"confidential client without secret", "", url.Values{"client_id": {"wiki client"}}, 401, "invalid_client"},
		{"unknown client", basic("nobody", "x"), nil, 401, "invalid_client"},
		{"no client", "", nil, 401, "invalid_client"},
		{"public client sends secret", "", url.Values{"client_id": {"laser-cli"}, "client_secret": {"x"}}, 401, "invalid_client"},
		{"bearer instead of basic", "Bearer abc", url.Values{"client_id": {"wiki client"}}, 401, "invalid_client"},
		{"client_id differs from basic", basic("wiki client", awkward), url.Values{"client_id": {"laser-cli"}}, 400, "invalid_request"},
		{"secret in basic and form", basic("wiki client", awkward), url.Values{"client_secret": {awkward}}, 400, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"grant_type": {"authorization_code"}, "code": {"unknown"}, "redirect_uri": {wikiRedirect}}
			for k, v := range tc.form {
				form[k] = v
			}
			req, err := http.NewRequest(http.MethodPost, env.TS.URL+"/oauth/token", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			body, resp := doJSON(t, env, req)
			tokenFails(t, resp, body, tc.status, tc.code)
		})
	}
}

func TestCodeExchangePublicPKCE(t *testing.T) {
	env := testenv.New(t)
	app := cliApp(t, env)
	c, _ := signedIn(t, env)

	code, verifier, _ := env.Authorize(t, c, app, true)
	body, resp := env.Exchange(t, app, "", code, verifier+"x", cliRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")

	code, _, _ = env.Authorize(t, c, app, true)
	body, resp = env.Exchange(t, app, "", code, "", cliRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")

	code, verifier, _ = env.Authorize(t, c, app, true)
	body, resp = env.Exchange(t, app, "", code, verifier, cliRedirect)
	tokenOK(t, resp, body)
	verifyToken(t, env, body["id_token"], "JWT")
	str(t, body, "refresh_token")

	body, resp = env.Exchange(t, app, "", code, verifier, cliRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

func TestCodeBoundToClientAndRedirectURI(t *testing.T) {
	env := testenv.New(t)
	const otherRedirect = "https://wiki.example.org/other"
	wiki := env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client",
		RedirectURIs: []string{wikiRedirect, otherRedirect},
	}, wikiSecret)
	tools := toolsApp(t, env)
	c, _ := signedIn(t, env)

	code, _, _ := env.Authorize(t, c, wiki, false)
	body, resp := env.Exchange(t, tools, toolsSecret, code, "", wikiRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")
	// Another client learns nothing, not even that the code is real: its
	// answer is the one for a code that never existed.
	unknown, resp := env.Exchange(t, tools, toolsSecret, secrets.RandomToken(32), "", wikiRedirect)
	tokenFails(t, resp, unknown, 400, "invalid_grant")
	if !reflect.DeepEqual(body, unknown) {
		t.Errorf("another client's code: %v\nunknown code: %v\nwant the same answer", body, unknown)
	}
	// The attempt used the code up.
	body, resp = env.Exchange(t, wiki, wikiSecret, code, "", wikiRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")

	for _, redirect := range []string{otherRedirect, ""} {
		code, _, _ = env.Authorize(t, c, wiki, false)
		body, resp = env.Exchange(t, wiki, wikiSecret, code, "", redirect)
		tokenFails(t, resp, body, 400, "invalid_grant")
	}

	// A verifier for a code issued without a challenge is refused, so a
	// stolen code cannot be passed off as a PKCE one (RFC 9700 §2.1.1).
	code, _, _ = env.Authorize(t, c, wiki, false)
	body, resp = env.Exchange(t, wiki, wikiSecret, code, secrets.RandomToken(32), wikiRedirect)
	tokenFails(t, resp, body, 400, "invalid_grant")

	if n := countRows(t, env, `SELECT COUNT(*) FROM refresh_tokens`); n != 0 {
		t.Errorf("%d refresh tokens issued, want none", n)
	}
}

func TestRefreshRotatesAndDetectsReuse(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u := signedIn(t, env)
	code, _, _, nonce := env.AuthorizeWithNonce(t, c, app, false)
	authTime := sessionOf(t, env, c).CreatedAt
	first, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
	tokenOK(t, resp, first)
	rt1 := str(t, first, "refresh_token")
	stored1 := storedRefresh(t, env, rt1)

	env.Clock.Advance(time.Hour)
	second, resp := env.Refresh(t, app, wikiSecret, rt1)
	tokenOK(t, resp, second)
	rt2 := str(t, second, "refresh_token")
	access := str(t, second, "access_token")
	if rt2 == rt1 || access == first["access_token"] {
		t.Fatal("refresh returned the same tokens")
	}
	now := env.Clock.Now()
	wantClaims(t, "response", second, map[string]any{"token_type": "Bearer", "scope": "openid profile email groups"})
	// A new ID token for the same authentication (OIDC Core §12.2).
	wantClaims(t, "refreshed ID token", verifyToken(t, env, second["id_token"], "JWT"), map[string]any{
		"sub": u.ID, "aud": "wiki-client", "nonce": nonce, "auth_time": float64(authTime.Unix()),
		"iat": float64(now.Unix()), "at_hash": atHash(access),
	})

	if old := storedRefresh(t, env, rt1); old.RevokedAt == nil {
		t.Error("presented refresh token not revoked")
	}
	stored2 := storedRefresh(t, env, rt2)
	if stored2.FamilyID != stored1.FamilyID || !stored2.AbsoluteExpiresAt.Equal(stored1.AbsoluteExpiresAt) ||
		!stored2.ExpiresAt.Equal(now.Add(30*day)) || stored2.Scope != stored1.Scope || stored2.Nonce != nonce {
		t.Errorf("rotated token %+v\nfrom %+v", stored2, stored1)
	}
	if n := countTokenIssued(t, env, model.ActorUser, u.ID, app, "refresh_token"); n != 1 {
		t.Errorf("%d %s events for the refresh, want 1", n, audit.TokenIssued)
	}

	// Replaying the first token is refused and ends the whole family.
	body, resp := env.Refresh(t, app, wikiSecret, rt1)
	tokenFails(t, resp, body, 400, "invalid_grant")
	body, resp = env.Refresh(t, app, wikiSecret, rt2)
	tokenFails(t, resp, body, 400, "invalid_grant")
	if storedRefresh(t, env, rt2).RevokedAt == nil {
		t.Error("newest token in the family not revoked after reuse")
	}
}

// Revoking a refresh token ends its whole family: revoking with a token
// already rotated (as a client holding a stale copy would) also stops its
// live successor.
func TestRevokeEndsTheFamily(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _ := signedIn(t, env)
	code, _, _ := env.Authorize(t, c, app, false)
	first, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
	tokenOK(t, resp, first)
	stale := str(t, first, "refresh_token")
	second, resp := env.Refresh(t, app, wikiSecret, stale)
	tokenOK(t, resp, second)
	live := str(t, second, "refresh_token")

	body, resp := env.PostAsClient(t, "/oauth/revoke", app, wikiSecret, url.Values{"token": {stale}})
	if resp.StatusCode != http.StatusOK || body != nil {
		t.Fatalf("revoke: status %d body %v, want 200 and no body", resp.StatusCode, body)
	}
	if storedRefresh(t, env, live).RevokedAt == nil {
		t.Error("the live successor was not revoked")
	}
	body, resp = env.Refresh(t, app, wikiSecret, live)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

func TestRefreshSlidesUpToAbsoluteLimit(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _, body := memberTokens(t, env, app, wikiSecret)
	active := str(t, body, "refresh_token")
	code, _, _ := env.Authorize(t, c, app, false)
	body, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
	tokenOK(t, resp, body)
	idle := str(t, body, "refresh_token")
	limit := storedRefresh(t, env, active).AbsoluteExpiresAt
	if want := env.Clock.Now().Add(90 * day); !limit.Equal(want) {
		t.Fatalf("absolute expiry %v, want %v", limit, want)
	}

	refresh := func(rt string) string {
		t.Helper()
		body, resp := env.Refresh(t, app, wikiSecret, rt)
		tokenOK(t, resp, body)
		return str(t, body, "refresh_token")
	}
	for range 3 { // day 87
		env.Clock.Advance(29 * day)
		active = refresh(active)
	}
	// Unused for 30 days.
	body, resp = env.Refresh(t, app, wikiSecret, idle)
	tokenFails(t, resp, body, 400, "invalid_grant")

	env.Clock.Advance(2 * day) // day 89
	active = refresh(active)
	if exp := storedRefresh(t, env, active).ExpiresAt; !exp.Equal(limit) {
		t.Errorf("expiry %v, want the absolute limit %v", exp, limit)
	}
	env.Clock.Advance(day) // day 90
	body, resp = env.Refresh(t, app, wikiSecret, active)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

// refreshResult is the outcome of postRefresh.
type refreshResult struct {
	status int
	body   map[string]any
	err    error
}

// postRefresh redeems token as app with Basic credentials. It takes no
// *testing.T so that other goroutines may call it.
func postRefresh(env *testenv.Env, app *model.Application, secret, token string) refreshResult {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	req, err := http.NewRequest(http.MethodPost, env.TS.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return refreshResult{err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(app.ClientID), url.QueryEscape(secret))
	resp, err := env.TS.Client().Do(req)
	if err != nil {
		return refreshResult{err: err}
	}
	defer resp.Body.Close()
	var body map[string]any
	err = json.NewDecoder(resp.Body).Decode(&body)
	return refreshResult{status: resp.StatusCode, body: body, err: err}
}

// Two redemptions of one refresh token racing each other: exactly one wins,
// and the loser counts as reuse, so the winner's new token dies with the
// family. Several rounds, so the requests interleave at least once.
func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, _, body := memberTokens(t, env, app, wikiSecret)
	rt := str(t, body, "refresh_token")

	for round := range 10 {
		if round > 0 {
			code, _, _ := env.Authorize(t, c, app, false)
			body, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
			tokenOK(t, resp, body)
			rt = str(t, body, "refresh_token")
		}
		start := make(chan struct{})
		results := make(chan refreshResult, 2)
		for range 2 {
			go func() {
				<-start
				results <- postRefresh(env, app, wikiSecret, rt)
			}()
		}
		close(start)

		var winner string
		var refused int
		for range 2 {
			r := <-results
			switch {
			case r.err != nil:
				t.Fatalf("round %d: %v", round, r.err)
			case r.status == http.StatusOK:
				if winner != "" {
					t.Fatalf("round %d: both concurrent refreshes succeeded", round)
				}
				winner, _ = r.body["refresh_token"].(string)
			case r.status == http.StatusBadRequest && r.body["error"] == "invalid_grant":
				refused++
			default:
				t.Fatalf("round %d: status %d %v", round, r.status, r.body)
			}
		}
		if winner == "" || refused != 1 {
			t.Fatalf("round %d: winner %q, %d refused; want one of each", round, winner, refused)
		}
		body, resp := env.Refresh(t, app, wikiSecret, winner)
		tokenFails(t, resp, body, 400, "invalid_grant")
	}
}

// Review Focus 4.
func TestRefreshDisabledUserFails(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	_, u, body := memberTokens(t, env, app, wikiSecret)
	rt := str(t, body, "refresh_token")
	ctx := context.Background()

	u.IsActive = false
	if err := env.Store.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	body, resp := env.Refresh(t, app, wikiSecret, rt)
	tokenFails(t, resp, body, 400, "invalid_grant")
	if storedRefresh(t, env, rt).RevokedAt == nil {
		t.Error("family not revoked")
	}

	u.IsActive = true
	if err := env.Store.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	body, resp = env.Refresh(t, app, wikiSecret, rt)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

func TestRefreshAfterLeavingAllowedGroupFails(t *testing.T) {
	env := testenv.New(t)
	doors := env.CreateGroup(t, "Doors", false, false)
	app := wikiApp(t, env, doors.ID)
	u := env.CreateUser(t, "sam@example.org", testPW, "Doors")
	c := env.Client(t)
	env.Login(t, c, u.Email, testPW)
	code, _, _ := env.Authorize(t, c, app, false)
	body, resp := env.Exchange(t, app, wikiSecret, code, "", wikiRedirect)
	tokenOK(t, resp, body)
	rt := str(t, body, "refresh_token")
	ctx := context.Background()

	if err := env.Store.RemoveMember(ctx, u.ID, doors.ID); err != nil {
		t.Fatal(err)
	}
	body, resp = env.Refresh(t, app, wikiSecret, rt)
	tokenFails(t, resp, body, 400, "invalid_grant")

	if err := env.Store.AddMember(ctx, u.ID, doors.ID); err != nil {
		t.Fatal(err)
	}
	body, resp = env.Refresh(t, app, wikiSecret, rt)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

func TestRefreshScopeMayOnlyNarrow(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	_, _, body := memberTokens(t, env, app, wikiSecret)
	rt := str(t, body, "refresh_token")
	refresh := func(scope string) (map[string]any, *http.Response) {
		return env.PostAsClient(t, "/oauth/token", app, wikiSecret,
			url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {scope}})
	}

	// Asking for more than was granted is refused and spends nothing.
	body, resp := refresh("openid email offline_access")
	tokenFails(t, resp, body, 400, "invalid_scope")

	body, resp = refresh("openid email")
	tokenOK(t, resp, body)
	if body["scope"] != "openid email" {
		t.Errorf("scope %v, want openid email", body["scope"])
	}
	at := verifyToken(t, env, body["access_token"], "at+jwt")
	if at["scope"] != "openid email" || at["email"] == nil || at["groups"] != nil {
		t.Errorf("narrowed access token scope %v email %v groups %v", at["scope"], at["email"], at["groups"])
	}
	// The new refresh token keeps the original grant (RFC 6749 §6).
	if s := storedRefresh(t, env, str(t, body, "refresh_token")).Scope; s != "openid profile email groups" {
		t.Errorf("rotated refresh token scope %q, want the original grant", s)
	}
}

func TestRefreshRequiresOfflineAccessWhenConfigured(t *testing.T) {
	env := testenv.New(t, testenv.WithConfig(func(c *config.Config) {
		c.Tokens.RequireOfflineAccessForRefresh = true
	}))
	app := wikiApp(t, env)
	c, _, body := memberTokens(t, env, app, wikiSecret) // scope without offline_access
	if _, ok := body["refresh_token"]; ok {
		t.Error("refresh token issued without offline_access")
	}

	p := authParams(app, wikiRedirect)
	p.Set("scope", "openid email offline_access")
	body, resp := env.Exchange(t, app, wikiSecret, authorizeCode(t, env, c, p), "", wikiRedirect)
	tokenOK(t, resp, body)
	str(t, body, "refresh_token")
	if body["scope"] != "openid email offline_access" {
		t.Errorf("scope %v", body["scope"])
	}
}

func TestClientCredentialsServiceAccount(t *testing.T) {
	env := testenv.New(t)
	ctx := context.Background()
	doors := env.CreateGroup(t, "Doors", false, false)
	sa := &model.User{Name: "Door controller", Type: model.UserTypeService, IsActive: true,
		Username: "door-controller", Metadata: map[string]any{"site": "front door"}}
	if err := env.Store.CreateUser(ctx, sa); err != nil {
		t.Fatal(err)
	}
	if err := env.Store.AddMember(ctx, sa.ID, doors.ID); err != nil {
		t.Fatal(err)
	}
	app := env.CreateApp(t, model.Application{
		Name: "Door Controller", Slug: "doors", ClientID: "doors-client",
		RedirectURIs: []string{"https://doors.example.org/cb"}, ServiceAccountID: sa.ID,
	}, "doors-secret")
	form := url.Values{"grant_type": {"client_credentials"}} // no scope: the §6.5 claims come regardless

	body, resp := env.PostAsClient(t, "/oauth/token", app, "doors-secret", form)
	tokenOK(t, resp, body)
	wantClaims(t, "response", body, map[string]any{"token_type": "Bearer", "expires_in": float64(3600), "scope": ""})
	for _, k := range []string{"id_token", "refresh_token"} {
		if _, ok := body[k]; ok {
			t.Errorf("client credentials response has %s", k)
		}
	}
	access := str(t, body, "access_token")
	at := verifyToken(t, env, access, "at+jwt")
	wantClaims(t, "access token", at, map[string]any{
		"iss": env.TS.URL, "sub": sa.ID, "aud": []any{"doors-client"}, "client_id": "doors-client", "scope": "",
		"groups": []any{"Doors"}, "metadata": map[string]any{"site": "front door"}, "preferred_username": "door-controller",
	})
	if _, ok := at["email"]; ok {
		t.Errorf("access token has email %v for a service account without one", at["email"])
	}
	if n := countTokenIssued(t, env, model.ActorServiceAccount, sa.ID, app, "client_credentials"); n != 1 {
		t.Errorf("%d %s events, want 1", n, audit.TokenIssued)
	}
	// Spec §6.5: userinfo accepts these tokens (its claims follow the
	// token's scopes, here none).
	if ui, resp := userinfo(t, env, access); resp.StatusCode != http.StatusOK || ui["sub"] != sa.ID {
		t.Errorf("userinfo status %d %v", resp.StatusCode, ui)
	}

	// email appears once the service account has one; scope is echoed.
	sa.Email = "doors@example.org"
	if err := env.Store.UpdateUser(ctx, sa); err != nil {
		t.Fatal(err)
	}
	body, resp = env.PostAsClient(t, "/oauth/token", app, "doors-secret",
		url.Values{"grant_type": {"client_credentials"}, "scope": {"email nonsense"}})
	tokenOK(t, resp, body)
	wantClaims(t, "access token with email", verifyToken(t, env, body["access_token"], "at+jwt"), map[string]any{
		"scope": "email", "email": "doors@example.org", "groups": []any{"Doors"}, "preferred_username": "door-controller",
	})

	body, resp = env.PostAsClient(t, "/oauth/token", wikiApp(t, env), wikiSecret, form)
	tokenFails(t, resp, body, 400, "unauthorized_client")

	body, resp = env.PostAsClient(t, "/oauth/token", cliApp(t, env), "", form)
	tokenFails(t, resp, body, 401, "invalid_client")

	sa.IsActive = false
	if err := env.Store.UpdateUser(ctx, sa); err != nil {
		t.Fatal(err)
	}
	body, resp = env.PostAsClient(t, "/oauth/token", app, "doors-secret", form)
	tokenFails(t, resp, body, 400, "unauthorized_client")
}

func TestUserinfoAndIntrospect(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	c, u, body := memberTokens(t, env, app, wikiSecret)
	access, rt, idToken := str(t, body, "access_token"), str(t, body, "refresh_token"), str(t, body, "id_token")

	ui, resp := userinfo(t, env, access)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("userinfo status %d Cache-Control %q, body %v", resp.StatusCode, resp.Header.Get("Cache-Control"), ui)
	}
	want := map[string]any{
		"sub": u.ID, "email": u.Email, "email_verified": true, "name": "alex", "preferred_username": "alex",
		"metadata": map[string]any{}, "updated_at": float64(u.UpdatedAt.Unix()), "groups": []any{"Members"},
		"group_metadata": map[string]any{"Members": map[string]any{}}, "is_admin": false,
	}
	if !reflect.DeepEqual(ui, want) {
		t.Errorf("userinfo %v\nwant %v", ui, want)
	}
	req, err := http.NewRequest(http.MethodPost, env.TS.URL+"/oauth/userinfo",
		strings.NewReader(url.Values{"access_token": {access}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if posted, resp := doJSON(t, env, req); resp.StatusCode != http.StatusOK || !reflect.DeepEqual(posted, want) {
		t.Errorf("userinfo by form: status %d %v", resp.StatusCode, posted)
	}

	// Only the scopes the token carries.
	p := authParams(app, wikiRedirect)
	p.Set("scope", "openid email")
	narrow, resp := env.Exchange(t, app, wikiSecret, authorizeCode(t, env, c, p), "", wikiRedirect)
	tokenOK(t, resp, narrow)
	ui, _ = userinfo(t, env, str(t, narrow, "access_token"))
	if want := (map[string]any{"sub": u.ID, "email": u.Email, "email_verified": true}); !reflect.DeepEqual(ui, want) {
		t.Errorf("userinfo for openid email: %v, want %v", ui, want)
	}

	introspect := func(a *model.Application, secret, token string) (map[string]any, *http.Response) {
		t.Helper()
		return env.PostAsClient(t, "/oauth/introspect", a, secret, url.Values{"token": {token}})
	}
	now := env.Clock.Now()
	body, resp = introspect(app, wikiSecret, access)
	tokenOK(t, resp, body)
	wantClaims(t, "introspected access token", body, map[string]any{
		"active": true, "sub": u.ID, "client_id": "wiki-client", "scope": "openid profile email groups",
		"iss": env.TS.URL, "username": u.Email, "iat": float64(now.Unix()), "exp": float64(now.Add(time.Hour).Unix()),
	})
	body, resp = introspect(app, wikiSecret, rt)
	tokenOK(t, resp, body)
	wantClaims(t, "introspected refresh token", body, map[string]any{
		"active": true, "sub": u.ID, "client_id": "wiki-client", "scope": "openid profile email groups",
		"iss": env.TS.URL, "username": u.Email, "iat": float64(now.Unix()), "exp": float64(now.Add(30 * day).Unix()),
	})
	for name, token := range map[string]string{"garbage": "garbage", "empty": "", "ID token": idToken} {
		body, resp = introspect(app, wikiSecret, token)
		if resp.StatusCode != http.StatusOK || !reflect.DeepEqual(body, map[string]any{"active": false}) {
			t.Errorf("introspect %s: status %d %v, want active false", name, resp.StatusCode, body)
		}
	}
	body, resp = introspect(app, "wrong", access)
	tokenFails(t, resp, body, 401, "invalid_client")
	body, resp = introspect(cliApp(t, env), "", access)
	tokenFails(t, resp, body, 401, "invalid_client")

	// Revocation: another client cannot revoke the token; its own can.
	revoke := func(a *model.Application, secret, token string) {
		t.Helper()
		body, resp := env.PostAsClient(t, "/oauth/revoke", a, secret, url.Values{"token": {token}})
		if resp.StatusCode != http.StatusOK || body != nil {
			t.Fatalf("revoke: status %d body %v, want 200 and no body", resp.StatusCode, body)
		}
	}
	revoke(toolsApp(t, env), toolsSecret, rt)
	if body, _ = introspect(app, wikiSecret, rt); body["active"] != true {
		t.Fatal("another client revoked the refresh token")
	}
	revoke(app, wikiSecret, rt)
	revoke(app, wikiSecret, "garbage")
	if body, _ = introspect(app, wikiSecret, rt); body["active"] != false {
		t.Error("revoked refresh token still active")
	}
	body, resp = env.Refresh(t, app, wikiSecret, rt)
	tokenFails(t, resp, body, 400, "invalid_grant")
}

func TestUserinfoRejectsBadTokens(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	_, u, body := memberTokens(t, env, app, wikiSecret)
	access := str(t, body, "access_token")
	ctx := context.Background()

	rejected := func(t *testing.T, token, challenge string) {
		t.Helper()
		body, resp := userinfo(t, env, token)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != challenge {
			t.Errorf("status %d WWW-Authenticate %q, body %v; want 401 %s",
				resp.StatusCode, resp.Header.Get("WWW-Authenticate"), body, challenge)
		}
	}
	const invalid = `Bearer realm="keywell", error="invalid_token"`
	t.Run("no token", func(t *testing.T) { rejected(t, "", `Bearer realm="keywell"`) })
	t.Run("garbage", func(t *testing.T) { rejected(t, "garbage", invalid) })
	t.Run("ID token", func(t *testing.T) { rejected(t, str(t, body, "id_token"), invalid) })
	t.Run("access token claims with typ JWT", func(t *testing.T) {
		retyped, err := env.Keys.Sign(verifyToken(t, env, access, "at+jwt"))
		if err != nil {
			t.Fatal(err)
		}
		rejected(t, retyped, invalid)
	})
	t.Run("other issuer", func(t *testing.T) {
		claims := verifyToken(t, env, access, "at+jwt")
		claims["iss"] = "https://evil.example"
		forged, err := env.Keys.SignTyped(claims, "at+jwt")
		if err != nil {
			t.Fatal(err)
		}
		rejected(t, forged, invalid)
	})
	t.Run("disabled member", func(t *testing.T) {
		u.IsActive = false
		if err := env.Store.UpdateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		rejected(t, access, invalid)
		u.IsActive = true
		if err := env.Store.UpdateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		if _, resp := userinfo(t, env, access); resp.StatusCode != http.StatusOK {
			t.Errorf("re-enabled member: status %d", resp.StatusCode)
		}
	})
	t.Run("key retired past its grace", func(t *testing.T) {
		var offset atomic.Int64
		env.Keys.SetClock(func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
		if _, err := env.Keys.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := env.Keys.RetireOlderThan(ctx, 0); err != nil {
			t.Fatal(err)
		}
		if _, resp := userinfo(t, env, access); resp.StatusCode != http.StatusOK {
			t.Fatalf("within the grace: status %d", resp.StatusCode)
		}
		offset.Store(int64(25 * time.Hour))
		rejected(t, access, invalid)
	})
	t.Run("expired", func(t *testing.T) {
		_, _, fresh := memberTokensAs(t, env, app, wikiSecret, "jo@example.org") // signed by the new key
		token := str(t, fresh, "access_token")
		env.Clock.Advance(time.Hour - time.Second)
		if _, resp := userinfo(t, env, token); resp.StatusCode != http.StatusOK {
			t.Fatalf("a second before expiry: status %d", resp.StatusCode)
		}
		env.Clock.Advance(time.Second)
		rejected(t, token, invalid)
	})
}

func TestPerAppTTLOverride(t *testing.T) {
	env := testenv.New(t)
	app := env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client", RedirectURIs: []string{wikiRedirect},
		AccessTokenTTL: 5 * time.Minute, IDTokenTTL: 10 * time.Minute, RefreshTokenTTL: day,
	}, wikiSecret)
	_, _, body := memberTokens(t, env, app, wikiSecret)
	now := env.Clock.Now()

	if body["expires_in"] != float64(300) {
		t.Errorf("expires_in %v, want 300", body["expires_in"])
	}
	at := verifyToken(t, env, body["access_token"], "at+jwt")
	id := verifyToken(t, env, body["id_token"], "JWT")
	if at["exp"] != float64(now.Add(5*time.Minute).Unix()) || id["exp"] != float64(now.Add(10*time.Minute).Unix()) {
		t.Errorf("access token exp %v, ID token exp %v", at["exp"], id["exp"])
	}
	rt := storedRefresh(t, env, str(t, body, "refresh_token"))
	if !rt.ExpiresAt.Equal(now.Add(day)) || !rt.AbsoluteExpiresAt.Equal(now.Add(90*day)) {
		t.Errorf("refresh expires %v absolute %v, want a day and the global 90 days", rt.ExpiresAt, rt.AbsoluteExpiresAt)
	}
}

func TestTokenErrorsAreJSONNoStore(t *testing.T) {
	env := testenv.New(t)
	app := wikiApp(t, env)
	form := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v.Encode()
	}
	for _, tc := range []struct {
		name, method, contentType, body string
		status                          int
		code                            string
	}{
		{"GET", http.MethodGet, "", "", 405, "invalid_request"},
		{"JSON body", http.MethodPost, "application/json", `{"grant_type":"client_credentials"}`, 400, "invalid_request"},
		{"no grant_type", http.MethodPost, "", form(), 400, "invalid_request"},
		{"password grant", http.MethodPost, "", form("grant_type", "password"), 400, "unsupported_grant_type"},
		{"no code", http.MethodPost, "", form("grant_type", "authorization_code", "redirect_uri", wikiRedirect), 400, "invalid_request"},
		{"unknown code", http.MethodPost, "", form("grant_type", "authorization_code", "code", "nope", "redirect_uri", wikiRedirect), 400, "invalid_grant"},
		{"no refresh token", http.MethodPost, "", form("grant_type", "refresh_token"), 400, "invalid_request"},
		{"unknown refresh token", http.MethodPost, "", form("grant_type", "refresh_token", "refresh_token", "nope"), 400, "invalid_grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, env.TS.URL+"/oauth/token", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			ct := tc.contentType
			if ct == "" && tc.method == http.MethodPost {
				ct = "application/x-www-form-urlencoded"
			}
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			req.SetBasicAuth(app.ClientID, wikiSecret)
			body, resp := doJSON(t, env, req)
			tokenFails(t, resp, body, tc.status, tc.code)
			if tc.status == http.StatusMethodNotAllowed && !slices.Contains(resp.Header.Values("Allow"), http.MethodPost) {
				t.Errorf("Allow %q, want POST", resp.Header.Values("Allow"))
			}
		})
	}
	t.Run("bad client", func(t *testing.T) {
		body, resp := env.Exchange(t, app, "wrong", "nope", "", wikiRedirect)
		tokenFails(t, resp, body, 401, "invalid_client")
	})
}
