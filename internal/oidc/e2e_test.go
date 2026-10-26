package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"keywell/internal/model"
	"keywell/internal/testenv"
)

// appCallback is the end-to-end applications' redirect URI. Nothing serves
// it: the browser's last redirect is read, never followed.
const appCallback = "https://app.test/cb"

// relyingParty is an application signing members in with go-oidc and
// golang.org/x/oauth2, as many Go applications do.
type relyingParty struct {
	ctx      context.Context // carries the test server's HTTP client
	provider *gooidc.Provider
	cfg      oauth2.Config
}

// newRelyingParty discovers the test server as an issuer and configures
// app (whose client secret is secret, "" for none) to authenticate with
// style and ask for scopes.
func newRelyingParty(t *testing.T, env *testenv.Env, app *model.Application, secret string, style oauth2.AuthStyle, scopes ...string) *relyingParty {
	t.Helper()
	ctx := gooidc.ClientContext(t.Context(), env.TS.Client())
	provider, err := gooidc.NewProvider(ctx, env.TS.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = style
	return &relyingParty{ctx: ctx, provider: provider, cfg: oauth2.Config{
		ClientID: app.ClientID, ClientSecret: secret, Endpoint: endpoint, RedirectURL: appCallback, Scopes: scopes,
	}}
}

// browserSignIn sends a new browser to authURL, signs in as u when asked,
// and returns the code the browser brings back to app, checking that state
// comes back with it.
func browserSignIn(t *testing.T, env *testenv.Env, app *model.Application, u *model.User, authURL, state string) string {
	t.Helper()
	c := env.Client(t)
	next := loginRedirect(t, get(t, c, authURL), app.Slug)
	env.Login(t, c, u.Email, testPW)
	q := clientRedirect(t, get(t, c, env.TS.URL+next), appCallback)
	if q.Get("state") != state || q.Get("iss") != env.TS.URL {
		t.Fatalf("state %q iss %q, want %q and %s", q.Get("state"), q.Get("iss"), state, env.TS.URL)
	}
	code := q.Get("code")
	if code == "" {
		t.Fatalf("no code: error %q (%s)", q.Get("error"), q.Get("error_description"))
	}
	return code
}

// verify checks tok's ID token as go-oidc does (signature against the
// published keys, issuer, audience, expiry), its at_hash, and its nonce
// when nonce is not empty, and returns it.
func (rp *relyingParty) verify(t *testing.T, tok *oauth2.Token, nonce string) *gooidc.IDToken {
	t.Helper()
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		t.Fatal("no ID token")
	}
	idt, err := rp.provider.Verifier(&gooidc.Config{ClientID: rp.cfg.ClientID}).Verify(rp.ctx, raw)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
		t.Errorf("at_hash: %v", err)
	}
	if nonce != "" && idt.Nonce != nonce {
		t.Errorf("nonce %q, want %q", idt.Nonce, nonce)
	}
	return idt
}

// userInfo fetches the userinfo for tok's access token and checks its sub
// matches the ID token's.
func (rp *relyingParty) userInfo(t *testing.T, tok *oauth2.Token, idt *gooidc.IDToken) *gooidc.UserInfo {
	t.Helper()
	ui, err := rp.provider.UserInfo(rp.ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if ui.Subject != idt.Subject {
		t.Errorf("userinfo sub %q, ID token sub %q", ui.Subject, idt.Subject)
	}
	return ui
}

func TestE2EConfidentialClientWithGoOIDC(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	app := env.CreateApp(t, model.Application{
		Name: "Tool Booking", Slug: "tools", ClientID: "tools-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{appCallback},
	}, toolsSecret)
	rp := newRelyingParty(t, env, app, toolsSecret, oauth2.AuthStyleInHeader,
		gooidc.ScopeOpenID, "profile", "email", "groups")

	state, nonce := "st-e2e", "n-e2e"
	code := browserSignIn(t, env, app, u, rp.cfg.AuthCodeURL(state, gooidc.Nonce(nonce)), state)
	tok, err := rp.cfg.Exchange(rp.ctx, code)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	idt := rp.verify(t, tok, nonce)
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims.Email != u.Email || !slices.Contains(claims.Groups, "Members") {
		t.Errorf("ID token email %q groups %v, want %s in Members", claims.Email, claims.Groups, u.Email)
	}
	if ui := rp.userInfo(t, tok, idt); ui.Email != u.Email || !ui.EmailVerified {
		t.Errorf("userinfo email %q verified %v, want %s verified", ui.Email, ui.EmailVerified, u.Email)
	}

	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	fresh, err := rp.cfg.TokenSource(rp.ctx, &oauth2.Token{
		RefreshToken: tok.RefreshToken, Expiry: time.Now().Add(-time.Minute),
	}).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if fresh.AccessToken == "" || fresh.AccessToken == tok.AccessToken {
		t.Errorf("refresh gave access token %q, want a new one", fresh.AccessToken)
	}
	if fresh.RefreshToken == "" || fresh.RefreshToken == tok.RefreshToken {
		t.Error("refresh token not rotated")
	}
	if again := rp.verify(t, fresh, nonce); again.Subject != idt.Subject {
		t.Errorf("refreshed ID token sub %q, want %q", again.Subject, idt.Subject)
	}
}

func TestE2EPublicClientPKCE(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	app := env.CreateApp(t, model.Application{
		Name: "Laser Kiosk", Slug: "kiosk", ClientID: "kiosk",
		ClientType: model.ClientTypePublic, RedirectURIs: []string{appCallback},
	}, "")
	rp := newRelyingParty(t, env, app, "", oauth2.AuthStyleInParams,
		gooidc.ScopeOpenID, "profile", "email", "groups")

	verifier := oauth2.GenerateVerifier()
	code := browserSignIn(t, env, app, u, rp.cfg.AuthCodeURL("st-1", oauth2.S256ChallengeOption(verifier)), "st-1")
	tok, err := rp.cfg.Exchange(rp.ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ui := rp.userInfo(t, tok, rp.verify(t, tok, "")); ui.Email != u.Email {
		t.Errorf("userinfo email %q, want %s", ui.Email, u.Email)
	}

	// The code is useless without the verifier.
	verifier = oauth2.GenerateVerifier()
	code = browserSignIn(t, env, app, u, rp.cfg.AuthCodeURL("st-2", oauth2.S256ChallengeOption(verifier)), "st-2")
	_, err = rp.cfg.Exchange(rp.ctx, code)
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.Response.StatusCode != http.StatusBadRequest || re.ErrorCode != "invalid_grant" {
		t.Errorf("exchange without the verifier: %v, want invalid_grant", err)
	}
}

func TestE2EMediaWikiShape(t *testing.T) {
	env := testenv.New(t)
	u := env.CreateUser(t, "alex@example.org", testPW, "Members")
	u.Username = "AlexM" // MediaWiki account names come from preferred_username
	if err := env.Store.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	app := env.CreateApp(t, model.Application{
		Name: "Members Wiki", Slug: "wiki", ClientID: "wiki-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{appCallback},
	}, wikiSecret)
	rp := newRelyingParty(t, env, app, wikiSecret, oauth2.AuthStyleInParams,
		gooidc.ScopeOpenID, "profile", "email")

	state, nonce := "st-wiki", "n-wiki"
	code := browserSignIn(t, env, app, u, rp.cfg.AuthCodeURL(state, gooidc.Nonce(nonce)), state)
	tok, err := rp.cfg.Exchange(rp.ctx, code)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	idt := rp.verify(t, tok, nonce)
	ui := rp.userInfo(t, tok, idt)
	for what, claimsOf := range map[string]func(any) error{"ID token": idt.Claims, "userinfo": ui.Claims} {
		var claims map[string]any
		if err := claimsOf(&claims); err != nil {
			t.Fatal(err)
		}
		if claims["preferred_username"] != u.Username || claims["email"] != u.Email || claims["name"] != u.Name {
			t.Errorf("%s preferred_username %v email %v name %v, want %s, %s, %s", what,
				claims["preferred_username"], claims["email"], claims["name"], u.Username, u.Email, u.Name)
		}
		for _, k := range []string{"groups", "group_metadata", "is_admin"} {
			if _, ok := claims[k]; ok {
				t.Errorf("%s has %s without the groups scope", what, k)
			}
		}
	}
}
