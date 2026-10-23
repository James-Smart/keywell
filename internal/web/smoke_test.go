package web_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"latch/internal/model"
	"latch/internal/testenv"
)

// TestSmokeFullFlow follows one member through a new installation: signing
// in, finding an app on the home page, signing in to it with OpenID Connect
// as a go-oidc application would, changing their password, and signing out
// from the app. Each step has its own tests; this one checks the pieces are
// wired together.
func TestSmokeFullFlow(t *testing.T) {
	const (
		callback   = "https://tools.example.org/callback"
		signedOut  = "https://tools.example.org/signed-out"
		toolSecret = "tool booking secret"
	)
	env := testenv.New(t)
	ctx := gooidc.ClientContext(context.Background(), env.TS.Client())

	// What latch init sets up: a signing key, the Admin group requiring
	// two-step sign in, and its first member.
	if env.Keys.ActiveKID() == "" {
		t.Fatal("no signing key")
	}
	env.CreateGroup(t, "Admin", true, true)
	env.CreateUser(t, "admin@example.org", testPW, "Admin")

	members := env.CreateGroup(t, "Members", false, false)
	alex := env.CreateUser(t, "alex@example.org", testPW, "Members")
	app := env.CreateApp(t, model.Application{
		Name: "Tool Booking", Slug: "tools", ClientID: "tools-client",
		ClientType: model.ClientTypeConfidential, RedirectURIs: []string{callback},
		PostLogoutRedirectURIs: []string{signedOut}, AllowedGroupIDs: []string{members.ID},
		ShowTile: true, LaunchURL: "https://tools.example.org/", Description: "Book the laser cutter",
	}, toolSecret)

	// The member signs in and finds the app on their home page.
	browser := env.Client(t)
	env.Login(t, browser, alex.Email, testPW)
	resp, body := get(t, browser, env.TS.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Tool Booking") ||
		!strings.Contains(body, `href="https://tools.example.org/"`) {
		t.Fatalf("home: status %d\n%s", resp.StatusCode, body)
	}

	// The app discovers Latch and signs the member in with a code.
	provider, err := gooidc.NewProvider(ctx, env.TS.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	rp := oauth2.Config{ClientID: app.ClientID, ClientSecret: toolSecret, Endpoint: provider.Endpoint(),
		RedirectURL: callback, Scopes: []string{gooidc.ScopeOpenID, "profile", "email", "groups"}}
	resp, _ = get(t, browser, rp.AuthCodeURL("st-smoke", gooidc.Nonce("n-smoke")))
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), callback+"?") {
		t.Fatalf("authorize: status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "st-smoke" {
		t.Fatalf("state %q", loc.Query().Get("state"))
	}
	tok, err := rp.Exchange(ctx, loc.Query().Get("code"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := provider.Verifier(&gooidc.Config{ClientID: app.ClientID}).Verify(ctx, rawID)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if idt.Nonce != "n-smoke" || claims.Email != alex.Email || !slices.Contains(claims.Groups, "Members") {
		t.Fatalf("ID token nonce %q email %q groups %v", idt.Nonce, claims.Email, claims.Groups)
	}
	if ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err != nil || ui.Subject != idt.Subject {
		t.Fatalf("userinfo: %+v, %v", ui, err)
	}
	if tok.RefreshToken == "" {
		t.Fatal("no refresh token")
	}

	// Changing the password ends the app's refresh token.
	resp, body = post(t, env, browser, "/account/password",
		url.Values{"current": {testPW}, "password": {newPW}, "confirm": {newPW}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, passwordChanged) {
		t.Fatalf("change password: status %d\n%s", resp.StatusCode, body)
	}
	_, err = rp.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken, Expiry: time.Now().Add(-time.Minute)}).Token()
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.ErrorCode != "invalid_grant" {
		t.Fatalf("refresh after password change: %v, want invalid_grant", err)
	}

	// The app signs the member out of Latch, which shows the signed-out
	// page.
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil || meta.EndSession == "" {
		t.Fatalf("end_session_endpoint %q, %v", meta.EndSession, err)
	}
	resp, body = get(t, browser, meta.EndSession+"?"+url.Values{"id_token_hint": {rawID}}.Encode())
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "You're signed out") {
		t.Fatalf("sign out: status %d Location %q\n%s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	resp, _ = get(t, browser, env.TS.URL+"/")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("home after sign out: status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
