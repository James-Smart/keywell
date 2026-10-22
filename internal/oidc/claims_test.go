package oidc_test

import (
	"reflect"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/oidc"
)

func TestSubjectModes(t *testing.T) {
	pk := int64(42)
	imported := &model.User{ID: "u-imported", Email: "Alex@Example.ORG", Username: "alex",
		AuthentikUUID: "8d1f6a8e-uuid", AuthentikUID: "5e3b-hash", AuthentikPK: &pk}
	fresh := &model.User{ID: "u-fresh", Email: "sam@example.org"}
	for _, tc := range []struct {
		mode model.SubjectMode
		user *model.User
		want string
	}{
		{"", imported, "u-imported"},
		{model.SubjectModeID, imported, "u-imported"},
		{model.SubjectModeEmail, imported, "alex@example.org"},
		{model.SubjectModeUsername, imported, "alex"},
		{model.SubjectModeUsername, fresh, "u-fresh"},
		{model.SubjectModeAuthentikUUID, imported, "8d1f6a8e-uuid"},
		{model.SubjectModeAuthentikUUID, fresh, "u-fresh"},
		{model.SubjectModeAuthentikUID, imported, "5e3b-hash"},
		{model.SubjectModeAuthentikUID, fresh, "u-fresh"},
		{model.SubjectModeAuthentikPK, imported, "42"},
		{model.SubjectModeAuthentikPK, fresh, "u-fresh"},
	} {
		app := &model.Application{SubjectMode: tc.mode}
		if got := oidc.Subject(tc.user, app); got != tc.want {
			t.Errorf("Subject(%s, mode %q) = %q, want %q", tc.user.ID, tc.mode, got, tc.want)
		}
	}
}

func TestBuildClaimsByScope(t *testing.T) {
	updated := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	u := &model.User{ID: "u-1", Name: "Alex Smith", Email: "alex@example.org", IsActive: true,
		Metadata: map[string]any{"door_pin": "1234"}, UpdatedAt: updated}
	groups := []model.Group{ // not in name order, to show the claim sorts them
		{ID: "g-members", Name: "Members", Metadata: map[string]any{"tier": "full"}},
		{ID: "g-admin", Name: "Admin", IsAdmin: true},
	}
	app := &model.Application{SubjectMode: model.SubjectModeID}

	for _, tc := range []struct {
		name   string
		scopes []string
		want   map[string]any
	}{
		{"openid", []string{"openid"}, map[string]any{"sub": "u-1"}},
		{"email", []string{"openid", "email"}, map[string]any{
			"sub": "u-1", "email": "alex@example.org", "email_verified": true,
		}},
		{"profile", []string{"openid", "profile"}, map[string]any{
			"sub": "u-1", "name": "Alex Smith", "preferred_username": "alex",
			"metadata": map[string]any{"door_pin": "1234"}, "updated_at": updated.Unix(),
		}},
		{"groups", []string{"openid", "groups"}, map[string]any{
			"sub": "u-1", "groups": []string{"Admin", "Members"},
			"group_metadata": map[string]any{"Admin": map[string]any{}, "Members": map[string]any{"tier": "full"}},
			"is_admin":       true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := oidc.BuildClaims(u, groups, app, tc.scopes); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("BuildClaims = %#v\nwant %#v", got, tc.want)
			}
		})
	}

	t.Run("username wins over email local part", func(t *testing.T) {
		withUsername := *u
		withUsername.Username = "asmith"
		got := oidc.BuildClaims(&withUsername, nil, app, []string{"openid", "profile"})
		if got["preferred_username"] != "asmith" {
			t.Errorf("preferred_username = %v, want asmith", got["preferred_username"])
		}
	})
	t.Run("no admin group", func(t *testing.T) {
		got := oidc.BuildClaims(u, groups[:1], app, []string{"openid", "groups"})
		if got["is_admin"] != false {
			t.Errorf("is_admin = %v, want false", got["is_admin"])
		}
	})
	t.Run("no groups is an empty list", func(t *testing.T) {
		got := oidc.BuildClaims(u, nil, app, []string{"openid", "groups"})
		if g, ok := got["groups"].([]string); !ok || g == nil || len(g) != 0 {
			t.Errorf("groups = %#v, want an empty, non-nil list", got["groups"])
		}
	})
	t.Run("sub follows the subject mode", func(t *testing.T) {
		byEmail := &model.Application{SubjectMode: model.SubjectModeEmail}
		if got := oidc.BuildClaims(u, nil, byEmail, []string{"openid"}); got["sub"] != "alex@example.org" {
			t.Errorf("sub = %v, want the email", got["sub"])
		}
	})
}

func TestParseScopes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"openid", []string{"openid"}},
		{"groups email openid profile offline_access", []string{"openid", "profile", "email", "groups", "offline_access"}},
		{"openid  openid email unknown:scope", []string{"openid", "email"}},
		{"profile email", []string{"profile", "email"}},
		{"", nil},
	} {
		if got := oidc.ParseScopes(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseScopes(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestUserAllowed(t *testing.T) {
	active := &model.User{ID: "u", IsActive: true}
	inactive := &model.User{ID: "u"}
	groups := []model.Group{{ID: "g-members"}}
	for _, tc := range []struct {
		name    string
		user    *model.User
		allowed []string
		want    bool
	}{
		{"open app", active, nil, true},
		{"in an allowed group", active, []string{"g-doors", "g-members"}, true},
		{"in no allowed group", active, []string{"g-doors"}, false},
		{"inactive", inactive, nil, false},
	} {
		app := &model.Application{AllowedGroupIDs: tc.allowed}
		if got := oidc.UserAllowed(tc.user, groups, app); got != tc.want {
			t.Errorf("%s: UserAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMatchRedirectURI(t *testing.T) {
	const wiki = "https://wiki.example.org/callback"
	for _, tc := range []struct {
		registered, candidate string
		want                  bool
	}{
		{wiki, wiki, true},
		{wiki, "https://wiki.example.org/callback/", false}, // Review Focus 3: trailing slash
		{wiki, "https://wiki.example.org:8443/callback", false},
		{wiki, "https://wiki.example.org/callbackx", false}, // never a prefix match
		{wiki, "https://wiki.example.org/callback?x=1", false},
		{wiki, "http://wiki.example.org/callback", false},
		{wiki, "", false},
		{"http://wiki.example.org/cb", "http://wiki.example.org:8080/cb", false}, // only loopback ignores the port
		{"http://127.0.0.1/cb", "http://127.0.0.1/cb", true},
		{"http://127.0.0.1/cb", "http://127.0.0.1:51234/cb", true}, // Review Focus 3: RFC 8252 loopback
		{"http://127.0.0.1/cb", "http://127.0.0.1:51234/other", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:51234/cb/", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:51234/cb?x=1", false},
		{"http://127.0.0.1/cb", "https://127.0.0.1:51234/cb", false},
		{"http://127.0.0.1/cb", "http://localhost:51234/cb", false},
		{"http://127.0.0.1/cb", "http://user@127.0.0.1:51234/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:51234/cb#frag", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:0/cb", false},
		{"http://127.0.0.1/cb?mode=cli", "http://127.0.0.1:51234/cb?mode=cli", true},
		{"http://localhost/cb", "http://localhost:3000/cb", true},
		{"http://localhost/cb", "http://localhost.evil.example:3000/cb", false},
		{"http://[::1]/cb", "http://[::1]:3000/cb", true},
		{"https://127.0.0.1:8443/cb", "https://127.0.0.1:8443/cb", true},
		{"https://127.0.0.1:8443/cb", "https://127.0.0.1:9443/cb", false}, // a registered port is matched exactly
	} {
		if got := oidc.MatchRedirectURI([]string{tc.registered}, tc.candidate); got != tc.want {
			t.Errorf("MatchRedirectURI([%q], %q) = %v, want %v", tc.registered, tc.candidate, got, tc.want)
		}
	}
	if !oidc.MatchRedirectURI([]string{"https://other.example/cb", wiki}, wiki) {
		t.Error("a URI matching the second registered entry was rejected")
	}
}
