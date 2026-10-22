package oidc

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"latch/internal/model"
)

// Scopes Latch knows, in the order ParseScopes returns them.
const (
	scopeOpenID        = "openid"
	scopeProfile       = "profile"
	scopeEmail         = "email"
	scopeGroups        = "groups"
	scopeOfflineAccess = "offline_access"
)

var knownScopes = []string{scopeOpenID, scopeProfile, scopeEmail, scopeGroups, scopeOfflineAccess}

// ParseScopes returns the known scopes named in the space-separated s, each
// once, in the order of knownScopes (openid first). Unknown scopes are
// dropped; the caller checks that openid is present.
func ParseScopes(s string) []string {
	requested := strings.Fields(s)
	var scopes []string
	for _, known := range knownScopes {
		if slices.Contains(requested, known) {
			scopes = append(scopes, known)
		}
	}
	return scopes
}

// Subject returns the sub claim for u at app, by the application's subject
// mode. Modes whose source is unset for u (Authentik values for members
// created after cutover, an empty username or email) fall back to u.ID, so
// sub is never empty.
func Subject(u *model.User, app *model.Application) string {
	var sub string
	switch app.SubjectMode {
	case model.SubjectModeEmail:
		sub = strings.ToLower(u.Email)
	case model.SubjectModeUsername:
		sub = u.Username
	case model.SubjectModeAuthentikUUID:
		sub = u.AuthentikUUID
	case model.SubjectModeAuthentikUID:
		sub = u.AuthentikUID
	case model.SubjectModeAuthentikPK:
		if u.AuthentikPK != nil {
			sub = strconv.FormatInt(*u.AuthentikPK, 10)
		}
	}
	if sub == "" {
		return u.ID
	}
	return sub
}

// BuildClaims returns the identity claims for u at app that scopes grant:
// sub always, and the rest by scope as in the spec's claims table (the email
// claims only when u has an email, which service accounts may not). groups
// is the user's groups. Token-specific claims (iss, aud, exp, ...) are added
// by the code that issues each token.
func BuildClaims(u *model.User, groups []model.Group, app *model.Application, scopes []string) map[string]any {
	claims := map[string]any{"sub": Subject(u, app)}
	if slices.Contains(scopes, scopeEmail) && u.Email != "" {
		claims["email"] = u.Email
		claims["email_verified"] = true // admins create accounts
	}
	if slices.Contains(scopes, scopeProfile) {
		claims["name"] = u.Name
		claims["preferred_username"] = preferredUsername(u)
		claims["metadata"] = orEmpty(u.Metadata)
		claims["updated_at"] = u.UpdatedAt.Unix()
	}
	if slices.Contains(scopes, scopeGroups) {
		names := make([]string, 0, len(groups))
		metadata := make(map[string]any, len(groups))
		isAdmin := false
		for _, g := range groups {
			names = append(names, g.Name)
			metadata[g.Name] = orEmpty(g.Metadata)
			isAdmin = isAdmin || g.IsAdmin
		}
		slices.Sort(names)
		claims["groups"] = names
		claims["group_metadata"] = metadata
		claims["is_admin"] = isAdmin
	}
	return claims
}

// preferredUsername is the username, or the local part of the email when
// there is none.
func preferredUsername(u *model.User) string {
	if u.Username != "" {
		return u.Username
	}
	local, _, _ := strings.Cut(u.Email, "@")
	return local
}

// orEmpty returns m, or an empty object when m is nil, so the claim is
// always a JSON object.
func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// UserAllowed reports whether u may sign in to app: u is active and, when
// the application lists allowed groups, a member of at least one of them.
func UserAllowed(u *model.User, groups []model.Group, app *model.Application) bool {
	if !u.IsActive {
		return false
	}
	if len(app.AllowedGroupIDs) == 0 {
		return true
	}
	return slices.ContainsFunc(groups, func(g model.Group) bool {
		return slices.Contains(app.AllowedGroupIDs, g.ID)
	})
}

// MatchRedirectURI reports whether candidate is one of the registered
// redirect URIs. Matching is exact, except for the loopback rule of RFC 8252
// §7.3: a registered URI whose host is 127.0.0.1, localhost or [::1] with no
// port matches the same URI with any port, because native apps listen on a
// port the system picks. Nothing ever matches by prefix.
func MatchRedirectURI(registered []string, candidate string) bool {
	if candidate == "" {
		return false
	}
	if slices.Contains(registered, candidate) {
		return true
	}
	c, err := url.Parse(candidate)
	if err != nil || !validPort(c.Port()) || c.User != nil || c.Fragment != "" {
		return false
	}
	return slices.ContainsFunc(registered, func(reg string) bool {
		r, err := url.Parse(reg)
		if err != nil || !isLoopbackHost(r.Host) { // r.Host includes any port, so a port fails here
			return false
		}
		return c.Scheme == r.Scheme && c.Hostname() == r.Hostname() &&
			c.EscapedPath() == r.EscapedPath() && c.RawQuery == r.RawQuery
	})
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "[::1]"
}

// validPort reports whether p is a TCP port number other than 0.
func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535
}
