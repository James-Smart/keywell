package importer

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/authentik"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/secrets"
)

// Report copy for an app's fields. The report never quotes a link, which
// could hold a password, and quotes patterns without one.
const (
	reasonSubjectMode = "Identifies people in a way Keywell doesn't support."
	warnSlugChanged   = "Its short name changed from %s to %s."
	warnPattern       = "Return address %s is a pattern. Add the real addresses on the app's page."
	warnLogoutPattern = "Sign-out return address %s is a pattern. Add the real addresses on the app's page."
	warnUPN           = "Identified people by UPN in Authentik. Keywell uses their email address instead."
	warnLaunchURL     = "Its link to open the app isn't a web address Keywell can use, so it was left off."
	warnIcon          = "Its icon is stored in Authentik. Upload it on the app's page."
	warnMapping       = `Authentik sent extra details through "%s", which Keywell doesn't send.`
	warnProfile       = `Authentik sent group names to it with "profile". Keywell sends them only when an app ` +
		`asks for "groups", so add groups to its scopes if it uses them.`
	warnServiceLogin = "Authentik let it sign in by itself. To allow that in Keywell, choose a service account " +
		"on the app's page."
)

// lifetimeCopy is the report copy for one kind of token lifetime (Ruling C).
type lifetimeCopy struct{ long, short, unread string }

var (
	accessCopy = lifetimeCopy{
		long:   "Authentik's access tokens lasted %s; Keywell's limit is %s, so it uses that.",
		short:  "Authentik's access tokens lasted %s; Keywell's minimum is %s, so it uses that.",
		unread: "Keywell couldn't read how long Authentik's access tokens lasted, so it uses the default.",
	}
	refreshCopy = lifetimeCopy{
		long:   "Authentik kept sign-ins for %s; Keywell's limit is %s, so it uses that.",
		short:  "Authentik kept sign-ins for %s; Keywell's minimum is %s, so it uses that.",
		unread: "Keywell couldn't read how long Authentik kept sign-ins, so it uses the default.",
	}
)

// subjectModes maps Authentik's sub_mode to Keywell's subject mode (spec §6.4).
var subjectModes = map[string]model.SubjectMode{
	"hashed_user_id": model.SubjectModeAuthentikUID,
	"user_id":        model.SubjectModeAuthentikPK,
	"user_uuid":      model.SubjectModeAuthentikUUID,
	"user_email":     model.SubjectModeEmail,
	"user_username":  model.SubjectModeUsername,
	"user_upn":       model.SubjectModeEmail,
}

// mapApp makes the Keywell app for a: the matched app with Authentik's values
// over every imported field, or a new one, allowing acc's groups. It keeps
// the matched app's service account, and its uploaded icon when Authentik
// has no usable one. It returns why instead when Keywell can't take the app
// as Authentik has it.
func (r *run) mapApp(a *importApp, acc access, mappings []authentik.ProviderMapping) (*model.Application, string) {
	src, p := &a.src, a.prov
	mode, ok := subjectModes[p.SubMode]
	if !ok {
		return nil, reasonSubjectMode
	}
	app := &model.Application{}
	if a.keywell != nil {
		*app = *a.keywell
	}
	app.Name = src.Name
	if app.Slug = admin.SlugFromName(src.Slug); app.Slug != src.Slug {
		a.warn(fmt.Sprintf(warnSlugChanged, src.Slug, app.Slug))
	}
	app.ClientID = p.ClientID
	app.ClientType = model.ClientType(p.ClientType)
	app.ClientSecretHash = ""
	if app.ClientType == model.ClientTypeConfidential {
		app.ClientSecretHash = secrets.HashToken(p.ClientSecret)
	}
	mapAddresses(a, app)
	if p.SubMode == "user_upn" {
		a.warn(warnUPN)
	}
	app.SubjectMode = mode
	// Authentik's ID tokens last as long as its access tokens.
	app.AccessTokenTTL = lifetime(a, p.AccessTokenValidity, admin.MaxTokenTTL, accessCopy)
	app.IDTokenTTL = app.AccessTokenTTL
	app.RefreshTokenTTL = lifetime(a, p.RefreshTokenValidity, r.cfg.Tokens.RefreshAbsolute, refreshCopy)
	mapLinks(a, app)
	app.Description = src.Description
	warnClaims(a, mappings)
	app.AllowedGroupIDs = slices.Clone(acc.groupIDs)
	if acc.with != "" {
		a.warn(fmt.Sprintf(warnAdminsOnly, acc.with))
	}
	if slices.Contains(p.GrantTypes, "client_credentials") && app.ClientType == model.ClientTypeConfidential &&
		app.ServiceAccountID == "" {
		a.warn(warnServiceLogin)
	}
	pk := p.PK
	app.AuthentikProviderPK = &pk
	return app, ""
}

// mapAddresses keeps the provider's strict return addresses, for signing in
// and after signing out, and warns about each pattern, which Keywell can't
// match.
func mapAddresses(a *importApp, app *model.Application) {
	app.RedirectURIs, app.PostLogoutRedirectURIs = []string{}, []string{}
	for _, u := range a.prov.RedirectURIs {
		logout := u.Type == "logout"
		switch {
		case u.MatchingMode != "strict" && logout:
			a.warn(fmt.Sprintf(warnLogoutPattern, withoutUserinfo(u.URL)))
		case u.MatchingMode != "strict":
			a.warn(fmt.Sprintf(warnPattern, withoutUserinfo(u.URL)))
		case logout:
			app.PostLogoutRedirectURIs = append(app.PostLogoutRedirectURIs, u.URL)
		default:
			app.RedirectURIs = append(app.RedirectURIs, u.URL)
		}
	}
}

// mapLinks sets the launch link, the tile and the icon. A launch link is
// kept only when the app pages would take it, and blank://blank, Authentik's
// "none", is dropped without a warning. The matched app keeps its uploaded
// /icons/ icon when Authentik has no https:// one.
func mapLinks(a *importApp, app *model.Application) {
	switch launch := strings.TrimSpace(a.src.LaunchURL); {
	case launch == "" || launch == "blank://blank":
		app.LaunchURL = ""
	case admin.IsWebAddress(launch, "http", "https"):
		app.LaunchURL = launch
	default:
		app.LaunchURL = ""
		a.warn(warnLaunchURL)
	}
	app.ShowTile = app.LaunchURL != "" && !a.src.Hide

	switch icon := strings.TrimSpace(a.src.Icon); {
	case admin.IsWebAddress(icon, "https"):
		app.IconURL = icon
	case a.keywell != nil && strings.HasPrefix(a.keywell.IconURL, "/icons/"):
		app.IconURL = a.keywell.IconURL
	default:
		app.IconURL = ""
		if icon != "" {
			a.warn(warnIcon)
		}
	}
}

// warnClaims warns about each claim mapping an admin wrote, which Keywell
// doesn't send, and about the profile scope, which sent group names.
func warnClaims(a *importApp, mappings []authentik.ProviderMapping) {
	profile := false
	for _, m := range mappings {
		switch m.Managed {
		case "":
			a.warn(fmt.Sprintf(warnMapping, m.Name))
		case authentik.ManagedProfileScope:
			profile = true
		}
	}
	if profile {
		a.warn(warnProfile)
	}
}

// lifetime reads an Authentik duration and fits it between
// admin.MinTokenTTL and longest, warning when it changes it. One Keywell
// can't read becomes 0, the default.
func lifetime(a *importApp, text string, longest time.Duration, c lifetimeCopy) time.Duration {
	d, err := authentik.ParseValidity(text)
	switch {
	case err != nil:
		a.warn(c.unread)
		return 0
	case d > longest:
		a.warn(fmt.Sprintf(c.long, cmp.Or(admin.FormatDuration(d), "0s"), admin.FormatDuration(longest)))
		return longest
	case d < admin.MinTokenTTL:
		a.warn(fmt.Sprintf(c.short, cmp.Or(admin.FormatDuration(d), "0s"), admin.FormatDuration(admin.MinTokenTTL)))
		return admin.MinTokenTTL
	}
	return d.Truncate(time.Second) // the store keeps whole seconds
}

// withoutUserinfo drops a user name and password from an address before the
// report quotes it: everything from "//" up to an "@" before the first "/".
// A pattern that matches real addresses can't have a bare "/" in a password.
func withoutUserinfo(s string) string {
	scheme, rest, ok := strings.Cut(s, "//")
	if !ok {
		return s
	}
	authority, _, _ := strings.Cut(rest, "/")
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		return scheme + "//" + rest[at+1:]
	}
	return s
}
