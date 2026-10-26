package importer

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"latch/internal/admin"
	"latch/internal/authentik"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// Report copy for apps. Item reasons are full sentences about the app the
// item names.
const (
	reasonNoProvider  = "Has nothing to sign in with in Authentik."
	reasonNotOIDC     = "Signs in with something other than OpenID Connect, which is all Latch supports."
	reasonOrphan      = "Isn't used by any application in Authentik."
	reasonSubjectMode = "Identifies people in a way Latch doesn't support."
	reasonClientTaken = "Another app in Latch already uses its client ID."
	warnSlugChanged   = "Its short name changed from %s to %s."
	warnPattern       = "Return address %s is a pattern. Add the real addresses on the app's page."
	warnLogoutPattern = "Sign-out return address %s is a pattern. Add the real addresses on the app's page."
	warnUPN           = "Identified people by UPN in Authentik. Latch uses their email address instead."
	warnLaunchURL     = "Its link to open the app, %s, isn't a full web address, so Latch left it off."
	warnIcon          = "Its icon is stored in Authentik. Upload it on the app's page."
	warnMapping       = `Authentik sent extra details through "%s", which Latch doesn't send.`
	warnProfile       = `Authentik sent group names to it with "profile". Latch sends them only when an app ` +
		`asks for "groups", so add groups to its scopes if it uses them.`
	warnServiceLogin = "Authentik let it sign in by itself. To allow that in Latch, choose a service account " +
		"on the app's page."
	warnAppGone = "Is no longer in Authentik. Latch has left it as it is."
)

// lifetimeCopy is the report copy for one kind of token lifetime (Ruling C).
type lifetimeCopy struct{ long, short, unread string }

var (
	accessCopy = lifetimeCopy{
		long:   "Authentik's access tokens lasted %s; Latch's limit is %s, so it uses that.",
		short:  "Authentik's access tokens lasted %s; Latch's minimum is %s, so it uses that.",
		unread: "Latch couldn't read how long Authentik's access tokens lasted, so it uses the default.",
	}
	refreshCopy = lifetimeCopy{
		long:   "Authentik kept sign-ins for %s; Latch's limit is %s, so it uses that.",
		short:  "Authentik kept sign-ins for %s; Latch's minimum is %s, so it uses that.",
		unread: "Latch couldn't read how long Authentik kept sign-ins, so it uses the default.",
	}
)

// Lifetimes the app pages accept for access and ID tokens.
const (
	minLifetime       = time.Minute
	maxAccessLifetime = 24 * time.Hour
)

// subjectModes maps Authentik's sub_mode to Latch's subject mode (spec §6.4).
var subjectModes = map[string]model.SubjectMode{
	"hashed_user_id": model.SubjectModeAuthentikUID,
	"user_id":        model.SubjectModeAuthentikPK,
	"user_uuid":      model.SubjectModeAuthentikUUID,
	"user_email":     model.SubjectModeEmail,
	"user_username":  model.SubjectModeUsername,
	"user_upn":       model.SubjectModeEmail,
}

// importApp is a snapshot application and what the import does with it.
type importApp struct {
	src     authentik.Application
	prov    *authentik.OAuth2Provider // its OpenID Connect provider; nil when it has none
	latch   *model.Application        // the Latch app matched, nil for a new one
	skipped bool
	items   []Item
}

func (a *importApp) warn(reason string) {
	a.items = append(a.items, Item{Kind: "app", Name: a.src.Name, Reason: reason})
}

// skip marks the app skipped. Its warnings no longer matter, so the reason
// replaces them.
func (a *importApp) skip(reason string) {
	a.skipped = true
	a.items = []Item{{Kind: "app", Name: a.src.Name, Skipped: true, Reason: reason}}
}

// writeApps turns each Authentik application with an OpenID Connect
// provider into a Latch app, checked with the app pages' rules, and lists
// the applications and providers it can't import. It runs after the groups
// are written.
func (r *run) writeApps() error {
	providers := map[int64]*authentik.OAuth2Provider{}
	for i := range r.snap.Providers {
		providers[r.snap.Providers[i].PK] = &r.snap.Providers[i]
	}
	bindings := map[string][]authentik.Binding{}
	for _, b := range r.snap.Bindings {
		bindings[b.TargetUUID] = append(bindings[b.TargetUUID], b)
	}
	mappings := map[int64][]authentik.ProviderMapping{}
	for _, m := range r.snap.Mappings {
		mappings[m.ProviderPK] = append(mappings[m.ProviderPK], m)
	}

	var apps []*importApp
	used := map[int64]bool{} // PKs of the providers applications use
	for _, src := range r.snap.Applications {
		a := &importApp{src: src}
		apps = append(apps, a)
		if src.ProviderPK == nil {
			a.skip(reasonNoProvider)
			continue
		}
		used[*src.ProviderPK] = true
		if a.prov = providers[*src.ProviderPK]; a.prov == nil {
			a.skip(reasonNotOIDC) // SAML, proxy and the like, which the snapshot doesn't hold
		}
	}
	claimed := r.matchApps(apps)

	if slices.ContainsFunc(apps, func(a *importApp) bool { return !a.skipped }) {
		if r.cfg == nil {
			return errors.New("importer: no config to check apps with")
		}
		ag, err := r.loadAccessGroups()
		if err != nil {
			return err
		}
		// CheckApp looks slugs and groups up through the transaction.
		svc := admin.New(admin.Deps{Cfg: r.cfg, Store: r.tx})
		for _, a := range apps {
			if a.skipped {
				continue
			}
			if err := r.writeApp(svc, a, ag, bindings[a.src.UUID], mappings[a.prov.PK]); err != nil {
				return err
			}
		}
	}
	for _, a := range apps {
		if a.skipped {
			r.rep.Apps.Skipped++
		}
		r.appItems = append(r.appItems, a.items...)
	}

	for _, p := range r.snap.Providers {
		if !used[p.PK] {
			r.rep.Apps.Skipped++
			r.appItems = append(r.appItems, Item{Kind: "app", Name: p.Name, Skipped: true, Reason: reasonOrphan})
		}
	}
	for i := range r.latchApps {
		if l := &r.latchApps[i]; l.AuthentikProviderPK != nil && !claimed[l.ID] {
			r.appItems = append(r.appItems, Item{Kind: "app", Name: l.Name, Reason: warnAppGone})
		}
	}
	return nil
}

// matchApps matches each application that has an OpenID Connect provider
// to a Latch app: on Authentik provider PK first, then on client ID. Each
// Latch app is matched at most once. It returns the IDs of the Latch apps
// matched.
func (r *run) matchApps(apps []*importApp) map[string]bool {
	byPK := map[int64]*model.Application{}
	byClientID := map[string]*model.Application{}
	for i := range r.latchApps {
		l := &r.latchApps[i]
		if pk := l.AuthentikProviderPK; pk != nil && byPK[*pk] == nil {
			byPK[*pk] = l
		}
		byClientID[l.ClientID] = l
	}
	claimed := map[string]bool{}
	claim := func(a *importApp, l *model.Application) {
		if a.latch == nil && l != nil && !claimed[l.ID] {
			a.latch = l
			claimed[l.ID] = true
		}
	}
	for _, a := range apps {
		if a.prov != nil {
			claim(a, byPK[a.prov.PK])
		}
	}
	for _, a := range apps {
		if a.prov != nil {
			claim(a, byClientID[a.prov.ClientID])
		}
	}
	return claimed
}

// writeApp maps one application, checks it with the app pages' rules, and
// adds or updates its Latch app. An app that breaks a rule, or whose client
// ID another Latch app has, is skipped; the store call undoes its own
// writes, so the import carries on.
func (r *run) writeApp(svc *admin.Service, a *importApp, ag accessGroups, bindings []authentik.Binding,
	mappings []authentik.ProviderMapping) error {
	app := r.mapApp(a, ag, bindings, mappings)
	if a.skipped {
		return nil
	}
	if err := svc.CheckApp(r.ctx, app); err != nil {
		var ve *admin.ValidationError
		if !errors.As(err, &ve) {
			return fmt.Errorf("importer: check app %s: %w", a.src.Name, err)
		}
		a.skip(joinMessages(ve.Fields))
		return nil
	}
	var err error
	switch {
	case a.latch == nil:
		if err = r.tx.CreateApplication(r.ctx, app); err == nil {
			r.rep.Apps.Added++
		}
	case appChanged(a.latch, app):
		if err = r.tx.UpdateApplication(r.ctx, app); err == nil {
			r.rep.Apps.Updated++
		}
	default:
		r.rep.Apps.Updated++
	}
	switch {
	case errors.Is(err, store.ErrConflict): // CheckApp checked the slug, so it is the client ID
		a.skip(reasonClientTaken)
	case err != nil:
		return fmt.Errorf("importer: save app %s: %w", a.src.Name, err)
	}
	return nil
}

// mapApp makes the Latch app for a: the matched app with Authentik's values
// over every imported field, or a new one. It keeps the matched app's
// service account, and its uploaded icon when Authentik has no usable one.
// It skips a when Latch can't import it as Authentik had it.
func (r *run) mapApp(a *importApp, ag accessGroups, bindings []authentik.Binding,
	mappings []authentik.ProviderMapping) *model.Application {
	src, p := &a.src, a.prov
	app := &model.Application{}
	if a.latch != nil {
		*app = *a.latch
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

	app.RedirectURIs, app.PostLogoutRedirectURIs = []string{}, []string{}
	for _, u := range p.RedirectURIs {
		logout := u.Type == "logout"
		switch {
		case u.MatchingMode != "strict" && logout:
			a.warn(fmt.Sprintf(warnLogoutPattern, u.URL))
		case u.MatchingMode != "strict":
			a.warn(fmt.Sprintf(warnPattern, u.URL))
		case logout:
			app.PostLogoutRedirectURIs = append(app.PostLogoutRedirectURIs, u.URL)
		default:
			app.RedirectURIs = append(app.RedirectURIs, u.URL)
		}
	}

	mode, ok := subjectModes[p.SubMode]
	if !ok {
		a.skip(reasonSubjectMode)
		return nil
	}
	if p.SubMode == "user_upn" {
		a.warn(warnUPN)
	}
	app.SubjectMode = mode

	// Authentik's ID tokens last as long as its access tokens.
	app.AccessTokenTTL = lifetime(a, p.AccessTokenValidity, maxAccessLifetime, accessCopy)
	app.IDTokenTTL = app.AccessTokenTTL
	app.RefreshTokenTTL = lifetime(a, p.RefreshTokenValidity, r.cfg.Tokens.RefreshAbsolute, refreshCopy)

	switch launch := strings.TrimSpace(src.LaunchURL); {
	case launch == "" || launch == "blank://blank": // blank://blank is Authentik's "none"
		app.LaunchURL = ""
	case webAddress(launch, "http", "https"):
		app.LaunchURL = launch
	default:
		app.LaunchURL = ""
		a.warn(fmt.Sprintf(warnLaunchURL, launch))
	}
	app.ShowTile = app.LaunchURL != "" && !src.Hide

	switch icon := strings.TrimSpace(src.Icon); {
	case webAddress(icon, "https"):
		app.IconURL = icon
	case a.latch != nil && strings.HasPrefix(a.latch.IconURL, "/icons/"):
		app.IconURL = a.latch.IconURL
	default:
		app.IconURL = ""
		if icon != "" {
			a.warn(warnIcon)
		}
	}
	app.Description = src.Description

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

	acc := appAccess(src.EngineMode, bindings, ag)
	if acc.skip != "" {
		a.skip(acc.skip)
		return nil
	}
	app.AllowedGroupIDs = acc.groupIDs
	if acc.warning != "" {
		a.warn(acc.warning)
	}

	if slices.Contains(p.GrantTypes, "client_credentials") && app.ClientType == model.ClientTypeConfidential &&
		app.ServiceAccountID == "" {
		a.warn(warnServiceLogin)
	}
	pk := p.PK
	app.AuthentikProviderPK = &pk
	return app
}

// lifetime reads an Authentik duration and fits it between a minute and
// longest, warning when it changes it. One Latch can't read becomes 0, the
// default.
func lifetime(a *importApp, text string, longest time.Duration, c lifetimeCopy) time.Duration {
	d, err := authentik.ParseValidity(text)
	switch {
	case err != nil:
		a.warn(c.unread)
		return 0
	case d > longest:
		a.warn(fmt.Sprintf(c.long, cmp.Or(admin.FormatDuration(d), "0s"), admin.FormatDuration(longest)))
		return longest
	case d < minLifetime:
		a.warn(fmt.Sprintf(c.short, cmp.Or(admin.FormatDuration(d), "0s"), admin.FormatDuration(minLifetime)))
		return minLifetime
	}
	return d.Truncate(time.Second) // the store keeps whole seconds
}

// webAddress reports whether s is an absolute address with one of these
// schemes, a host and no user name or password, as the app pages require.
func webAddress(s string, schemes ...string) bool {
	u, err := url.Parse(s)
	return err == nil && slices.Contains(schemes, u.Scheme) && u.Host != "" && u.User == nil
}

// joinMessages makes one reason from a validation error's messages, in
// field-name order, each message once.
func joinMessages(fields map[string]string) string {
	var msgs []string
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		if !slices.Contains(msgs, fields[k]) {
			msgs = append(msgs, fields[k])
		}
	}
	return strings.Join(msgs, " ")
}

// appChanged reports whether any field the import writes differs.
func appChanged(a, b *model.Application) bool {
	return a.Name != b.Name || a.Slug != b.Slug || a.ClientID != b.ClientID || a.ClientSecretHash != b.ClientSecretHash ||
		a.ClientType != b.ClientType || !slices.Equal(a.RedirectURIs, b.RedirectURIs) ||
		!slices.Equal(a.PostLogoutRedirectURIs, b.PostLogoutRedirectURIs) ||
		!slices.Equal(slices.Sorted(slices.Values(a.AllowedGroupIDs)), slices.Sorted(slices.Values(b.AllowedGroupIDs))) ||
		a.SubjectMode != b.SubjectMode || a.AccessTokenTTL != b.AccessTokenTTL || a.IDTokenTTL != b.IDTokenTTL ||
		a.RefreshTokenTTL != b.RefreshTokenTTL || a.LaunchURL != b.LaunchURL || a.IconURL != b.IconURL ||
		a.Description != b.Description || a.ShowTile != b.ShowTile || a.ServiceAccountID != b.ServiceAccountID ||
		!samePK(a.AuthentikProviderPK, b.AuthentikProviderPK)
}
