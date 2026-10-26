package importer

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"keywell/internal/admin"
	"keywell/internal/authentik"
	"keywell/internal/model"
	"keywell/internal/store"
)

// Report copy for apps. Item reasons are full sentences about the app the
// item names. The copy for an app's fields is in appfields.go.
const (
	reasonNoProvider  = "Has nothing to sign in with in Authentik."
	reasonNotOIDC     = "Signs in with something other than OpenID Connect, which is all Keywell supports."
	reasonOrphan      = "Isn't used by any application in Authentik."
	reasonClientTaken = "Another app in Keywell already uses its client ID."
	warnAppGone       = "Is no longer in Authentik. Keywell has left it as it is."
)

// importApp is a snapshot application and what the import does with it.
type importApp struct {
	src     authentik.Application
	prov    *authentik.OAuth2Provider // its OpenID Connect provider; nil when it has none
	keywell *model.Application        // the Keywell app matched, nil for a new one
	rule    accessRule                // who Authentik let use it, decided before anything can skip it
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

// planApps decides, before anything is written, what happens to each
// snapshot application: whether it has an OpenID Connect provider, which
// Keywell app it matches and who may use it. An app only admins may use
// blocks the import when Keywell will have no admin group (Ruling P), since
// no groups means open to all. It lists the providers no application uses
// and the Keywell apps whose Authentik app is gone. It runs after planGroups.
func (r *run) planApps() {
	providers := map[int64]*authentik.OAuth2Provider{}
	for i := range r.snap.Providers {
		providers[r.snap.Providers[i].PK] = &r.snap.Providers[i]
	}
	bindings := map[string][]authentik.Binding{}
	for _, b := range r.snap.Bindings {
		bindings[b.TargetUUID] = append(bindings[b.TargetUUID], b)
	}
	// Keywell's admin groups never lose admin access (Ruling 4), and each
	// imported superuser group is one.
	imported := map[string]bool{} // UUIDs of the snapshot groups Keywell will have
	hasAdmin := slices.ContainsFunc(r.keywellGroups, func(g model.Group) bool { return g.IsAdmin })
	for _, g := range r.groups {
		if !g.skipped {
			imported[g.src.UUID] = true
			hasAdmin = hasAdmin || g.src.IsSuperuser
		}
	}

	used := map[int64]bool{} // PKs of the providers applications use
	for _, src := range r.snap.Applications {
		a := &importApp{src: src}
		r.apps = append(r.apps, a)
		if src.ProviderPK == nil {
			a.skip(reasonNoProvider)
			continue
		}
		used[*src.ProviderPK] = true
		if a.prov = providers[*src.ProviderPK]; a.prov == nil {
			a.skip(reasonNotOIDC) // SAML, proxy and the like, which the snapshot doesn't hold
			continue
		}
		if a.rule = decideAccess(src.EngineMode, bindings[src.UUID], imported); a.rule.with != "" && !hasAdmin {
			r.block(blockNoAdminGroup, src.Name)
		}
	}
	claimed := r.matchApps()

	for _, p := range r.snap.Providers {
		if !used[p.PK] {
			r.rep.Apps.Skipped++
			r.otherAppItems = append(r.otherAppItems, Item{Kind: "app", Name: p.Name, Skipped: true, Reason: reasonOrphan})
		}
	}
	for i := range r.keywellApps {
		if l := &r.keywellApps[i]; l.AuthentikProviderPK != nil && !claimed[l.ID] {
			r.otherAppItems = append(r.otherAppItems, Item{Kind: "app", Name: l.Name, Reason: warnAppGone})
		}
	}
}

// matchApps matches each application that has an OpenID Connect provider
// to a Keywell app: on Authentik provider PK first, then on client ID. Each
// Keywell app is matched at most once. It returns the IDs of the Keywell apps
// matched.
func (r *run) matchApps() map[string]bool {
	byPK := map[int64]*model.Application{}
	byClientID := map[string]*model.Application{}
	for i := range r.keywellApps {
		l := &r.keywellApps[i]
		if pk := l.AuthentikProviderPK; pk != nil && byPK[*pk] == nil {
			byPK[*pk] = l
		}
		byClientID[l.ClientID] = l
	}
	claimed := map[string]bool{}
	claim := func(a *importApp, l *model.Application) {
		if a.keywell == nil && l != nil && !claimed[l.ID] {
			a.keywell = l
			claimed[l.ID] = true
		}
	}
	for _, a := range r.apps {
		if a.prov != nil {
			claim(a, byPK[a.prov.PK])
		}
	}
	for _, a := range r.apps {
		if a.prov != nil {
			claim(a, byClientID[a.prov.ClientID])
		}
	}
	return claimed
}

// writeApps adds and updates the Keywell apps planApps decided on, each
// checked with the app pages' rules. It runs after the groups are written.
func (r *run) writeApps() error {
	if slices.ContainsFunc(r.apps, func(a *importApp) bool { return !a.skipped }) {
		if r.cfg == nil {
			return errors.New("importer: no config to check apps with")
		}
		ag, err := r.loadAccessGroups()
		if err != nil {
			return err
		}
		mappings := map[int64][]authentik.ProviderMapping{}
		for _, m := range r.snap.Mappings {
			mappings[m.ProviderPK] = append(mappings[m.ProviderPK], m)
		}
		// CheckApp looks slugs and groups up through the transaction.
		svc := admin.New(admin.Deps{Cfg: r.cfg, Store: r.tx})
		for _, a := range r.apps {
			if a.skipped {
				continue
			}
			acc, err := ag.resolve(a.rule)
			if err != nil {
				return err
			}
			if err := r.writeApp(svc, a, acc, mappings[a.prov.PK]); err != nil {
				return err
			}
		}
	}
	for _, a := range r.apps {
		if a.skipped {
			r.rep.Apps.Skipped++
		}
	}
	return nil
}

// writeApp maps one application, checks it with the app pages' rules, and
// adds or updates its Keywell app. An app Keywell can't take as Authentik has
// it, that breaks a rule, or whose client ID another Keywell app has, is
// skipped (a failed store call undoes its own writes, so the import
// carries on), but who can use it still follows Authentik (Rulings N, P).
func (r *run) writeApp(svc *admin.Service, a *importApp, acc access, mappings []authentik.ProviderMapping) error {
	app, reason := r.mapApp(a, acc, mappings)
	if reason != "" {
		return r.skipFollowingAccess(a, reason, acc)
	}
	if err := svc.CheckApp(r.ctx, app); err != nil {
		var ve *admin.ValidationError
		if !errors.As(err, &ve) {
			return fmt.Errorf("importer: check app %s: %w", a.src.Name, err)
		}
		return r.skipFollowingAccess(a, joinMessages(ve.Fields), acc)
	}
	var err error
	switch {
	case a.keywell == nil:
		if err = r.tx.CreateApplication(r.ctx, app); err == nil {
			r.rep.Apps.Added++
		}
	case appChanged(a.keywell, app):
		if err = r.tx.UpdateApplication(r.ctx, app); err == nil {
			r.rep.Apps.Updated++
		}
	default:
		r.rep.Apps.Updated++
	}
	switch {
	case errors.Is(err, store.ErrConflict): // CheckApp checked the slug, so it is the client ID
		return r.skipFollowingAccess(a, reasonClientTaken, acc)
	case err != nil:
		return fmt.Errorf("importer: save app %s: %w", a.src.Name, err)
	}
	return nil
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
		!sameIDs(a.AllowedGroupIDs, b.AllowedGroupIDs) ||
		a.SubjectMode != b.SubjectMode || a.AccessTokenTTL != b.AccessTokenTTL || a.IDTokenTTL != b.IDTokenTTL ||
		a.RefreshTokenTTL != b.RefreshTokenTTL || a.LaunchURL != b.LaunchURL || a.IconURL != b.IconURL ||
		a.Description != b.Description || a.ShowTile != b.ShowTile || a.ServiceAccountID != b.ServiceAccountID ||
		!samePK(a.AuthentikProviderPK, b.AuthentikProviderPK)
}
