package admin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/secrets"
	"github.com/James-Smart/keywell/internal/store"
)

// Messages and limits for applications.
const (
	msgSlug            = "Use lower-case letters, numbers and hyphens."
	msgSlugTaken       = "Another app already uses that short name."
	msgClientType      = "Choose whether the app keeps a secret."
	msgSubjectMode     = "Choose how the app identifies people."
	msgURIFormat       = "Line %d isn't a full web address starting with https:// or http://."
	msgURIFragment     = "Line %d can't contain a # part."
	msgURITooMany      = "Add at most 20 addresses."
	msgTokenTTL        = "Use a time between 1m and 24h, like 1h."
	msgRefreshTTL      = "Use a time between 1m and %s."
	msgLaunchURL       = "Enter a full web address starting with https:// or http://."
	msgTileNeedsLink   = "Add a link to open the app, or untick Show on members' home page."
	msgIconURL         = "Use an https:// address or a path starting with /icons/."
	msgSecretlessLogin = "Only apps that keep a secret can sign in by themselves."
	msgServiceAccount  = "Choose a service account."
	msgNoSecret        = "This app doesn't use a secret."

	maxAppNameLen = 100
	maxSlugLen    = 64
	maxRedirects  = 20
)

// The shortest and longest lifetimes an app's access and ID tokens may
// have. Refresh tokens are limited by the tokens.refresh_absolute setting.
const (
	MinTokenTTL = time.Minute
	MaxTokenTTL = 24 * time.Hour
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// AppInput is an application to add. A zero TTL means the global default.
type AppInput struct {
	Name, Slug                                  string // Slug "" = made from Name
	ClientType                                  model.ClientType
	RedirectURIs, PostLogoutRedirectURIs        []string
	AllowedGroupIDs                             []string
	SubjectMode                                 model.SubjectMode // "" = id
	AccessTokenTTL, IDTokenTTL, RefreshTokenTTL time.Duration
	LaunchURL, IconURL, Description             string
	ShowTile                                    bool
	ServiceAccountID                            string // "" = no machine-to-machine sign-in
}

// AppPatch is a change to an application. Nil fields are left alone.
type AppPatch struct {
	Name, Slug                                  *string
	ClientType                                  *model.ClientType
	RedirectURIs, PostLogoutRedirectURIs        *[]string
	AllowedGroupIDs                             *[]string
	SubjectMode                                 *model.SubjectMode
	AccessTokenTTL, IDTokenTTL, RefreshTokenTTL *time.Duration
	LaunchURL, IconURL, Description             *string
	ShowTile                                    *bool
	ServiceAccountID                            *string
}

// FormatDuration writes d the way admins type it: "" for 0, then whole days
// ("90d"), whole hours ("36h") or whole minutes ("90m"), else as
// time.Duration.String does.
func FormatDuration(d time.Duration) string {
	switch {
	case d == 0:
		return ""
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// CreateApp adds an application and records app.create. A confidential app
// gets a client secret, returned here and nowhere else; only its hash is
// kept. A public app returns "".
func (s *Service) CreateApp(ctx context.Context, a Actor, in AppInput) (*model.Application, string, error) {
	app := &model.Application{
		Name: in.Name, Slug: in.Slug, ClientType: in.ClientType,
		RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
		AllowedGroupIDs: in.AllowedGroupIDs, SubjectMode: in.SubjectMode,
		AccessTokenTTL: in.AccessTokenTTL, IDTokenTTL: in.IDTokenTTL, RefreshTokenTTL: in.RefreshTokenTTL,
		LaunchURL: in.LaunchURL, IconURL: in.IconURL, Description: in.Description,
		ShowTile: in.ShowTile, ServiceAccountID: in.ServiceAccountID,
	}
	p := problems{}
	if err := s.validateApp(ctx, p, app, ""); err != nil {
		return nil, "", err
	}
	if err := p.err(); err != nil {
		return nil, "", err
	}

	app.ClientID = secrets.RandomToken(18)
	var secret string
	if app.ClientType == model.ClientTypeConfidential {
		secret = secrets.RandomToken(32)
		app.ClientSecretHash = secrets.HashToken(secret)
	}
	if err := s.d.Store.CreateApplication(ctx, app); err != nil {
		return nil, "", s.explainAppConflict(ctx, fmt.Errorf("admin: create app: %w", err), app.Slug, "")
	}
	s.record(ctx, a, audit.AppCreate, targetApp, app.ID, "Added application "+app.Name,
		map[string]any{"name": app.Name, "slug": app.Slug, "client_type": string(app.ClientType)})
	return app, secret, nil
}

// UpdateApp applies the non-nil fields of patch and returns the application
// as saved. The whole result is validated again. It records app.update for
// the fields that changed. Switching to public clears the client secret;
// switching to confidential makes one, returned here and nowhere else.
func (s *Service) UpdateApp(ctx context.Context, a Actor, id string, patch AppPatch) (*model.Application, string, error) {
	old, err := s.d.Store.GetApplication(ctx, id)
	if err != nil {
		return nil, "", err
	}
	next := *old
	if patch.Name != nil {
		next.Name = *patch.Name
	}
	if patch.Slug != nil {
		next.Slug = *patch.Slug
	}
	if patch.ClientType != nil {
		next.ClientType = *patch.ClientType
	}
	if patch.RedirectURIs != nil {
		next.RedirectURIs = *patch.RedirectURIs
	}
	if patch.PostLogoutRedirectURIs != nil {
		next.PostLogoutRedirectURIs = *patch.PostLogoutRedirectURIs
	}
	if patch.AllowedGroupIDs != nil {
		next.AllowedGroupIDs = *patch.AllowedGroupIDs
	}
	if patch.SubjectMode != nil {
		next.SubjectMode = *patch.SubjectMode
	}
	if patch.AccessTokenTTL != nil {
		next.AccessTokenTTL = *patch.AccessTokenTTL
	}
	if patch.IDTokenTTL != nil {
		next.IDTokenTTL = *patch.IDTokenTTL
	}
	if patch.RefreshTokenTTL != nil {
		next.RefreshTokenTTL = *patch.RefreshTokenTTL
	}
	if patch.LaunchURL != nil {
		next.LaunchURL = *patch.LaunchURL
	}
	if patch.IconURL != nil {
		next.IconURL = *patch.IconURL
	}
	if patch.Description != nil {
		next.Description = *patch.Description
	}
	if patch.ShowTile != nil {
		next.ShowTile = *patch.ShowTile
	}
	if patch.ServiceAccountID != nil {
		next.ServiceAccountID = *patch.ServiceAccountID
	}
	p := problems{}
	if err := s.validateApp(ctx, p, &next, id); err != nil {
		return nil, "", err
	}
	if err := p.err(); err != nil {
		return nil, "", err
	}

	var secret string
	if next.ClientType != old.ClientType {
		next.ClientSecretHash = ""
		if next.ClientType == model.ClientTypeConfidential {
			secret = secrets.RandomToken(32)
			next.ClientSecretHash = secrets.HashToken(secret)
		}
	}

	changes := changeSet{}
	noteChange(changes, "name", old.Name, next.Name)
	noteChange(changes, "slug", old.Slug, next.Slug)
	noteChange(changes, "client_type", old.ClientType, next.ClientType)
	noteSliceChange(changes, "redirect_uris", old.RedirectURIs, next.RedirectURIs)
	noteSliceChange(changes, "post_logout_redirect_uris", old.PostLogoutRedirectURIs, next.PostLogoutRedirectURIs)
	noteSliceChange(changes, "allowed_groups", old.AllowedGroupIDs, next.AllowedGroupIDs)
	noteChange(changes, "subject_mode", old.SubjectMode, next.SubjectMode)
	noteChange(changes, "access_token_ttl", FormatDuration(old.AccessTokenTTL), FormatDuration(next.AccessTokenTTL))
	noteChange(changes, "id_token_ttl", FormatDuration(old.IDTokenTTL), FormatDuration(next.IDTokenTTL))
	noteChange(changes, "refresh_token_ttl", FormatDuration(old.RefreshTokenTTL), FormatDuration(next.RefreshTokenTTL))
	noteChange(changes, "launch_url", old.LaunchURL, next.LaunchURL)
	noteChange(changes, "icon_url", old.IconURL, next.IconURL)
	noteChange(changes, "description", old.Description, next.Description)
	noteChange(changes, "show_tile", old.ShowTile, next.ShowTile)
	noteChange(changes, "service_account_id", old.ServiceAccountID, next.ServiceAccountID)
	if len(changes) == 0 {
		return &next, "", nil
	}
	if err := s.d.Store.UpdateApplication(ctx, &next); err != nil {
		return nil, "", s.explainAppConflict(ctx, fmt.Errorf("admin: update app: %w", err), next.Slug, id)
	}
	s.record(ctx, a, audit.AppUpdate, targetApp, id, "Updated application "+next.Name, changes.detail())
	return &next, secret, nil
}

// DeleteApp deletes the application, with its sign-in codes and refresh
// tokens, and records app.delete with its name, slug and client ID.
func (s *Service) DeleteApp(ctx context.Context, a Actor, id string) error {
	app, err := s.d.Store.GetApplication(ctx, id)
	if err != nil {
		return err
	}
	if err := s.d.Store.DeleteApplication(ctx, id); err != nil {
		return fmt.Errorf("admin: delete app: %w", err)
	}
	s.record(ctx, a, audit.AppDelete, targetApp, id, "Deleted application "+app.Name,
		map[string]any{"name": app.Name, "slug": app.Slug, "client_id": app.ClientID})
	return nil
}

// RotateAppSecret replaces the client secret of a confidential app and
// records app.secret.rotate. The new secret is returned here and nowhere
// else; the old one stops working at once.
func (s *Service) RotateAppSecret(ctx context.Context, a Actor, id string) (string, error) {
	app, err := s.d.Store.GetApplication(ctx, id)
	if err != nil {
		return "", err
	}
	if app.ClientType != model.ClientTypeConfidential {
		return "", &RefusedError{Message: msgNoSecret}
	}
	secret := secrets.RandomToken(32)
	app.ClientSecretHash = secrets.HashToken(secret)
	if err := s.d.Store.UpdateApplication(ctx, app); err != nil {
		return "", fmt.Errorf("admin: rotate app secret: %w", err)
	}
	s.record(ctx, a, audit.AppSecretRotate, targetApp, id, "Made a new secret for application "+app.Name,
		map[string]any{"name": app.Name, "slug": app.Slug})
	return secret, nil
}

// ResolveApp finds an application by ID or by "slug:<slug>".
func (s *Service) ResolveApp(ctx context.Context, ref string) (*model.Application, error) {
	if slug, ok := strings.CutPrefix(ref, "slug:"); ok {
		return s.d.Store.GetApplicationBySlug(ctx, slug)
	}
	return s.d.Store.GetApplication(ctx, ref)
}

// CheckApp tidies app in place and checks it with the rules of the app
// pages, for an app that comes from elsewhere, such as an import. app.ID,
// when set, is the app's own ID, so its own slug is not taken. It returns a
// *ValidationError when app breaks a rule; any other error is a failed
// lookup.
func (s *Service) CheckApp(ctx context.Context, app *model.Application) error {
	p := problems{}
	if err := s.validateApp(ctx, p, app, app.ID); err != nil {
		return err
	}
	return p.err()
}

// validateApp tidies app in place (trimmed text, a slug made from the name
// when blank, cleaned address lists, an ID for the default subject mode)
// and adds a message to p for each rule it breaks. selfID is the app's own
// ID ("" for a new app), whose slug is not taken. The error is for failed
// lookups, not for invalid input.
func (s *Service) validateApp(ctx context.Context, p problems, app *model.Application, selfID string) error {
	app.Name = p.text("name", app.Name, maxAppNameLen, msgName)

	app.Slug = strings.TrimSpace(app.Slug)
	if app.Slug == "" {
		app.Slug = SlugFromName(app.Name)
	}
	switch {
	case utf8.RuneCountInString(app.Slug) > maxSlugLen:
		p.add("slug", fmt.Sprintf(msgTooLongFormat, maxSlugLen))
	case !slugPattern.MatchString(app.Slug):
		p.add("slug", msgSlug)
	default:
		other, err := s.d.Store.GetApplicationBySlug(ctx, app.Slug)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return fmt.Errorf("admin: check slug is free: %w", err)
		case other.ID != selfID:
			p.add("slug", msgSlugTaken)
		}
	}

	if app.ClientType != model.ClientTypeConfidential && app.ClientType != model.ClientTypePublic {
		p.add("client_type", msgClientType)
	}

	app.RedirectURIs = cleanAddresses(p, "redirect_uris", app.RedirectURIs)
	app.PostLogoutRedirectURIs = cleanAddresses(p, "post_logout_redirect_uris", app.PostLogoutRedirectURIs)

	groups, err := s.groupsByID(ctx, app.AllowedGroupIDs, p)
	if err != nil {
		return err
	}
	if msg, ok := p["groups"]; ok { // groupsByID's field name; here the field is allowed_groups
		delete(p, "groups")
		p.add("allowed_groups", msg)
	}
	app.AllowedGroupIDs = groupIDs(groups)

	switch app.SubjectMode {
	case "":
		app.SubjectMode = model.SubjectModeID
	case model.SubjectModeID, model.SubjectModeEmail, model.SubjectModeUsername,
		model.SubjectModeAuthentikUUID, model.SubjectModeAuthentikUID, model.SubjectModeAuthentikPK:
	default:
		p.add("subject_mode", msgSubjectMode)
	}

	checkTTL(p, "access_token_ttl", app.AccessTokenTTL, MaxTokenTTL, msgTokenTTL)
	checkTTL(p, "id_token_ttl", app.IDTokenTTL, MaxTokenTTL, msgTokenTTL)
	longest := s.d.Cfg.Tokens.RefreshAbsolute
	checkTTL(p, "refresh_token_ttl", app.RefreshTokenTTL, longest, fmt.Sprintf(msgRefreshTTL, FormatDuration(longest)))

	app.LaunchURL = strings.TrimSpace(app.LaunchURL)
	switch {
	case app.LaunchURL != "" && !IsWebAddress(app.LaunchURL, "http", "https"):
		p.add("launch_url", msgLaunchURL)
	case app.LaunchURL == "" && app.ShowTile: // the home page shows no tile without a link
		p.add("launch_url", msgTileNeedsLink)
	}
	app.IconURL = strings.TrimSpace(app.IconURL)
	if app.IconURL != "" && !IsWebAddress(app.IconURL, "https") && !strings.HasPrefix(app.IconURL, "/icons/") {
		p.add("icon_url", msgIconURL)
	}
	app.Description = p.text("description", app.Description, maxDescriptionLen, "")

	app.ServiceAccountID = strings.TrimSpace(app.ServiceAccountID)
	if app.ServiceAccountID != "" {
		switch _, err := s.serviceAccount(ctx, app.ServiceAccountID); {
		case app.ClientType == model.ClientTypePublic:
			p.add("service_account_id", msgSecretlessLogin)
		case errors.Is(err, store.ErrNotFound):
			p.add("service_account_id", msgServiceAccount)
		case err != nil:
			return fmt.Errorf("admin: check service account: %w", err)
		}
	}
	return nil
}

// explainAppConflict turns a store.ErrConflict into the slug message when
// the slug was taken by another request since it was checked. Other errors
// pass through.
func (s *Service) explainAppConflict(ctx context.Context, err error, slug, selfID string) error {
	if !errors.Is(err, store.ErrConflict) {
		return err
	}
	if other, gerr := s.d.Store.GetApplicationBySlug(ctx, slug); gerr == nil && other.ID != selfID {
		return &ValidationError{Fields: map[string]string{"slug": msgSlugTaken}}
	}
	return err
}

// SlugFromName makes a short name from an app's name: lower-case letters
// and digits, with each other run of characters turned into one hyphen. It
// is at most 64 characters, and "app" when nothing is left.
func SlugFromName(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	slug := b.String()
	if len(slug) > maxSlugLen {
		slug = strings.TrimRight(slug[:maxSlugLen], "-")
	}
	if slug == "" {
		return "app"
	}
	return slug
}

// cleanAddresses trims each address, drops empty ones and repeats, and
// checks the rest, adding a message for field to p. Line numbers count the
// entries as submitted, starting at 1, blank ones included.
func cleanAddresses(p problems, field string, in []string) []string {
	out := []string{}
	for i, raw := range in {
		addr := strings.TrimSpace(raw)
		if addr == "" || slices.Contains(out, addr) {
			continue
		}
		switch {
		case !IsWebAddress(addr, "http", "https"):
			p.add(field, fmt.Sprintf(msgURIFormat, i+1))
		case strings.Contains(addr, "#"):
			p.add(field, fmt.Sprintf(msgURIFragment, i+1))
		}
		out = append(out, addr)
	}
	if len(out) > maxRedirects {
		p.add(field, msgURITooMany)
	}
	return out
}

// IsWebAddress reports whether s is an absolute address with one of these
// schemes, a host and no user name or password: the app pages' rule for
// addresses, links and icons.
func IsWebAddress(s string, schemes ...string) bool {
	u, err := url.Parse(s)
	return err == nil && slices.Contains(schemes, u.Scheme) && u.Host != "" && u.User == nil
}

// checkTTL adds msg for field to p unless d is 0 (the default) or between
// MinTokenTTL and max.
func checkTTL(p problems, field string, d, max time.Duration, msg string) {
	if d != 0 && (d < MinTokenTTL || d > max) {
		p.add(field, msg)
	}
}
