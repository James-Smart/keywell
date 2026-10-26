package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"latch/internal/model"
	"latch/internal/session"
)

// homeTile is one app on the member home.
type homeTile struct {
	Name, Description string
	LaunchURL         string
	IconURL           string // "" shows Initial instead
	Initial           string // the name's first letter, upper-cased
}

// homeData is what home.html shows.
type homeData struct {
	FirstName string
	Tiles     []homeTile
}

// home is the member home: a greeting and the apps the member may open.
// The account menu in the header leads to everything else.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, user, _ := session.FromContext(ctx) // RequireUser: a complete session
	apps, err := s.d.Store.ListTileApplicationsForUser(ctx, user.ID)
	if err != nil {
		s.serverError(w, r, "home: list apps", err)
		return
	}
	tiles := make([]homeTile, 0, len(apps))
	for _, a := range apps {
		if !webURL(a.LaunchURL) {
			s.skipTile(ctx, a)
			continue
		}
		tiles = append(tiles, homeTile{
			Name:        a.Name,
			Description: a.Description,
			LaunchURL:   a.LaunchURL,
			IconURL:     a.IconURL,
			Initial:     initial(a.Name),
		})
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "home", Page{Title: "Home",
		Data: homeData{FirstName: firstName(user), Tiles: tiles}})
}

// webURL reports whether s is an absolute http or https URL. Launch URLs
// are set by admins; anything else (javascript:, data:, a relative URL) is
// never offered as a link.
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// skipTile warns, once per app and launch URL, that the app's tile is left
// off the home page. Only the scheme is logged, not the URL.
func (s *Server) skipTile(ctx context.Context, a model.Application) {
	if _, logged := s.skippedTiles.LoadOrStore(a.ID+" "+a.LaunchURL, true); logged {
		return
	}
	scheme := "(unparseable)"
	if u, err := url.Parse(a.LaunchURL); err == nil {
		scheme = u.Scheme
	}
	s.d.Log.WarnContext(ctx, "app tile hidden: launch URL is not http or https",
		"app_id", a.ID, "slug", a.Slug, "scheme", scheme)
}

// firstName is the first word of the user's name, or the part of their
// email address before the @ when they have no name.
func firstName(u *model.User) string {
	if words := strings.Fields(u.Name); len(words) > 0 {
		return words[0]
	}
	local, _, _ := strings.Cut(u.Email, "@")
	return local
}

// initial is the first letter of name, upper-cased.
func initial(name string) string {
	r, _ := utf8.DecodeRuneInString(strings.TrimSpace(name))
	if r == utf8.RuneError {
		return ""
	}
	return string(unicode.ToUpper(r))
}
