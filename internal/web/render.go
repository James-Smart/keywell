package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"latch/internal/config"
	"latch/internal/model"
	"latch/internal/session"
)

//go:embed templates/*.html static/*
var content embed.FS

// Brand is the configured look of every page.
type Brand struct{ Name, LogoURL, PrimaryColor, SupportText string }

// Renderer executes page templates inside the branded frame. It does not
// depend on Server so the oidc package can render pages too.
type Renderer struct {
	pages map[string]*template.Template // page name -> frame.html + partials + page file
	brand Brand
	log   *slog.Logger
}

// Page is what a handler passes to Render.
type Page struct {
	Title         string
	Error, Notice string
	Data          any
	// Section is the admin sidebar entry the page belongs to: "members",
	// "groups", "apps", "service-accounts", "settings" or "audit". Setting
	// it shows the admin layout; member pages leave it "".
	Section string
}

// adminLink is an entry of the admin sidebar.
type adminLink struct{ Section, Href, Label string }

// adminNav is the admin sidebar, in order.
var adminNav = []adminLink{
	{"members", "/admin/members", "Members"},
	{"groups", "/admin/groups", "Groups"},
	{"apps", "/admin/apps", "Applications"},
	{"service-accounts", "/admin/service-accounts", "Service accounts"},
	{"settings", "/admin/settings", "Settings"},
	{"audit", "/admin/audit", "Audit log"},
}

// view is what templates see: the Page plus values Render injects.
type view struct {
	Page
	Brand    Brand
	User     *model.User // nil unless signed in with every login step passed
	AdminNav []adminLink
}

// NewRenderer parses the embedded templates once. Each page file is parsed
// together with frame.html and the partials into its own set, so every
// page can define its own "content" block. Partials are the files whose
// names start with "_": they hold templates shared by several pages and
// are never pages themselves.
func NewRenderer(cfg *config.Config, log *slog.Logger) (*Renderer, error) {
	if log == nil {
		log = slog.Default()
	}
	files, err := fs.Glob(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: list templates: %w", err)
	}
	shared := []string{"templates/frame.html"}
	var pageFiles []string
	for _, file := range files {
		switch base := path.Base(file); {
		case base == "frame.html":
		case strings.HasPrefix(base, "_"):
			shared = append(shared, file)
		default:
			pageFiles = append(pageFiles, file)
		}
	}
	funcs := templateFuncs()
	pages := make(map[string]*template.Template, len(pageFiles))
	for _, file := range pageFiles {
		t, err := template.New("frame.html").Funcs(funcs).ParseFS(content, append(shared, file)...)
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", file, err)
		}
		pages[strings.TrimSuffix(path.Base(file), ".html")] = t
	}
	brand := Brand{
		Name:         cfg.Branding.Name,
		PrimaryColor: cfg.Branding.PrimaryColor,
		SupportText:  cfg.Branding.SupportText,
	}
	if cfg.Branding.Logo != "" {
		brand.LogoURL = "/static/logo"
	}
	return &Renderer{pages: pages, brand: brand, log: log}, nil
}

// Render writes page name (without ".html") with the given status. The page
// is rendered to a buffer first so a template error becomes a clean 500.
func (rd *Renderer) Render(w http.ResponseWriter, r *http.Request, status int, name string, p Page) {
	var user *model.User
	if sess, u, ok := session.FromContext(r.Context()); ok && sess.TOTPPassed {
		user = u
	}
	rd.render(w, r, status, name, p, user)
}

// render is Render showing user (nil for nobody) as signed in.
func (rd *Renderer) render(w http.ResponseWriter, r *http.Request, status int, name string, p Page, user *model.User) {
	t, ok := rd.pages[name]
	if !ok {
		rd.fail(w, r, fmt.Errorf("no template %q", name))
		return
	}
	v := view{Page: p, Brand: rd.brand, User: user, AdminNav: adminNav}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "frame.html", v); err != nil {
		rd.fail(w, r, fmt.Errorf("execute %s: %w", name, err))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// RenderError writes the error page. title and message are shown to the
// visitor as given, so callers must never pass internal error text.
func (rd *Renderer) RenderError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	rd.Render(w, r, status, "error", Page{Title: title, Data: struct{ Message string }{message}})
}

// RenderNoAccess writes the page shown when a signed-in member may not use
// appName.
func (rd *Renderer) RenderNoAccess(w http.ResponseWriter, r *http.Request, appName string) {
	rd.Render(w, r, http.StatusOK, "no_access", Page{Title: "No access", Data: struct{ AppName string }{appName}})
}

// RenderSignedOut writes the page shown once a member has signed out. It
// never shows anyone as signed in, even when the request that just ended
// the session still carries it.
func (rd *Renderer) RenderSignedOut(w http.ResponseWriter, r *http.Request) {
	rd.render(w, r, http.StatusOK, "signed_out", Page{Title: "Signed out"}, nil)
}

// fail logs a rendering problem and writes a bare 500; it cannot use a
// template because templates are what failed.
func (rd *Renderer) fail(w http.ResponseWriter, r *http.Request, err error) {
	rd.log.ErrorContext(r.Context(), "render page", "error", err)
	http.Error(w, "Something went wrong.", http.StatusInternalServerError)
}

// templateFuncs are the functions every template can call.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"ago":        func(t *time.Time) string { return ago(time.Now(), t) },
		"date":       func(t time.Time) string { return t.UTC().Format("2 Jan 2006") },
		"datetime":   func(t time.Time) string { return t.UTC().Format("2 Jan 2006 15:04 UTC") },
		"prettyJSON": prettyJSON,
	}
}

// ago says roughly how long before now t was: "Never" for nil, then
// "Today", "Yesterday", "N days ago", "N months ago" (30-day months) or
// "N years ago".
func ago(now time.Time, t *time.Time) string {
	if t == nil {
		return "Never"
	}
	d := now.Sub(*t)
	days := int(d / (24 * time.Hour))
	switch {
	case d < 24*time.Hour:
		return "Today"
	case d < 48*time.Hour:
		return "Yesterday"
	case days < 30:
		return plural(days, "day") + " ago"
	case days < 365:
		return plural(days/30, "month") + " ago"
	}
	return plural(days/365, "year") + " ago"
}

// plural is "1 day" or "N days".
func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// prettyJSON formats metadata for reading and editing: indented by two
// spaces, with characters such as < and & left as they are (the template
// escapes them for the page). nil is "{}".
func prettyJSON(m map[string]any) string {
	if m == nil {
		return "{}"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return "{}" // not reached: metadata is decoded from JSON
	}
	return strings.TrimSuffix(buf.String(), "\n")
}
