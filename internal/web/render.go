package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

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
	pages map[string]*template.Template // page name -> frame.html + page file
	brand Brand
	log   *slog.Logger
}

// Page is what a handler passes to Render.
type Page struct {
	Title         string
	Error, Notice string
	Data          any
}

// view is what templates see: the Page plus values Render injects.
type view struct {
	Page
	Brand Brand
	User  *model.User // nil unless signed in with every login step passed
}

// NewRenderer parses the embedded templates once. Each page file is parsed
// together with frame.html into its own set, so every page can define its
// own "content" block.
func NewRenderer(cfg *config.Config, log *slog.Logger) (*Renderer, error) {
	if log == nil {
		log = slog.Default()
	}
	files, err := fs.Glob(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: list templates: %w", err)
	}
	pages := make(map[string]*template.Template, len(files))
	for _, file := range files {
		name := strings.TrimSuffix(path.Base(file), ".html")
		if name == "frame" {
			continue
		}
		t, err := template.New("frame.html").ParseFS(content, "templates/frame.html", file)
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", file, err)
		}
		pages[name] = t
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
	t, ok := rd.pages[name]
	if !ok {
		rd.fail(w, r, fmt.Errorf("no template %q", name))
		return
	}
	v := view{Page: p, Brand: rd.brand}
	if sess, u, ok := session.FromContext(r.Context()); ok && sess.TOTPPassed {
		v.User = u
	}
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

// fail logs a rendering problem and writes a bare 500; it cannot use a
// template because templates are what failed.
func (rd *Renderer) fail(w http.ResponseWriter, r *http.Request, err error) {
	rd.log.ErrorContext(r.Context(), "render page", "error", err)
	http.Error(w, "Something went wrong.", http.StatusInternalServerError)
}
