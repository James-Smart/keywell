// Package web serves Latch's member-facing pages and wires the HTTP
// middleware every route shares.
package web

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/mail"
	"latch/internal/ratelimit"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
)

// Deps are the collaborators the web handlers use.
type Deps struct {
	Cfg      *config.Config
	Store    *store.Store
	Sessions *session.Manager
	Mailer   mail.Mailer
	Audit    *audit.Recorder
	Enc      *secrets.Encryptor
	Log      *slog.Logger
	Renderer *Renderer

	LoginLimiterAccount, LoginLimiterIP, ResetLimiterAccount, ResetLimiterIP *ratelimit.Limiter

	// OIDC mounts the OpenID Connect endpoints; nil leaves them out.
	OIDC interface{ Mount(*http.ServeMux) }

	Version string
}

// Server holds the dependencies of the page handlers.
type Server struct{ d Deps }

// New returns the complete HTTP handler: routes wrapped in the middleware
// chain (outermost first) recover, real IP, request log, security headers,
// cross-origin protection, sessions. Health checks and static files are
// served without a session lookup.
func New(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	s := &Server{d: d}

	pages := http.NewServeMux()
	s.routes(pages)
	if d.OIDC != nil {
		d.OIDC.Mount(pages)
	}

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", s.healthz)
	root.Handle("GET /static/", staticFiles())
	root.HandleFunc("GET /static/logo", s.logo)
	root.Handle("/", d.Sessions.Middleware(pages))

	var h http.Handler = root
	h = crossOriginProtection(d.Renderer).Handler(h)
	h = securityHeaders(h)
	h = requestLog(d.Log)(h)
	h = realIP(parseProxies(d.Cfg.TrustedProxies, d.Log))(h)
	h = recoverer(d.Log, d.Renderer)(h)
	return h
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.loginPlaceholder)
	mux.HandleFunc("POST /login", s.loginPlaceholder)
}

// loginPlaceholder shows the sign-in form for both GET and POST until the
// real sign-in handlers replace it.
func (s *Server) loginPlaceholder(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.Render(w, r, http.StatusOK, "login", Page{Title: "Sign in"})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}{"ok", s.d.Version})
}

// staticFiles serves the embedded static directory, without listings.
func staticFiles() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err) // "static" is embedded at build time
	}
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		files.ServeHTTP(w, r)
	})
}

// logo serves branding.logo: a redirect when it is a URL, the file when it
// is a path, 404 when unset.
func (s *Server) logo(w http.ResponseWriter, r *http.Request) {
	logo := s.d.Cfg.Branding.Logo
	if logo == "" {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(logo, "https://") || strings.HasPrefix(logo, "http://") {
		http.Redirect(w, r, logo, http.StatusFound)
		return
	}
	f, err := os.Open(logo)
	if err != nil {
		s.d.Log.ErrorContext(r.Context(), "open logo", "error", err)
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		s.d.Log.ErrorContext(r.Context(), "logo is not a readable file", "path", logo)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}
