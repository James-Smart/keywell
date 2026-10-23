// Package web serves Latch's member-facing pages and wires the HTTP
// middleware every route shares.
package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/mail"
	"latch/internal/password"
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
	Limits   Limiters

	// OIDC mounts the OpenID Connect endpoints; nil leaves them out.
	OIDC interface{ Mount(*http.ServeMux) }

	// Background counts work handlers carry on with after responding
	// (emailing reset links), so the caller can wait for it, e.g. before
	// exiting. nil when nobody waits.
	Background *sync.WaitGroup

	Version string
}

// Server holds the dependencies of the page handlers.
type Server struct {
	d Deps
	// dummyHash is verified against when a sign-in names no usable
	// password, so the response time does not reveal whether it exists.
	dummyHash string
	// skippedTiles remembers the app tiles already logged as hidden for a
	// bad launch URL (keyed by app ID and URL), so each is logged once.
	skippedTiles sync.Map
}

// dummyPassword is what dummyHash hashes. Knowing it gains nothing: a
// sign-in that matches no user fails whatever the password.
const dummyPassword = "latch dummy password"

func newServer(d Deps) *Server {
	dummy, err := password.Hash(dummyPassword)
	if err != nil {
		panic(fmt.Sprintf("web: hash dummy password: %v", err)) // crypto/rand failed
	}
	if d.Background == nil {
		d.Background = new(sync.WaitGroup)
	}
	return &Server{d: d, dummyHash: dummy}
}

// New returns the complete HTTP handler: routes wrapped in the middleware
// chain (outermost first) recover, real IP, request log, security headers,
// cross-origin protection, sessions. Health checks and static files are
// served without a session lookup.
func New(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	s := newServer(d)

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
	mux.Handle("GET /{$}", session.RequireUser(http.HandlerFunc(s.home)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /logout", s.logoutPage)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /logout/done", s.signedOut)
	mux.HandleFunc("GET /reset", s.resetRequestPage)
	mux.HandleFunc("POST /reset", s.resetRequest)
	mux.HandleFunc("GET /reset/{token}", s.resetSetPage)
	mux.HandleFunc("POST /reset/{token}", s.resetSet)

	signedIn := func(h http.HandlerFunc) http.Handler { return session.RequireUser(h) }
	mux.Handle("GET /account/password", signedIn(s.accountPasswordPage))
	mux.Handle("POST /account/password", signedIn(s.changePassword))

	// The TOTP step checks its own session state; the account TOTP pages
	// are also open to a session waiting for enrolment (AllowIncomplete).
	mux.HandleFunc("GET /login/totp", s.loginTOTPPage)
	mux.HandleFunc("POST /login/totp", s.loginTOTP)
	mux.Handle("GET /account/totp", signedIn(s.accountTOTPPage))
	mux.Handle("POST /account/totp/begin", signedIn(s.beginTOTP))
	mux.Handle("GET /account/totp/qr.png", signedIn(s.totpQR))
	mux.Handle("POST /account/totp/confirm", signedIn(s.confirmTOTP))
	mux.Handle("GET /account/totp/codes", signedIn(s.totpCodes))
	mux.Handle("POST /account/totp/disable", signedIn(s.disableTOTP))
}

// serverError logs err and shows the generic error page. what names the
// failed step for the log; the visitor never sees it.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.d.Log.ErrorContext(r.Context(), what, "error", err)
	s.d.Renderer.RenderError(w, r, http.StatusInternalServerError, "Something went wrong",
		"Something went wrong on our side. Please try again in a moment.")
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
