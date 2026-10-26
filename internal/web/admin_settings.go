package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/importer"
	"github.com/James-Smart/keywell/internal/session"
	"github.com/James-Smart/keywell/internal/store"
)

// settingsData is what admin_settings.html shows.
type settingsData struct {
	Branding   config.BrandingConfig
	LogoURL    string // "" when there is no logo
	SMTP       smtpSettings
	AdminEmail string // where the test email goes
	Keys       []settingsKey
	RetireDays int             // how long a replaced key stays published
	Import     *settingsImport // nil: nothing has been imported
}

// settingsImport is the last import from Authentik, as shown.
type settingsImport struct {
	At         time.Time
	Source     string
	CountLines []string
	Items      []importer.Item
}

// smtpSettings are the email settings shown: never the password.
type smtpSettings struct {
	Host, From, TLS string
	Port            int
}

// settingsKey is a row of the signing keys table.
type settingsKey struct {
	KID       string
	CreatedAt time.Time
	RetiredAt *time.Time
	Active    bool // signs new tokens
}

// tlsLabels name the smtp.tls modes.
var tlsLabels = map[string]string{"starttls": "STARTTLS", "tls": "TLS", "none": "None (unencrypted)"}

// settingsPage shows the branding, email and signing key settings.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, Page{Notice: adminNotice(r)})
}

// renderSettings writes the Settings page with status, and p's Error or
// Notice.
func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, p Page) {
	ctx := r.Context()
	_, user, _ := session.FromContext(ctx)
	rows, err := s.d.Store.ListSigningKeys(ctx)
	if err != nil {
		s.serverError(w, r, "settings: list signing keys", err)
		return
	}
	active := s.d.Keys.ActiveKID()
	keys := make([]settingsKey, len(rows))
	for i, k := range rows {
		keys[i] = settingsKey{KID: k.KID, CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt, Active: k.KID == active}
	}
	cfg := s.d.Cfg
	tls := tlsLabels[cfg.SMTP.TLS]
	if tls == "" {
		tls = cfg.SMTP.TLS
	}
	d := settingsData{
		Branding:   cfg.Branding,
		SMTP:       smtpSettings{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From, TLS: tls},
		AdminEmail: user.Email,
		Keys:       keys,
		RetireDays: int(admin.KeyRetireAfter / (24 * time.Hour)),
	}
	run, err := s.d.Store.LastImportRun(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.serverError(w, r, "settings: last import run", err)
		return
	default:
		var rep importer.Report
		if err := json.Unmarshal([]byte(run.Report), &rep); err != nil {
			s.serverError(w, r, "settings: decode import report", err)
			return
		}
		d.Import = &settingsImport{At: run.FinishedAt, Source: run.Source, CountLines: rep.CountLines(), Items: rep.Items}
	}
	if cfg.Branding.Logo != "" {
		d.LogoURL = "/static/logo"
	}
	p.Title, p.Section, p.Data = "Settings", "settings", d
	s.d.Renderer.Render(w, r, status, "admin_settings", p)
}

// settingsTestEmail sends a test email to the signed-in admin. A failure
// shows the mailer's own error, which SendTestEmail returns as it is: the
// admin needs it to fix the settings. It is the one admin page that shows
// a raw error, so it does not go through adminFailed.
func (s *Server) settingsTestEmail(w http.ResponseWriter, r *http.Request) {
	_, user, _ := session.FromContext(r.Context())
	if err := s.admin.SendTestEmail(r.Context(), adminActor(r), user); err != nil {
		s.renderSettings(w, r, http.StatusBadGateway, Page{Error: "The test email couldn't be sent: " + err.Error()})
		return
	}
	redirectNotice(w, r, "/admin/settings", "test_email_sent")
}

// settingsRotateKeys makes a new signing key and retires the keys replaced
// long enough ago.
func (s *Server) settingsRotateKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kid, _, err := s.admin.RotateKeys(ctx, adminActor(r))
	switch {
	case err != nil && kid == "":
		s.serverError(w, r, "settings: rotate signing keys", err)
		return
	case err != nil:
		// The new key is in use, so the rotation worked; the old keys stay
		// published until a later rotation retires them.
		s.d.Log.ErrorContext(ctx, "settings: retire old signing keys", "error", err)
	}
	redirectNotice(w, r, "/admin/settings", "key_rotated")
}
