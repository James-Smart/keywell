// Package session manages browser sessions: a random ID in the latch_session
// cookie referencing a row in the sessions table.
package session

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// CookieName is the name of the session cookie.
const CookieName = "latch_session"

// touchEvery is how old LastSeenAt must be before a request writes it again.
const touchEvery = time.Minute

// Manager creates, loads and ends sessions.
type Manager struct {
	store          *store.Store
	idle, absolute time.Duration
	secure         bool
	now            func() time.Time
}

// NewManager returns a Manager whose sessions end after idle without use or
// absolute after creation, whichever comes first. secure sets the cookie's
// Secure attribute.
func NewManager(s *store.Store, idle, absolute time.Duration, secure bool) *Manager {
	return &Manager{store: s, idle: idle, absolute: absolute, secure: secure, now: time.Now}
}

// SetClock replaces the time source. It exists for tests only.
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// Start creates a session for userID and sets the cookie. Any session the
// request already carried is deleted so a session ID never survives a login.
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string, totpPassed bool) (*model.Session, error) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		if err := m.store.DeleteSession(ctx, c.Value); err != nil {
			return nil, err
		}
	}
	now := m.now().UTC()
	sess := &model.Session{
		ID:         secrets.RandomToken(32),
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  m.expiry(now, now),
		TOTPPassed: totpPassed,
		IP:         remoteIP(r),
		UserAgent:  r.UserAgent(),
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	http.SetCookie(w, m.cookie(sess.ID, int(m.absolute/time.Second)))
	return sess, nil
}

// End deletes the request's session, if any, and clears the cookie.
func (m *Manager) End(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, m.cookie("", -1))
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	return m.store.DeleteSession(ctx, c.Value)
}

// Update saves sess's LastSeenAt, ExpiresAt and TOTPPassed, e.g. after the
// second factor is checked.
func (m *Manager) Update(ctx context.Context, sess *model.Session) error {
	return m.store.UpdateSession(ctx, sess)
}

// Middleware loads the session and its user into the request context when
// the cookie names a live session of an active user. Expired sessions and
// sessions of inactive or deleted users are deleted and the cookie cleared.
// LastSeenAt and ExpiresAt are written at most once per minute.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
			if sess, user := m.load(w, r, c.Value); sess != nil {
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, loaded{sess, user}))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// load returns the live session named by id and its active user, or nils.
func (m *Manager) load(w http.ResponseWriter, r *http.Request, id string) (*model.Session, *model.User) {
	ctx := r.Context()
	sess, err := m.store.GetSession(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		http.SetCookie(w, m.cookie("", -1))
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "session: load", "error", err)
		return nil, nil
	}
	now := m.now().UTC()
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.CreatedAt.Add(m.absolute)) {
		m.drop(w, r, sess.ID)
		return nil, nil
	}
	user, err := m.store.GetUser(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !user.IsActive) {
		m.drop(w, r, sess.ID)
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "session: load user", "error", err)
		return nil, nil
	}
	if now.Sub(sess.LastSeenAt) >= touchEvery {
		sess.LastSeenAt = now
		sess.ExpiresAt = m.expiry(sess.CreatedAt, now)
		if err := m.store.UpdateSession(ctx, sess); err != nil {
			slog.ErrorContext(ctx, "session: touch", "error", err)
		}
	}
	return sess, user
}

// drop deletes a session that may no longer be used and clears the cookie.
func (m *Manager) drop(w http.ResponseWriter, r *http.Request, id string) {
	if err := m.store.DeleteSession(r.Context(), id); err != nil {
		slog.ErrorContext(r.Context(), "session: delete", "error", err)
	}
	http.SetCookie(w, m.cookie("", -1))
}

// expiry is min(now+idle, created+absolute).
func (m *Manager) expiry(created, now time.Time) time.Time {
	idle, abs := now.Add(m.idle), created.Add(m.absolute)
	if idle.Before(abs) {
		return idle
	}
	return abs
}

func (m *Manager) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// remoteIP is the host part of r.RemoteAddr. The web package's RealIP
// middleware has already replaced RemoteAddr with the client address when
// the request came through a trusted proxy.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type ctxKey struct{}

type loaded struct {
	sess *model.Session
	user *model.User
}

// FromContext returns the session and user the middleware loaded, if any.
func FromContext(ctx context.Context) (*model.Session, *model.User, bool) {
	l, ok := ctx.Value(ctxKey{}).(loaded)
	if !ok {
		return nil, nil, false
	}
	return l.sess, l.user, true
}

// RequireUser redirects to the login page, with the current URL as next,
// unless the request has a session that has passed every login step. A
// session still waiting for its second factor counts only on the pages
// AllowIncomplete names.
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := FromContext(r.Context())
		if !ok || (!sess.TOTPPassed && !AllowIncomplete(r.URL.Path)) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AllowIncomplete reports whether a session that has not yet passed its
// second factor may use path: the TOTP step, signing out, and enrolment.
func AllowIncomplete(path string) bool {
	switch path {
	case "/login/totp", "/logout", "/logout/done", "/account/totp":
		return true
	}
	return strings.HasPrefix(path, "/account/totp/")
}
