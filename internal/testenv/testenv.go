// Package testenv starts a complete Latch HTTP stack on an httptest server
// for tests in the web and oidc packages (which use external test packages
// so they can import this one without a cycle).
package testenv

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/mail"
	"latch/internal/model"
	"latch/internal/oidc"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/totp"
	"latch/internal/web"
)

// Version is the version string the test server reports.
const Version = "test"

// Clock is a settable time source shared by the session manager and the
// rate limiters. It starts at the real current time because the store
// compares session expiry with the real clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the clock's current time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Env is a running test stack.
type Env struct {
	TS    *httptest.Server
	Store *store.Store
	// DB is the store's database, for reading tables the store has no
	// reader for, such as audit_events.
	DB     *sql.DB
	Mailer *mail.Memory
	Cfg    *config.Config
	Clock  *Clock
	// Enc is the server's encryptor, for sealing and opening TOTP secrets.
	Enc *secrets.Encryptor
	// Keys holds the token signing keys, stored in Store and sealed by Enc.
	Keys *oidc.KeyManager

	// background counts the server's work after responding (reset emails).
	background *sync.WaitGroup
}

// mailWait bounds WaitMail, so a stuck send fails the test instead of
// hanging it.
const mailWait = 10 * time.Second

// WaitMail waits for the emails the server is sending in the background,
// so a test can then assert on Mailer.Sent.
func (e *Env) WaitMail(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		e.background.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(mailWait):
		t.Fatalf("testenv: emails still sending after %v", mailWait)
	}
}

// Option adjusts how New builds the stack.
type Option func(*options)

type options struct {
	config []func(*config.Config)
	mailer func(*mail.Memory) mail.Mailer
}

// WithConfig edits the config after the defaults (and PublicURL) are set.
func WithConfig(f func(*config.Config)) Option {
	return func(o *options) { o.config = append(o.config, f) }
}

// WithMailer gives the server wrap(Env.Mailer) as its mailer, e.g. to hold
// or fail sends. Env.Mailer records what the wrapper passes on.
func WithMailer(wrap func(*mail.Memory) mail.Mailer) Option {
	return func(o *options) { o.mailer = wrap }
}

// New builds the full stack: test store, memory mailer, fake clock, the
// production rate limits, and a config whose PublicURL is the server's URL.
func New(t *testing.T, opts ...Option) *Env {
	t.Helper()
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	// The server must exist before the config (PublicURL is its URL), and
	// the handler needs the config, so the handler is swapped in afterwards.
	var handler atomic.Pointer[http.Handler]
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*handler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatalf("testenv: default config: %v", err)
	}
	cfg.PublicURL = ts.URL
	cfg.DataDir = t.TempDir()
	cfg.EncryptionKey = secrets.GenerateKey()
	for _, f := range o.config {
		f(cfg)
	}

	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("testenv: encryptor: %v", err)
	}
	log := slog.New(slog.DiscardHandler)
	rend, err := web.NewRenderer(cfg, log)
	if err != nil {
		t.Fatalf("testenv: renderer: %v", err)
	}
	st, db := store.OpenTestDB(t)
	mailer := &mail.Memory{}
	var serverMailer mail.Mailer = mailer
	if o.mailer != nil {
		serverMailer = o.mailer(mailer)
	}
	clock := &Clock{t: time.Now().UTC()}
	// Registered after the database's cleanup, so it runs first: background
	// work finishes before the database closes.
	background := new(sync.WaitGroup)
	t.Cleanup(background.Wait)

	sessions := session.NewManager(st, cfg.Sessions.Idle, cfg.Sessions.Absolute, cfg.SecureCookies())
	sessions.SetClock(clock.Now)
	rec := audit.New(st, log)
	keys, err := oidc.NewKeyManager(context.Background(), st, enc)
	if err != nil {
		t.Fatalf("testenv: signing keys: %v", err)
	}
	keys.WithAudit(rec)

	h := web.New(web.Deps{
		Cfg:        cfg,
		Store:      st,
		Sessions:   sessions,
		Mailer:     serverMailer,
		Audit:      rec,
		Enc:        enc,
		Log:        log,
		Renderer:   rend,
		Limits:     web.NewLimiters(clock.Now),
		Background: background,
		Version:    Version,
	})
	handler.Store(&h)

	return &Env{TS: ts, Store: st, DB: db, Mailer: mailer, Cfg: cfg, Clock: clock, Enc: enc, Keys: keys, background: background}
}

// EnrolTOTP enrols u in TOTP directly through the store, as if they had
// confirmed it, and returns the base32 secret for generating codes. u's
// TOTP fields are updated to match.
func (e *Env) EnrolTOTP(t *testing.T, u *model.User) (secret string) {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("testenv: totp secret: %v", err)
	}
	sealed, err := e.Enc.Seal([]byte(secret))
	if err != nil {
		t.Fatalf("testenv: seal totp secret: %v", err)
	}
	confirmed := time.Now().UTC()
	if err := e.Store.SetTOTP(context.Background(), u.ID, sealed, &confirmed); err != nil {
		t.Fatalf("testenv: enrol %s in totp: %v", u.Email, err)
	}
	u.TOTPSecretEnc, u.TOTPConfirmedAt = sealed, &confirmed
	return secret
}

// CreateUser creates an active member with the given password (none if
// empty), adding them to the named groups, which are created if missing.
func (e *Env) CreateUser(t *testing.T, email, pw string, groups ...string) *model.User {
	t.Helper()
	ctx := context.Background()
	name, _, _ := strings.Cut(email, "@")
	u := &model.User{Name: name, Email: email, IsActive: true}
	if pw != "" {
		hash, err := password.Hash(pw)
		if err != nil {
			t.Fatalf("testenv: hash password: %v", err)
		}
		u.PasswordHash = hash
	}
	if err := e.Store.CreateUser(ctx, u); err != nil {
		t.Fatalf("testenv: create user %s: %v", email, err)
	}
	for _, name := range groups {
		g, err := e.Store.GetGroupByName(ctx, name)
		if errors.Is(err, store.ErrNotFound) {
			g = e.CreateGroup(t, name, false, false)
		} else if err != nil {
			t.Fatalf("testenv: get group %s: %v", name, err)
		}
		if err := e.Store.AddMember(ctx, u.ID, g.ID); err != nil {
			t.Fatalf("testenv: add %s to %s: %v", email, name, err)
		}
	}
	return u
}

// CreateGroup creates a group.
func (e *Env) CreateGroup(t *testing.T, name string, isAdmin, requireTOTP bool) *model.Group {
	t.Helper()
	g := &model.Group{Name: name, IsAdmin: isAdmin, RequireTOTP: requireTOTP}
	if err := e.Store.CreateGroup(context.Background(), g); err != nil {
		t.Fatalf("testenv: create group %s: %v", name, err)
	}
	return g
}

// CreateApp stores a, hashing secret into ClientSecretHash when non-empty.
func (e *Env) CreateApp(t *testing.T, a model.Application, secret string) *model.Application {
	t.Helper()
	if secret != "" {
		a.ClientSecretHash = secrets.HashToken(secret)
	}
	if err := e.Store.CreateApplication(context.Background(), &a); err != nil {
		t.Fatalf("testenv: create application %s: %v", a.Name, err)
	}
	return &a
}

// Client returns a browser-like client with its own cookie jar that does
// not follow redirects, so tests can assert on each one.
func (e *Env) Client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("testenv: cookie jar: %v", err)
	}
	return &http.Client{
		Jar:       jar,
		Transport: e.TS.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Login posts the sign-in form with c and fails the test unless the
// password is accepted: a 303 and a session cookie in c's jar.
func (e *Env) Login(t *testing.T, c *http.Client, email, pw string) {
	t.Helper()
	resp, err := c.PostForm(e.TS.URL+"/login", url.Values{"email": {email}, "password": {pw}})
	if err != nil {
		t.Fatalf("testenv: login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("testenv: login %s: status %d, want 303", email, resp.StatusCode)
	}
	u, err := url.Parse(e.TS.URL)
	if err != nil {
		t.Fatalf("testenv: parse server URL: %v", err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == session.CookieName {
			return
		}
	}
	t.Fatalf("testenv: login %s: no %s cookie", email, session.CookieName)
}
