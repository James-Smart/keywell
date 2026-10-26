// Package testenv starts a complete Keywell HTTP stack on an httptest server
// for tests in the web, oidc and api packages (which use external test
// packages so they can import this one without a cycle).
package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/mail"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/oidc"
	"github.com/James-Smart/keywell/internal/password"
	"github.com/James-Smart/keywell/internal/secrets"
	"github.com/James-Smart/keywell/internal/session"
	"github.com/James-Smart/keywell/internal/store"
	"github.com/James-Smart/keywell/internal/store/storetest"
	"github.com/James-Smart/keywell/internal/totp"
	"github.com/James-Smart/keywell/internal/web"
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
	// Provider serves the OpenID Connect endpoints, on Clock's time.
	Provider *oidc.Provider

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
	log    *slog.Logger
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

// WithLog gives the stack log instead of a logger that discards
// everything, so a test can assert on what the server logs.
func WithLog(log *slog.Logger) Option {
	return func(o *options) { o.log = log }
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
	if o.log != nil {
		log = o.log
	}
	rend, err := web.NewRenderer(cfg, log)
	if err != nil {
		t.Fatalf("testenv: renderer: %v", err)
	}
	st, db := storetest.OpenTestDB(t)
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
	prov := oidc.NewProvider(oidc.Deps{
		Cfg: cfg, Store: st, Keys: keys, Audit: rec, Log: log, Renderer: rend, Sessions: sessions, Now: clock.Now,
	})

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
		OIDC:       prov,
		Keys:       keys,
		Background: background,
		Now:        clock.Now,
		Version:    Version,
	})
	handler.Store(&h)

	return &Env{TS: ts, Store: st, DB: db, Mailer: mailer, Cfg: cfg, Clock: clock, Enc: enc, Keys: keys,
		Provider: prov, background: background}
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

// AdminEmail and AdminPassword are the account AdminClient signs in as.
const (
	AdminEmail    = "admin@example.org"
	AdminPassword = "admin password for tests"
)

// AdminClient returns a client signed in as AdminEmail, a member of the
// group "Admin", and that member. Both are created when missing: the group
// as an admin group with no second step. A group "Admin" a test already
// made is used as it is.
func (e *Env) AdminClient(t *testing.T) (*http.Client, *model.User) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.Store.GetGroupByName(ctx, "Admin"); errors.Is(err, store.ErrNotFound) {
		e.CreateGroup(t, "Admin", true, false)
	} else if err != nil {
		t.Fatalf("testenv: get group Admin: %v", err)
	}
	u, err := e.Store.GetUserByEmail(ctx, AdminEmail)
	if errors.Is(err, store.ErrNotFound) {
		u = e.CreateUser(t, AdminEmail, AdminPassword, "Admin")
	} else if err != nil {
		t.Fatalf("testenv: get user %s: %v", AdminEmail, err)
	}
	c := e.Client(t)
	e.Login(t, c, AdminEmail, AdminPassword)
	return c, u
}

// Page gets path with c and returns the response, its body already
// closed, and the body as text.
func (e *Env) Page(t *testing.T, c *http.Client, path string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(e.TS.URL + path)
	if err != nil {
		t.Fatalf("testenv: get %s: %v", path, err)
	}
	return resp, readBody(t, resp)
}

// Submit posts form to path with c, as a browser submits a form, and
// returns the response, its body already closed, and the body as text.
func (e *Env) Submit(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := c.PostForm(e.TS.URL+path, form)
	if err != nil {
		t.Fatalf("testenv: post %s: %v", path, err)
	}
	return resp, readBody(t, resp)
}

// SubmitMultipart posts form plus one file part (field file, named
// filename, holding content) to path with c, as a browser submits a
// multipart form, and returns the response and its body as Submit does.
func (e *Env) SubmitMultipart(t *testing.T, c *http.Client, path string, form url.Values, file, filename string, content []byte) (*http.Response, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vs := range form {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatalf("testenv: multipart field %s: %v", k, err)
			}
		}
	}
	fw, err := mw.CreateFormFile(file, filename)
	if err != nil {
		t.Fatalf("testenv: multipart file %s: %v", file, err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("testenv: multipart file %s: %v", file, err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("testenv: multipart close: %v", err)
	}
	resp, err := c.Post(e.TS.URL+path, mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("testenv: post %s: %v", path, err)
	}
	return resp, readBody(t, resp)
}

// APIToken stores a new API token with scope for the service account
// username, creating the account (named after its username, in no groups)
// when there is none, and returns the raw token and the account. Each call
// makes another token, so calling it twice with one username gives the
// same account two tokens.
func (e *Env) APIToken(t *testing.T, username string, scope model.APITokenScope) (raw string, account *model.User) {
	t.Helper()
	ctx := context.Background()
	account, err := e.Store.GetUserByUsername(ctx, username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		account = &model.User{Type: model.UserTypeService, Name: username, Username: username, IsActive: true}
		if err := e.Store.CreateUser(ctx, account); err != nil {
			t.Fatalf("testenv: create service account %s: %v", username, err)
		}
	case err != nil:
		t.Fatalf("testenv: get user %s: %v", username, err)
	case account.Type != model.UserTypeService:
		t.Fatalf("testenv: %s is a member, not a service account", username)
	}
	raw = "keywell_" + secrets.RandomToken(32)
	tok := &model.APIToken{ServiceAccountID: account.ID, Label: username + " test token",
		TokenHash: secrets.HashToken(raw), Scope: scope}
	if err := e.Store.CreateAPIToken(ctx, tok); err != nil {
		t.Fatalf("testenv: create API token for %s: %v", username, err)
	}
	return raw, account
}

// API sends a request to the admin API, with token as its bearer token
// (none when ""). path is from the server root, such as "/api/v1/me". body
// is sent as JSON unless it is nil (no body) or an io.Reader (sent as is).
// It returns the response body decoded as a JSON object (nil when empty)
// and the response, whose body is already closed. A body that is not a
// JSON object fails the test. Cookies are never sent.
func (e *Env) API(t *testing.T, token, method, path string, body any) (map[string]any, *http.Response) {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case io.Reader:
		r = b
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("testenv: %s %s: encode body: %v", method, path, err)
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, e.TS.URL+path, r)
	if err != nil {
		t.Fatalf("testenv: %s %s request: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.TS.Client().Do(req)
	if err != nil {
		t.Fatalf("testenv: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testenv: read %s %s response: %v", method, path, err)
	}
	if len(raw) == 0 {
		return nil, resp
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("testenv: %s %s: status %d, body is not a JSON object: %v\n%s", method, path, resp.StatusCode, err, raw)
	}
	return out, resp
}

// readBody reads and closes resp's body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testenv: read %s response: %v", resp.Request.URL.Path, err)
	}
	return string(b)
}

// AuthorizeRaw sends an authorization request with params from c and
// returns the response unread; the caller closes its body.
func (e *Env) AuthorizeRaw(t *testing.T, c *http.Client, params url.Values) *http.Response {
	t.Helper()
	resp, err := c.Get(e.TS.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("testenv: authorize: %v", err)
	}
	return resp
}

// Authorize asks for a code for app with c, which must be signed in, at
// app's first redirect URI with scope "openid profile email groups" and a
// random state and nonce, using PKCE (S256) when pkce is set. It fails the
// test unless the server redirects back with a code and the same state, and
// returns the code, the PKCE verifier ("" without PKCE) and the state.
func (e *Env) Authorize(t *testing.T, c *http.Client, app *model.Application, pkce bool) (code, verifier, state string) {
	t.Helper()
	code, verifier, state, _ = e.AuthorizeWithNonce(t, c, app, pkce)
	return code, verifier, state
}

// AuthorizeWithNonce is Authorize that also returns the nonce it sent.
func (e *Env) AuthorizeWithNonce(t *testing.T, c *http.Client, app *model.Application, pkce bool) (code, verifier, state, nonce string) {
	t.Helper()
	state, nonce = secrets.RandomToken(16), secrets.RandomToken(16)
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {app.ClientID},
		"redirect_uri":  {app.RedirectURIs[0]},
		"scope":         {"openid profile email groups"},
		"state":         {state},
		"nonce":         {nonce},
	}
	if pkce {
		verifier = secrets.RandomToken(32)
		sum := sha256.Sum256([]byte(verifier))
		params.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		params.Set("code_challenge_method", "S256")
	}
	resp := e.AuthorizeRaw(t, c, params)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("testenv: authorize %s: status %d (Location %q), want 302",
			app.Slug, resp.StatusCode, resp.Header.Get("Location"))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("testenv: authorize %s: Location: %v", app.Slug, err)
	}
	q := loc.Query()
	if code = q.Get("code"); code == "" {
		t.Fatalf("testenv: authorize %s: no code (error %q: %s)", app.Slug, q.Get("error"), q.Get("error_description"))
	}
	if q.Get("state") != state {
		t.Fatalf("testenv: authorize %s: state %q, want %q", app.Slug, q.Get("state"), state)
	}
	return code, verifier, state, nonce
}

// PostAsClient posts form to path as app: with HTTP Basic credentials when
// secret is non-empty (each part form-urlencoded, RFC 6749 §2.3.1), else
// with client_id in the form. It returns the body decoded as a JSON object
// (nil when empty) and the response, whose body is already closed.
func (e *Env) PostAsClient(t *testing.T, path string, app *model.Application, secret string, form url.Values) (map[string]any, *http.Response) {
	t.Helper()
	form = maps.Clone(form)
	if form == nil {
		form = url.Values{}
	}
	if secret == "" {
		form.Set("client_id", app.ClientID)
	}
	req, err := http.NewRequest(http.MethodPost, e.TS.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("testenv: %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(app.ClientID), url.QueryEscape(secret))
	}
	resp, err := e.TS.Client().Do(req)
	if err != nil {
		t.Fatalf("testenv: post %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testenv: read %s response: %v", path, err)
	}
	if len(raw) == 0 {
		return nil, resp
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("testenv: %s: status %d, body is not a JSON object: %v\n%s", path, resp.StatusCode, err, raw)
	}
	return body, resp
}

// Exchange trades an authorization code for tokens as app (see
// PostAsClient), sending verifier as code_verifier when non-empty.
func (e *Env) Exchange(t *testing.T, app *model.Application, secret, code, verifier, redirectURI string) (map[string]any, *http.Response) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return e.PostAsClient(t, "/oauth/token", app, secret, form)
}

// Refresh redeems refreshToken for new tokens as app (see PostAsClient).
func (e *Env) Refresh(t *testing.T, app *model.Application, secret, refreshToken string) (map[string]any, *http.Response) {
	t.Helper()
	return e.PostAsClient(t, "/oauth/token", app, secret,
		url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}
