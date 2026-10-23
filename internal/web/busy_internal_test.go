package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/store/storetest"
)

const busyPW = "a long enough password 1"

// busyServer is a server whose password hashing always finds every slot
// taken (password.ErrBusy), with the member alex@example.org.
func busyServer(t *testing.T) (*Server, *store.Store, *model.User) {
	t.Helper()
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "http://latch.test"
	log := slog.New(slog.DiscardHandler)
	rd, err := NewRenderer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.OpenTest(t)
	s := newServer(Deps{Cfg: cfg, Store: st, Log: log, Renderer: rd, Audit: audit.New(st, log),
		Sessions: session.NewManager(st, time.Hour, 2*time.Hour, false), Limits: NewLimiters(time.Now)})
	s.verifyPassword = func(context.Context, string, string) (bool, error) { return false, password.ErrBusy }
	s.hashPassword = func(context.Context, string) (string, error) { return "", password.ErrBusy }
	hash, err := password.Hash(busyPW)
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{Name: "Alex", Email: "alex@example.org", PasswordHash: hash, IsActive: true}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return s, st, u
}

func postForm(target string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// assertThrottledPage checks for the form again, status 200, with the
// throttled message.
func assertThrottledPage(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), msgThrottled) {
		t.Fatalf("status %d, want 200 with %q:\n%s", w.Code, msgThrottled, w.Body)
	}
}

// When the server is too busy to check a password, the sign-in form says
// to try again later, no session starts, and the attempt does not count
// against the account or the address.
func TestLoginBusyShowsThrottled(t *testing.T) {
	s, _, _ := busyServer(t)
	w := httptest.NewRecorder()
	s.login(w, postForm("/login", url.Values{"email": {"alex@example.org"}, "password": {busyPW}}))
	assertThrottledPage(t, w)
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName && c.MaxAge >= 0 {
			t.Fatal("a busy sign-in set a session cookie")
		}
	}
	for i := range 10 {
		if !s.d.Limits.LoginAccount.Allow(loginAccountKey("alex@example.org")) {
			t.Fatalf("account limit spent after %d more attempts; the busy one counted", i)
		}
	}
}

// signedIn starts a complete session for u and returns its cookie.
func signedIn(t *testing.T, s *Server, u *model.User) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if _, err := s.d.Sessions.Start(context.Background(), w, httptest.NewRequest(http.MethodGet, "/", nil), u.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

// Changing the password: busy checking the current one, or hashing the new
// one, shows the throttled message and changes nothing.
func TestChangePasswordBusyShowsThrottled(t *testing.T) {
	s, st, u := busyServer(t)
	h := s.d.Sessions.Middleware(session.RequireUser(http.HandlerFunc(s.changePassword)))
	form := url.Values{"current": {busyPW}, "password": {"a brand new passphrase"}, "confirm": {"a brand new passphrase"}}

	r := postForm("/account/password", form)
	r.AddCookie(signedIn(t, s, u))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertThrottledPage(t, w)

	s.verifyPassword = password.VerifyCtx // the current password checks; hashing the new one is busy
	r = postForm("/account/password", form)
	r.AddCookie(signedIn(t, s, u))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertThrottledPage(t, w)

	got, err := st.GetUser(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != u.PasswordHash {
		t.Fatal("password changed while busy")
	}
}

// Choosing a password from a reset link while busy shows the throttled
// message and leaves the link usable.
func TestResetSetBusyShowsThrottled(t *testing.T) {
	s, st, u := busyServer(t)
	link, err := IssueResetLink(context.Background(), st, s.d.Cfg.Issuer(), u.ID, model.ResetPurposeReset)
	if err != nil {
		t.Fatal(err)
	}
	token := link[strings.LastIndex(link, "/")+1:]
	r := postForm("/reset/"+token, url.Values{"password": {"a brand new passphrase"}, "confirm": {"a brand new passphrase"}})
	r.SetPathValue("token", token)
	w := httptest.NewRecorder()
	s.resetSet(w, r)
	assertThrottledPage(t, w)
	if _, err := st.PeekResetToken(context.Background(), secrets.HashToken(token)); err != nil {
		t.Fatalf("link used up while busy: %v", err)
	}
}
