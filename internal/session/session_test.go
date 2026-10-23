package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"latch/internal/model"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/store/storetest"
)

// harness wires a Manager to a test store with a settable clock that starts
// at the real current time (the store hides sessions whose expires_at is
// before the real clock).
type harness struct {
	st  *store.Store
	m   *session.Manager
	now time.Time
}

func newHarness(t *testing.T, idle, absolute time.Duration) *harness {
	t.Helper()
	h := &harness{st: storetest.OpenTest(t), now: time.Now().UTC()}
	h.m = session.NewManager(h.st, idle, absolute, true)
	h.m.SetClock(func() time.Time { return h.now })
	return h
}

func (h *harness) user(t *testing.T, email string) *model.User {
	t.Helper()
	u := &model.User{Name: "Test", Email: email, IsActive: true}
	if err := h.st.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// start begins a session for u and returns it with its cookie.
func (h *harness) start(t *testing.T, u *model.User, totpPassed bool) (*model.Session, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("User-Agent", "test-agent")
	sess, err := h.m.Start(context.Background(), rec, req, u.ID, totpPassed)
	if err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(rec.Result())
	if c == nil {
		t.Fatal("Start set no session cookie")
	}
	return sess, c
}

// visit sends one request carrying c through the middleware and reports the
// user the handler saw in its context.
func (h *harness) visit(t *testing.T, c *http.Cookie) (*model.User, *http.Response) {
	t.Helper()
	var seen *model.User
	handler := h.m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, u, ok := session.FromContext(r.Context()); ok {
			seen = u
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	handler.ServeHTTP(rec, req)
	return seen, rec.Result()
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

func assertCleared(t *testing.T, resp *http.Response) {
	t.Helper()
	c := sessionCookie(resp)
	if c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("session cookie not cleared: %+v", c)
	}
}

func assertGone(t *testing.T, st *store.Store, id string) {
	t.Helper()
	if _, err := st.GetSession(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session still present: err=%v", err)
	}
}

func TestStartLoadsUserAndExtends(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "start@example.org")
	t0 := h.now
	sess, c := h.start(t, u, true)

	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != 86400 {
		t.Fatalf("cookie attributes: %+v", c)
	}
	if c.Value != sess.ID || len(sess.ID) != 43 {
		t.Fatalf("cookie value %q, session id %q", c.Value, sess.ID)
	}
	if sess.IP != "192.0.2.10" || sess.UserAgent != "test-agent" || !sess.TOTPPassed {
		t.Fatalf("session fields: %+v", sess)
	}
	if !sess.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("initial expiry %v, want %v", sess.ExpiresAt, t0.Add(time.Hour))
	}

	h.now = t0.Add(2 * time.Minute)
	seen, _ := h.visit(t, c)
	if seen == nil || seen.ID != u.ID {
		t.Fatalf("user in context: %+v", seen)
	}
	got, err := h.st.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeenAt.Equal(h.now) || !got.ExpiresAt.Equal(h.now.Add(time.Hour)) {
		t.Fatalf("after touch: last seen %v, expires %v", got.LastSeenAt, got.ExpiresAt)
	}

	// Within a minute of the last touch nothing is written.
	h.now = t0.Add(2*time.Minute + 30*time.Second)
	if seen, _ := h.visit(t, c); seen == nil {
		t.Fatal("user missing on second visit")
	}
	again, err := h.st.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.LastSeenAt.Equal(got.LastSeenAt) || !again.ExpiresAt.Equal(got.ExpiresAt) {
		t.Fatalf("touched again within a minute: %+v", again)
	}
}

func TestAbsoluteCapRespected(t *testing.T) {
	h := newHarness(t, time.Hour, 3*time.Hour)
	u := h.user(t, "cap@example.org")
	t0 := h.now
	sess, c := h.start(t, u, true)

	// Keep the session busy so the idle timeout never ends it.
	for _, at := range []time.Duration{50 * time.Minute, 100 * time.Minute, 150 * time.Minute} {
		h.now = t0.Add(at)
		if seen, _ := h.visit(t, c); seen == nil {
			t.Fatalf("user missing at +%v", at)
		}
	}
	got, err := h.st.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := t0.Add(3 * time.Hour); !got.ExpiresAt.Equal(want) {
		t.Fatalf("expiry %v, want capped at %v", got.ExpiresAt, want)
	}

	h.now = sess.CreatedAt.Add(3*time.Hour + time.Second)
	seen, resp := h.visit(t, c)
	if seen != nil {
		t.Fatal("user still loaded after the absolute lifetime")
	}
	assertCleared(t, resp)
	assertGone(t, h.st, sess.ID)
}

func TestInactiveUserDropped(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "inactive@example.org")
	sess, c := h.start(t, u, true)

	u.IsActive = false
	if err := h.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	seen, resp := h.visit(t, c)
	if seen != nil {
		t.Fatal("inactive user loaded into context")
	}
	assertCleared(t, resp)
	assertGone(t, h.st, sess.ID)
}

// A service account cannot use the login pages, so a session it somehow
// holds (say the account was a member's, turned into a service account) is
// ended, not loaded.
func TestServiceAccountSessionDropped(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "door@example.org")
	sess, c := h.start(t, u, true)

	u.Type = model.UserTypeService
	if err := h.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	seen, resp := h.visit(t, c)
	if seen != nil {
		t.Fatal("service account loaded into context")
	}
	assertCleared(t, resp)
	assertGone(t, h.st, sess.ID)
}

func TestEndClearsCookie(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "end@example.org")
	sess, c := h.start(t, u, true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(c)
	if err := h.m.End(context.Background(), rec, req); err != nil {
		t.Fatal(err)
	}
	assertCleared(t, rec.Result())
	assertGone(t, h.st, sess.ID)
	if seen, _ := h.visit(t, c); seen != nil {
		t.Fatal("ended session still loads a user")
	}
}

func TestStartReplacesExistingSession(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "replace@example.org")
	old, c := h.start(t, u, true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.AddCookie(c)
	fresh, err := h.m.Start(context.Background(), rec, req, u.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ID == old.ID {
		t.Fatal("session ID reused")
	}
	assertGone(t, h.st, old.ID)
}

func TestRequireUser(t *testing.T) {
	h := newHarness(t, time.Hour, 24*time.Hour)
	u := h.user(t, "require@example.org")
	_, full := h.start(t, u, true)
	// u is not enrolled, so this session is waiting for enrolment (a group
	// requires it).
	_, enrolling := h.start(t, u, false)
	enrolled := h.user(t, "enrolled@example.org")
	confirmed := h.now
	if err := h.st.SetTOTP(context.Background(), enrolled.ID, []byte("sealed"), &confirmed); err != nil {
		t.Fatal(err)
	}
	_, awaitingCode := h.start(t, enrolled, false)

	protected := h.m.Middleware(session.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	cases := []struct {
		name     string
		cookie   *http.Cookie
		target   string
		status   int
		location string
	}{
		{"no session", nil, "/account?x=1", http.StatusSeeOther, "/login?next=%2Faccount%3Fx%3D1"},
		{"complete session", full, "/account", http.StatusOK, ""},
		{"awaiting code", awaitingCode, "/account?x=1", http.StatusSeeOther, "/login/totp?next=%2Faccount%3Fx%3D1"},
		{"awaiting enrolment", enrolling, "/account?x=1", http.StatusSeeOther, "/account/totp?required=1&next=%2Faccount%3Fx%3D1"},
		{"awaiting code on an allowed page", awaitingCode, "/account/totp", http.StatusOK, ""},
		{"awaiting enrolment on an allowed page", enrolling, "/account/totp", http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			protected.ServeHTTP(rec, req)
			if rec.Code != tc.status || rec.Header().Get("Location") != tc.location {
				t.Fatalf("status %d location %q, want %d %q", rec.Code, rec.Header().Get("Location"), tc.status, tc.location)
			}
		})
	}
}

func TestAllowIncomplete(t *testing.T) {
	for path, want := range map[string]bool{
		"/login/totp":         true,
		"/logout":             true,
		"/logout/done":        true,
		"/account/totp":       true,
		"/account/totp/codes": true,
		"/account/password":   false,
		"/":                   false,
		"/login":              false,
	} {
		if got := session.AllowIncomplete(path); got != want {
			t.Errorf("AllowIncomplete(%q) = %v, want %v", path, got, want)
		}
	}
}
