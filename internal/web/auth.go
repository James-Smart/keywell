package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"keywell/internal/audit"
	"keywell/internal/model"
	"keywell/internal/password"
	"keywell/internal/secrets"
	"keywell/internal/session"
	"keywell/internal/store"
)

// Every rejected sign-in shows msgNoMatch, whatever the reason, so the page
// never reveals whether an account exists or is active.
const (
	msgNoMatch   = "That email and password didn't match."
	msgThrottled = "Too many attempts. Try again in a few minutes."
)

// loginData is what login.html shows. Next and App are carried through the
// form unchanged; AppName is set when App is the slug of an application.
type loginData struct {
	Email, Next, App, AppName string
}

// loginPage shows the sign-in form. ?next= is where to go afterwards and
// ?app=<slug> names the application the member is signing in to.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderLogin(w, r, "", loginData{Next: q.Get("next"), App: q.Get("app")})
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, message string, d loginData) {
	if d.App != "" {
		app, err := s.d.Store.GetApplicationBySlug(r.Context(), d.App)
		switch {
		case err == nil:
			d.AppName = app.Name
		case !errors.Is(err, store.ErrNotFound):
			s.d.Log.ErrorContext(r.Context(), "login: look up application", "error", err)
		}
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "login", Page{Title: "Sign in", Error: message, Data: d})
}

// login checks the email and password and starts a session. Every failure,
// throttling included, re-renders the form with status 200.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	typed := strings.TrimSpace(r.PostFormValue("email"))
	email := strings.ToLower(typed)
	pw := r.PostFormValue("password")
	form := loginData{Email: typed, Next: r.PostFormValue("next"), App: r.PostFormValue("app")}

	// Each attempt reserves a place in both limits before the password is
	// checked, so a concurrent burst cannot exceed them; a successful
	// sign-in gives its places back, so only failures use up the budget and
	// members sharing one address (the space's NAT) can all sign in.
	ipKey, acctKey := "ip:"+ClientIP(r), loginAccountKey(email)
	if !s.d.Limits.LoginIP.Allow(ipKey) {
		s.renderLogin(w, r, msgThrottled, form)
		return
	}
	if !s.d.Limits.LoginAccount.Allow(acctKey) {
		s.d.Limits.LoginIP.Forgive(ipKey) // turned away unchecked: not a guess
		s.renderLogin(w, r, msgThrottled, form)
		return
	}

	user, ok, err := s.authenticate(ctx, email, pw)
	if errors.Is(err, password.ErrBusy) {
		// Too busy to check the password: not a guess, so neither limit
		// keeps this attempt's place.
		s.d.Limits.LoginIP.Forgive(ipKey)
		s.d.Limits.LoginAccount.Forgive(acctKey)
		s.renderLogin(w, r, msgThrottled, form)
		return
	}
	if err != nil {
		s.serverError(w, r, "login: look up user", err)
		return
	}
	if !ok {
		if user != nil {
			s.auditUser(ctx, audit.LoginFailure, user.ID, "Sign-in failed", nil)
		} else {
			s.auditUser(ctx, audit.LoginFailure, "", "Sign-in failed for an unknown email",
				map[string]any{"email_hash": secrets.HashToken(email)})
		}
		s.renderLogin(w, r, msgNoMatch, form)
		return
	}

	// Give back the IP's place; the account's failures are over, so Reset
	// (which also drops this attempt's place) rather than Forgive.
	s.d.Limits.LoginIP.Forgive(ipKey)
	s.d.Limits.LoginAccount.Reset(acctKey)
	if password.IsLegacy(storedHash(user)) {
		s.upgradeHash(ctx, user, pw)
	}
	due, err := s.secondFactorDue(ctx, user)
	if err != nil {
		s.serverError(w, r, "login: list groups", err)
		return
	}
	sess, err := s.d.Sessions.Start(ctx, w, r, user.ID, !due)
	if err != nil {
		s.serverError(w, r, "login: start session", err)
		return
	}
	if err := s.d.Store.TouchLastLogin(ctx, user.ID, sess.CreatedAt); err != nil {
		s.d.Log.ErrorContext(ctx, "login: record last login", "user_id", user.ID, "error", err)
	}
	if due {
		// Recorded now so a correct password is in the log even if the
		// second step never completes; that step records its own success.
		s.auditUser(ctx, audit.LoginSuccess, user.ID, "Password accepted, second step due",
			map[string]any{"second_factor": "pending"})
	} else {
		s.auditUser(ctx, audit.LoginSuccess, user.ID, "Signed in", nil)
	}
	s.afterLogin(w, r, user, sess)
}

// authenticate reports whether pw is the password of the active member
// with the (normalised) email. It returns the user the email names even
// when ok is false, and nil when it names none. A password is always
// verified, the dummy hash standing in for a missing one, so timing does
// not reveal whether the account exists. err is reserved for store
// failures and password.ErrBusy (no hashing slot came free).
func (s *Server) authenticate(ctx context.Context, email, pw string) (user *model.User, ok bool, err error) {
	hash := s.dummyHash
	user, err = s.d.Store.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		user = nil
	case err != nil:
		return nil, false, err
	default:
		hash = storedHash(user)
	}
	match, err := s.verifyPassword(ctx, pw, hash)
	if errors.Is(err, password.ErrBusy) {
		return nil, false, err
	}
	if err != nil {
		// The user has no hash that can be checked (the dummy hash always
		// can): spend the time a real check takes.
		if _, err := s.verifyPassword(ctx, pw, s.dummyHash); errors.Is(err, password.ErrBusy) {
			return nil, false, err
		}
		if !errors.Is(err, password.ErrUnusable) {
			s.d.Log.ErrorContext(ctx, "login: stored password hash cannot be checked", "user_id", user.ID, "error", err)
		}
	}
	// A service account cannot use the login pages (spec §4), whatever its
	// password; that is decided only after the check, so it takes as long.
	if user == nil || !match || !user.IsActive || user.Type != model.UserTypeMember {
		return user, false, nil
	}
	return user, true, nil
}

// loginAccountKey is the key in Limiters.LoginAccount of the account with
// email.
func loginAccountKey(email string) string {
	return "acct:" + strings.ToLower(strings.TrimSpace(email))
}

// checkCurrentPassword reports whether pw is the signed-in user's password,
// for pages that ask for it again. The check draws on the account's
// sign-in budget (Limiters.LoginAccount, shared with the sign-in form) as a
// sign-in does: a wrong password uses up a place, a right one clears the
// count. Once the budget is spent the password is not checked and
// throttled is true; so it is, without using up a place, when the server
// is too busy to check it.
func (s *Server) checkCurrentPassword(ctx context.Context, user *model.User, pw string) (ok, throttled bool) {
	key := loginAccountKey(user.Email)
	if !s.d.Limits.LoginAccount.Allow(key) {
		return false, true
	}
	match, err := s.passwordMatches(ctx, user, pw)
	if err != nil { // password.ErrBusy
		s.d.Limits.LoginAccount.Forgive(key)
		return false, true
	}
	if !match {
		return false, false
	}
	s.d.Limits.LoginAccount.Reset(key)
	return true, false
}

// passwordMatches reports whether pw is the user's password. A hash that
// cannot be checked counts as no match. err is password.ErrBusy when no
// hashing slot came free, and otherwise nil.
func (s *Server) passwordMatches(ctx context.Context, user *model.User, pw string) (bool, error) {
	match, err := s.verifyPassword(ctx, pw, storedHash(user))
	switch {
	case errors.Is(err, password.ErrBusy):
		return false, err
	case err != nil && !errors.Is(err, password.ErrUnusable):
		s.d.Log.ErrorContext(ctx, "stored password hash cannot be checked", "user_id", user.ID, "error", err)
	}
	return match, nil
}

// storedHash is the hash a user's password is checked against: the native
// one, or the legacy one carried over from Authentik until it is upgraded.
func storedHash(u *model.User) string {
	if u.PasswordHash != "" {
		return u.PasswordHash
	}
	return u.LegacyPasswordHash
}

// upgradeHash replaces a legacy hash with a native one now that the password
// is known. A failure is only logged: the legacy hash still works and the
// upgrade is tried again at the next sign-in.
func (s *Server) upgradeHash(ctx context.Context, u *model.User, pw string) {
	hash, err := s.hashPassword(ctx, pw)
	if err == nil {
		err = s.d.Store.SetPassword(ctx, u.ID, hash)
	}
	if err != nil {
		s.d.Log.ErrorContext(ctx, "login: upgrade legacy password hash", "user_id", u.ID, "error", err)
		return
	}
	u.PasswordHash, u.LegacyPasswordHash = hash, ""
}

// secondFactorDue reports whether a new session for user must wait for a
// second step: their TOTP code, or enrolling in TOTP because one of their
// groups requires it.
func (s *Server) secondFactorDue(ctx context.Context, user *model.User) (bool, error) {
	if user.TOTPEnrolled() {
		return true, nil
	}
	return s.groupRequiresTOTP(ctx, user.ID)
}

// groupRequiresTOTP reports whether any of the user's groups requires TOTP.
func (s *Server) groupRequiresTOTP(ctx context.Context, userID string) (bool, error) {
	groups, err := s.d.Store.ListGroupsForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(groups, func(g model.Group) bool { return g.RequireTOTP }), nil
}

// afterLogin sends the member on from a newly started session: to the TOTP
// step when they are enrolled, to enrolment when the session is waiting for
// it, otherwise to the form's next (if it is a path on this site).
func (s *Server) afterLogin(w http.ResponseWriter, r *http.Request, user *model.User, sess *model.Session) {
	next := safeNext(r.FormValue("next"))
	switch {
	case sess.TOTPPassed:
		http.Redirect(w, r, next, http.StatusSeeOther)
	case user.TOTPEnrolled():
		http.Redirect(w, r, "/login/totp?next="+url.QueryEscape(next), http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/account/totp?required=1&next="+url.QueryEscape(next), http.StatusSeeOther)
	}
}

// safeNext returns raw when it is a path on this site, else "/". Anything a
// browser could read as another site is refused: a scheme or host, a leading
// "//", any backslash (browsers treat "\" as "/"), and control characters
// (url.Parse rejects those).
func safeNext(raw string) string {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, `\`) {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return raw
}

// logoutPage asks for confirmation, so a link or image on another site
// cannot sign a member out.
func (s *Server) logoutPage(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.Render(w, r, http.StatusOK, "logout", Page{Title: "Sign out"})
}

// logout ends the session, if there is one, and sends the browser to the
// signed-out page.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, user, signedIn := session.FromContext(ctx)
	if err := s.d.Sessions.End(ctx, w, r); err != nil {
		s.serverError(w, r, "logout: end session", err)
		return
	}
	if signedIn {
		s.auditUser(ctx, audit.Logout, user.ID, "Signed out", nil)
	}
	http.Redirect(w, r, "/logout/done", http.StatusSeeOther)
}

func (s *Server) signedOut(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.RenderSignedOut(w, r)
}

// auditUser records action by the user with userID on their own account.
// userID is "" when the user is unknown.
func (s *Server) auditUser(ctx context.Context, action, userID, summary string, detail map[string]any) {
	actorType, actorID := audit.UserActor(userID)
	e := model.AuditEvent{ActorType: actorType, ActorID: actorID, Action: action, Summary: summary, Detail: detail}
	if userID != "" {
		e.TargetType, e.TargetID = "user", userID
	}
	s.d.Audit.Record(ctx, e)
}
