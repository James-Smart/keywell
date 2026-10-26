package web

import (
	"errors"
	"net/http"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/password"
	"github.com/James-Smart/keywell/internal/session"
)

const (
	msgCurrentMismatch = "Your current password didn't match."
	msgPasswordChanged = "Password changed."
	msgNameSaved       = "Name saved."
)

// accountData is what account.html shows.
type accountData struct {
	Name, NameError string // the name as typed, and the message beside it
	Email, Username string
	TOTPOn          bool
}

// accountPage shows the member's details: their name to edit, their email
// and username (which admins change), and the ways to their password and
// two-step sign in.
func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	_, user, _ := session.FromContext(r.Context()) // RequireUser: a complete session
	notice := ""
	if r.URL.Query().Get("notice") == "name_saved" {
		notice = msgNameSaved
	}
	s.renderAccount(w, r, http.StatusOK, user, user.Name, "", notice)
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, user *model.User, name, nameError, notice string) {
	s.d.Renderer.Render(w, r, status, "account", Page{Title: "Your account", Notice: notice, Data: accountData{
		Name: name, NameError: nameError, Email: user.Email, Username: user.Username,
		TOTPOn: user.TOTPConfirmedAt != nil,
	}})
}

// saveOwnName changes the member's name and returns to their account page.
func (s *Server) saveOwnName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, user, _ := session.FromContext(ctx) // RequireUser: a complete session
	name := r.PostFormValue("name")
	_, err := s.admin.SetOwnName(ctx, user.ID, name)
	var invalid *admin.ValidationError
	switch {
	case errors.As(err, &invalid):
		s.renderAccount(w, r, http.StatusUnprocessableEntity, user, name, invalid.Fields["name"], "")
	case err != nil:
		s.serverError(w, r, "account: save name", err)
	default:
		http.Redirect(w, r, "/account?notice=name_saved", http.StatusSeeOther)
	}
}

// accountPasswordData is what account_password.html shows.
type accountPasswordData struct{ MinLength int }

// accountPasswordPage shows the form for changing the password.
func (s *Server) accountPasswordPage(w http.ResponseWriter, r *http.Request) {
	s.renderAccountPassword(w, r, "", "")
}

func (s *Server) renderAccountPassword(w http.ResponseWriter, r *http.Request, message, notice string) {
	s.d.Renderer.Render(w, r, http.StatusOK, "account_password", Page{Title: "Change password",
		Error: message, Notice: notice, Data: accountPasswordData{MinLength: s.d.Cfg.Password.MinLength}})
}

// changePassword sets a new password given the current one, then ends the
// account's other sessions and its refresh tokens; this session carries
// on. Wrong current passwords draw on the account's sign-in budget.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, _ := session.FromContext(ctx) // RequireUser: a complete session
	ok, throttled := s.checkCurrentPassword(ctx, user, r.PostFormValue("current"))
	if throttled {
		s.renderAccountPassword(w, r, msgThrottled, "")
		return
	}
	if !ok {
		s.renderAccountPassword(w, r, msgCurrentMismatch, "")
		return
	}
	pw := r.PostFormValue("password")
	if msg := s.newPasswordProblem(pw, r.PostFormValue("confirm")); msg != "" {
		s.renderAccountPassword(w, r, msg, "")
		return
	}
	phc, err := s.hashPassword(ctx, pw)
	if errors.Is(err, password.ErrBusy) {
		s.renderAccountPassword(w, r, msgThrottled, "")
		return
	}
	if err != nil {
		s.serverError(w, r, "change password: hash", err)
		return
	}
	if err := s.d.Store.SetPassword(ctx, user.ID, phc); err != nil {
		s.serverError(w, r, "change password: set", err)
		return
	}
	if err := s.d.Store.DeleteOtherSessions(ctx, user.ID, sess.ID); err != nil {
		s.serverError(w, r, "change password: end other sessions", err)
		return
	}
	if err := s.d.Store.RevokeRefreshTokensForUser(ctx, user.ID); err != nil {
		s.serverError(w, r, "change password: revoke refresh tokens", err)
		return
	}
	s.auditUser(ctx, audit.PasswordChanged, user.ID, "Changed password", nil)
	s.renderAccountPassword(w, r, "", msgPasswordChanged)
}
