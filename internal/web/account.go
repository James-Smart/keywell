package web

import (
	"net/http"

	"latch/internal/audit"
	"latch/internal/password"
	"latch/internal/session"
)

const (
	msgCurrentMismatch = "Your current password didn't match."
	msgPasswordChanged = "Password changed."
)

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
	phc, err := password.Hash(pw)
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
