package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"latch/internal/audit"
	"latch/internal/mail"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/store"
)

// How long the links IssueResetLink makes can be used.
const (
	ResetTokenTTL  = 1 * time.Hour
	InviteTokenTTL = 7 * 24 * time.Hour
)

// Copy for a new password that cannot be used.
const (
	msgTooCommon       = "That password is too common. Pick something less guessable."
	msgPasswordsDiffer = "Those passwords don't match."
	msgTooShortFormat  = "Use at least %d characters."
)

// resetSetData is what reset_set.html shows.
type resetSetData struct {
	Invite    bool // the link is an invitation, not a reset
	MinLength int
}

// IssueResetLink creates a single-use link with which the user chooses a
// password: a reset (lasting ResetTokenTTL) or an invitation (lasting
// InviteTokenTTL). Only the token's hash is stored; the link is
// issuer + "/reset/" + token.
func IssueResetLink(ctx context.Context, st *store.Store, issuer string, userID string, purpose model.ResetPurpose) (link string, err error) {
	ttl, err := resetTTL(purpose)
	if err != nil {
		return "", err
	}
	token := secrets.RandomToken(32)
	now := time.Now().UTC()
	err = st.CreateResetToken(ctx, &model.ResetToken{
		TokenHash: secrets.HashToken(token),
		UserID:    userID,
		Purpose:   purpose,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return "", err
	}
	return issuer + "/reset/" + token, nil
}

func resetTTL(purpose model.ResetPurpose) (time.Duration, error) {
	switch purpose {
	case model.ResetPurposeReset:
		return ResetTokenTTL, nil
	case model.ResetPurposeInvite:
		return InviteTokenTTL, nil
	}
	return 0, fmt.Errorf("web: unknown reset purpose %q", purpose)
}

// SendReset emails user a link to choose a password, as a reset or an
// invitation by purpose, and records the request.
func (s *Server) SendReset(ctx context.Context, user *model.User, purpose model.ResetPurpose) error {
	link, err := IssueResetLink(ctx, s.d.Store, s.d.Cfg.PublicURL, user.ID, purpose)
	if err != nil {
		return err
	}
	brand := mail.Brand{Name: s.d.Cfg.Branding.Name, SupportText: s.d.Cfg.Branding.SupportText, PublicURL: s.d.Cfg.PublicURL}
	msg, summary := mail.ResetEmail(brand, link, ResetTokenTTL), "Emailed a password reset link"
	if purpose == model.ResetPurposeInvite {
		msg, summary = mail.InviteEmail(brand, link, InviteTokenTTL), "Emailed an invitation"
	}
	msg.To = user.Email
	if err := s.d.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("send %s email: %w", purpose, err)
	}
	s.auditUser(ctx, audit.PasswordResetRequested, user.ID, summary, map[string]any{"purpose": string(purpose)})
	return nil
}

// resetRequestPage asks for the email address to send a reset link to.
func (s *Server) resetRequestPage(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.Render(w, r, http.StatusOK, "reset_request", Page{Title: "Reset your password"})
}

// resetRequest emails a reset link when the address belongs to an active
// user. The page that follows is the same whatever happened (no account,
// an inactive one, throttled, or the email failed), so it does not reveal
// which addresses have accounts.
func (s *Server) resetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	if email == "" {
		s.resetRequestPage(w, r)
		return
	}
	sent := func() {
		s.d.Renderer.Render(w, r, http.StatusOK, "reset_sent", Page{Title: "Check your email"})
	}
	// Every request counts, whatever its outcome: any of them may cost an
	// email.
	if !s.d.Limits.ResetIP.Allow("ip:"+ClientIP(r)) || !s.d.Limits.ResetAccount.Allow("reset:"+email) {
		sent()
		return
	}
	user, err := s.d.Store.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.serverError(w, r, "reset request: look up user", err)
		return
	case user.IsActive:
		if err := s.SendReset(ctx, user, model.ResetPurposeReset); err != nil {
			s.d.Log.ErrorContext(ctx, "reset request: send link", "user_id", user.ID, "error", err)
		}
	}
	sent()
}

// resetTarget returns the hash of the request's {token} and, when the token
// is live and its user active, the token and user. Otherwise (no such
// token, used, expired, or the user gone or inactive) it shows the expired
// page and ok is false.
func (s *Server) resetTarget(w http.ResponseWriter, r *http.Request) (hash string, tok *model.ResetToken, user *model.User, ok bool) {
	ctx := r.Context()
	hash = secrets.HashToken(r.PathValue("token"))
	tok, err := s.d.Store.PeekResetToken(ctx, hash)
	if err == nil {
		user, err = s.d.Store.GetUser(ctx, tok.UserID)
	}
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && !user.IsActive):
		s.resetExpired(w, r)
	case err != nil:
		s.serverError(w, r, "reset link: look up token", err)
	default:
		return hash, tok, user, true
	}
	return hash, nil, nil, false
}

// resetExpired is the page for a reset or invite link that cannot be used.
func (s *Server) resetExpired(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.Render(w, r, http.StatusOK, "reset_expired", Page{Title: "Link expired"})
}

// resetSetPage shows the form for choosing a password from a link, without
// using the link up.
func (s *Server) resetSetPage(w http.ResponseWriter, r *http.Request) {
	if _, tok, _, ok := s.resetTarget(w, r); ok {
		s.renderResetSet(w, r, tok.Purpose, "")
	}
}

func (s *Server) renderResetSet(w http.ResponseWriter, r *http.Request, purpose model.ResetPurpose, message string) {
	invite := purpose == model.ResetPurposeInvite
	title := "Choose a new password"
	if invite {
		title = "Choose your password"
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "reset_set", Page{Title: title, Error: message,
		Data: resetSetData{Invite: invite, MinLength: s.d.Cfg.Password.MinLength}})
}

// resetSet sets the password from a link, ends the account's sessions and
// refresh tokens, and signs the member in afresh. Only a password the
// policy accepts uses the link up.
func (s *Server) resetSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hash, tok, user, ok := s.resetTarget(w, r)
	if !ok {
		return
	}
	pw := r.PostFormValue("password")
	if msg := s.newPasswordProblem(pw, r.PostFormValue("confirm")); msg != "" {
		s.renderResetSet(w, r, tok.Purpose, msg)
		return
	}
	phc, err := password.Hash(pw)
	if err != nil {
		s.serverError(w, r, "reset: hash password", err)
		return
	}
	_, err = s.d.Store.ConsumeResetToken(ctx, hash)
	if errors.Is(err, store.ErrNotFound) { // used by a concurrent request, or just expired
		s.resetExpired(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "reset: use token", err)
		return
	}
	if err := s.d.Store.SetPassword(ctx, user.ID, phc); err != nil {
		s.serverError(w, r, "reset: set password", err)
		return
	}
	if err := s.d.Store.DeleteSessionsForUser(ctx, user.ID); err != nil {
		s.serverError(w, r, "reset: end sessions", err)
		return
	}
	if err := s.d.Store.RevokeRefreshTokensForUser(ctx, user.ID); err != nil {
		s.serverError(w, r, "reset: revoke refresh tokens", err)
		return
	}
	summary := "Reset password from an emailed link"
	if tok.Purpose == model.ResetPurposeInvite {
		summary = "Chose a password from an invitation"
	}
	s.auditUser(ctx, audit.PasswordResetCompleted, user.ID, summary, map[string]any{"purpose": string(tok.Purpose)})

	due, err := s.secondFactorDue(ctx, user)
	if err != nil {
		s.serverError(w, r, "reset: list groups", err)
		return
	}
	sess, err := s.d.Sessions.Start(ctx, w, r, user.ID, !due)
	if err != nil {
		s.serverError(w, r, "reset: start session", err)
		return
	}
	if err := s.d.Store.TouchLastLogin(ctx, user.ID, sess.CreatedAt); err != nil {
		s.d.Log.ErrorContext(ctx, "reset: record last login", "user_id", user.ID, "error", err)
	}
	s.afterLogin(w, r, user, sess)
}

// newPasswordProblem returns what is wrong with a new password and its
// confirmation, or "" when the policy accepts the password and the two
// match.
func (s *Server) newPasswordProblem(pw, confirm string) string {
	err := password.CheckPolicy(pw, s.d.Cfg.Password.MinLength)
	var short password.ErrTooShort
	switch {
	case errors.As(err, &short):
		return fmt.Sprintf(msgTooShortFormat, short.Min)
	case err != nil: // password.ErrCommon, the only other refusal
		return msgTooCommon
	case pw != confirm:
		return msgPasswordsDiffer
	}
	return ""
}
