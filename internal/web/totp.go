package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/totp"
)

const (
	msgCodeMismatch    = "That code didn't match. Check your phone's clock and try again."
	msgDisableMismatch = "Your password or code didn't match."
	msgGroupRequires   = "Your group requires two-step sign in."
	msgEnrolRequired   = "Your group requires two-step sign in. Set it up now."
)

const (
	// maxTOTPFailures wrong codes at the TOTP step end the session. The
	// login limiter cannot cover this step: the correct password that
	// started the session reset it.
	maxTOTPFailures   = 5
	recoveryCodeCount = 10
	qrSize            = 256
)

// recoveryCodeRE matches a normalised recovery code; anything else typed at
// a code prompt is treated as a six-digit TOTP code.
var recoveryCodeRE = regexp.MustCompile(`^[a-z2-9]{5}-[a-z2-9]{5}$`)

// loginTOTPData is what login_totp.html shows.
type loginTOTPData struct{ Next string }

// accountTOTPData is what account_totp.html shows. Exactly one of
// EnrolledOn and ManualKey is set when the member is enrolled or has an
// enrolment pending; neither when they can start one.
type accountTOTPData struct {
	Next          string
	EnrolledOn    string // date TOTP was confirmed, "" when not enrolled
	GroupRequires bool   // a group requires TOTP, so it cannot be turned off
	ManualKey     string // pending secret in groups of four, "" when none
}

// codesData is what account_totp_codes.html shows.
type codesData struct {
	Codes []string
	Next  string
}

// loginTOTPPage asks a session waiting for its TOTP code for it.
func (s *Server) loginTOTPPage(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if _, _, ok := s.awaitingCode(w, r, next); ok {
		s.renderLoginTOTP(w, r, "", next)
	}
}

func (s *Server) renderLoginTOTP(w http.ResponseWriter, r *http.Request, message, next string) {
	s.d.Renderer.Render(w, r, http.StatusOK, "login_totp",
		Page{Title: "Two-step sign in", Error: message, Data: loginTOTPData{Next: safeNext(next)}})
}

// loginTOTP checks a TOTP or recovery code and completes the session's
// sign-in. The maxTOTPFailures-th wrong code ends the session.
func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	next := r.PostFormValue("next")
	sess, user, ok := s.awaitingCode(w, r, next)
	if !ok {
		return
	}
	factor, passed, err := s.checkCode(ctx, user, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, "totp step: check code", err)
		return
	}
	if !passed {
		s.codeFailed(w, r, sess, user, next)
		return
	}

	sess.TOTPPassed = true
	if err := s.d.Sessions.Update(ctx, sess); err != nil {
		s.serverError(w, r, "totp step: complete session", err)
		return
	}
	if err := s.d.Store.TouchLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		s.d.Log.ErrorContext(ctx, "totp step: record last login", "user_id", user.ID, "error", err)
	}
	s.auditUser(ctx, audit.LoginSuccess, user.ID, "Signed in", map[string]any{"second_factor": factor})
	if factor == "recovery" {
		s.noteLastRecoveryCode(ctx, user.ID)
	}
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

// awaitingCode returns the request's session and user when the session is
// waiting for a TOTP code. Otherwise it redirects and returns ok false:
// without a session to sign in, with a complete session on to next, and
// with a session waiting for enrolment to enrolment.
func (s *Server) awaitingCode(w http.ResponseWriter, r *http.Request, next string) (*model.Session, *model.User, bool) {
	sess, user, ok := session.FromContext(r.Context())
	next = safeNext(next)
	switch {
	case !ok:
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
	case sess.TOTPPassed:
		http.Redirect(w, r, next, http.StatusSeeOther)
	case !user.TOTPEnrolled():
		http.Redirect(w, r, "/account/totp?required=1&next="+url.QueryEscape(next), http.StatusSeeOther)
	default:
		return sess, user, true
	}
	return nil, nil, false
}

// checkCode reports whether code is the user's current TOTP code or one of
// their unused recovery codes, which it uses up. factor says which kind of
// code it was taken for: "totp" or "recovery".
func (s *Server) checkCode(ctx context.Context, user *model.User, code string) (factor string, ok bool, err error) {
	if rc := totp.NormalizeRecoveryCode(code); recoveryCodeRE.MatchString(rc) {
		ok, err := s.d.Store.ConsumeRecoveryCode(ctx, user.ID, secrets.HashToken(rc))
		return "recovery", ok, err
	}
	secret, err := s.openSecret(user.TOTPSecretEnc)
	if err != nil {
		return "", false, err
	}
	return "totp", totp.Validate(secret, code), nil
}

// codeFailed counts a wrong code against the session. Below the limit the
// form is shown again; at it the session ends. Only that last failure is
// audited, so guessing cannot grow the audit log.
func (s *Server) codeFailed(w http.ResponseWriter, r *http.Request, sess *model.Session, user *model.User, next string) {
	ctx := r.Context()
	n, err := s.d.Store.IncrementTOTPFailures(ctx, sess.ID)
	if errors.Is(err, store.ErrNotFound) { // ended by a concurrent request
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, r, "totp step: count failure", err)
		return
	}
	if n < maxTOTPFailures {
		s.renderLoginTOTP(w, r, msgCodeMismatch, next)
		return
	}
	if err := s.d.Sessions.End(ctx, w, r); err != nil {
		s.serverError(w, r, "totp step: end session", err)
		return
	}
	s.auditUser(ctx, audit.LoginTOTPFailure, user.ID, "Signed out after too many wrong codes",
		map[string]any{"failures": n})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// noteLastRecoveryCode logs when a member has used their last recovery code.
func (s *Server) noteLastRecoveryCode(ctx context.Context, userID string) {
	n, err := s.d.Store.CountUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		s.d.Log.ErrorContext(ctx, "totp step: count recovery codes", "user_id", userID, "error", err)
		return
	}
	if n == 0 {
		s.d.Log.InfoContext(ctx, "totp step: last recovery code used", "user_id", userID)
	}
}

// openSecret unseals a stored TOTP secret.
func (s *Server) openSecret(sealed []byte) (string, error) {
	plain, err := s.d.Enc.Open(sealed)
	if err != nil {
		return "", fmt.Errorf("open totp secret: %w", err)
	}
	return string(plain), nil
}

// enrolmentSession returns the session and user for the /account/totp
// pages, which RequireUser opens to a session waiting for enrolment
// (AllowIncomplete). A session waiting for its code is sent to the TOTP step
// instead: these pages must not stand in for it.
func (s *Server) enrolmentSession(w http.ResponseWriter, r *http.Request) (*model.Session, *model.User, bool) {
	sess, user, _ := session.FromContext(r.Context())
	if !sess.TOTPPassed && user.TOTPEnrolled() {
		http.Redirect(w, r, "/login/totp?next="+url.QueryEscape("/account/totp"), http.StatusSeeOther)
		return nil, nil, false
	}
	return sess, user, true
}

// withNext returns path with next as its query, or path alone when next is "".
func withNext(path, next string) string {
	if next == "" {
		return path
	}
	return path + "?next=" + url.QueryEscape(next)
}

// accountTOTPPage shows whether TOTP is on, with the form to turn it off;
// otherwise the pending enrolment (QR code, key, confirm form) or the form
// to start one.
func (s *Server) accountTOTPPage(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := s.enrolmentSession(w, r)
	if ok {
		s.renderAccountTOTP(w, r, sess, user, "", r.URL.Query().Get("next"))
	}
}

func (s *Server) renderAccountTOTP(w http.ResponseWriter, r *http.Request, sess *model.Session, user *model.User, message, next string) {
	ctx := r.Context()
	d := accountTOTPData{Next: next}
	if user.TOTPEnrolled() {
		d.EnrolledOn = user.TOTPConfirmedAt.Format("2 January 2006")
		required, err := s.groupRequiresTOTP(ctx, user.ID)
		if err != nil {
			s.serverError(w, r, "totp page: list groups", err)
			return
		}
		d.GroupRequires = required
	} else {
		sealed, _, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			s.serverError(w, r, "totp page: load enrolment", err)
			return
		default:
			secret, err := s.openSecret(sealed)
			if err != nil {
				s.serverError(w, r, "totp page: open pending secret", err)
				return
			}
			d.ManualKey = spacedKey(secret)
		}
	}
	p := Page{Title: "Two-step sign in", Error: message, Data: d}
	if !sess.TOTPPassed { // waiting for this enrolment
		p.Notice = msgEnrolRequired
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "account_totp", p)
}

// spacedKey writes a base32 key in groups of four, which is easier to type.
func spacedKey(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(key[i:min(i+4, len(key))])
	}
	return b.String()
}

// beginTOTP starts an enrolment for the session with a new secret, replacing
// any pending one, and shows it on the TOTP page.
func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	next := r.PostFormValue("next")
	if user.TOTPEnrolled() {
		http.Redirect(w, r, withNext("/account/totp", next), http.StatusSeeOther)
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		s.serverError(w, r, "totp begin: generate secret", err)
		return
	}
	sealed, err := s.d.Enc.Seal([]byte(secret))
	if err != nil {
		s.serverError(w, r, "totp begin: seal secret", err)
		return
	}
	if err := s.d.Store.PutTOTPEnrolment(ctx, sess.ID, sealed); err != nil {
		s.serverError(w, r, "totp begin: store enrolment", err)
		return
	}
	http.Redirect(w, r, withNext("/account/totp", next), http.StatusSeeOther)
}

// totpQR serves the QR code of the session's pending secret, and 404 when
// nothing is pending.
func (s *Server) totpQR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	if user.TOTPEnrolled() {
		http.NotFound(w, r)
		return
	}
	sealed, _, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "totp qr: load enrolment", err)
		return
	}
	secret, err := s.openSecret(sealed)
	if err != nil {
		s.serverError(w, r, "totp qr: open pending secret", err)
		return
	}
	png, err := totp.QRPNG(totp.ProvisioningURI(secret, s.d.Cfg.Branding.Name, user.Email), qrSize)
	if err != nil {
		s.serverError(w, r, "totp qr: render", err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// confirmTOTP turns TOTP on when code matches the pending secret: it stores
// the secret, replaces the recovery codes, completes a session that was
// waiting for this enrolment, and sends the member to see the codes once.
func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	next := r.PostFormValue("next")
	if user.TOTPEnrolled() {
		http.Redirect(w, r, withNext("/account/totp", next), http.StatusSeeOther)
		return
	}
	sealed, _, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, withNext("/account/totp", next), http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, r, "totp confirm: load enrolment", err)
		return
	}
	secret, err := s.openSecret(sealed)
	if err != nil {
		s.serverError(w, r, "totp confirm: open pending secret", err)
		return
	}
	if !totp.Validate(secret, r.PostFormValue("code")) {
		s.renderAccountTOTP(w, r, sess, user, msgCodeMismatch, next)
		return
	}

	codes, err := totp.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		s.serverError(w, r, "totp confirm: generate recovery codes", err)
		return
	}
	codesJSON, err := json.Marshal(codes)
	if err != nil {
		s.serverError(w, r, "totp confirm: encode recovery codes", err)
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = secrets.HashToken(c)
	}
	now := time.Now().UTC()
	if err := s.d.Store.SetTOTP(ctx, user.ID, sealed, &now); err != nil {
		s.serverError(w, r, "totp confirm: store secret", err)
		return
	}
	if err := s.d.Store.ReplaceRecoveryCodes(ctx, user.ID, hashes); err != nil {
		s.serverError(w, r, "totp confirm: store recovery codes", err)
		return
	}
	if err := s.d.Store.SetTOTPEnrolmentCodes(ctx, sess.ID, string(codesJSON)); err != nil {
		s.serverError(w, r, "totp confirm: keep codes to show", err)
		return
	}
	if !sess.TOTPPassed {
		sess.TOTPPassed = true
		if err := s.d.Sessions.Update(ctx, sess); err != nil {
			s.serverError(w, r, "totp confirm: complete session", err)
			return
		}
	}
	s.auditUser(ctx, audit.TOTPEnrolled, user.ID, "Turned on two-step sign in", nil)
	http.Redirect(w, r, withNext("/account/totp/codes", next), http.StatusSeeOther)
}

// totpCodes shows the recovery codes made at confirmation, once: the
// enrolment holding them is deleted before the page is written.
func (s *Server) totpCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, _, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	_, codesJSON, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && codesJSON == "") {
		http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, r, "totp codes: load enrolment", err)
		return
	}
	var codes []string
	if err := json.Unmarshal([]byte(codesJSON), &codes); err != nil {
		s.serverError(w, r, "totp codes: decode", err)
		return
	}
	if err := s.d.Store.DeleteTOTPEnrolment(ctx, sess.ID); err != nil {
		s.serverError(w, r, "totp codes: delete enrolment", err)
		return
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "account_totp_codes", Page{
		Title: "Your recovery codes",
		Data:  codesData{Codes: codes, Next: safeNext(r.URL.Query().Get("next"))},
	})
}

// disableTOTP turns TOTP off given the current password and a code (from
// the app, or a recovery code), unless one of the member's groups requires
// it.
func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	if !user.TOTPEnrolled() {
		http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
		return
	}
	required, err := s.groupRequiresTOTP(ctx, user.ID)
	if err != nil {
		s.serverError(w, r, "totp disable: list groups", err)
		return
	}
	if required {
		s.renderAccountTOTP(w, r, sess, user, msgGroupRequires, "")
		return
	}
	match, err := s.passwordAndCodeMatch(ctx, user, r.PostFormValue("password"), r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, "totp disable: check password and code", err)
		return
	}
	if !match {
		s.renderAccountTOTP(w, r, sess, user, msgDisableMismatch, "")
		return
	}
	if err := s.d.Store.ClearTOTP(ctx, user.ID); err != nil {
		s.serverError(w, r, "totp disable: clear", err)
		return
	}
	// Drop any recovery codes still waiting to be shown.
	if err := s.d.Store.DeleteTOTPEnrolment(ctx, sess.ID); err != nil {
		s.d.Log.ErrorContext(ctx, "totp disable: delete enrolment", "user_id", user.ID, "error", err)
	}
	s.auditUser(ctx, audit.TOTPDisabled, user.ID, "Turned off two-step sign in", nil)
	http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
}

// passwordAndCodeMatch reports whether pw is the user's password and code
// one of their codes. The password is always checked, and the code only
// after it matches (a recovery code is used up only then), so the one
// failure message tells a guesser nothing about either.
func (s *Server) passwordAndCodeMatch(ctx context.Context, user *model.User, pw, code string) (bool, error) {
	match, err := password.Verify(pw, storedHash(user))
	if err != nil && !errors.Is(err, password.ErrUnusable) {
		s.d.Log.ErrorContext(ctx, "totp disable: stored password hash cannot be checked", "user_id", user.ID, "error", err)
	}
	if !match {
		return false, nil
	}
	_, ok, err := s.checkCode(ctx, user, code)
	return ok, err
}
