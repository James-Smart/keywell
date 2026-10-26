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

	"keywell/internal/audit"
	"keywell/internal/model"
	"keywell/internal/secrets"
	"keywell/internal/session"
	"keywell/internal/store"
	"keywell/internal/totp"
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

// recoveryCodeRE matches a normalised Keywell recovery code. Anything else
// typed at a code prompt that looks like an imported Authentik token
// (importedRecoveryRE) is tried as one; the rest is treated as a TOTP code.
var recoveryCodeRE = regexp.MustCompile(`^[a-z2-9]{5}-[a-z2-9]{5}$`)

// importedRecoveryRE matches the shape of a recovery code imported from
// Authentik (a static token, 7 to 100 letters and digits). Such a code is
// stored as the hash of the exact token, so it is matched case-sensitively.
// A 6-digit TOTP code is too short to match.
var importedRecoveryRE = regexp.MustCompile(`^[A-Za-z0-9]{7,100}$`)

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
	if !s.codeBudget(w, r, user) {
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
	s.d.Limits.TOTPAccount.Reset(totpLimitKey(user.ID))

	sess.TOTPPassed = true
	if err := s.d.Sessions.Update(ctx, sess); err != nil {
		s.serverError(w, r, "totp step: complete session", err)
		return
	}
	if err := s.d.Store.TouchLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		s.d.Log.ErrorContext(ctx, "totp step: record last login", "user_id", user.ID, "error", err)
	}
	s.auditUser(ctx, audit.LoginSuccess, user.ID, "Signed in", map[string]any{"second_factor": factor})
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
// their unused recovery codes, and uses it up. A TOTP code already used
// (its time step claimed, at sign-in or by the confirmation of the
// enrolment) does not match: no code is accepted twice (RFC 6238 §5.2).
// factor says which kind of code it was taken for: "totp" or "recovery".
func (s *Server) checkCode(ctx context.Context, user *model.User, code string) (factor string, ok bool, err error) {
	imported := strings.TrimSpace(code)
	isImported := importedRecoveryRE.MatchString(imported)
	if rc := totp.NormalizeRecoveryCode(code); recoveryCodeRE.MatchString(rc) {
		ok, err := s.d.Store.ConsumeRecoveryCode(ctx, user.ID, secrets.HashToken(rc))
		if ok || err != nil || !isImported {
			return "recovery", ok, err
		}
		// A 10-character token from a non-default Authentik stage looks like
		// a Keywell code once normalised, so try it as typed too.
		ok, err = s.d.Store.ConsumeRecoveryCode(ctx, user.ID, secrets.HashToken(imported))
		return "recovery", ok, err
	}
	if isImported {
		ok, err := s.d.Store.ConsumeRecoveryCode(ctx, user.ID, secrets.HashToken(imported))
		return "recovery", ok, err
	}
	secret, err := s.openSecret(user.TOTPSecretEnc)
	if err != nil {
		return "", false, err
	}
	step, match := totp.MatchStep(secret, code, s.d.Now())
	if !match {
		return "totp", false, nil
	}
	ok, err = s.d.Store.ClaimTOTPStep(ctx, user.ID, step)
	return "totp", ok, err
}

func totpLimitKey(userID string) string { return "totp:" + userID }

// codeBudget takes a place for one more code in the account's limit
// (Limiters.TOTPAccount) before the code is checked, so once the limit is
// reached no code is checked at all, however many fresh sessions a
// password buys. A correct code resets the limit, so only wrong codes use
// it up. When the limit is reached the session ends and codeBudget returns
// false.
func (s *Server) codeBudget(w http.ResponseWriter, r *http.Request, user *model.User) bool {
	if s.d.Limits.TOTPAccount.Allow(totpLimitKey(user.ID)) {
		return true
	}
	s.endSecondStep(w, r, user, "Signed out: too many wrong codes for this account",
		map[string]any{"reason": "account_throttled"})
	return false
}

// codeFailed counts a wrong code against the session. Below the limit the
// form is shown again; at it the session ends. Only that last failure is
// audited, so guessing cannot grow the audit log.
func (s *Server) codeFailed(w http.ResponseWriter, r *http.Request, sess *model.Session, user *model.User, next string) {
	n, err := s.d.Store.IncrementTOTPFailures(r.Context(), sess.ID)
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
	s.endSecondStep(w, r, user, "Signed out after too many wrong codes", map[string]any{"failures": n})
}

// endSecondStep ends the session after too many wrong codes, audits it as
// LoginTOTPFailure, and sends the browser to sign in again.
func (s *Server) endSecondStep(w http.ResponseWriter, r *http.Request, user *model.User, summary string, detail map[string]any) {
	ctx := r.Context()
	if err := s.d.Sessions.End(ctx, w, r); err != nil {
		s.serverError(w, r, "totp: end session", err)
		return
	}
	s.auditUser(ctx, audit.LoginTOTPFailure, user.ID, summary, detail)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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
//
// Recovery codes from this session's confirmation that have not been shown
// yet come first. That happens when the browser showed another response
// than the confirm's, e.g. to a double-submitted confirm form.
func (s *Server) accountTOTPPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	next := r.URL.Query().Get("next")
	if user.TOTPEnrolled() {
		_, codesJSON, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, "totp page: load enrolment", err)
			return
		}
		if codesJSON != "" {
			http.Redirect(w, r, withNext("/account/totp/codes", next), http.StatusSeeOther)
			return
		}
	}
	s.renderAccountTOTP(w, r, sess, user, "", next)
}

// pendingSecret returns the sealed secret of the session's enrolment while
// it is unconfirmed; ok is false when there is none.
func (s *Server) pendingSecret(ctx context.Context, sessionID string) (sealed []byte, ok bool, err error) {
	sealed, codesJSON, err := s.d.Store.GetTOTPEnrolment(ctx, sessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return sealed, codesJSON == "", nil // with codes, it is confirmed
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
		sealed, pending, err := s.pendingSecret(ctx, sess.ID)
		if err != nil {
			s.serverError(w, r, "totp page: load enrolment", err)
			return
		}
		if pending {
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
	sealed, pending, err := s.pendingSecret(ctx, sess.ID)
	if err != nil {
		s.serverError(w, r, "totp qr: load enrolment", err)
		return
	}
	if !pending {
		http.NotFound(w, r)
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

// confirmTOTP turns TOTP on when code matches the pending secret: in one
// transaction it stores the secret, replaces the recovery codes and keeps
// them to show; then it completes a session that was waiting for this
// enrolment and sends the member to see the codes once. A confirm that
// finds the user already enrolled (a double-submitted form) goes to the TOTP
// page, which shows any codes still waiting.
func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	next := r.PostFormValue("next")
	already := func() { http.Redirect(w, r, withNext("/account/totp", next), http.StatusSeeOther) }
	if user.TOTPEnrolled() {
		already()
		return
	}
	sealed, pending, err := s.pendingSecret(ctx, sess.ID)
	if err != nil {
		s.serverError(w, r, "totp confirm: load enrolment", err)
		return
	}
	if !pending {
		already()
		return
	}
	secret, err := s.openSecret(sealed)
	if err != nil {
		s.serverError(w, r, "totp confirm: open pending secret", err)
		return
	}
	step, match := totp.MatchStep(secret, r.PostFormValue("code"), s.d.Now())
	if !match {
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
	err = s.d.Store.CompleteTOTPEnrolment(ctx, user.ID, sess.ID, sealed, time.Now().UTC(), step, hashes, string(codesJSON))
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		// Another confirm got there first, or the enrolment is gone.
		already()
		return
	}
	if err != nil {
		s.serverError(w, r, "totp confirm: complete enrolment", err)
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
// enrolment holding them is deleted before the page is written. Codes left
// from an enrolment that has since been cleared are not shown.
func (s *Server) totpCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, user, ok := s.enrolmentSession(w, r)
	if !ok {
		return
	}
	_, codesJSON, err := s.d.Store.GetTOTPEnrolment(ctx, sess.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (codesJSON == "" || !user.TOTPEnrolled())) {
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
	// The password is checked first, against the account's sign-in budget,
	// and the code only after it matches (so a recovery code is used up, and
	// the account's code limit spent, only then); the one failure message
	// tells a guesser nothing about either.
	pwOK, throttled := s.checkCurrentPassword(ctx, user, r.PostFormValue("password"))
	if throttled {
		s.renderAccountTOTP(w, r, sess, user, msgThrottled, "")
		return
	}
	if !pwOK {
		s.renderAccountTOTP(w, r, sess, user, msgDisableMismatch, "")
		return
	}
	if !s.codeBudget(w, r, user) {
		return
	}
	_, match, err := s.checkCode(ctx, user, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, "totp disable: check code", err)
		return
	}
	if !match {
		s.renderAccountTOTP(w, r, sess, user, msgDisableMismatch, "")
		return
	}
	s.d.Limits.TOTPAccount.Reset(totpLimitKey(user.ID))
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
