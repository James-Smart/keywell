package web

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/session"
	"latch/internal/store"
)

// Admin pages live under /admin and make every change through the admin
// service (s.admin), acting as adminActor(r). They follow one convention:
//
//   - A successful POST redirects (303) with redirectNotice to a page, which
//     shows adminNotice(r): the message adminNotices has for its ?notice=
//     key. An unknown key shows nothing, so no request text is ever echoed.
//   - A failed POST passes the error to s.adminFailed. For a missing record
//     (store.ErrNotFound) it shows the 404 page, and for an unexpected
//     error the 500 page. Otherwise the handler renders its page again
//     directly, keeping what was typed, with the adminFailure: 422 and
//     messages beside the fields for an *admin.ValidationError, 409 and
//     Page.Error for an *admin.RefusedError, 502 and Page.Error for an
//     *admin.EmailError.
//   - An *admin.EmailError is a failure only when sending the email was
//     the whole action, such as a "Send password reset email" button.
//     When the change itself was made and only its email failed (as when
//     CreateMember returns the new member with an *admin.EmailError), the
//     POST succeeded: it redirects with a notice that says the email was
//     not sent, such as added_no_email.
//   - GET pages for a missing record show s.adminNotFound.
//
// Each page sets Page.Section to its sidebar entry, which gives it the
// admin layout.

// adminNotices are the messages shown after a successful change, by the
// key it redirected with.
var adminNotices = map[string]string{
	"saved":           "Changes saved.",
	"invited":         "Member added. We've emailed them an invitation.",
	"added":           "Member added.",
	"added_no_email":  "Member added, but the invitation email couldn't be sent. Check the email settings on the Settings page, then use Send invite email.",
	"invite_sent":     "Invitation emailed.",
	"reset_sent":      "Password reset email sent.",
	"password_set":    "Password set. They've been signed out everywhere.",
	"totp_cleared":    "Two-step sign in cleared.",
	"disabled":        "Account disabled. They've been signed out everywhere.",
	"enabled":         "Account enabled.",
	"signed_out":      "Signed out everywhere.",
	"deleted":         "Deleted.",
	"member_added":    "Added to the group.",
	"member_removed":  "Removed from the group.",
	"token_revoked":   "Token revoked.",
	"test_email_sent": "Test email sent. Check your inbox.",
	"key_rotated":     "New signing key in use. Apps pick it up automatically.",
}

// adminNotice is the message for the request's ?notice= key, or "" when
// the key is not in adminNotices.
func adminNotice(r *http.Request) string {
	return adminNotices[r.URL.Query().Get("notice")]
}

// redirectNotice ends a successful change: a 303 to path (which carries
// no query) with ?notice=key, where key is one of adminNotices.
func redirectNotice(w http.ResponseWriter, r *http.Request, path, key string) {
	http.Redirect(w, r, path+"?notice="+key, http.StatusSeeOther)
}

// msgEmailNotSent is Page.Error when an email the admin asked for was not
// sent. The mailer's error is not shown: only the Settings page's test
// email shows it, as the admin needs it to fix the settings.
const msgEmailNotSent = "The email couldn't be sent. Check the email settings on the Settings page, then try again."

// adminFailure is how a page shows a change that failed: the status to
// render it with, Page.Error, and the messages beside the form's fields.
type adminFailure struct {
	Status  int
	Message string            // Page.Error; "" for a validation error
	Fields  map[string]string // field name -> message; nil unless a validation error
}

// adminFailureFor maps an error from the admin service to what the page
// shows: 422 and Fields for an *admin.ValidationError, 409 and its message
// for an *admin.RefusedError, 502 for an *admin.EmailError, and 404 for
// store.ErrNotFound. ok is false for any other error.
func adminFailureFor(err error) (f adminFailure, ok bool) {
	var (
		invalid *admin.ValidationError
		refused *admin.RefusedError
		email   *admin.EmailError
	)
	switch {
	case errors.As(err, &invalid):
		return adminFailure{Status: http.StatusUnprocessableEntity, Fields: invalid.Fields}, true
	case errors.As(err, &refused):
		return adminFailure{Status: http.StatusConflict, Message: refused.Message}, true
	case errors.As(err, &email):
		return adminFailure{Status: http.StatusBadGateway, Message: msgEmailNotSent}, true
	case errors.Is(err, store.ErrNotFound):
		return adminFailure{Status: http.StatusNotFound}, true
	}
	return adminFailure{}, false
}

// adminFailed handles err, from the admin service, for a failed POST.
// For a missing record it writes the 404 page; for an unexpected error it
// logs it as what and writes the 500 page. ok is then false and the
// handler just returns. Otherwise the handler renders its page again with
// f, keeping what was typed:
//
//	if f, ok := s.adminFailed(w, r, "members: save", err); ok {
//		s.renderMember(w, r, f.Status, Page{Error: f.Message}, form, f.Fields)
//	}
//	return
func (s *Server) adminFailed(w http.ResponseWriter, r *http.Request, what string, err error) (f adminFailure, ok bool) {
	f, ok = adminFailureFor(err)
	switch {
	case !ok:
		s.serverError(w, r, what, err)
		return f, false
	case f.Status == http.StatusNotFound:
		s.adminNotFound(w, r)
		return f, false
	}
	return f, true
}

// adminNotFound writes the 404 page for an admin page whose record does
// not exist, or is of another kind (such as a service account's ID on a
// member page).
func (s *Server) adminNotFound(w http.ResponseWriter, r *http.Request) {
	s.d.Renderer.RenderError(w, r, http.StatusNotFound, "Not found",
		"We couldn't find that. It may have been deleted, or the link may be wrong.")
}

// requireAdmin lets the request through only when the signed-in member is
// in an admin group, and otherwise shows a 403 page. It runs inside
// session.RequireUser, which has already sent anyone without a complete
// session to sign in, and checks the groups afresh on every request.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, user, _ := session.FromContext(r.Context())
		ok, err := s.isAdmin(r.Context(), user.ID)
		if err != nil {
			s.serverError(w, r, "admin: list groups", err)
			return
		}
		if !ok {
			s.d.Renderer.RenderError(w, r, http.StatusForbidden, "Admins only",
				"You need to be in an admin group to use these pages. Ask an existing admin if you think you should be.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAdmin reports whether the user is in any admin group.
func (s *Server) isAdmin(ctx context.Context, userID string) (bool, error) {
	groups, err := s.d.Store.ListGroupsForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(groups, func(g model.Group) bool { return g.IsAdmin }), nil
}

// adminActor is the signed-in admin, as the admin service records them.
func adminActor(r *http.Request) admin.Actor {
	_, user, _ := session.FromContext(r.Context())
	return admin.Actor{Type: model.ActorUser, ID: user.ID}
}

// adminHome sends /admin to the first sidebar entry.
func (s *Server) adminHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/members", http.StatusSeeOther)
}
