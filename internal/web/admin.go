package web

import (
	"context"
	"net/http"
	"slices"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/session"
)

// Admin pages live under /admin and make every change through the admin
// service (s.admin), acting as adminActor(r). They follow one convention:
//
//   - A successful POST redirects (303) with redirectNotice to a page, which
//     shows adminNotice(r): the message adminNotices has for its ?notice=
//     key. An unknown key shows nothing, so no request text is ever echoed.
//   - A failed POST renders the page again directly, with Page.Error (or
//     messages beside the fields) and status 422 for an
//     *admin.ValidationError, 409 for an *admin.RefusedError or 502 for an
//     email that was not sent.
//   - store.ErrNotFound shows the 404 error page.
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
