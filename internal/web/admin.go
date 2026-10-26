package web

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"keywell/internal/admin"
	"keywell/internal/model"
	"keywell/internal/session"
	"keywell/internal/store"
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
//   - An action on a record's page (a small form among its actions) that
//     fails always says so at the top: Page.Error is the adminFailure's
//     pageError, with a summary of its own for a validation error, and
//     the action's own check that fails (such as a mistyped confirmation)
//     uses such a summary too.
//   - So does an add or edit form: Page.Error is the adminFailure's
//     formError, and the handler's own checks of the form (such as
//     metadata that isn't JSON) use msgNotSaved.
//   - An *admin.EmailError is a failure only when sending the email was
//     the whole action, such as a "Send password reset email" button.
//     When the change itself was made and only its email failed (as when
//     CreateMember returns the new member with an *admin.EmailError), the
//     POST succeeded: it redirects with a notice that says the email was
//     not sent, such as added_no_email.
//   - GET pages for a missing record show s.adminNotFound.
//
// Each page sets Page.Section to its sidebar entry, which gives it the
// admin layout. Markup several pages share is in templates/_admin.html,
// with the types below as the data of its partials.

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

// pageError is Page.Error for a page shown again after an action on it
// failed: f's own message (a refusal, an unsent email) or, for a
// validation error, summary. A summary is one line naming the action and
// where to look, such as "The password wasn't set. See Set password
// manually below.": the field's message may sit far down the page,
// inside the action's disclosure, where nobody sees it after the reload.
func (f adminFailure) pageError(summary string) string { return cmp.Or(f.Message, summary) }

// msgNotSaved is Page.Error when an add or edit form is shown again with
// messages beside its fields, which may be far down the page.
const msgNotSaved = "Nothing was saved. Check the highlighted fields below."

// formError is Page.Error for an add or edit form shown again after its
// save failed: f's own message (a refusal) or, for a validation error,
// msgNotSaved.
func (f adminFailure) formError() string { return f.pageError(msgNotSaved) }

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
//
// A session's second step is settled when it starts, but an admin's groups
// can change after that: they may join an admin group that requires
// two-step sign in, or their group may start requiring it. So an admin
// without two-step sign in, any of whose groups requires it, is sent to
// set it up (with the current URL as next, as session.RequireUser does)
// before any admin page.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, user, _ := session.FromContext(r.Context())
		groups, err := s.d.Store.ListGroupsForUser(r.Context(), user.ID)
		if err != nil {
			s.serverError(w, r, "admin: list groups", err)
			return
		}
		if !slices.ContainsFunc(groups, func(g model.Group) bool { return g.IsAdmin }) {
			s.d.Renderer.RenderError(w, r, http.StatusForbidden, "Admins only",
				"You need to be in an admin group to use these pages. Ask an existing admin if you think you should be.")
			return
		}
		if !user.TOTPEnrolled() && slices.ContainsFunc(groups, func(g model.Group) bool { return g.RequireTOTP }) {
			http.Redirect(w, r, "/account/totp?required=1&next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
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

// fieldErrors are the messages shown beside a form's fields, by field
// name: an adminFailure's Fields, or a handler's own checks.
type fieldErrors map[string]string

// fieldError is one field's message, the data of the admin-field-error
// partial, which shows nothing when Message is "".
type fieldError struct{ Field, Message string }

// For returns field's message for the admin-field-error partial, which
// gives it the id "<field>-error" for the input's aria-describedby:
//
//	{{template "admin-field-error" .Errors.For "email"}}
func (e fieldErrors) For(field string) fieldError { return fieldError{field, e[field]} }

// listPerPage is how many rows an admin list shows a page.
const listPerPage = 50

// pageNumber is a list's ?page=: anything but a positive number is 1.
func pageNumber(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// pager is the data of the admin-pagination partial, under a list.
type pager struct {
	First, Last, Total int    // the rows shown (1-based; 0 when none are) and how many there are
	Prev, Next         string // links to the pages either side; "" when there is none
}

// newPager returns the pager for page (1-based) of a list of total rows,
// perPage to a page. Its links go to path with params, the list's search
// and filters, and the page number.
func newPager(path string, params url.Values, page, perPage, total int) pager {
	link := func(n int) string {
		q := url.Values{}
		maps.Copy(q, params)
		q.Set("page", strconv.Itoa(n))
		return path + "?" + q.Encode()
	}
	p := pager{Total: total}
	pages := (total + perPage - 1) / perPage
	if page <= pages {
		p.First, p.Last = (page-1)*perPage+1, min(page*perPage, total)
	}
	if page > 1 && pages > 0 {
		p.Prev = link(min(page-1, pages))
	}
	if page < pages {
		p.Next = link(page + 1)
	}
	return p
}

// groupChecks is the data of the admin-group-checks partial: a "groups"
// checkbox for each group, ticked when its ID is in Checked, and the
// field's message.
type groupChecks struct {
	Groups  []model.Group
	Checked map[string]bool
	Error   string
}

// newGroupChecks lists groups with the IDs in checked ticked.
func newGroupChecks(groups []model.Group, checked []string, msg string) groupChecks {
	c := groupChecks{Groups: groups, Checked: map[string]bool{}, Error: msg}
	for _, id := range checked {
		c.Checked[id] = true
	}
	return c
}

// metadataField is the data of the admin-metadata partial: a "metadata"
// textarea holding Value, folded away unless Open or there is a message.
type metadataField struct {
	Value, Error string
	Open         bool
}

// newMetadataField shows value, the metadata as typed or stored, open
// when it holds something.
func newMetadataField(value, msg string) metadataField {
	v := strings.TrimSpace(value)
	return metadataField{Value: value, Error: msg, Open: v != "" && v != "{}"}
}

// confirmBox is the data of the admin-confirm partial: a destructive
// action behind an inline confirmation. Summary is the red button that
// opens it, showing Message and a form posting to Action with the Button
// that does it. With Typed set the form also has a "confirm" field, so
// at most one such box per page, labelled Typed, with Error beside it;
// the box then starts open.
type confirmBox struct {
	Summary, Message, Action, Button string
	Typed, Error                     string
}
