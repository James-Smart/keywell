package web

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/session"
	"latch/internal/store"
)

// memberStatusLabels name each member status in the admin pages.
var memberStatusLabels = map[model.UserStatus]string{
	model.UserStatusActive:        "Active",
	model.UserStatusInvited:       "Invited, not set up",
	model.UserStatusNeedsPassword: "Needs password",
	model.UserStatusDisabled:      "Disabled",
}

// listFilter is an option of a list's filter: Value is what the store
// filters by, Label what the admin sees.
type listFilter struct{ Value, Label string }

// memberFilters are the members list's status filter, in order. The
// values are store.UserFilter Status values.
var memberFilters = []listFilter{
	{"", "All"},
	{"active", "Active"},
	{"invited", "Invited"},
	{"needs_password", "Needs password"},
	{"disabled", "Disabled"},
	{"no_2fa", "No two-step sign in"},
	{"admins", "Admins"},
}

// Messages of the members pages' own checks; the admin service has the
// rest.
const (
	msgPasswordNeeded = "Enter a password, or choose to email them an invitation."
	msgConfirmEmail   = "Type the email address exactly to confirm."
)

// Page.Error summaries of the member actions that failed, naming the
// action and where to look; see adminFailure.pageError. Only setting a
// password and deleting take input, so only their summaries point below;
// the others back up messages the service always gives.
const (
	msgNotSent        = "The email wasn't sent."
	msgPasswordNotSet = "The password wasn't set. See Set password manually below."
	msgTOTPNotCleared = "Two-step sign in wasn't cleared."
	msgNotSignedOut   = "They weren't signed out."
	msgNotDisabled    = "The account wasn't disabled."
	msgNotEnabled     = "The account wasn't enabled."
	msgNotDeleted     = "The member wasn't deleted. See Delete member below."
)

// membersData is what admin_members.html shows.
type membersData struct {
	Query, Status string // the search and filter, as applied
	Filters       []listFilter
	Rows          []memberRow
	Pager         pager
}

// memberRow is a row of the members list.
type memberRow struct {
	store.UserRow
	StatusLabel string
}

// membersPage lists members, 50 a page, searched by ?q= and filtered by
// ?status=. An unknown status lists everyone.
func (s *Server) membersPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := membersData{Query: strings.TrimSpace(q.Get("q")), Filters: memberFilters}
	if slices.ContainsFunc(memberFilters, func(f listFilter) bool { return f.Value == q.Get("status") }) {
		d.Status = q.Get("status")
	}
	page, err := s.d.Store.ListUsers(r.Context(), store.UserFilter{
		Type: model.UserTypeMember, Query: d.Query, Status: d.Status, Page: pageNumber(r), PerPage: listPerPage,
	})
	if err != nil {
		s.serverError(w, r, "members: list", err)
		return
	}
	for _, row := range page.Rows {
		d.Rows = append(d.Rows, memberRow{row, memberStatusLabels[row.Status]})
	}
	params := url.Values{}
	if d.Query != "" {
		params.Set("q", d.Query)
	}
	if d.Status != "" {
		params.Set("status", d.Status)
	}
	d.Pager = newPager("/admin/members", params, page.Page, page.PerPage, page.Total)
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_members",
		Page{Title: "Members", Section: "members", Notice: adminNotice(r), Data: d})
}

// memberForm is the add or edit form, as typed or as stored. It never
// holds a password, so a form shown again never shows one.
type memberForm struct {
	Name, Email, Username string
	GroupIDs              []string
	Metadata              string // JSON text
	Setup                 string // add form: "invite" or "password"
}

// readMemberForm reads the add or edit form from the request.
func readMemberForm(r *http.Request) memberForm {
	f := memberForm{
		Name:     r.PostFormValue("name"),
		Email:    r.PostFormValue("email"),
		Username: r.PostFormValue("username"),
		Metadata: r.PostFormValue("metadata"),
		Setup:    r.PostFormValue("setup"),
	}
	f.GroupIDs = r.PostForm["groups"]
	return f
}

// memberFields is the data of the admin-member-fields partial: the fields
// the add and edit forms share.
type memberFields struct {
	Name, Email, Username string
	Groups                groupChecks
	Metadata              metadataField
	Errors                fieldErrors
}

// fields is what admin-member-fields shows for f: every group as a
// checkbox, and errs beside the fields.
func (f memberForm) fields(groups []model.Group, errs fieldErrors) memberFields {
	return memberFields{
		Name: f.Name, Email: f.Email, Username: f.Username,
		Groups:   newGroupChecks(groups, f.GroupIDs, errs["groups"]),
		Metadata: newMetadataField(f.Metadata, errs["metadata"]),
		Errors:   errs,
	}
}

// newMemberData is what admin_member_new.html shows.
type newMemberData struct {
	Fields    memberFields
	Setup     string      // "invite" or "password"
	Errors    fieldErrors // the password field's message
	MinLength int
}

// newMemberPage shows the add form: an invitation, and no metadata.
func (s *Server) newMemberPage(w http.ResponseWriter, r *http.Request) {
	s.renderNewMember(w, r, http.StatusOK, Page{}, memberForm{Metadata: "{}", Setup: "invite"}, nil)
}

// renderNewMember writes the add form holding f, with errs beside the
// fields.
func (s *Server) renderNewMember(w http.ResponseWriter, r *http.Request, status int, p Page, f memberForm, errs fieldErrors) {
	groups, err := s.d.Store.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, "members: list groups", err)
		return
	}
	p.Title, p.Section = "Add member", "members"
	p.Data = newMemberData{Fields: f.fields(groups, errs), Setup: f.Setup, Errors: errs,
		MinLength: s.d.Cfg.Password.MinLength}
	s.d.Renderer.Render(w, r, status, "admin_member_new", p)
}

// createMember adds a member and shows their page. They are emailed an
// invitation unless the admin chose to set a password now, which then
// must be given. When the invitation cannot be sent the member is still
// added, and their page says so.
func (s *Server) createMember(w http.ResponseWriter, r *http.Request) {
	f := readMemberForm(r)
	password := r.PostFormValue("password")
	invite := f.Setup != "password"
	if invite {
		f.Setup = "invite"
	}
	errs := fieldErrors{}
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		maps.Copy(errs, invalid.Fields)
	}
	if !invite && password == "" {
		errs["password"] = msgPasswordNeeded
	}
	if len(errs) > 0 {
		s.renderNewMember(w, r, http.StatusUnprocessableEntity, Page{}, f, errs)
		return
	}

	in := admin.NewMember{Name: f.Name, Email: f.Email, Username: f.Username, GroupIDs: f.GroupIDs,
		Metadata: meta, Invite: invite}
	if !invite {
		in.Password = password
	}
	u, err := s.admin.CreateMember(r.Context(), adminActor(r), in)
	var unsent *admin.EmailError
	switch {
	case u != nil && errors.As(err, &unsent):
		s.logUnsent(r.Context(), "members: send invitation", u, err)
		redirectNotice(w, r, "/admin/members/"+u.ID, "added_no_email")
	case err != nil:
		if fail, ok := s.adminFailed(w, r, "members: add", err); ok {
			s.renderNewMember(w, r, fail.Status, Page{Error: fail.Message}, f, fail.Fields)
		}
	case invite:
		redirectNotice(w, r, "/admin/members/"+u.ID, "invited")
	default:
		redirectNotice(w, r, "/admin/members/"+u.ID, "added")
	}
}

// memberData is what admin_member.html shows.
type memberData struct {
	Member      *model.User
	Status      model.UserStatus
	StatusLabel string
	Own         bool   // the signed-in admin's own account
	Imported    bool   // imported from Authentik
	RequiredBy  string // the groups requiring two-step sign in, while the member has none
	Fields      memberFields
	Errors      fieldErrors // the actions' messages: "password" and "confirm"
	MinLength   int

	ClearTOTP, Disable, Delete confirmBox
}

// memberPage shows a member: their form, details and actions.
func (s *Server) memberPage(w http.ResponseWriter, r *http.Request) {
	s.showMember(w, r, http.StatusOK, Page{Notice: adminNotice(r)}, nil, nil)
}

// loadMember returns the member the path's {id} names. When there is
// none, or it is a service account's, it writes the 404 page (or the 500
// page when the read fails) and returns nil.
func (s *Server) loadMember(w http.ResponseWriter, r *http.Request) *model.User {
	u, err := s.d.Store.GetUser(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && u.Type != model.UserTypeMember:
		s.adminNotFound(w, r)
		return nil
	case err != nil:
		s.serverError(w, r, "members: get member", err)
		return nil
	}
	return u
}

// showMember writes the page of the member the path names, or the 404
// page. form is what was typed, or nil for the member as stored; errs are
// the messages beside the fields.
func (s *Server) showMember(w http.ResponseWriter, r *http.Request, status int, p Page, form *memberForm, errs fieldErrors) {
	if u := s.loadMember(w, r); u != nil {
		s.renderMember(w, r, u, status, p, form, errs)
	}
}

// renderMember writes u's page; see showMember.
func (s *Server) renderMember(w http.ResponseWriter, r *http.Request, u *model.User, status int, p Page,
	form *memberForm, errs fieldErrors) {
	ctx := r.Context()
	current, err := s.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		s.serverError(w, r, "members: list the member's groups", err)
		return
	}
	groups, err := s.d.Store.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, "members: list groups", err)
		return
	}
	st, err := s.d.Store.GetUserStatus(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		s.adminNotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, "members: get status", err)
		return
	}
	if form == nil {
		stored := memberForm{Name: u.Name, Email: u.Email, Username: u.Username, Metadata: prettyJSON(u.Metadata)}
		for _, g := range current {
			stored.GroupIDs = append(stored.GroupIDs, g.ID)
		}
		form = &stored
	}
	var requiredBy []string
	if !u.TOTPEnrolled() {
		for _, g := range current {
			if g.RequireTOTP {
				requiredBy = append(requiredBy, g.Name)
			}
		}
	}
	_, me, _ := session.FromContext(ctx)
	base := "/admin/members/" + u.ID
	d := memberData{
		Member:      u,
		Status:      st,
		StatusLabel: memberStatusLabels[st],
		Own:         me != nil && me.ID == u.ID,
		Imported:    u.AuthentikUUID != "" || u.AuthentikPK != nil,
		RequiredBy:  strings.Join(requiredBy, ", "),
		Fields:      form.fields(groups, errs),
		Errors:      errs,
		MinLength:   s.d.Cfg.Password.MinLength,
		ClearTOTP: confirmBox{
			Summary: "Clear two-step sign in",
			Message: "This removes their authenticator app and recovery codes. If one of their groups requires two-step sign in, they'll set it up again next time they sign in.",
			Action:  base + "/clear-totp",
			Button:  "Clear two-step sign in",
		},
		Disable: confirmBox{
			Summary: "Disable account",
			Message: "They'll be signed out everywhere and can't sign in again until the account is enabled.",
			Action:  base + "/disable",
			Button:  "Disable account",
		},
		Delete: confirmBox{
			Summary: "Delete member",
			Message: "This deletes their account, group memberships, sessions and tokens. It can't be undone. The audit log keeps its record.",
			Action:  base + "/delete",
			Button:  "Delete member",
			Typed:   "Type their email address to confirm",
			Error:   errs["confirm"],
		},
	}
	p.Title, p.Section, p.Data = cmp.Or(u.Name, u.Email), "members", d
	s.d.Renderer.Render(w, r, status, "admin_member", p)
}

// saveMember saves the edit form: name, email, username, groups (none
// ticked leaves the member in none) and metadata.
func (s *Server) saveMember(w http.ResponseWriter, r *http.Request) {
	f := readMemberForm(r)
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		s.showMember(w, r, http.StatusUnprocessableEntity, Page{}, &f, invalid.Fields)
		return
	}
	id := r.PathValue("id")
	_, err := s.admin.UpdateMember(r.Context(), adminActor(r), id, admin.MemberPatch{
		Name: &f.Name, Email: &f.Email, Username: &f.Username, GroupIDs: &f.GroupIDs, Metadata: &meta,
	})
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "members: save", err); ok {
			s.showMember(w, r, fail.Status, Page{Error: fail.Message}, &f, fail.Fields)
		}
		return
	}
	redirectNotice(w, r, "/admin/members/"+id, "saved")
}

// memberAction makes the change do on the member the path names and
// returns to their page with notice. When it fails, their page is shown
// again saying why, with summary at the top for a validation error; see
// memberActionFailed.
func (s *Server) memberAction(w http.ResponseWriter, r *http.Request, what, notice, summary string,
	do func(ctx context.Context, a admin.Actor, id string) error) {
	id := r.PathValue("id")
	if err := do(r.Context(), adminActor(r), id); err != nil {
		s.memberActionFailed(w, r, what, summary, err)
		return
	}
	redirectNotice(w, r, "/admin/members/"+id, notice)
}

// memberActionFailed shows the member page again, as stored, after an
// action on the member failed with err (see adminFailed): the messages
// beside the action's fields, and at the top the failure's own message,
// or summary when it has none.
func (s *Server) memberActionFailed(w http.ResponseWriter, r *http.Request, what, summary string, err error) {
	if fail, ok := s.adminFailed(w, r, what, err); ok {
		s.showMember(w, r, fail.Status, Page{Error: fail.pageError(summary)}, nil, fail.Fields)
	}
}

// sendMemberEmail emails the member a link to choose a password: an
// invitation when they have none, otherwise a reset. Sending is the whole
// action, so a failed send is an error.
func (s *Server) sendMemberEmail(w http.ResponseWriter, r *http.Request) {
	u := s.loadMember(w, r)
	if u == nil {
		return
	}
	purpose, err := s.admin.SendPasswordEmail(r.Context(), adminActor(r), u.ID)
	if err != nil {
		var unsent *admin.EmailError
		if errors.As(err, &unsent) {
			s.logUnsent(r.Context(), "members: send password email", u, err)
		}
		s.memberActionFailed(w, r, "members: send password email", msgNotSent, err)
		return
	}
	notice := "reset_sent"
	if purpose == model.ResetPurposeInvite {
		notice = "invite_sent"
	}
	redirectNotice(w, r, "/admin/members/"+u.ID, notice)
}

// setMemberPassword sets the password typed, which signs the member out
// everywhere.
func (s *Server) setMemberPassword(w http.ResponseWriter, r *http.Request) {
	password := r.PostFormValue("password")
	s.memberAction(w, r, "members: set password", "password_set", msgPasswordNotSet,
		func(ctx context.Context, a admin.Actor, id string) error {
			return s.admin.SetMemberPassword(ctx, a, id, password)
		})
}

// clearMemberTOTP removes the member's two-step sign in.
func (s *Server) clearMemberTOTP(w http.ResponseWriter, r *http.Request) {
	s.memberAction(w, r, "members: clear two-step sign in", "totp_cleared", msgTOTPNotCleared, s.admin.ClearMemberTOTP)
}

// signOutMember ends the member's sessions everywhere.
func (s *Server) signOutMember(w http.ResponseWriter, r *http.Request) {
	s.memberAction(w, r, "members: sign out everywhere", "signed_out", msgNotSignedOut, s.admin.SignOutEverywhere)
}

// disableMember disables the member, which signs them out everywhere. An
// admin cannot disable their own account.
func (s *Server) disableMember(w http.ResponseWriter, r *http.Request) {
	s.memberAction(w, r, "members: disable", "disabled", msgNotDisabled, s.setMemberActive(false))
}

// enableMember lets a disabled member sign in again.
func (s *Server) enableMember(w http.ResponseWriter, r *http.Request) {
	s.memberAction(w, r, "members: enable", "enabled", msgNotEnabled, s.setMemberActive(true))
}

// setMemberActive is the change that enables (active) or disables a
// member.
func (s *Server) setMemberActive(active bool) func(context.Context, admin.Actor, string) error {
	return func(ctx context.Context, a admin.Actor, id string) error {
		_, err := s.admin.UpdateMember(ctx, a, id, admin.MemberPatch{IsActive: &active})
		return err
	}
}

// deleteMember deletes the member once their email address is typed to
// confirm (trimmed, in any case), and shows the members list.
func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request) {
	u := s.loadMember(w, r)
	if u == nil {
		return
	}
	confirm := strings.TrimSpace(r.PostFormValue("confirm"))
	if u.Email == "" || !strings.EqualFold(confirm, u.Email) {
		s.renderMember(w, r, u, http.StatusUnprocessableEntity, Page{Error: msgNotDeleted}, nil,
			fieldErrors{"confirm": msgConfirmEmail})
		return
	}
	if err := s.admin.DeleteMember(r.Context(), adminActor(r), u.ID); err != nil {
		s.memberActionFailed(w, r, "members: delete", msgNotDeleted, err)
		return
	}
	redirectNotice(w, r, "/admin/members", "deleted")
}

// logUnsent logs why an email to member u was not sent, without their
// address, for whoever fixes the email settings.
func (s *Server) logUnsent(ctx context.Context, what string, u *model.User, err error) {
	s.d.Log.ErrorContext(ctx, what, "user_id", u.ID, "error", redactAddress(err.Error(), u.Email))
}
