package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/store"
)

// Messages of the service accounts pages' own checks and the summaries
// shown at the top when an action fails; see adminFailure.pageError.
const (
	msgConfirmAccountName = "Type the name exactly to confirm."
	msgAccountNotDeleted  = "The service account wasn't deleted. See Delete service account below."
	msgTokenNotMade       = "The token wasn't made. See New API token below."
	msgTokenNotRevoked    = "The token wasn't revoked."
	msgTokenCopyHeading   = "Copy the API token now"
	msgTokenCopyIntro     = "This is the only time the token is shown. Latch keeps only a fingerprint of it, so if you lose it, make a new one and revoke this one."
	deletedAccountName    = "a deleted account"
)

// tokenExpiryChoices are the "Expires" options of the new token form: the
// value posted as expires_days, its label, and the days it stands for.
type tokenExpiry struct {
	Value, Label string
	Days         int
}

var tokenExpiryChoices = []tokenExpiry{
	{"", "Never", 0},
	{"30", "In 30 days", 30},
	{"90", "In 90 days", 90},
	{"365", "In a year", 365},
}

// serviceAccountsData is what admin_service_accounts.html shows.
type serviceAccountsData struct{ Rows []store.UserRow }

// serviceAccountsPage lists the service accounts.
func (s *Server) serviceAccountsPage(w http.ResponseWriter, r *http.Request) {
	page, err := s.d.Store.ListUsers(r.Context(), store.UserFilter{Type: model.UserTypeService, PerPage: 500})
	if err != nil {
		s.serverError(w, r, "service accounts: list", err)
		return
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_service_accounts",
		Page{Title: "Service accounts", Section: "service-accounts", Notice: adminNotice(r), Data: serviceAccountsData{Rows: page.Rows}})
}

// serviceAccountForm is the add or edit form, as typed or as stored.
type serviceAccountForm struct {
	Name, Username, Description string
	GroupIDs                    []string
	Metadata                    string // JSON text
}

// readServiceAccountForm reads the add or edit form from the request.
func readServiceAccountForm(r *http.Request) serviceAccountForm {
	_ = r.ParseForm()
	return serviceAccountForm{
		Name:        r.PostFormValue("name"),
		Username:    r.PostFormValue("username"),
		Description: r.PostFormValue("description"),
		GroupIDs:    r.PostForm["groups"],
		Metadata:    r.PostFormValue("metadata"),
	}
}

// tokenForm is the new token form, as typed.
type tokenForm struct{ Label, Scope, ExpiresDays string }

// tokenRow is a row of the account's tokens table.
type tokenRow struct {
	Token   model.APIToken
	Creator string
}

// serviceAccountData is what admin_service_account.html shows. Account is
// nil on the add form, which has only the details.
type serviceAccountData struct {
	Account   *model.User
	Form      serviceAccountForm
	Groups    groupChecks
	Metadata  metadataField
	Errors    fieldErrors
	Heading   string
	SubmitTxt string

	Tokens      []tokenRow
	NewToken    tokenForm
	TokenErrors fieldErrors
	Expiry      []tokenExpiry
	Apps        []model.Application // apps that sign in as this account
	Delete      confirmBox
}

// newServiceAccountPage shows the add form.
func (s *Server) newServiceAccountPage(w http.ResponseWriter, r *http.Request) {
	s.renderServiceAccount(w, r, nil, http.StatusOK, Page{}, &serviceAccountForm{Metadata: "{}"}, nil, nil, nil)
}

// createServiceAccount adds a service account and shows its page.
func (s *Server) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	f := readServiceAccountForm(r)
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		s.renderServiceAccount(w, r, nil, http.StatusUnprocessableEntity, Page{}, &f, nil, invalid.Fields, nil)
		return
	}
	u, err := s.admin.CreateServiceAccount(r.Context(), adminActor(r), admin.ServiceAccountInput{
		Name: f.Name, Username: f.Username, Description: f.Description, GroupIDs: f.GroupIDs, Metadata: meta,
	})
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "service accounts: add", err); ok {
			s.renderServiceAccount(w, r, nil, fail.Status, Page{Error: fail.Message}, &f, nil, fail.Fields, nil)
		}
		return
	}
	redirectNotice(w, r, "/admin/service-accounts/"+u.ID, "saved")
}

// loadServiceAccount returns the service account the path's {id} names.
// When there is none, or it is a member, it writes the 404 page (or the
// 500 page when the read fails) and returns nil.
func (s *Server) loadServiceAccount(w http.ResponseWriter, r *http.Request) *model.User {
	u, err := s.d.Store.GetUser(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && u.Type != model.UserTypeService:
		s.adminNotFound(w, r)
		return nil
	case err != nil:
		s.serverError(w, r, "service accounts: get", err)
		return nil
	}
	return u
}

// serviceAccountPage shows a service account.
func (s *Server) serviceAccountPage(w http.ResponseWriter, r *http.Request) {
	if u := s.loadServiceAccount(w, r); u != nil {
		s.renderServiceAccount(w, r, u, http.StatusOK, Page{Notice: adminNotice(r)}, nil, nil, nil, nil)
	}
}

// renderServiceAccount writes the add form (u nil) or u's page. A nil
// form means u as stored; otherwise it is what was typed, with errs beside
// its fields. tf and terrs are the same for the new token form.
func (s *Server) renderServiceAccount(w http.ResponseWriter, r *http.Request, u *model.User, status int, p Page,
	f *serviceAccountForm, tf *tokenForm, errs, terrs fieldErrors) {
	ctx := r.Context()
	groups, err := s.d.Store.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, "service accounts: list groups", err)
		return
	}
	d := serviceAccountData{Errors: errs, TokenErrors: terrs, Heading: "Add service account", SubmitTxt: "Add service account",
		Expiry: tokenExpiryChoices}
	if u != nil {
		if f == nil {
			current, err := s.d.Store.ListGroupsForUser(ctx, u.ID)
			if err != nil {
				s.serverError(w, r, "service accounts: list the account's groups", err)
				return
			}
			f = &serviceAccountForm{Name: u.Name, Username: u.Username, Description: u.Description, Metadata: prettyJSON(u.Metadata)}
			for _, g := range current {
				f.GroupIDs = append(f.GroupIDs, g.ID)
			}
		}
		if err := s.loadAccountDetails(ctx, u, &d); err != nil {
			s.serverError(w, r, "service accounts: load page", err)
			return
		}
		d.Account, d.Heading, d.SubmitTxt = u, displayAccountName(u), "Save changes"
		d.Delete = s.deleteAccountBox(u, d, errs["confirm"])
		p.Title = d.Heading
	} else {
		p.Title = "Add service account"
	}
	if f == nil {
		f = &serviceAccountForm{Metadata: "{}"}
	}
	if tf == nil {
		tf = &tokenForm{Scope: string(model.APITokenScopeRead)}
	}
	d.Form, d.NewToken = *f, *tf
	d.Groups = newGroupChecks(groups, f.GroupIDs, errs["groups"])
	d.Metadata = newMetadataField(f.Metadata, errs["metadata"])
	p.Section, p.Data = "service-accounts", d
	s.d.Renderer.Render(w, r, status, "admin_service_account", p)
}

// displayAccountName is what to call a service account.
func displayAccountName(u *model.User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

// loadAccountDetails fills d with u's tokens, with the names of who made
// them, and the apps that sign in as u.
func (s *Server) loadAccountDetails(ctx context.Context, u *model.User, d *serviceAccountData) error {
	tokens, err := s.d.Store.ListAPITokens(ctx, u.ID)
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, t := range tokens {
		name, seen := names[t.CreatedByUserID]
		if !seen {
			name = deletedAccountName
			if t.CreatedByUserID != "" {
				c, err := s.d.Store.GetUser(ctx, t.CreatedByUserID)
				switch {
				case err == nil:
					name = cmpName(c)
				case !errors.Is(err, store.ErrNotFound):
					return err
				}
			}
			names[t.CreatedByUserID] = name
		}
		d.Tokens = append(d.Tokens, tokenRow{Token: t, Creator: name})
	}
	apps, err := s.d.Store.ListApplications(ctx)
	if err != nil {
		return err
	}
	for _, a := range apps {
		if a.ServiceAccountID == u.ID {
			d.Apps = append(d.Apps, a)
		}
	}
	return nil
}

// cmpName is a user's name, or their email or username without one.
func cmpName(u *model.User) string {
	switch {
	case u.Name != "":
		return u.Name
	case u.Email != "":
		return u.Email
	}
	return u.Username
}

// deleteAccountBox is the delete disclosure, whose warning says what stops
// working.
func (s *Server) deleteAccountBox(u *model.User, d serviceAccountData, msg string) confirmBox {
	var b strings.Builder
	b.WriteString("This deletes the account for good. ")
	if n := len(d.Tokens); n == 0 {
		b.WriteString("It has no API tokens. ")
	} else {
		b.WriteString(plural(n, "API token") + " will stop working. ")
	}
	if len(d.Apps) > 0 {
		names := make([]string, len(d.Apps))
		for i, a := range d.Apps {
			names[i] = a.Name
		}
		b.WriteString("These apps lose machine sign-in: " + strings.Join(names, ", ") + ".")
	} else {
		b.WriteString("No app signs in as it.")
	}
	return confirmBox{
		Summary: "Delete service account",
		Message: b.String(),
		Action:  "/admin/service-accounts/" + u.ID + "/delete",
		Button:  "Delete service account",
		Typed:   "Type the account's name to confirm",
		Error:   msg,
	}
}

// saveServiceAccount saves the edit form.
func (s *Server) saveServiceAccount(w http.ResponseWriter, r *http.Request) {
	u := s.loadServiceAccount(w, r)
	if u == nil {
		return
	}
	f := readServiceAccountForm(r)
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		s.renderServiceAccount(w, r, u, http.StatusUnprocessableEntity, Page{}, &f, nil, invalid.Fields, nil)
		return
	}
	_, err := s.admin.UpdateServiceAccount(r.Context(), adminActor(r), u.ID, admin.ServiceAccountPatch{
		Name: &f.Name, Username: &f.Username, Description: &f.Description, GroupIDs: &f.GroupIDs, Metadata: &meta,
	})
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "service accounts: save", err); ok {
			s.renderServiceAccount(w, r, u, fail.Status, Page{Error: fail.Message}, &f, nil, fail.Fields, nil)
		}
		return
	}
	redirectNotice(w, r, "/admin/service-accounts/"+u.ID, "saved")
}

// createToken makes an API token and shows it, once, in this response.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	u := s.loadServiceAccount(w, r)
	if u == nil {
		return
	}
	tf := tokenForm{
		Label:       r.PostFormValue("label"),
		Scope:       r.PostFormValue("scope"),
		ExpiresDays: r.PostFormValue("expires_days"),
	}
	if tf.Scope == "" {
		tf.Scope = string(model.APITokenScopeRead)
	}
	in := admin.NewToken{Label: tf.Label, Scope: model.APITokenScope(tf.Scope)}
	if tf.ExpiresDays != "" {
		days := -1
		for _, c := range tokenExpiryChoices {
			if c.Value == tf.ExpiresDays {
				days = c.Days
			}
		}
		if days < 0 {
			s.renderServiceAccount(w, r, u, http.StatusUnprocessableEntity, Page{Error: msgTokenNotMade}, nil, &tf, nil,
				fieldErrors{"expires_days": "Choose when the token expires."})
			return
		}
		at := s.d.Now().Add(time.Duration(days) * 24 * time.Hour)
		in.ExpiresAt = &at
	}
	_, raw, err := s.admin.CreateToken(r.Context(), adminActor(r), u.ID, in)
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "service accounts: make token", err); ok {
			terrs := fieldErrors{}
			for k, v := range fail.Fields {
				if k == "expires_at" {
					k = "expires_days"
				}
				terrs[k] = v
			}
			s.renderServiceAccount(w, r, u, fail.Status, Page{Error: fail.pageError(msgTokenNotMade)}, nil, &tf, nil, terrs)
		}
		return
	}
	s.renderSecret(w, r, "service-accounts", secretPage{
		Heading: msgTokenCopyHeading,
		Intro:   msgTokenCopyIntro,
		Items:   []secretItem{{"Token", raw}},
		Example: `curl -H "Authorization: Bearer ` + raw + `" ` + s.d.Cfg.Issuer() + `/api/v1/me`,
		Back:    "/admin/service-accounts/" + u.ID,
	})
}

// revokeToken revokes the token the path's {tid} names.
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	u := s.loadServiceAccount(w, r)
	if u == nil {
		return
	}
	if err := s.admin.RevokeToken(r.Context(), adminActor(r), u.ID, r.PathValue("tid")); err != nil {
		if fail, ok := s.adminFailed(w, r, "service accounts: revoke token", err); ok {
			s.renderServiceAccount(w, r, u, fail.Status, Page{Error: fail.pageError(msgTokenNotRevoked)}, nil, nil, nil, nil)
		}
		return
	}
	redirectNotice(w, r, "/admin/service-accounts/"+u.ID, "token_revoked")
}

// deleteServiceAccount deletes the account once its name is typed to
// confirm, and shows the list.
func (s *Server) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	u := s.loadServiceAccount(w, r)
	if u == nil {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != displayAccountName(u) {
		s.renderServiceAccount(w, r, u, http.StatusUnprocessableEntity, Page{Error: msgAccountNotDeleted}, nil, nil,
			fieldErrors{"confirm": msgConfirmAccountName}, nil)
		return
	}
	if err := s.admin.DeleteServiceAccount(r.Context(), adminActor(r), u.ID); err != nil {
		if fail, ok := s.adminFailed(w, r, "service accounts: delete", err); ok {
			s.renderServiceAccount(w, r, u, fail.Status, Page{Error: fail.pageError(msgAccountNotDeleted)}, nil, nil, fail.Fields, nil)
		}
		return
	}
	redirectNotice(w, r, "/admin/service-accounts", "deleted")
}
