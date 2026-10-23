package web

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"latch/internal/admin"
	"latch/internal/config"
	"latch/internal/icons"
	"latch/internal/model"
	"latch/internal/store"
)

// Messages of the applications pages' own checks and the summaries shown
// at the top when an action fails; see adminFailure.pageError.
const (
	msgBadLifetime       = "Use a time like 1h or 30d."
	msgPickServiceAcct   = "Choose a service account."
	msgConfirmAppName    = "Type the name exactly to confirm."
	msgAppNotDeleted     = "The application wasn't deleted. See Delete application below."
	msgSecretNotMade     = "The secret wasn't replaced."
	msgSecretCopyHeading = "Copy the client secret now"
	msgSecretCopyIntro   = "You won't be able to see it again. If you lose it, regenerate it from the app's page."
	msgSecretExample     = "For MediaWiki, add this to LocalSettings.php:"
)

// secretItem is one value on the secret page.
type secretItem struct{ Label, Value string }

// secretPage is the data of admin_secret.html: something shown once, in
// the response to the request that made it. Items are the values to copy
// (the last is the secret itself), Example is optional text to paste
// somewhere ("" shows none) under ExampleLabel, which says what it is,
// and Back is the link to go to afterwards.
type secretPage struct {
	Heading, Intro string
	Items          []secretItem
	ExampleLabel   string // says what Example is and where it goes
	Example        string
	Back           string
}

// renderSecret writes the secret page with a 200.
func (s *Server) renderSecret(w http.ResponseWriter, r *http.Request, section string, d secretPage) {
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_secret", Page{Title: d.Heading, Section: section, Data: d})
}

// formatTTL writes a lifetime the way admins type it: "" for 0, then
// whole days, hours or minutes.
func formatTTL(d time.Duration) string { return admin.FormatDuration(d) }

// appRow is a row of the applications list.
type appRow struct {
	App     model.Application
	Initial string
	Groups  []string // names of the groups allowed in; none means everyone
}

// appsData is what admin_apps.html shows.
type appsData struct{ Rows []appRow }

// appsPage lists the applications.
func (s *Server) appsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	apps, err := s.d.Store.ListApplications(ctx)
	if err != nil {
		s.serverError(w, r, "apps: list", err)
		return
	}
	groups, err := s.d.Store.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, "apps: list groups", err)
		return
	}
	names := make(map[string]string, len(groups))
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	d := appsData{Rows: make([]appRow, 0, len(apps))}
	for _, a := range apps {
		row := appRow{App: a, Initial: initial(a.Name)}
		for _, id := range a.AllowedGroupIDs {
			if name, ok := names[id]; ok {
				row.Groups = append(row.Groups, name)
			}
		}
		d.Rows = append(d.Rows, row)
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_apps",
		Page{Title: "Applications", Section: "apps", Notice: adminNotice(r), Data: d})
}

// appForm is the add or edit form, as typed or as stored. The lifetimes
// and the address lists are text, exactly as typed.
type appForm struct {
	Name, Slug, ClientType                      string
	RedirectURIs, PostLogoutRedirectURIs        string // one address per line
	Groups                                      []string
	SubjectMode                                 string
	AccessTokenTTL, IDTokenTTL, RefreshTokenTTL string
	ShowTile                                    bool
	LaunchURL, Description, IconURL             string
	Machine                                     bool
	ServiceAccountID                            string
}

// readAppForm reads the add or edit form from the request.
func readAppForm(r *http.Request) appForm {
	f := appForm{
		Name:                   r.PostFormValue("name"),
		Slug:                   r.PostFormValue("slug"),
		ClientType:             r.PostFormValue("client_type"),
		RedirectURIs:           r.PostFormValue("redirect_uris"),
		PostLogoutRedirectURIs: r.PostFormValue("post_logout_redirect_uris"),
		SubjectMode:            r.PostFormValue("subject_mode"),
		AccessTokenTTL:         r.PostFormValue("access_token_ttl"),
		IDTokenTTL:             r.PostFormValue("id_token_ttl"),
		RefreshTokenTTL:        r.PostFormValue("refresh_token_ttl"),
		ShowTile:               r.PostFormValue("show_tile") != "",
		LaunchURL:              r.PostFormValue("launch_url"),
		Description:            r.PostFormValue("description"),
		IconURL:                r.PostFormValue("icon_url"),
		Machine:                r.PostFormValue("machine") != "",
		ServiceAccountID:       r.PostFormValue("service_account_id"),
	}
	f.Groups = r.PostForm["allowed_groups"]
	return f
}

// appFormOf is app as stored, in the form's terms.
func appFormOf(a *model.Application) appForm {
	return appForm{
		Name: a.Name, Slug: a.Slug, ClientType: string(a.ClientType),
		RedirectURIs:           strings.Join(a.RedirectURIs, "\n"),
		PostLogoutRedirectURIs: strings.Join(a.PostLogoutRedirectURIs, "\n"),
		Groups:                 a.AllowedGroupIDs,
		SubjectMode:            string(a.SubjectMode),
		AccessTokenTTL:         formatTTL(a.AccessTokenTTL),
		IDTokenTTL:             formatTTL(a.IDTokenTTL),
		RefreshTokenTTL:        formatTTL(a.RefreshTokenTTL),
		ShowTile:               a.ShowTile,
		LaunchURL:              a.LaunchURL, Description: a.Description, IconURL: a.IconURL,
		Machine:          a.ServiceAccountID != "",
		ServiceAccountID: a.ServiceAccountID,
	}
}

// lines splits a textarea on "\n". Every line goes to the service, blank
// and "\r"-ended ones included: it tidies the list and numbers the lines
// of its messages by what was submitted.
func lines(text string) []string { return strings.Split(text, "\n") }

// lifetime parses a lifetime field; blank means 0, the global default.
func lifetime(errs fieldErrors, field, text string) time.Duration {
	if strings.TrimSpace(text) == "" {
		return 0
	}
	d, err := config.ParseDuration(text)
	if err != nil {
		errs[field] = msgBadLifetime
	}
	return d
}

// parse checks what the service cannot see (the lifetimes' text, a
// service account chosen without one picked) and returns the form as
// the service takes it.
func (f appForm) parse() (in admin.AppInput, errs fieldErrors) {
	errs = fieldErrors{}
	in = admin.AppInput{
		Name: f.Name, Slug: f.Slug, ClientType: model.ClientType(f.ClientType),
		RedirectURIs: lines(f.RedirectURIs), PostLogoutRedirectURIs: lines(f.PostLogoutRedirectURIs),
		AllowedGroupIDs: f.Groups, SubjectMode: model.SubjectMode(f.SubjectMode),
		AccessTokenTTL:  lifetime(errs, "access_token_ttl", f.AccessTokenTTL),
		IDTokenTTL:      lifetime(errs, "id_token_ttl", f.IDTokenTTL),
		RefreshTokenTTL: lifetime(errs, "refresh_token_ttl", f.RefreshTokenTTL),
		LaunchURL:       f.LaunchURL, IconURL: f.IconURL, Description: f.Description, ShowTile: f.ShowTile,
	}
	if f.Machine {
		if in.ServiceAccountID = strings.TrimSpace(f.ServiceAccountID); in.ServiceAccountID == "" {
			errs["service_account_id"] = msgPickServiceAcct
		}
	}
	return in, errs
}

// patch is in as a change that sets every field.
func patch(in admin.AppInput) admin.AppPatch {
	return admin.AppPatch{
		Name: &in.Name, Slug: &in.Slug, ClientType: &in.ClientType,
		RedirectURIs: &in.RedirectURIs, PostLogoutRedirectURIs: &in.PostLogoutRedirectURIs,
		AllowedGroupIDs: &in.AllowedGroupIDs, SubjectMode: &in.SubjectMode,
		AccessTokenTTL: &in.AccessTokenTTL, IDTokenTTL: &in.IDTokenTTL, RefreshTokenTTL: &in.RefreshTokenTTL,
		LaunchURL: &in.LaunchURL, IconURL: &in.IconURL, Description: &in.Description,
		ShowTile: &in.ShowTile, ServiceAccountID: &in.ServiceAccountID,
	}
}

// setupDetails is the Setup details panel of an application's page.
type setupDetails struct {
	Issuer, Discovery, ClientID string
	Redirects                   []string
	Confidential, Machine       bool
	SnippetName                 string // the app's name, safe inside a PHP string
	TokenURL                    string
}

// appData is what admin_app.html shows. App is nil on the add form.
type appData struct {
	App      *model.Application
	Form     appForm
	Errors   fieldErrors
	Groups   groupChecks
	Accounts []model.User
	Setup    setupDetails
	Rotate   confirmBox
	Delete   confirmBox
	Heading  string
	Submit   string

	DefaultAccess, DefaultID, DefaultRefresh string // the global lifetimes, as placeholders
	LifetimesOpen                            bool
}

// loadApp returns the application the path's {id} names. When there is
// none it writes the 404 page (or the 500 page when the read fails) and
// returns nil.
func (s *Server) loadApp(w http.ResponseWriter, r *http.Request) *model.Application {
	a, err := s.d.Store.GetApplication(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.adminNotFound(w, r)
		return nil
	case err != nil:
		s.serverError(w, r, "apps: get", err)
		return nil
	}
	return a
}

// newAppPage shows the add form.
func (s *Server) newAppPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, nil, http.StatusOK, Page{}, &appForm{
		ClientType: string(model.ClientTypeConfidential), SubjectMode: string(model.SubjectModeID), ShowTile: true,
	}, nil)
}

// appPage shows an application: its form, its setup details and its
// actions.
func (s *Server) appPage(w http.ResponseWriter, r *http.Request) {
	if a := s.loadApp(w, r); a != nil {
		s.renderApp(w, r, a, http.StatusOK, Page{Notice: adminNotice(r)}, nil, nil)
	}
}

// renderApp writes the add form (a nil) or a's page. A nil form means a
// as stored; otherwise it is what was typed, with errs beside the fields.
func (s *Server) renderApp(w http.ResponseWriter, r *http.Request, a *model.Application, status int, p Page,
	f *appForm, errs fieldErrors) {
	ctx := r.Context()
	groups, err := s.d.Store.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, "apps: list groups", err)
		return
	}
	accounts, err := s.d.Store.ListUsers(ctx, store.UserFilter{Type: model.UserTypeService, PerPage: 500})
	if err != nil {
		s.serverError(w, r, "apps: list service accounts", err)
		return
	}
	if f == nil {
		stored := appFormOf(a)
		f = &stored
	}
	cfg := s.d.Cfg
	d := appData{
		Form: *f, Errors: errs, Heading: "Add application", Submit: "Add application",
		Groups:        newGroupChecks(groups, f.Groups, errs["allowed_groups"]),
		DefaultAccess: formatTTL(cfg.Tokens.Access), DefaultID: formatTTL(cfg.Tokens.ID),
		DefaultRefresh: formatTTL(cfg.Tokens.Refresh),
		LifetimesOpen:  errs["access_token_ttl"] != "" || errs["id_token_ttl"] != "" || errs["refresh_token_ttl"] != "",
	}
	for _, row := range accounts.Rows {
		d.Accounts = append(d.Accounts, row.User)
	}
	p.Title = "Add application"
	if a != nil {
		d.App, d.Heading, d.Submit = a, a.Name, "Save changes"
		d.Setup = setupFor(cfg.Issuer(), a)
		d.Rotate = confirmBox{
			Summary: "Regenerate secret",
			Message: "The old secret stops working straight away.",
			Action:  "/admin/apps/" + a.ID + "/rotate-secret",
			Button:  "Regenerate secret",
		}
		d.Delete = confirmBox{
			Summary: "Delete application",
			Message: "This removes the application and ends everyone's sign-in to it. Members are not affected.",
			Action:  "/admin/apps/" + a.ID + "/delete",
			Button:  "Delete application",
			Typed:   "Type the application's name to confirm",
			Error:   errs["confirm"],
		}
		p.Title = a.Name
	}
	p.Section, p.Data = "apps", d
	s.d.Renderer.Render(w, r, status, "admin_app", p)
}

// phpQuoted escapes s for a single-quoted PHP string.
var phpQuoted = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// setupFor is what an admin needs to set the app up against Latch.
func setupFor(issuer string, a *model.Application) setupDetails {
	return setupDetails{
		Issuer: issuer, Discovery: issuer + "/.well-known/openid-configuration", ClientID: a.ClientID,
		Redirects: a.RedirectURIs, Confidential: a.ClientType == model.ClientTypeConfidential,
		Machine:     a.ServiceAccountID != "",
		SnippetName: phpQuoted.Replace(a.Name), TokenURL: issuer + "/oauth/token",
	}
}

// mediaWikiExample is the LocalSettings.php entry for a confidential app
// with secret in place of the placeholder.
func mediaWikiExample(sd setupDetails, secret string) string {
	return "$wgPluggableAuth_Config['" + sd.SnippetName + "'] = [ 'plugin' => 'OpenIDConnect', 'data' => [\n" +
		"    'providerURL' => '" + sd.Issuer + "', 'clientID' => '" + sd.ClientID + "',\n" +
		"    'clientsecret' => '" + phpQuoted.Replace(secret) + "',\n" +
		"    'scope' => [ 'openid', 'profile', 'email', 'groups' ] ] ];"
}

// showNewSecret writes the secret page for app and its new secret.
func (s *Server) showNewSecret(w http.ResponseWriter, r *http.Request, a *model.Application, secret string) {
	sd := setupFor(s.d.Cfg.Issuer(), a)
	s.renderSecret(w, r, "apps", secretPage{
		Heading:      msgSecretCopyHeading,
		Intro:        msgSecretCopyIntro,
		Items:        []secretItem{{"Client ID", a.ClientID}, {"Client secret", secret}},
		ExampleLabel: msgSecretExample,
		Example:      mediaWikiExample(sd, secret),
		Back:         "/admin/apps/" + a.ID,
	})
}

// createApp adds an application. A confidential one shows its secret in
// this response; a public one goes to its page.
func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	f := readAppForm(r)
	in, errs := f.parse()
	if len(errs) > 0 {
		s.renderApp(w, r, nil, http.StatusUnprocessableEntity, Page{Error: msgNotSaved}, &f, errs)
		return
	}
	a, secret, err := s.admin.CreateApp(r.Context(), adminActor(r), in)
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "apps: add", err); ok {
			s.renderApp(w, r, nil, fail.Status, Page{Error: fail.formError()}, &f, fail.Fields)
		}
		return
	}
	if secret != "" {
		s.showNewSecret(w, r, a, secret)
		return
	}
	redirectNotice(w, r, "/admin/apps/"+a.ID, "saved")
}

// saveApp saves the edit form, which may be url-encoded or multipart. An
// uploaded icon is part of the same save: a bad icon, or any other
// refusal, saves nothing and leaves no file behind. When the save made
// the app confidential the response is the secret page.
func (s *Server) saveApp(w http.ResponseWriter, r *http.Request) {
	a := s.loadApp(w, r)
	if a == nil {
		return
	}
	if err := r.ParseMultipartForm(maxBodyBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		s.renderApp(w, r, a, http.StatusUnprocessableEntity, Page{Error: msgNotSaved}, nil, fieldErrors{"icon": msgIconRead})
		return
	}
	f := readAppForm(r)
	in, errs := f.parse()
	if r.PostFormValue("remove_icon") != "" {
		in.IconURL, f.IconURL = "", ""
	}
	upload, problem := readIconUpload(r)
	if problem != "" {
		errs["icon"] = problem
	}
	if len(errs) > 0 {
		s.renderApp(w, r, a, http.StatusUnprocessableEntity, Page{Error: msgNotSaved}, &f, errs)
		return
	}
	newIcon := ""
	if upload != nil {
		var err error
		if newIcon, _, err = icons.Save(s.d.Cfg.DataDir, a.ID, upload); err != nil {
			s.serverError(w, r, "apps: save icon", err)
			return
		}
		in.IconURL = newIcon
	}
	saved, secret, err := s.admin.UpdateApp(r.Context(), adminActor(r), a.ID, patch(in))
	if err != nil {
		if newIcon != "" && newIcon != a.IconURL {
			s.removeIconFile(a.ID, newIcon)
		}
		if fail, ok := s.adminFailed(w, r, "apps: save", err); ok {
			s.renderApp(w, r, a, fail.Status, Page{Error: fail.formError()}, &f, fail.Fields)
		}
		return
	}
	if a.IconURL != saved.IconURL {
		s.removeIconFile(a.ID, a.IconURL)
	}
	if secret != "" {
		s.showNewSecret(w, r, saved, secret)
		return
	}
	redirectNotice(w, r, "/admin/apps/"+a.ID, "saved")
}

// readIconUpload returns the bytes of the form's icon file, nil when none
// was chosen, or a message for the upload field when it can't be used.
// The type and size are checked here, before anything is written.
func readIconUpload(r *http.Request) (data []byte, problem string) {
	file, _, err := r.FormFile("icon")
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) || errors.Is(err, http.ErrNotMultipart) {
			return nil, ""
		}
		return nil, msgIconRead
	}
	defer file.Close()
	data, err = io.ReadAll(io.LimitReader(file, icons.MaxBytes+1))
	if err != nil {
		return nil, msgIconRead
	}
	if len(data) == 0 {
		return nil, "" // an empty file field: no file chosen
	}
	if _, problem := icons.Check(data); problem != "" {
		return nil, problem
	}
	return data, ""
}

// rotateAppSecret replaces a confidential app's secret and shows the new
// one in this response.
func (s *Server) rotateAppSecret(w http.ResponseWriter, r *http.Request) {
	a := s.loadApp(w, r)
	if a == nil {
		return
	}
	secret, err := s.admin.RotateAppSecret(r.Context(), adminActor(r), a.ID)
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "apps: rotate secret", err); ok {
			s.renderApp(w, r, a, fail.Status, Page{Error: fail.pageError(msgSecretNotMade)}, nil, fail.Fields)
		}
		return
	}
	s.showNewSecret(w, r, a, secret)
}

// deleteApp deletes the application once its name is typed to confirm,
// and shows the applications list.
func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	a := s.loadApp(w, r)
	if a == nil {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != a.Name {
		s.renderApp(w, r, a, http.StatusUnprocessableEntity, Page{Error: msgAppNotDeleted}, nil,
			fieldErrors{"confirm": msgConfirmAppName})
		return
	}
	if err := s.admin.DeleteApp(r.Context(), adminActor(r), a.ID); err != nil {
		if fail, ok := s.adminFailed(w, r, "apps: delete", err); ok {
			s.renderApp(w, r, a, fail.Status, Page{Error: fail.pageError(msgAppNotDeleted)}, nil, fail.Fields)
		}
		return
	}
	s.removeIconFile(a.ID, a.IconURL)
	redirectNotice(w, r, "/admin/apps", "deleted")
}
