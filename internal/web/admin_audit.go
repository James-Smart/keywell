package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"latch/internal/model"
	"latch/internal/store"
)

// auditCategories are the audit log's categories, in order. Actions are
// the action prefixes each one shows; "all" has none, so it shows every
// event.
var auditCategories = []struct {
	Key, Label string
	Actions    []string
}{
	{"changes", "Changes", []string{"user.", "group.", "app.", "service_account.", "api_token.", "settings.", "oidc.key."}},
	{"signins", "Sign-ins", []string{"login.", "logout", "oidc.authorize."}},
	{"tokens", "App tokens", []string{"oidc.token."}},
	{"all", "Everything", nil},
}

// auditDays is how far back the log goes when ?from= is missing or bad.
const auditDays = 30

const auditDateLayout = "2006-01-02"

// auditData is what admin_audit.html shows.
type auditData struct {
	Category, Action, Query string
	From, To                string // the dates applied, YYYY-MM-DD; To is "" when unbounded
	ActorID, TargetID       string
	ActorName, TargetName   string // who ActorID and TargetID are, for the line above the table
	Categories              []listFilter
	Rows                    []auditView
	Pager                   pager
}

// auditView is a row of the audit table.
type auditView struct {
	At                 time.Time
	Actor, ActorLink   string // ActorLink is "" for an actor with no ID
	Summary, Action    string
	Count              int
	ActionLink         string
	Target, TargetLink string // both "" when the event has no target; TargetLink "" when it is gone
}

// auditLookup finds each user, group or application once.
type auditLookup struct {
	ctx    context.Context
	st     *store.Store
	users  map[string]*model.User
	groups map[string]*model.Group
	apps   map[string]*model.Application
}

func newAuditLookup(ctx context.Context, st *store.Store) *auditLookup {
	return &auditLookup{ctx: ctx, st: st, users: map[string]*model.User{},
		groups: map[string]*model.Group{}, apps: map[string]*model.Application{}}
}

// user returns the user with id, or nil when there is none.
func (l *auditLookup) user(id string) (*model.User, error) {
	if u, ok := l.users[id]; ok {
		return u, nil
	}
	u, err := l.st.GetUser(l.ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		u, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.users[id] = u
	return u, nil
}

// group returns the group with id, or nil when there is none.
func (l *auditLookup) group(id string) (*model.Group, error) {
	if g, ok := l.groups[id]; ok {
		return g, nil
	}
	g, err := l.st.GetGroup(l.ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		g, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.groups[id] = g
	return g, nil
}

// app returns the application with id, or nil when there is none.
func (l *auditLookup) app(id string) (*model.Application, error) {
	if a, ok := l.apps[id]; ok {
		return a, nil
	}
	a, err := l.st.GetApplication(l.ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		a, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.apps[id] = a
	return a, nil
}

// userName is how an account is shown: its name, or its email.
func userName(u *model.User) string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

// userPage is the admin page of u: a member's or a service account's.
func userPage(u *model.User) string {
	if u.Type == model.UserTypeService {
		return "/admin/service-accounts/" + u.ID
	}
	return "/admin/members/" + u.ID
}

// actor names the actor of e and links to its activity.
func (l *auditLookup) actor(e model.AuditEvent) (name, link string, err error) {
	if e.ActorID != "" {
		link = "/admin/audit?" + url.Values{"actor": {e.ActorID}, "category": {"all"}}.Encode()
	}
	switch e.ActorType {
	case model.ActorSystem:
		return "Latch", link, nil
	case model.ActorImporter:
		return "Importer", link, nil
	}
	u, err := l.user(e.ActorID)
	if err != nil {
		return "", "", err
	}
	if u == nil {
		return "Deleted account", link, nil
	}
	return userName(u), link, nil
}

// target names the target of e and links to its admin page. When the
// record is gone, or its type has no page (an API token), the name is the
// one the event kept in its detail (see keptName) and link is "". Both are
// "" when it has no target.
func (l *auditLookup) target(e model.AuditEvent) (name, link string, err error) {
	if e.TargetID == "" {
		return "", "", nil
	}
	switch e.TargetType {
	case "user", "service_account":
		u, err := l.user(e.TargetID)
		if err != nil || u != nil {
			if err != nil {
				return "", "", err
			}
			return userName(u), userPage(u), nil
		}
	case "group":
		g, err := l.group(e.TargetID)
		if err != nil || g != nil {
			if err != nil {
				return "", "", err
			}
			return g.Name, "/admin/groups/" + g.ID, nil
		}
	case "application":
		a, err := l.app(e.TargetID)
		if err != nil || a != nil {
			if err != nil {
				return "", "", err
			}
			return a.Name, "/admin/apps/" + a.ID, nil
		}
	}
	return keptName(e.Detail), "", nil
}

// keptName is the name an event's detail kept for its target, so a deleted
// record can still be named: its name, else its email, username or label
// (an API token's). It is "" when the detail has none of them.
func keptName(detail map[string]any) string {
	for _, key := range []string{"name", "email", "username", "label"} {
		if s, ok := detail[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// subject names whatever id is (an account, group or application), for
// the line that says whose activity is shown. It falls back to the id.
func (l *auditLookup) subject(id string) (string, error) {
	u, err := l.user(id)
	if err != nil || u != nil {
		if err != nil {
			return "", err
		}
		return userName(u), nil
	}
	g, err := l.group(id)
	if err != nil || g != nil {
		if err != nil {
			return "", err
		}
		return g.Name, nil
	}
	a, err := l.app(id)
	if err != nil || a != nil {
		if err != nil {
			return "", err
		}
		return a.Name, nil
	}
	return id, nil
}

// auditPage lists audit events, 50 a page, newest first. ?category= picks
// the kinds of event (default changes); ?action= replaces its list with
// one action prefix; ?from= and ?to= are UTC dates (default from is 30
// days ago; to is inclusive); ?q= searches the summary; ?actor= and
// ?target= show one ID's activity.
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := auditData{
		Category: "changes", Action: strings.TrimSpace(q.Get("action")), Query: strings.TrimSpace(q.Get("q")),
		ActorID: strings.TrimSpace(q.Get("actor")), TargetID: strings.TrimSpace(q.Get("target")),
	}
	var actions []string
	for _, c := range auditCategories {
		d.Categories = append(d.Categories, listFilter{c.Key, c.Label})
		if c.Key == q.Get("category") {
			d.Category = c.Key
		}
	}
	for _, c := range auditCategories {
		if c.Key == d.Category {
			actions = c.Actions
		}
	}
	if d.Action != "" {
		actions = []string{d.Action}
	}

	f := store.AuditFilter{
		ActorID: d.ActorID, TargetID: d.TargetID, Actions: actions, Query: d.Query,
		CollapseLoginFailures: true, Page: pageNumber(r), PerPage: listPerPage,
	}
	params := url.Values{"category": {d.Category}}
	f.Since = s.d.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -auditDays)
	if t, err := time.Parse(auditDateLayout, q.Get("from")); err == nil {
		f.Since = t
		params.Set("from", q.Get("from"))
	}
	d.From = f.Since.Format(auditDateLayout)
	if t, err := time.Parse(auditDateLayout, q.Get("to")); err == nil {
		f.Until = t.AddDate(0, 0, 1)
		d.To = q.Get("to")
		params.Set("to", d.To)
	}
	for k, v := range map[string]string{"action": d.Action, "q": d.Query, "actor": d.ActorID, "target": d.TargetID} {
		if v != "" {
			params.Set(k, v)
		}
	}

	page, err := s.d.Store.ListAuditEvents(r.Context(), f)
	if err != nil {
		s.serverError(w, r, "audit: list", err)
		return
	}
	l := newAuditLookup(r.Context(), s.d.Store)
	for _, row := range page.Rows {
		v := auditView{At: row.At, Summary: row.Summary, Action: row.Action, Count: row.Count,
			ActionLink: "/admin/audit?" + url.Values{"action": {row.Action}, "category": {"all"}}.Encode()}
		if v.Actor, v.ActorLink, err = l.actor(row.AuditEvent); err == nil {
			v.Target, v.TargetLink, err = l.target(row.AuditEvent)
		}
		if err != nil {
			s.serverError(w, r, "audit: look up names", err)
			return
		}
		d.Rows = append(d.Rows, v)
	}
	if d.ActorID != "" {
		d.ActorName, err = l.subject(d.ActorID)
	}
	if err == nil && d.TargetID != "" {
		d.TargetName, err = l.subject(d.TargetID)
	}
	if err != nil {
		s.serverError(w, r, "audit: look up names", err)
		return
	}
	d.Pager = newPager("/admin/audit", params, page.Page, page.PerPage, page.Total)
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_audit", Page{Title: "Audit log", Section: "audit", Data: d})
}
