package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/store"
)

// Messages of the groups pages' own checks and the summaries shown at the
// top when an action fails; see adminFailure.pageError.
const (
	msgConfirmGroupName = "Type the name exactly to confirm."
	msgGroupNotDeleted  = "The group wasn't deleted. See Delete group below."
	msgNotAdded         = "They weren't added to the group."
	msgNotRemoved       = "They weren't removed from the group."
)

// addCandidates is how many people the add search lists at most.
const addCandidates = 20

// groupsData is what admin_groups.html shows.
type groupsData struct{ Rows []store.GroupRow }

// groupsPage lists the groups with their member counts.
func (s *Server) groupsPage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.ListGroupsWithCounts(r.Context())
	if err != nil {
		s.serverError(w, r, "groups: list", err)
		return
	}
	s.d.Renderer.Render(w, r, http.StatusOK, "admin_groups",
		Page{Title: "Groups", Section: "groups", Notice: adminNotice(r), Data: groupsData{Rows: rows}})
}

// groupForm is the add or edit form, as typed or as stored.
type groupForm struct {
	Name, Description    string
	IsAdmin, RequireTOTP bool
	Metadata             string // JSON text
}

// readGroupForm reads the add or edit form from the request.
func readGroupForm(r *http.Request) groupForm {
	return groupForm{
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		IsAdmin:     r.PostFormValue("is_admin") != "",
		RequireTOTP: r.PostFormValue("require_totp") != "",
		Metadata:    r.PostFormValue("metadata"),
	}
}

// groupData is what admin_group.html shows. Group is nil on the add form,
// which has no members section.
type groupData struct {
	Group    *model.Group
	Form     groupForm
	Metadata metadataField
	Errors   fieldErrors

	Members   []store.UserRow
	Pager     pager
	Query     string          // the add search, as applied
	Matches   []store.UserRow // people the search found who can be added
	Delete    confirmBox
	Heading   string
	SubmitTxt string
}

// newGroupPage shows the add form.
func (s *Server) newGroupPage(w http.ResponseWriter, r *http.Request) {
	s.renderGroup(w, r, nil, http.StatusOK, Page{}, &groupForm{Metadata: "{}"}, nil)
}

// createGroup adds a group and shows its page.
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	f := readGroupForm(r)
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		s.renderGroup(w, r, nil, http.StatusUnprocessableEntity, Page{}, &f, invalid.Fields)
		return
	}
	g, err := s.admin.CreateGroup(r.Context(), adminActor(r), admin.GroupInput{
		Name: f.Name, Description: f.Description, IsAdmin: f.IsAdmin, RequireTOTP: f.RequireTOTP, Metadata: meta,
	})
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "groups: add", err); ok {
			s.renderGroup(w, r, nil, fail.Status, Page{Error: fail.Message}, &f, fail.Fields)
		}
		return
	}
	redirectNotice(w, r, "/admin/groups/"+g.ID, "saved")
}

// loadGroup returns the group the path's {id} names. When there is none
// it writes the 404 page (or the 500 page when the read fails) and
// returns nil.
func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request) *model.Group {
	g, err := s.d.Store.GetGroup(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.adminNotFound(w, r)
		return nil
	case err != nil:
		s.serverError(w, r, "groups: get group", err)
		return nil
	}
	return g
}

// groupPage shows a group: its form, its members, and a search for
// people to add (?q=).
func (s *Server) groupPage(w http.ResponseWriter, r *http.Request) {
	if g := s.loadGroup(w, r); g != nil {
		s.renderGroup(w, r, g, http.StatusOK, Page{Notice: adminNotice(r)}, nil, nil)
	}
}

// renderGroup writes the add form (g nil) or g's page. A nil form means g as stored; otherwise it is what was typed, with errs
// beside the fields.
func (s *Server) renderGroup(w http.ResponseWriter, r *http.Request, g *model.Group, status int, p Page,
	f *groupForm, errs fieldErrors) {
	d := groupData{Errors: errs, Heading: "Add group", SubmitTxt: "Add group"}
	if g != nil {
		if f == nil {
			f = &groupForm{g.Name, g.Description, g.IsAdmin, g.RequireTOTP, prettyJSON(g.Metadata)}
		}
		d.Group, d.Heading, d.SubmitTxt = g, g.Name, "Save changes"
		if err := s.loadGroupMembers(r, g, &d); err != nil {
			s.serverError(w, r, "groups: list members", err)
			return
		}
		d.Delete = confirmBox{
			Summary: "Delete group",
			Message: "This removes the group and everyone's place in it. Apps that only this group could open will no longer open for them. The people themselves are kept.",
			Action:  "/admin/groups/" + g.ID + "/delete",
			Button:  "Delete group",
			Typed:   "Type the group's name to confirm",
			Error:   errs["confirm"],
		}
		p.Title = g.Name
	} else {
		p.Title = "Add group"
	}
	if f == nil {
		f = &groupForm{Metadata: "{}"}
	}
	d.Form, d.Metadata = *f, newMetadataField(f.Metadata, errs["metadata"])
	p.Section, p.Data = "groups", d
	s.d.Renderer.Render(w, r, status, "admin_group", p)
}

// loadGroupMembers fills d with g's members, a page at a time, and the
// people the add search (?q=) finds who are not in g.
func (s *Server) loadGroupMembers(r *http.Request, g *model.Group, d *groupData) error {
	ctx := r.Context()
	page, err := s.d.Store.ListUsers(ctx, store.UserFilter{GroupID: g.ID, Page: pageNumber(r), PerPage: listPerPage})
	if err != nil {
		return err
	}
	d.Members = page.Rows
	d.Pager = newPager("/admin/groups/"+g.ID, nil, page.Page, page.PerPage, page.Total)

	d.Query = strings.TrimSpace(r.URL.Query().Get("q"))
	if d.Query == "" {
		return nil
	}
	found, err := s.d.Store.ListUsers(ctx, store.UserFilter{Query: d.Query, PerPage: 500})
	if err != nil {
		return err
	}
	for _, row := range found.Rows {
		if slices.ContainsFunc(row.Groups, func(h model.Group) bool { return h.ID == g.ID }) {
			continue
		}
		if d.Matches = append(d.Matches, row); len(d.Matches) == addCandidates {
			break
		}
	}
	return nil
}

// saveGroup saves the edit form: name, description, both flags and
// metadata.
func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request) {
	g := s.loadGroup(w, r)
	if g == nil {
		return
	}
	f := readGroupForm(r)
	meta, invalid := admin.ParseMetadata(f.Metadata)
	if invalid != nil {
		s.renderGroup(w, r, g, http.StatusUnprocessableEntity, Page{}, &f, invalid.Fields)
		return
	}
	_, err := s.admin.UpdateGroup(r.Context(), adminActor(r), g.ID, admin.GroupPatch{
		Name: &f.Name, Description: &f.Description, IsAdmin: &f.IsAdmin, RequireTOTP: &f.RequireTOTP, Metadata: &meta,
	})
	if err != nil {
		if fail, ok := s.adminFailed(w, r, "groups: save", err); ok {
			s.renderGroup(w, r, g, fail.Status, Page{Error: fail.Message}, &f, fail.Fields)
		}
		return
	}
	redirectNotice(w, r, "/admin/groups/"+g.ID, "saved")
}

// groupAction makes the change do and returns to the group's page with
// notice. When it fails the page is shown again, as stored, saying why.
func (s *Server) groupAction(w http.ResponseWriter, r *http.Request, what, notice, summary string,
	do func(ctx context.Context, a admin.Actor, groupID string) error) {
	g := s.loadGroup(w, r)
	if g == nil {
		return
	}
	if err := do(r.Context(), adminActor(r), g.ID); err != nil {
		if fail, ok := s.adminFailed(w, r, what, err); ok {
			s.renderGroup(w, r, g, fail.Status, Page{Error: fail.pageError(summary)}, nil, fail.Fields)
		}
		return
	}
	redirectNotice(w, r, "/admin/groups/"+g.ID, notice)
}

// addGroupMember adds the member or service account in field user_id.
func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request) {
	userID := r.PostFormValue("user_id")
	s.groupAction(w, r, "groups: add member", "member_added", msgNotAdded,
		func(ctx context.Context, a admin.Actor, groupID string) error {
			return s.admin.AddToGroup(ctx, a, userID, groupID)
		})
}

// removeGroupMember removes the person the path's {uid} names.
func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("uid")
	s.groupAction(w, r, "groups: remove member", "member_removed", msgNotRemoved,
		func(ctx context.Context, a admin.Actor, groupID string) error {
			return s.admin.RemoveFromGroup(ctx, a, userID, groupID)
		})
}

// deleteGroup deletes the group once its name is typed to confirm, and
// shows the groups list.
func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g := s.loadGroup(w, r)
	if g == nil {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != g.Name {
		s.renderGroup(w, r, g, http.StatusUnprocessableEntity, Page{Error: msgGroupNotDeleted}, nil,
			fieldErrors{"confirm": msgConfirmGroupName})
		return
	}
	if err := s.admin.DeleteGroup(r.Context(), adminActor(r), g.ID); err != nil {
		if fail, ok := s.adminFailed(w, r, "groups: delete", err); ok {
			s.renderGroup(w, r, g, fail.Status, Page{Error: fail.pageError(msgGroupNotDeleted)}, nil, fail.Fields)
		}
		return
	}
	redirectNotice(w, r, "/admin/groups", "deleted")
}
