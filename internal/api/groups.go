package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/store"
)

// groupResponse makes the JSON of group g, counting its members.
func (h *handler) groupResponse(ctx context.Context, g *model.Group) (groupJSON, error) {
	n, err := h.d.Store.ListUsers(ctx, store.UserFilter{GroupID: g.ID, PerPage: 1})
	if err != nil {
		return groupJSON{}, err
	}
	return newGroupJSON(g, n.Total), nil
}

// writeGroup answers with group g.
func (h *handler) writeGroup(w http.ResponseWriter, r *http.Request, status int, g *model.Group) {
	out, err := h.groupResponse(r.Context(), g)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, status, out)
}

// group finds the group named by the request's {id}: an ID or
// "name:<name>". Otherwise it answers and ok is false.
func (h *handler) group(w http.ResponseWriter, r *http.Request) (g *model.Group, ok bool) {
	g, err := h.d.Admin.ResolveGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return g, true
}

// listGroups answers GET /groups: every group, ordered by name, paged
// like any list.
func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	rows, err := h.d.Store.ListGroupsWithCounts(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rows, total := pageOf(rows, page, perPage)
	out := make([]groupJSON, len(rows))
	for i, row := range rows {
		out[i] = newGroupJSON(&row.Group, row.MemberCount)
	}
	writeJSON(w, http.StatusOK, newList(out, page, perPage, total))
}

// createGroup answers POST /groups.
func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		IsAdmin     bool            `json:"is_admin"`
		RequireTOTP bool            `json:"require_totp"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if !decode(w, r, &in) {
		return
	}
	meta, ok := h.metadataPatch(w, r, in.Metadata)
	if !ok {
		return
	}
	gi := admin.GroupInput{Name: in.Name, Description: in.Description, IsAdmin: in.IsAdmin, RequireTOTP: in.RequireTOTP}
	if meta != nil {
		gi.Metadata = *meta
	}
	g, err := h.d.Admin.CreateGroup(r.Context(), actor(r), gi)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeGroup(w, r, http.StatusCreated, g)
}

// getGroup answers GET /groups/{id}.
func (h *handler) getGroup(w http.ResponseWriter, r *http.Request) {
	if g, ok := h.group(w, r); ok {
		h.writeGroup(w, r, http.StatusOK, g)
	}
}

// patchGroup answers PATCH /groups/{id}.
func (h *handler) patchGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        *string         `json:"name"`
		Description *string         `json:"description"`
		IsAdmin     *bool           `json:"is_admin"`
		RequireTOTP *bool           `json:"require_totp"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if !decode(w, r, &in) {
		return
	}
	g, ok := h.group(w, r)
	if !ok {
		return
	}
	patch := admin.GroupPatch{Name: in.Name, Description: in.Description, IsAdmin: in.IsAdmin, RequireTOTP: in.RequireTOTP}
	if patch.Metadata, ok = h.metadataPatch(w, r, in.Metadata); !ok {
		return
	}
	g, err := h.d.Admin.UpdateGroup(r.Context(), actor(r), g.ID, patch)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeGroup(w, r, http.StatusOK, g)
}

// deleteGroup answers DELETE /groups/{id}.
func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := h.group(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.DeleteGroup(r.Context(), actor(r), g.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listGroupMembers answers GET /groups/{id}/members: members and service
// accounts.
func (h *handler) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	g, ok := h.group(w, r)
	if !ok {
		return
	}
	res, err := h.d.Store.ListUsers(r.Context(), store.UserFilter{GroupID: g.ID, Page: page, PerPage: perPage})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]groupMemberJSON, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = newGroupMemberJSON(&row.User)
	}
	writeJSON(w, http.StatusOK, newList(out, res.Page, res.PerPage, res.Total))
}
