package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"keywell/internal/admin"
	"keywell/internal/model"
	"keywell/internal/store"
)

// memberStatuses are the ?status= values GET /users takes.
var memberStatuses = []string{"active", "invited", "needs_password", "disabled", "no_2fa", "admins"}

// userResponse makes the JSON of member u, reading its status and groups.
func (h *handler) userResponse(ctx context.Context, u *model.User) (userJSON, error) {
	status, err := h.d.Store.GetUserStatus(ctx, u)
	if err != nil {
		return userJSON{}, err
	}
	groups, err := h.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return userJSON{}, err
	}
	return newUserJSON(u, status, groups), nil
}

// writeUser answers with member u as saved, with status.
func (h *handler) writeUser(w http.ResponseWriter, r *http.Request, status int, u *model.User) {
	out, err := h.userResponse(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, status, out)
}

// reloadUser answers with the member with this ID as it is now.
func (h *handler) reloadUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.d.Store.GetUser(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeUser(w, r, http.StatusOK, u)
}

// member finds the member named by the request's {id} (an ID or
// "email:<address>"). Otherwise it answers (404 for a service account too)
// and ok is false.
func (h *handler) member(w http.ResponseWriter, r *http.Request) (u *model.User, ok bool) {
	u, err := h.d.Admin.ResolveMember(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return u, true
}

// groupRef finds the group a path segment names: an ID, "name:<name>" or
// a bare name.
func (h *handler) groupRef(ctx context.Context, ref string) (*model.Group, error) {
	g, err := h.d.Admin.ResolveGroup(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		g, err = h.d.Store.GetGroupByName(ctx, ref)
	}
	return g, err
}

// listUsers answers GET /users.
func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx, q := r.Context(), r.URL.Query()
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	f := store.UserFilter{Type: model.UserTypeMember, Query: q.Get("q"), Status: q.Get("status"), Page: page, PerPage: perPage}
	if f.Status != "" && !slices.Contains(memberStatuses, f.Status) {
		writeInvalid(w, map[string]string{"status": msgStatusUnknown})
		return
	}
	if ref := q.Get("group"); ref != "" {
		g, err := h.groupRef(ctx, ref)
		if errors.Is(err, store.ErrNotFound) {
			writeInvalid(w, map[string]string{"group": `No group called "` + ref + `".`})
			return
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		f.GroupID = g.ID
	}
	res, err := h.d.Store.ListUsers(ctx, f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]userJSON, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = newUserJSON(&row.User, row.Status, row.Groups)
	}
	writeJSON(w, http.StatusOK, newList(out, res.Page, res.PerPage, res.Total))
}

// createUser answers POST /users.
func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string          `json:"name"`
		Email    string          `json:"email"`
		Username string          `json:"username"`
		Groups   []string        `json:"groups"`
		Metadata json.RawMessage `json:"metadata"`
		Invite   bool            `json:"invite"`
		Password string          `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	meta, ok := h.metadataPatch(w, r, in.Metadata)
	if !ok {
		return
	}
	nm := admin.NewMember{Name: in.Name, Email: in.Email, Username: in.Username, Invite: in.Invite, Password: in.Password}
	if meta != nil {
		nm.Metadata = *meta
	}
	var err error
	if nm.GroupIDs, err = h.d.Admin.ResolveGroups(r.Context(), in.Groups); err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := h.d.Admin.CreateMember(r.Context(), actor(r), nm)
	var unsent *admin.EmailError
	if errors.As(err, &unsent) && u != nil {
		h.logUnsent(r, "api: send invitation", u, err)
		out, err := h.userResponse(r.Context(), u)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			userJSON
			InviteError string `json:"invite_error"`
		}{out, msgInviteNotSent})
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeUser(w, r, http.StatusCreated, u)
}

// getUser answers GET /users/{id}.
func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	if u, ok := h.member(w, r); ok {
		h.writeUser(w, r, http.StatusOK, u)
	}
}

// patchUser answers PATCH /users/{id}.
func (h *handler) patchUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     *string         `json:"name"`
		Email    *string         `json:"email"`
		Username *string         `json:"username"`
		Groups   *[]string       `json:"groups"`
		Metadata json.RawMessage `json:"metadata"`
		IsActive *bool           `json:"is_active"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	patch := admin.MemberPatch{Name: in.Name, Email: in.Email, Username: in.Username, IsActive: in.IsActive}
	if patch.Metadata, ok = h.metadataPatch(w, r, in.Metadata); !ok {
		return
	}
	if in.Groups != nil {
		ids, err := h.d.Admin.ResolveGroups(r.Context(), *in.Groups)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		patch.GroupIDs = &ids
	}
	if _, err := h.d.Admin.UpdateMember(r.Context(), actor(r), u.ID, patch); err != nil {
		h.fail(w, r, err)
		return
	}
	h.reloadUser(w, r, u.ID)
}

// deleteUser answers DELETE /users/{id}.
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.DeleteMember(r.Context(), actor(r), u.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resetEmail answers POST /users/{id}/reset-email: an invitation for a
// member with no password, otherwise a reset link.
func (h *handler) resetEmail(w http.ResponseWriter, r *http.Request) {
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	purpose, err := h.d.Admin.SendPasswordEmail(r.Context(), actor(r), u.ID)
	var unsent *admin.EmailError
	if errors.As(err, &unsent) {
		h.failUnsent(w, r, "api: send password email", u, err)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	sent := "reset"
	if purpose == model.ResetPurposeInvite {
		sent = "invite"
	}
	writeJSON(w, http.StatusOK, map[string]string{"sent": sent})
}

// setUserPassword answers POST /users/{id}/password.
func (h *handler) setUserPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.SetMemberPassword(r.Context(), actor(r), u.ID, in.Password); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clearUserTOTP answers POST /users/{id}/totp/clear.
func (h *handler) clearUserTOTP(w http.ResponseWriter, r *http.Request) {
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.ClearMemberTOTP(r.Context(), actor(r), u.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeUserSessions answers POST /users/{id}/sessions/revoke.
func (h *handler) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.SignOutEverywhere(r.Context(), actor(r), u.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setUserGroups answers PUT /users/{id}/groups: the complete list.
func (h *handler) setUserGroups(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Groups *[]string `json:"groups"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	if in.Groups == nil {
		writeInvalid(w, map[string]string{"groups": msgGroupsRequired})
		return
	}
	ids, err := h.d.Admin.ResolveGroups(r.Context(), *in.Groups)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if _, err := h.d.Admin.UpdateMember(r.Context(), actor(r), u.ID, admin.MemberPatch{GroupIDs: &ids}); err != nil {
		h.fail(w, r, err)
		return
	}
	h.reloadUser(w, r, u.ID)
}

// addUserGroup answers POST /users/{id}/groups/{group}.
func (h *handler) addUserGroup(w http.ResponseWriter, r *http.Request) {
	h.changeUserGroup(w, r, h.d.Admin.AddToGroup)
}

// removeUserGroup answers DELETE /users/{id}/groups/{group}.
func (h *handler) removeUserGroup(w http.ResponseWriter, r *http.Request) {
	h.changeUserGroup(w, r, h.d.Admin.RemoveFromGroup)
}

// changeUserGroup finds the member and the group of the request, applies
// change (AddToGroup or RemoveFromGroup) and answers with the member.
func (h *handler) changeUserGroup(w http.ResponseWriter, r *http.Request, change func(ctx context.Context, a admin.Actor, userID, groupID string) error) {
	u, ok := h.member(w, r)
	if !ok {
		return
	}
	g, err := h.groupRef(r.Context(), strings.TrimSpace(r.PathValue("group")))
	if err == nil {
		err = change(r.Context(), actor(r), u.ID, g.ID)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.reloadUser(w, r, u.ID)
}
