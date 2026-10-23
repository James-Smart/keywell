package api

import (
	"encoding/json"
	"net/http"
	"time"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/store"
)

// serviceAccount finds the service account named by the request's {id}: an
// ID or "username:<name>". Otherwise it answers and ok is false.
func (h *handler) serviceAccount(w http.ResponseWriter, r *http.Request) (u *model.User, ok bool) {
	u, err := h.d.Admin.ResolveServiceAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return u, true
}

// writeServiceAccount answers with service account u.
func (h *handler) writeServiceAccount(w http.ResponseWriter, r *http.Request, status int, u *model.User) {
	row, err := h.serviceAccountRow(r.Context(), u)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, status, newServiceAccountJSON(row))
}

// listServiceAccounts answers GET /service-accounts, with ?q= matching name
// or username.
func (h *handler) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	res, err := h.d.Store.ListUsers(r.Context(), store.UserFilter{
		Type: model.UserTypeService, Query: r.URL.Query().Get("q"), Page: page, PerPage: perPage})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]serviceAccountJSON, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = newServiceAccountJSON(row)
	}
	writeJSON(w, http.StatusOK, newList(out, res.Page, res.PerPage, res.Total))
}

// createServiceAccount answers POST /service-accounts.
func (h *handler) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string          `json:"name"`
		Username    string          `json:"username"`
		Description string          `json:"description"`
		Groups      []string        `json:"groups"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if !decode(w, r, &in) {
		return
	}
	meta, ok := h.metadataPatch(w, r, in.Metadata)
	if !ok {
		return
	}
	groups, err := h.d.Admin.ResolveGroups(r.Context(), in.Groups)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	si := admin.ServiceAccountInput{Name: in.Name, Username: in.Username, Description: in.Description, GroupIDs: groups}
	if meta != nil {
		si.Metadata = *meta
	}
	u, err := h.d.Admin.CreateServiceAccount(r.Context(), actor(r), si)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeServiceAccount(w, r, http.StatusCreated, u)
}

// getServiceAccount answers GET /service-accounts/{id}.
func (h *handler) getServiceAccount(w http.ResponseWriter, r *http.Request) {
	if u, ok := h.serviceAccount(w, r); ok {
		h.writeServiceAccount(w, r, http.StatusOK, u)
	}
}

// patchServiceAccount answers PATCH /service-accounts/{id}.
func (h *handler) patchServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        *string         `json:"name"`
		Username    *string         `json:"username"`
		Description *string         `json:"description"`
		Groups      *[]string       `json:"groups"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := h.serviceAccount(w, r)
	if !ok {
		return
	}
	patch := admin.ServiceAccountPatch{Name: in.Name, Username: in.Username, Description: in.Description}
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
	u, err := h.d.Admin.UpdateServiceAccount(r.Context(), actor(r), u.ID, patch)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeServiceAccount(w, r, http.StatusOK, u)
}

// deleteServiceAccount answers DELETE /service-accounts/{id}.
func (h *handler) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	u, ok := h.serviceAccount(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.DeleteServiceAccount(r.Context(), actor(r), u.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listTokens answers GET /service-accounts/{id}/tokens, newest first.
func (h *handler) listTokens(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	u, ok := h.serviceAccount(w, r)
	if !ok {
		return
	}
	tokens, err := h.d.Store.ListAPITokens(r.Context(), u.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	tokens, total := pageOf(tokens, page, perPage)
	out := make([]tokenJSON, len(tokens))
	for i := range tokens {
		out[i] = newTokenJSON(&tokens[i])
	}
	writeJSON(w, http.StatusOK, newList(out, page, perPage, total))
}

// createToken answers POST /service-accounts/{id}/tokens. The response has
// the raw token, which can't be shown again.
func (h *handler) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label     string  `json:"label"`
		Scope     string  `json:"scope"`
		ExpiresAt *string `json:"expires_at"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, ok := h.serviceAccount(w, r)
	if !ok {
		return
	}
	nt := admin.NewToken{Label: in.Label, Scope: model.APITokenScope(in.Scope)}
	if in.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *in.ExpiresAt)
		if err != nil {
			writeInvalid(w, map[string]string{"expires_at": msgBadExpiry})
			return
		}
		nt.ExpiresAt = &t
	}
	t, raw, err := h.d.Admin.CreateToken(r.Context(), actor(r), u.ID, nt)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		tokenJSON
		Token string `json:"token"`
	}{newTokenJSON(t), raw})
}

// deleteToken answers DELETE /service-accounts/{id}/tokens/{tid}.
func (h *handler) deleteToken(w http.ResponseWriter, r *http.Request) {
	u, ok := h.serviceAccount(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.RevokeToken(r.Context(), actor(r), u.ID, r.PathValue("tid")); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
