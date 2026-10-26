package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"keywell/internal/admin"
	"keywell/internal/icons"
	"keywell/internal/model"
)

// maxTTLSeconds stops a huge number of seconds overflowing a Duration. It
// is far past the longest lifetime an app can have, so the admin service
// still refuses it.
const maxTTLSeconds = 1_000_000_000

// duration converts seconds from a request to a Duration; nil is 0, the
// global default.
func duration(seconds *int64) time.Duration {
	if seconds == nil {
		return 0
	}
	return time.Duration(max(min(*seconds, maxTTLSeconds), -maxTTLSeconds)) * time.Second
}

// groupIDs turns the allowed_groups of a request, names or IDs, into IDs.
// An unknown group is answered 422 invalid, naming allowed_groups, and ok
// is false.
func (h *handler) groupIDs(w http.ResponseWriter, r *http.Request, refs []string) (ids []string, ok bool) {
	ids, err := h.d.Admin.ResolveGroups(r.Context(), refs)
	var invalid *admin.ValidationError
	if errors.As(err, &invalid) && invalid.Fields["groups"] != "" {
		err = &admin.ValidationError{Fields: map[string]string{"allowed_groups": invalid.Fields["groups"]}}
	}
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return ids, true
}

// groupNameByID maps every group's ID to its name.
func (h *handler) groupNameByID(ctx context.Context) (map[string]string, error) {
	groups, err := h.d.Store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(groups))
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	return names, nil
}

// writeApp answers with application a. secret, when not empty, is added as
// client_secret: only the responses that made or replaced it have one.
func (h *handler) writeApp(w http.ResponseWriter, r *http.Request, status int, a *model.Application, secret string) {
	names, err := h.groupNameByID(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := newAppJSON(a, names)
	if secret == "" {
		writeJSON(w, status, out)
		return
	}
	writeJSON(w, status, struct {
		appJSON
		ClientSecret string `json:"client_secret"`
	}{out, secret})
}

// app finds the application named by the request's {id}: an ID or
// "slug:<slug>". Otherwise it answers and ok is false.
func (h *handler) app(w http.ResponseWriter, r *http.Request) (a *model.Application, ok bool) {
	a, err := h.d.Admin.ResolveApp(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return a, true
}

// removeIcon deletes the icon file iconURL names when app appID owns it.
// A failure is logged and does not undo the change that left the file
// unused.
func (h *handler) removeIcon(r *http.Request, appID, iconURL string) {
	if err := icons.RemoveIfOwned(h.d.DataDir, appID, iconURL); err != nil {
		h.d.Log.ErrorContext(r.Context(), "api: remove unused app icon", "app_id", appID, "error", err)
	}
}

// listApps answers GET /apps: every application, ordered by name, paged
// like any list.
func (h *handler) listApps(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	apps, err := h.d.Store.ListApplications(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	names, err := h.groupNameByID(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	apps, total := pageOf(apps, page, perPage)
	out := make([]appJSON, len(apps))
	for i := range apps {
		out[i] = newAppJSON(&apps[i], names)
	}
	writeJSON(w, http.StatusOK, newList(out, page, perPage, total))
}

// createApp answers POST /apps. A confidential app's response has its
// client_secret.
func (h *handler) createApp(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                   string   `json:"name"`
		Slug                   string   `json:"slug"`
		ClientType             string   `json:"client_type"`
		RedirectURIs           []string `json:"redirect_uris"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
		AllowedGroups          []string `json:"allowed_groups"`
		SubjectMode            string   `json:"subject_mode"`
		AccessTokenTTL         *int64   `json:"access_token_ttl"`
		IDTokenTTL             *int64   `json:"id_token_ttl"`
		RefreshTokenTTL        *int64   `json:"refresh_token_ttl"`
		LaunchURL              string   `json:"launch_url"`
		IconURL                string   `json:"icon_url"`
		Description            string   `json:"description"`
		ShowTile               bool     `json:"show_tile"`
		ServiceAccountID       string   `json:"service_account_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	groups, ok := h.groupIDs(w, r, in.AllowedGroups)
	if !ok {
		return
	}
	app, secret, err := h.d.Admin.CreateApp(r.Context(), actor(r), admin.AppInput{
		Name: in.Name, Slug: in.Slug, ClientType: model.ClientType(in.ClientType),
		RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
		AllowedGroupIDs: groups, SubjectMode: model.SubjectMode(in.SubjectMode),
		AccessTokenTTL: duration(in.AccessTokenTTL), IDTokenTTL: duration(in.IDTokenTTL),
		RefreshTokenTTL: duration(in.RefreshTokenTTL),
		LaunchURL:       in.LaunchURL, IconURL: in.IconURL, Description: in.Description,
		ShowTile: in.ShowTile, ServiceAccountID: in.ServiceAccountID,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeApp(w, r, http.StatusCreated, app, secret)
}

// getApp answers GET /apps/{id}.
func (h *handler) getApp(w http.ResponseWriter, r *http.Request) {
	if a, ok := h.app(w, r); ok {
		h.writeApp(w, r, http.StatusOK, a, "")
	}
}

// patchApp answers PATCH /apps/{id}. A field left out is kept. As in POST,
// null for a lifetime (or 0) means the global default, and null for
// service_account_id means none; other fields treat null as absent. The
// response has a client_secret when the app became confidential.
func (h *handler) patchApp(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                   *string   `json:"name"`
		Slug                   *string   `json:"slug"`
		ClientType             *string   `json:"client_type"`
		RedirectURIs           *[]string `json:"redirect_uris"`
		PostLogoutRedirectURIs *[]string `json:"post_logout_redirect_uris"`
		AllowedGroups          *[]string `json:"allowed_groups"`
		SubjectMode            *string   `json:"subject_mode"`
		LaunchURL              *string   `json:"launch_url"`
		IconURL                *string   `json:"icon_url"`
		Description            *string   `json:"description"`
		ShowTile               *bool     `json:"show_tile"`
		// Raw, to tell null (reset) from absent (leave alone).
		AccessTokenTTL   json.RawMessage `json:"access_token_ttl"`
		IDTokenTTL       json.RawMessage `json:"id_token_ttl"`
		RefreshTokenTTL  json.RawMessage `json:"refresh_token_ttl"`
		ServiceAccountID json.RawMessage `json:"service_account_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	old, ok := h.app(w, r)
	if !ok {
		return
	}
	patch := admin.AppPatch{
		Name: in.Name, Slug: in.Slug,
		RedirectURIs: in.RedirectURIs, PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
		LaunchURL: in.LaunchURL, IconURL: in.IconURL, Description: in.Description,
		ShowTile: in.ShowTile,
	}
	if in.ClientType != nil {
		v := model.ClientType(*in.ClientType)
		patch.ClientType = &v
	}
	if in.SubjectMode != nil {
		v := model.SubjectMode(*in.SubjectMode)
		patch.SubjectMode = &v
	}
	bad := map[string]string{}
	for _, t := range []struct {
		field string
		raw   json.RawMessage
		out   **time.Duration
	}{
		{"access_token_ttl", in.AccessTokenTTL, &patch.AccessTokenTTL},
		{"id_token_ttl", in.IDTokenTTL, &patch.IDTokenTTL},
		{"refresh_token_ttl", in.RefreshTokenTTL, &patch.RefreshTokenTTL},
	} {
		if len(t.raw) == 0 {
			continue // absent: leave alone
		}
		var secs *int64 // null: the global default
		if err := json.Unmarshal(t.raw, &secs); err != nil {
			bad[t.field] = msgBadSeconds
			continue
		}
		d := duration(secs)
		*t.out = &d
	}
	if len(in.ServiceAccountID) > 0 {
		var id string // null: machine sign-in off
		if err := json.Unmarshal(in.ServiceAccountID, &id); err != nil {
			bad["service_account_id"] = msgBadServiceAccount
		}
		patch.ServiceAccountID = &id
	}
	if len(bad) > 0 {
		writeInvalid(w, bad)
		return
	}
	if in.AllowedGroups != nil {
		ids, ok := h.groupIDs(w, r, *in.AllowedGroups)
		if !ok {
			return
		}
		patch.AllowedGroupIDs = &ids
	}
	app, secret, err := h.d.Admin.UpdateApp(r.Context(), actor(r), old.ID, patch)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if app.IconURL != old.IconURL {
		h.removeIcon(r, old.ID, old.IconURL)
	}
	h.writeApp(w, r, http.StatusOK, app, secret)
}

// deleteApp answers DELETE /apps/{id}, and removes the icon file the app
// owned.
func (h *handler) deleteApp(w http.ResponseWriter, r *http.Request) {
	app, ok := h.app(w, r)
	if !ok {
		return
	}
	if err := h.d.Admin.DeleteApp(r.Context(), actor(r), app.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.removeIcon(r, app.ID, app.IconURL)
	w.WriteHeader(http.StatusNoContent)
}

// rotateAppSecret answers POST /apps/{id}/rotate-secret with the new
// client secret.
func (h *handler) rotateAppSecret(w http.ResponseWriter, r *http.Request) {
	app, ok := h.app(w, r)
	if !ok {
		return
	}
	secret, err := h.d.Admin.RotateAppSecret(r.Context(), actor(r), app.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ClientSecret string `json:"client_secret"`
	}{secret})
}
