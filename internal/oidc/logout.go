package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/session"
	"latch/internal/store"
)

// logout handles GET and POST /oauth/logout, RP-initiated logout (OpenID
// Connect RP-Initiated Logout 1.0). It always ends the browser's session,
// if there is one. Signing out is always safe, so any site may send a
// member here, and a parameter that is missing or wrong never causes an
// error: the browser just stays on the signed-out page instead of going
// back to the application (see postLogoutTarget).
func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	params := r.URL.Query()
	if r.Method == http.MethodPost {
		params = url.Values{} // a form that cannot be read asks for nothing
		if r.ParseForm() == nil {
			params = r.PostForm
		}
	}
	_, user, signedIn := session.FromContext(ctx)
	app, target := p.postLogoutTarget(ctx, params, user)

	if err := p.d.Sessions.End(ctx, w, r); err != nil {
		p.serverError(w, r, "logout: end session", err)
		return
	}
	if signedIn {
		summary, detail := "Signed out", map[string]any{"via": "rp"}
		if app != nil {
			summary, detail["client_id"] = "Signed out from "+app.Name, app.ClientID
		}
		actorType, actorID := audit.UserActor(user.ID)
		p.d.Audit.Record(ctx, model.AuditEvent{ActorType: actorType, ActorID: actorID, Action: audit.Logout,
			TargetType: "user", TargetID: user.ID, Summary: summary, Detail: detail})
	}
	if target == "" {
		p.d.Renderer.RenderSignedOut(w, r)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// postLogoutTarget returns the application named by a valid id_token_hint
// in params (nil if there is none) and where to send the browser once user
// (nil without a session) is signed out: post_logout_redirect_uri with
// state added, or "" to show the signed-out page. The browser goes back
// only when the hint is valid, the address is exactly one registered for
// the hint's application, and the hint is for user; a hint for someone
// else did not come from this member's visit to the application.
func (p *Provider) postLogoutTarget(ctx context.Context, params url.Values, user *model.User) (*model.Application, string) {
	app, sub := p.logoutHint(ctx, params.Get("id_token_hint"))
	uri := params.Get("post_logout_redirect_uri")
	switch {
	case app == nil || uri == "":
		return app, ""
	case !slices.Contains(app.PostLogoutRedirectURIs, uri):
		p.d.Log.InfoContext(ctx, "logout: post_logout_redirect_uri is not registered",
			"client_id", app.ClientID, "uri", uri)
		return app, ""
	case user != nil && sub != Subject(user, app):
		p.d.Log.InfoContext(ctx, "logout: id_token_hint is for another member", "client_id", app.ClientID)
		return app, ""
	}
	target, err := url.Parse(uri)
	if err != nil {
		p.d.Log.WarnContext(ctx, "logout: registered post_logout_redirect_uri is not a URL",
			"client_id", app.ClientID, "error", err)
		return app, ""
	}
	q := url.Values{}
	if state := params.Get("state"); state != "" {
		q.Set("state", state)
	}
	return app, withQuery(*target, q)
}

// logoutHint returns the application an id_token_hint was issued to and the
// subject it names, or a nil application when raw is empty or is not an ID
// token this issuer signed for an application that exists. Its first
// audience names the application. exp is not checked: applications often
// send the hint after the ID token has expired.
func (p *Provider) logoutHint(ctx context.Context, raw string) (*model.Application, string) {
	if raw == "" {
		return nil, ""
	}
	claims, err := p.verifyJWT(raw, idTokenType)
	if err != nil {
		p.d.Log.InfoContext(ctx, "logout: id_token_hint ignored", "reason", err)
		return nil, ""
	}
	var clientID string
	switch aud := claims["aud"].(type) {
	case string:
		clientID = aud
	case []any:
		if len(aud) > 0 {
			clientID, _ = aud[0].(string)
		}
	}
	if clientID == "" {
		p.d.Log.InfoContext(ctx, "logout: id_token_hint ignored", "reason", "no audience")
		return nil, ""
	}
	app, err := p.d.Store.GetApplicationByClientID(ctx, clientID)
	if errors.Is(err, store.ErrNotFound) {
		p.d.Log.InfoContext(ctx, "logout: id_token_hint ignored", "reason", "unknown application", "client_id", clientID)
		return nil, ""
	}
	if err != nil {
		p.d.Log.ErrorContext(ctx, "logout: look up application", "error", err)
		return nil, ""
	}
	sub, _ := claims["sub"].(string)
	return app, sub
}
