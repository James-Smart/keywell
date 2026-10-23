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
// Connect RP-Initiated Logout 1.0). Any site may send a browser here, and
// the endpoint is exempt from cross-origin protection, so a session ends
// at once only when id_token_hint shows the request comes from this
// member's visit to an application: a valid ID token for them. Otherwise
// the member is asked first (§2), on the confirmation page of GET /logout,
// whose form is cross-origin protected; no return address is carried
// there. A browser with no session is shown the signed-out page, or sent
// back to the application (see postLogoutTarget). A parameter that is
// missing or wrong never causes an error.
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
	app, sub := p.logoutHint(ctx, params.Get("id_token_hint"))
	if signedIn && (app == nil || sub != Subject(user, app)) {
		if app != nil {
			p.d.Log.InfoContext(ctx, "logout: id_token_hint is for another member", "client_id", app.ClientID)
		}
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}

	target := p.postLogoutTarget(ctx, app, params)
	if err := p.d.Sessions.End(ctx, w, r); err != nil {
		p.serverError(w, r, "logout: end session", err)
		return
	}
	if signedIn { // so app is the hint's application, not nil
		actorType, actorID := audit.UserActor(user.ID)
		p.d.Audit.Record(ctx, model.AuditEvent{ActorType: actorType, ActorID: actorID, Action: audit.Logout,
			TargetType: "user", TargetID: user.ID, Summary: "Signed out from " + app.Name,
			Detail: map[string]any{"via": "rp", "client_id": app.ClientID}})
	}
	if target == "" {
		p.d.Renderer.RenderSignedOut(w, r)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// postLogoutTarget returns where to send the browser after logout for app,
// the application a valid id_token_hint named (nil if none did):
// post_logout_redirect_uri with state added, or "" to show the signed-out
// page. The browser goes back only to an address registered for app,
// exactly, and not when client_id names a different application.
func (p *Provider) postLogoutTarget(ctx context.Context, app *model.Application, params url.Values) string {
	uri := params.Get("post_logout_redirect_uri")
	switch {
	case app == nil || uri == "":
		return ""
	case params.Get("client_id") != "" && params.Get("client_id") != app.ClientID:
		p.d.Log.InfoContext(ctx, "logout: client_id differs from the id_token_hint's application",
			"client_id", app.ClientID)
		return ""
	case !slices.Contains(app.PostLogoutRedirectURIs, uri):
		p.d.Log.InfoContext(ctx, "logout: post_logout_redirect_uri is not registered",
			"client_id", app.ClientID, "uri", uri)
		return ""
	}
	target, err := url.Parse(uri)
	if err != nil {
		p.d.Log.WarnContext(ctx, "logout: registered post_logout_redirect_uri is not a URL",
			"client_id", app.ClientID, "error", err)
		return ""
	}
	q := url.Values{}
	if state := params.Get("state"); state != "" {
		q.Set("state", state)
	}
	return withQuery(*target, q)
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
