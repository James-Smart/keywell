package oidc

import (
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
)

// pkceS256 is the only PKCE method accepted (RFC 7636 §4.2); plain is not.
const pkceS256 = "S256"

// codeTTL is how long an authorization code can be exchanged (spec §6.2).
const codeTTL = 60 * time.Second

// authRequest is a validated authorization request.
type authRequest struct {
	scopes                     []string
	nonce                      string
	challenge, challengeMethod string
	promptNone, promptLogin    bool
	maxAge                     int64 // seconds; -1 when not given
}

// tooOld reports whether a session that began at created is older than the
// request's max_age.
func (a *authRequest) tooOld(now, created time.Time) bool {
	return a.maxAge >= 0 && now.Sub(created).Seconds() > float64(a.maxAge)
}

// oauthError is an error returned to the application (RFC 6749 §4.1.2.1).
type oauthError struct{ code, description string }

var errServer = &oauthError{"server_error", "something went wrong on our side, try again"}

// authorize handles GET and POST /oauth/authorize, the start of the
// authorization code flow. Until the client and redirect URI check out,
// problems are shown on an error page and the browser is never sent
// anywhere; after that they go back to the application as error redirects.
// A member signed in with every login step passed, recently enough, gets a
// code; anyone else is sent to sign in and returns here.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	params := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			p.badLink(w, r, "That application sent a request we couldn't read.")
			return
		}
		params = r.PostForm
	}

	app, err := p.d.Store.GetApplicationByClientID(ctx, params.Get("client_id"))
	if errors.Is(err, store.ErrNotFound) {
		p.badLink(w, r, "Unknown application.")
		return
	}
	if err != nil {
		p.serverError(w, r, "authorize: look up application", err)
		return
	}
	redirectURI := params.Get("redirect_uri")
	target, err := url.Parse(redirectURI)
	if err != nil || !MatchRedirectURI(app.RedirectURIs, redirectURI) {
		p.badLink(w, r, "That application sent an address we don't recognise.")
		return
	}
	state := params.Get("state")
	fail := func(e *oauthError) {
		p.redirectToClient(w, r, target, state, url.Values{"error": {e.code}, "error_description": {e.description}})
	}

	req, oerr := parseAuthRequest(app, params)
	if oerr != nil {
		fail(oerr)
		return
	}
	sess, user, ok := session.FromContext(ctx)
	// Only members use the login pages; the session middleware already
	// drops anyone else's session.
	ok = ok && user.Type == model.UserTypeMember
	if !ok || !sess.TOTPPassed || req.promptLogin || req.tooOld(p.now(), sess.CreatedAt) {
		if req.promptNone {
			fail(&oauthError{"login_required", "the member must sign in"})
			return
		}
		redirectToLogin(w, r, app, params)
		return
	}

	groups, err := p.d.Store.ListGroupsForUser(ctx, user.ID)
	if err != nil {
		p.d.Log.ErrorContext(ctx, "authorize: list groups", "error", err)
		fail(errServer)
		return
	}
	if !UserAllowed(user, groups, app) {
		actorType, actorID := audit.UserActor(user.ID)
		p.d.Audit.Record(ctx, model.AuditEvent{ActorType: actorType, ActorID: actorID,
			Action: audit.AuthorizeDenied, TargetType: "application", TargetID: app.ID,
			Summary: "Turned away from " + app.Name + ": not in an allowed group"})
		if req.promptNone { // the application asked for no page to be shown
			fail(&oauthError{"access_denied", "you don't have access to this application"})
			return
		}
		p.d.Renderer.RenderNoAccess(w, r, app.Name)
		return
	}

	code := secrets.RandomToken(32)
	err = p.d.Store.CreateAuthCode(ctx, &model.AuthCode{
		CodeHash:            secrets.HashToken(code),
		ApplicationID:       app.ID,
		UserID:              user.ID,
		SessionID:           sess.ID,
		RedirectURI:         redirectURI,
		Scope:               strings.Join(req.scopes, " "),
		Nonce:               req.nonce,
		CodeChallenge:       req.challenge,
		CodeChallengeMethod: req.challengeMethod,
		AuthTime:            sess.CreatedAt,
		ExpiresAt:           p.now().Add(codeTTL),
	})
	if err != nil {
		p.d.Log.ErrorContext(ctx, "authorize: store code", "error", err)
		fail(errServer)
		return
	}
	p.redirectToClient(w, r, target, state, url.Values{"code": {code}})
}

// parseAuthRequest validates the parameters checked after the client and
// redirect URI.
func parseAuthRequest(app *model.Application, params url.Values) (*authRequest, *oauthError) {
	switch params.Get("response_type") {
	case "code":
	case "":
		return nil, &oauthError{"invalid_request", "response_type is required"}
	default:
		return nil, &oauthError{"unsupported_response_type", "only response_type code is supported"}
	}

	req := &authRequest{
		nonce:           params.Get("nonce"),
		challenge:       params.Get("code_challenge"),
		challengeMethod: params.Get("code_challenge_method"),
		maxAge:          -1,
	}
	switch {
	case req.challenge == "" && app.ClientType == model.ClientTypePublic:
		return nil, &oauthError{"invalid_request", "code_challenge is required for public clients"}
	case req.challenge == "" && req.challengeMethod != "":
		return nil, &oauthError{"invalid_request", "code_challenge_method was sent without code_challenge"}
	case req.challenge != "" && req.challengeMethod != pkceS256:
		return nil, &oauthError{"invalid_request", "code_challenge_method must be S256"}
	}

	req.scopes = ParseScopes(params.Get("scope"))
	if !slices.Contains(req.scopes, scopeOpenID) {
		return nil, &oauthError{"invalid_scope", "scope must include openid"}
	}

	prompts := strings.Fields(params.Get("prompt"))
	req.promptNone, req.promptLogin = slices.Contains(prompts, "none"), slices.Contains(prompts, "login")
	if req.promptNone && len(prompts) > 1 {
		return nil, &oauthError{"invalid_request", "prompt none cannot be combined with other values"}
	}
	if v := params.Get("max_age"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, &oauthError{"invalid_request", "max_age must be a whole number of seconds"}
		}
		req.maxAge = n
	}
	return req, nil
}

// redirectToLogin sends the browser to sign in for app, returning to this
// request afterwards. max_age and prompt=login are left out of the return
// address: the sign-in about to happen is the fresh authentication they ask
// for, and keeping them would ask again on return, without end. Dropping
// them gives nothing away, since anyone can drop them from the request;
// an application that must know checks auth_time in the ID token.
func redirectToLogin(w http.ResponseWriter, r *http.Request, app *model.Application, params url.Values) {
	back := maps.Clone(params)
	back.Del("max_age")
	prompts := slices.DeleteFunc(strings.Fields(back.Get("prompt")), func(v string) bool { return v == "login" })
	if len(prompts) == 0 {
		back.Del("prompt")
	} else {
		back.Set("prompt", strings.Join(prompts, " "))
	}
	next := "/oauth/authorize?" + back.Encode()
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next)+"&app="+url.QueryEscape(app.Slug), http.StatusSeeOther)
}

// redirectToClient sends the browser back to the application's redirect
// URI (already matched against the registered ones) with params, the
// application's state when it sent one, and iss (RFC 9207) added to its
// query.
func (p *Provider) redirectToClient(w http.ResponseWriter, r *http.Request, target *url.URL, state string, params url.Values) {
	if state != "" {
		params.Set("state", state)
	}
	params.Set("iss", p.issuer)
	http.Redirect(w, r, withQuery(*target, params), http.StatusFound)
}

// withQuery returns u with params added after any query it already has.
func withQuery(u url.URL, params url.Values) string {
	if len(params) == 0 {
		return u.String()
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += params.Encode()
	return u.String()
}

// badLink shows the error page for an authorization request that cannot
// safely be answered with a redirect.
func (p *Provider) badLink(w http.ResponseWriter, r *http.Request, msg string) {
	p.d.Renderer.RenderError(w, r, http.StatusBadRequest, "Something's wrong with that link", msg)
}

// serverError logs err and shows the generic error page. what names the
// failed step for the log; the visitor never sees it.
func (p *Provider) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.d.Log.ErrorContext(r.Context(), what, "error", err)
	p.d.Renderer.RenderError(w, r, http.StatusInternalServerError, "Something went wrong",
		"Something went wrong on our side. Please try again in a moment.")
}
