package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// Grant types the token endpoint accepts.
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	grantClientCredentials = "client_credentials"
)

// accessTokenType is the typ header of access tokens (RFC 9068 §2.1). ID
// tokens carry "JWT", so one is never accepted in place of the other.
const accessTokenType = "at+jwt"

// userIDClaim is a private access-token claim holding the Latch user ID.
// sub depends on the application's subject mode and may be an email or an
// Authentik value, which can change hands; userinfo and introspection find
// the member by this instead.
const userIDClaim = "latch_uid"

// Token kinds for ttl.
const (
	ttlAccess          = "access"
	ttlID              = "id"
	ttlRefresh         = "refresh"
	ttlRefreshAbsolute = "refresh_absolute"
)

// tokenResponse is a successful token endpoint response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

func (e *oauthError) Error() string { return e.code + ": " + e.description }

var (
	errClientAuth = &oauthError{"invalid_client", "client authentication failed"}
	errNoAccess   = &oauthError{"invalid_grant", "the account is disabled or no longer has access to this application"}
	errBadRefresh = &oauthError{"invalid_grant", "the refresh token is invalid, expired or revoked"}
)

// errInvalidToken means a token is not one Latch issued and still honours,
// or its member or application is gone, or the member is disabled.
var errInvalidToken = errors.New("oidc: invalid token")

// token handles POST /oauth/token.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if !readForm(w, r) {
		return
	}
	ctx := r.Context()
	app, err := p.authenticateClient(r)
	if err != nil {
		p.tokenError(w, r, err)
		return
	}
	var (
		resp tokenResponse
		u    *model.User
	)
	grant := r.PostForm.Get("grant_type")
	switch grant {
	case grantAuthorizationCode:
		resp, u, err = p.codeGrant(ctx, app, r.PostForm)
	case grantRefreshToken:
		resp, u, err = p.refreshGrant(ctx, app, r.PostForm)
	case grantClientCredentials:
		resp, u, err = p.clientCredentialsGrant(ctx, app, r.PostForm)
	case "":
		err = &oauthError{"invalid_request", "grant_type is required"}
	default:
		err = &oauthError{"unsupported_grant_type", "grant_type must be authorization_code, refresh_token or client_credentials"}
	}
	if err != nil {
		p.tokenError(w, r, err)
		return
	}

	actorType, actorID := audit.UserActor(u.ID)
	if grant == grantClientCredentials {
		actorType = model.ActorServiceAccount
	}
	p.d.Audit.Record(ctx, model.AuditEvent{ActorType: actorType, ActorID: actorID, Action: audit.TokenIssued,
		TargetType: "application", TargetID: app.ID, Summary: "Tokens issued to " + app.Name,
		Detail: map[string]any{"grant": grant, "client_id": app.ClientID}})
	writeJSON(w, http.StatusOK, "no-store", resp)
}

// readForm checks that r is a POST of a urlencoded form, as the token,
// introspection and revocation endpoints require, and parses it; otherwise
// it writes the error and returns false. It marks every response from these
// endpoints uncacheable (RFC 6749 §5.1): writeJSON adds Cache-Control.
func readForm(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, &oauthError{"invalid_request", "use POST"})
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest,
			&oauthError{"invalid_request", "send the parameters as an application/x-www-form-urlencoded form"})
		return false
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, &oauthError{"invalid_request", "the form could not be read"})
		return false
	}
	return true
}

// tokenError writes err as an error response (RFC 6749 §5.2). Anything
// but an *oauthError is an internal failure: it is logged and answered with
// server_error.
func (p *Provider) tokenError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		p.d.Log.ErrorContext(r.Context(), "oauth endpoint", "path", r.URL.Path, "error", err)
		oe = errServer
	}
	status := http.StatusBadRequest
	switch oe.code {
	case errClientAuth.code:
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="latch"`)
	case errServer.code:
		status = http.StatusInternalServerError
	}
	writeOAuthError(w, status, oe)
}

// writeOAuthError writes e as an uncacheable JSON error with status.
func writeOAuthError(w http.ResponseWriter, status int, e *oauthError) {
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, "no-store", map[string]string{"error": e.code, "error_description": e.description})
}

// authenticateClient identifies the calling application from HTTP Basic
// credentials (client_secret_basic), client_id and client_secret in the form
// (client_secret_post), or client_id alone for a public client (none). A
// public client must not send a secret; a confidential one must send its
// own. Secrets are compared as hashes, in constant time.
func (p *Provider) authenticateClient(r *http.Request) (*model.Application, error) {
	id, secret, err := clientCredentials(r)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, &oauthError{"invalid_client", "client authentication is required"}
	}
	app, err := p.d.Store.GetApplicationByClientID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errClientAuth
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate client: %w", err)
	}
	if app.ClientType == model.ClientTypePublic {
		if secret != "" {
			return nil, &oauthError{"invalid_client", "this application has no client secret; do not send one"}
		}
		return app, nil
	}
	if secret == "" || app.ClientSecretHash == "" ||
		subtle.ConstantTimeCompare([]byte(secrets.HashToken(secret)), []byte(app.ClientSecretHash)) != 1 {
		return nil, errClientAuth
	}
	return app, nil
}

// clientCredentials returns the client ID and secret the request carries:
// from an Authorization: Basic header, where each is form-urlencoded
// (RFC 6749 §2.3.1), or from the form. Using both for the secret, or naming
// different clients in each, is an error.
func clientCredentials(r *http.Request) (id, secret string, err error) {
	formID, formSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if r.Header.Get("Authorization") == "" {
		return formID, formSecret, nil
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", "", &oauthError{"invalid_client", "only Basic client authentication is supported"}
	}
	if id, err = url.QueryUnescape(user); err == nil {
		secret, err = url.QueryUnescape(pass)
	}
	if err != nil {
		return "", "", &oauthError{"invalid_client", "the Basic credentials must be form-urlencoded"}
	}
	if formSecret != "" {
		return "", "", &oauthError{"invalid_request", "send the client secret once, in the Authorization header or the form"}
	}
	if formID != "" && formID != id {
		return "", "", &oauthError{"invalid_request", "client_id in the form differs from the Authorization header"}
	}
	return id, secret, nil
}

// codeGrant redeems an authorization code (RFC 6749 §4.1.3, RFC 7636
// §4.6). The code is spent by the attempt whether or not it succeeds.
func (p *Provider) codeGrant(ctx context.Context, app *model.Application, form url.Values) (tokenResponse, *model.User, error) {
	code := form.Get("code")
	if code == "" {
		return tokenResponse{}, nil, &oauthError{"invalid_request", "code is required"}
	}
	ac, err := p.d.Store.ConsumeAuthCode(ctx, secrets.HashToken(code))
	if errors.Is(err, store.ErrNotFound) {
		return tokenResponse{}, nil, &oauthError{"invalid_grant", "the code is invalid, expired or already used"}
	}
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("code grant: consume code: %w", err)
	}
	switch {
	case ac.ApplicationID != app.ID:
		return tokenResponse{}, nil, &oauthError{"invalid_grant", "the code was issued to another application"}
	case ac.RedirectURI != form.Get("redirect_uri"):
		return tokenResponse{}, nil, &oauthError{"invalid_grant", "redirect_uri does not match the authorization request"}
	case !verifierMatches(ac.CodeChallenge, form.Get("code_verifier")):
		return tokenResponse{}, nil, &oauthError{"invalid_grant", "code_verifier does not match the code challenge"}
	}
	u, err := p.allowedUser(ctx, ac.UserID, app)
	if err != nil {
		return tokenResponse{}, nil, err
	}
	scopes := ParseScopes(ac.Scope)
	resp, err := p.issueTokens(ctx, u, app, scopes, ac.Nonce, ac.AuthTime, true, p.refreshAllowed(scopes), nil)
	return resp, u, err
}

// verifierMatches reports whether verifier answers the S256 challenge
// (RFC 7636 §4.6). With no challenge there must be no verifier either, so a
// code from a request without PKCE cannot pass as a protected one
// (RFC 9700 §2.1.1).
func verifierMatches(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return challenge == verifier
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// refreshGrant redeems a refresh token (RFC 6749 §6), rotating it: the
// presented token is revoked, atomically, and a new one joins its family.
// Presenting a revoked token means it was copied, so the whole family is
// revoked, as it is when two redemptions of one token race; so is it when
// the member has been disabled or lost access to the application.
func (p *Provider) refreshGrant(ctx context.Context, app *model.Application, form url.Values) (tokenResponse, *model.User, error) {
	raw := form.Get("refresh_token")
	if raw == "" {
		return tokenResponse{}, nil, &oauthError{"invalid_request", "refresh_token is required"}
	}
	rt, err := p.d.Store.GetRefreshToken(ctx, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) || err == nil && rt.ApplicationID != app.ID {
		return tokenResponse{}, nil, errBadRefresh
	}
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("refresh grant: get token: %w", err)
	}
	if rt.RevokedAt != nil {
		p.d.Log.WarnContext(ctx, "revoked refresh token presented; revoking its family",
			"family_id", rt.FamilyID, "client_id", app.ClientID)
		return p.endFamily(ctx, rt, errBadRefresh)
	}
	if !p.now().Before(rt.ExpiresAt) {
		return p.endFamily(ctx, rt, errBadRefresh)
	}
	u, err := p.allowedUser(ctx, rt.UserID, app)
	if errors.Is(err, errNoAccess) {
		return p.endFamily(ctx, rt, err)
	}
	if err != nil {
		return tokenResponse{}, nil, err
	}

	granted := ParseScopes(rt.Scope)
	scopes := granted
	if s := form.Get("scope"); s != "" {
		scopes = ParseScopes(s)
		for _, sc := range scopes {
			if !slices.Contains(granted, sc) {
				return tokenResponse{}, nil, &oauthError{"invalid_scope", "scope may only narrow the original grant"}
			}
		}
	}
	resp, err := p.issueTokens(ctx, u, app, scopes, rt.Nonce, rt.AuthTime,
		slices.Contains(scopes, scopeOpenID), p.refreshAllowed(granted), rt)
	if err != nil {
		return tokenResponse{}, nil, err
	}
	// Claim the presented token only now that its successor is stored, and
	// hand the successor out only if the claim succeeds. A redemption racing
	// this one either loses the claim or finds the token revoked, and either
	// way revokes the family, which by then holds this successor. Claiming
	// first would let that family revocation land before the successor
	// exists, and the successor would outlive it.
	claimed, err := p.d.Store.RevokeRefreshTokenIfActive(ctx, rt.TokenHash, p.now())
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("refresh grant: revoke presented token: %w", err)
	}
	if !claimed {
		p.d.Log.WarnContext(ctx, "refresh token redeemed twice at once; revoking its family",
			"family_id", rt.FamilyID, "client_id", app.ClientID)
		return p.endFamily(ctx, rt, errBadRefresh)
	}
	return resp, u, nil
}

// endFamily revokes every refresh token in rt's family and returns cause.
func (p *Provider) endFamily(ctx context.Context, rt *model.RefreshToken, cause error) (tokenResponse, *model.User, error) {
	if err := p.d.Store.RevokeRefreshTokenFamily(ctx, rt.FamilyID); err != nil {
		return tokenResponse{}, nil, fmt.Errorf("refresh grant: revoke family: %w", err)
	}
	return tokenResponse{}, nil, cause
}

// clientCredentialsGrant issues an access token for an application's own
// service account (spec §6.5). There is no ID token and no refresh token.
func (p *Provider) clientCredentialsGrant(ctx context.Context, app *model.Application, form url.Values) (tokenResponse, *model.User, error) {
	if app.ClientType == model.ClientTypePublic {
		return tokenResponse{}, nil, &oauthError{"invalid_client", "client_credentials needs a client secret"}
	}
	if app.ServiceAccountID == "" {
		return tokenResponse{}, nil, &oauthError{"unauthorized_client", "this application is not allowed to sign in by itself"}
	}
	u, err := p.d.Store.GetUser(ctx, app.ServiceAccountID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (!u.IsActive || u.Type != model.UserTypeService) {
		return tokenResponse{}, nil, &oauthError{"unauthorized_client", "this application's service account is disabled"}
	}
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("client credentials: get service account: %w", err)
	}
	groups, err := p.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return tokenResponse{}, nil, fmt.Errorf("client credentials: list groups: %w", err)
	}
	// Every identity claim is built, whatever the scope; serviceAccessClaims
	// picks the ones the token carries.
	identity := BuildClaims(u, groups, app, []string{scopeProfile, scopeEmail, scopeGroups})
	resp, err := p.accessTokenResponse(u, app, identity, serviceAccessClaims, ParseScopes(form.Get("scope")), p.now())
	return resp, u, err
}

// The identity claims an access token carries, besides sub. A member's
// token has them only when its scopes granted them (BuildClaims leaves the
// others out); a service account's (client credentials) always has them
// (spec §6.5), email only when the account has one.
var (
	memberAccessClaims  = []string{"email", "groups"}
	serviceAccessClaims = []string{"email", "groups", "metadata", "preferred_username"}
)

// accessTokenResponse signs an access token for u at app and returns a
// token response holding it. The token carries sub and the claims named in
// keys from identity (BuildClaims output), and scope lists scopes.
func (p *Provider) accessTokenResponse(u *model.User, app *model.Application, identity map[string]any, keys, scopes []string, now time.Time) (tokenResponse, error) {
	ttl := p.ttl(app, ttlAccess)
	scope := strings.Join(scopes, " ")
	at := map[string]any{
		"iss": p.issuer, "sub": identity["sub"], "aud": []string{app.ClientID}, "client_id": app.ClientID,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": secrets.RandomToken(16), "scope": scope,
		userIDClaim: u.ID,
	}
	for _, k := range keys {
		if v, ok := identity[k]; ok {
			at[k] = v
		}
	}
	access, err := p.d.Keys.SignTyped(at, accessTokenType)
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int(ttl / time.Second), Scope: scope}, nil
}

// allowedUser loads the user with id and checks they may still use app,
// failing with errNoAccess if not.
func (p *Provider) allowedUser(ctx context.Context, id string, app *model.Application) (*model.User, error) {
	u, err := p.d.Store.GetUser(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNoAccess
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	groups, err := p.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	if !UserAllowed(u, groups, app) {
		return nil, errNoAccess
	}
	return u, nil
}

// refreshAllowed reports whether a grant of scopes earns a refresh token:
// always, unless the configuration requires offline_access for one.
func (p *Provider) refreshAllowed(scopes []string) bool {
	return !p.d.Cfg.Tokens.RequireOfflineAccessForRefresh || slices.Contains(scopes, scopeOfflineAccess)
}

// issueTokens signs an access token for u at app with scopes and, when
// asked, an ID token (for an authentication at authTime, echoing nonce) and
// a refresh token. prev is the refresh token being rotated: the new one
// joins its family and keeps its scope and absolute expiry. With prev nil
// the refresh token starts a new family.
func (p *Provider) issueTokens(ctx context.Context, u *model.User, app *model.Application, scopes []string,
	nonce string, authTime time.Time, withIDToken, withRefresh bool, prev *model.RefreshToken) (tokenResponse, error) {
	groups, err := p.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("issue tokens: list groups: %w", err)
	}
	now := p.now()
	scope := strings.Join(scopes, " ")
	identity := BuildClaims(u, groups, app, scopes)
	resp, err := p.accessTokenResponse(u, app, identity, memberAccessClaims, scopes, now)
	if err != nil {
		return tokenResponse{}, err
	}
	access := resp.AccessToken

	if withIDToken {
		id := identity // the identity claims plus these; the access token is already signed
		id["iss"], id["aud"] = p.issuer, app.ClientID
		id["iat"], id["exp"] = now.Unix(), now.Add(p.ttl(app, ttlID)).Unix()
		id["auth_time"], id["at_hash"] = authTime.Unix(), atHash(access)
		if nonce != "" {
			id["nonce"] = nonce
		}
		if resp.IDToken, err = p.d.Keys.Sign(id); err != nil {
			return tokenResponse{}, err
		}
	}

	if withRefresh {
		raw := secrets.RandomToken(32)
		rt := &model.RefreshToken{
			TokenHash: secrets.HashToken(raw), FamilyID: secrets.NewID(), ApplicationID: app.ID, UserID: u.ID,
			Scope: scope, Nonce: nonce, AuthTime: authTime, CreatedAt: now,
			AbsoluteExpiresAt: now.Add(p.ttl(app, ttlRefreshAbsolute)),
		}
		if prev != nil {
			rt.FamilyID, rt.Scope, rt.AbsoluteExpiresAt = prev.FamilyID, prev.Scope, prev.AbsoluteExpiresAt
		}
		rt.ExpiresAt = now.Add(p.ttl(app, ttlRefresh))
		if rt.ExpiresAt.After(rt.AbsoluteExpiresAt) {
			rt.ExpiresAt = rt.AbsoluteExpiresAt
		}
		if err := p.d.Store.CreateRefreshToken(ctx, rt); err != nil {
			return tokenResponse{}, fmt.Errorf("issue tokens: store refresh token: %w", err)
		}
		resp.RefreshToken = raw
	}
	return resp, nil
}

// atHash is the at_hash of an access token (OIDC Core §3.1.3.6): the left
// half of its SHA-256, base64url-encoded.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// ttl is the lifetime of a token of kind (access, id, refresh or
// refresh_absolute) at app: the application's own setting when it has one,
// else the global one. The absolute refresh limit is only global.
func (p *Provider) ttl(app *model.Application, kind string) time.Duration {
	cfg := p.d.Cfg.Tokens
	var own, global time.Duration
	switch kind {
	case ttlAccess:
		own, global = app.AccessTokenTTL, cfg.Access
	case ttlID:
		own, global = app.IDTokenTTL, cfg.ID
	case ttlRefresh:
		own, global = app.RefreshTokenTTL, cfg.Refresh
	case ttlRefreshAbsolute:
		global = cfg.RefreshAbsolute
	default:
		panic("oidc: unknown token kind " + kind)
	}
	if own > 0 {
		return own
	}
	return global
}

// parseAccessToken verifies raw as an access token from this issuer: a
// compact RS256 JWS with typ at+jwt, signed by a key that still verifies,
// with iss this issuer and exp in the future. The key is looked up on every
// call, never cached, so a retired key stops working when its grace ends.
// Numbers in the returned claims are json.Number.
func (p *Provider) parseAccessToken(raw string) (map[string]any, error) {
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("access token: %w", err)
	}
	h := jws.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != accessTokenType {
		return nil, fmt.Errorf("access token: typ %q", typ)
	}
	pub, ok := p.d.Keys.PublicKey(h.KeyID)
	if !ok {
		return nil, fmt.Errorf("access token: no usable key %q", h.KeyID)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, fmt.Errorf("access token: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("access token: claims: %w", err)
	}
	if claims["iss"] != p.issuer {
		return nil, errors.New("access token: wrong issuer")
	}
	expNum, _ := claims["exp"].(json.Number)
	exp, err := expNum.Int64()
	if err != nil || !p.now().Before(time.Unix(exp, 0)) {
		return nil, errors.New("access token: expired")
	}
	return claims, nil
}

// accessTokenHolder returns the member an access token was issued to and
// the application it was issued for, as they are now, or errInvalidToken if
// either is gone or the member is disabled.
func (p *Provider) accessTokenHolder(ctx context.Context, claims map[string]any) (*model.User, *model.Application, error) {
	clientID, _ := claims["client_id"].(string)
	app, err := p.d.Store.GetApplicationByClientID(ctx, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, errInvalidToken
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get application: %w", err)
	}
	userID, _ := claims[userIDClaim].(string)
	u, err := p.activeUser(ctx, userID)
	return u, app, err
}

// activeUser loads the user with id, or fails with errInvalidToken if they
// are gone or disabled.
func (p *Provider) activeUser(ctx context.Context, id string) (*model.User, error) {
	u, err := p.d.Store.GetUser(ctx, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !u.IsActive {
		return nil, errInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// userinfo handles GET and POST /oauth/userinfo (OIDC Core §5.3).
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="latch"`)
		writeOAuthError(w, http.StatusUnauthorized, &oauthError{"invalid_request", "an access token is required"})
		return
	}
	claims, err := p.userinfoClaims(r.Context(), raw)
	if errors.Is(err, errInvalidToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="latch", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, &oauthError{"invalid_token", "the access token is invalid or expired"})
		return
	}
	if err != nil {
		p.d.Log.ErrorContext(r.Context(), "userinfo", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, errServer)
		return
	}
	writeJSON(w, http.StatusOK, "no-store", claims)
}

// userinfoClaims returns the claims the access token's scopes grant, for
// the member as they are now. sub is the token's own, so it matches the ID
// token even if the member's email or the application's subject mode has
// changed since (OIDC Core §5.3.2).
func (p *Provider) userinfoClaims(ctx context.Context, raw string) (map[string]any, error) {
	token, err := p.parseAccessToken(raw)
	if err != nil {
		return nil, errInvalidToken
	}
	u, app, err := p.accessTokenHolder(ctx, token)
	if err != nil {
		return nil, err
	}
	groups, err := p.d.Store.ListGroupsForUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	scope, _ := token["scope"].(string)
	claims := BuildClaims(u, groups, app, ParseScopes(scope))
	claims["sub"] = token["sub"]
	return claims, nil
}

// bearerToken returns the access token from the Authorization header
// (RFC 6750 §2.1) or, for a form POST, the access_token field (§2.2).
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, token, _ := strings.Cut(h, " ")
		if !strings.EqualFold(scheme, "Bearer") {
			return ""
		}
		return strings.TrimSpace(token)
	}
	if r.Method == http.MethodPost {
		return r.PostFormValue("access_token")
	}
	return ""
}

// introspect handles POST /oauth/introspect (RFC 7662) for applications
// with a client secret. Anything that is not an active refresh or access
// token Latch issued, for whatever reason, is {"active": false}.
func (p *Provider) introspect(w http.ResponseWriter, r *http.Request) {
	if !readForm(w, r) {
		return
	}
	app, err := p.authenticateClient(r)
	if err == nil && app.ClientType == model.ClientTypePublic {
		err = &oauthError{"invalid_client", "only applications with a client secret may introspect tokens"}
	}
	var info map[string]any
	if err == nil {
		info, err = p.introspection(r.Context(), r.PostForm.Get("token"))
	}
	if err != nil {
		p.tokenError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, "no-store", info)
}

// introspection describes the refresh or access token raw. A token is
// active only while its member is.
func (p *Provider) introspection(ctx context.Context, raw string) (map[string]any, error) {
	if raw == "" {
		return map[string]any{"active": false}, nil
	}
	info, err := p.refreshTokenInfo(ctx, raw)
	if errors.Is(err, store.ErrNotFound) {
		info, err = p.accessTokenInfo(ctx, raw)
	}
	if errors.Is(err, errInvalidToken) {
		return map[string]any{"active": false}, nil
	}
	return info, err
}

// refreshTokenInfo describes raw if it is a refresh token. It fails with
// store.ErrNotFound if raw is not one, and errInvalidToken if it can no
// longer be used.
func (p *Provider) refreshTokenInfo(ctx context.Context, raw string) (map[string]any, error) {
	rt, err := p.d.Store.GetRefreshToken(ctx, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("introspect: get refresh token: %w", err)
	}
	if rt.RevokedAt != nil || !p.now().Before(rt.ExpiresAt) {
		return nil, errInvalidToken
	}
	app, err := p.d.Store.GetApplication(ctx, rt.ApplicationID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("introspect: get application: %w", err)
	}
	u, err := p.activeUser(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}
	return tokenInfo(u, p.issuer, Subject(u, app), app.ClientID, rt.Scope, rt.ExpiresAt.Unix(), rt.CreatedAt.Unix()), nil
}

// accessTokenInfo describes raw if it is a valid access token, and
// otherwise fails with errInvalidToken.
func (p *Provider) accessTokenInfo(ctx context.Context, raw string) (map[string]any, error) {
	claims, err := p.parseAccessToken(raw)
	if err != nil {
		return nil, errInvalidToken
	}
	u, _, err := p.accessTokenHolder(ctx, claims)
	if err != nil {
		return nil, err
	}
	return tokenInfo(u, claims["iss"], claims["sub"], claims["client_id"], claims["scope"], claims["exp"], claims["iat"]), nil
}

// tokenInfo is the introspection response for an active token of u's.
func tokenInfo(u *model.User, iss, sub, clientID, scope, exp, iat any) map[string]any {
	info := map[string]any{"active": true, "iss": iss, "sub": sub, "client_id": clientID, "scope": scope, "exp": exp, "iat": iat}
	if u.Email != "" {
		info["username"] = u.Email
	}
	return info
}

// revoke handles POST /oauth/revoke (RFC 7009) for refresh tokens. It
// answers 200 whether or not the token was valid, and leaves alone a token
// issued to another application. Access tokens are self-contained JWTs and
// cannot be revoked; they expire.
func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	if !readForm(w, r) {
		return
	}
	app, err := p.authenticateClient(r)
	if err == nil {
		err = p.revokeRefreshToken(r.Context(), app, r.PostForm.Get("token"))
	}
	if err != nil {
		p.tokenError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// revokeRefreshToken revokes raw if it is a refresh token issued to app.
func (p *Provider) revokeRefreshToken(ctx context.Context, app *model.Application, raw string) error {
	if raw == "" {
		return &oauthError{"invalid_request", "token is required"}
	}
	rt, err := p.d.Store.GetRefreshToken(ctx, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revoke: get refresh token: %w", err)
	}
	if rt.ApplicationID != app.ID {
		return nil
	}
	if err := p.d.Store.RevokeRefreshToken(ctx, rt.TokenHash); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	return nil
}
