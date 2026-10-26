package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/store"
)

// Renderer shows the branded pages the OpenID Connect endpoints need. It is
// satisfied by *web.Renderer, which oidc cannot import.
type Renderer interface {
	RenderError(w http.ResponseWriter, r *http.Request, status int, title, msg string)
	RenderNoAccess(w http.ResponseWriter, r *http.Request, appName string)
	RenderSignedOut(w http.ResponseWriter, r *http.Request)
}

// Deps are the collaborators the OpenID Connect endpoints use.
type Deps struct {
	Cfg      *config.Config
	Store    *store.Store
	Keys     *KeyManager
	Audit    *audit.Recorder
	Log      *slog.Logger
	Renderer Renderer
	// Sessions ends the browser's session at logout. It is satisfied by
	// *session.Manager.
	Sessions interface {
		End(ctx context.Context, w http.ResponseWriter, r *http.Request) error
	}
	Now func() time.Time // nil means time.Now
}

// Provider serves the OpenID Connect endpoints.
type Provider struct {
	d      Deps
	issuer string
	cors   *corsOrigins
}

// NewProvider returns a Provider whose issuer is the configured public URL.
func NewProvider(d Deps) *Provider {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Provider{d: d, issuer: d.Cfg.Issuer(), cors: &corsOrigins{store: d.Store, log: d.Log, now: d.Now}}
}

// Mount registers the OpenID Connect routes on mux.
//
// Browser apps (public clients) call the token, userinfo and revocation
// endpoints from their own origin, so those answer CORS requests from the
// origins of registered redirect URIs (withCORS); discovery and the keys
// are open to any origin. Introspection is for servers, and authorization
// and logout are top-level navigations, so they get no CORS.
func (p *Provider) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", p.jwks)
	mux.HandleFunc("GET /oauth/authorize", p.authorize)
	mux.HandleFunc("POST /oauth/authorize", p.authorize)
	// The token, introspection and revocation endpoints take every method
	// so that a wrong one gets a JSON error, not the mux's plain text.
	mux.Handle("/oauth/token", p.withCORS(p.token))
	mux.HandleFunc("/oauth/introspect", p.introspect)
	mux.Handle("/oauth/revoke", p.withCORS(p.revoke))
	mux.Handle("GET /oauth/userinfo", p.withCORS(p.userinfo))
	mux.Handle("POST /oauth/userinfo", p.withCORS(p.userinfo))
	mux.Handle("OPTIONS /oauth/userinfo", p.withCORS(p.userinfo))
	mux.HandleFunc("GET /oauth/logout", p.logout)
	mux.HandleFunc("POST /oauth/logout", p.logout)
}

func (p *Provider) now() time.Time { return p.d.Now().UTC() }

// discoveryDocument is the OpenID Provider metadata (OpenID Connect
// Discovery 1.0 §3).
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	// RFC 9207: authorization responses carry iss.
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	// Request objects are not supported. Both are always false, written out
	// because request_uri_parameter_supported defaults to true.
	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, "public, max-age=3600", discoveryDocument{
		Issuer:                            p.issuer,
		AuthorizationEndpoint:             p.issuer + "/oauth/authorize",
		TokenEndpoint:                     p.issuer + "/oauth/token",
		UserinfoEndpoint:                  p.issuer + "/oauth/userinfo",
		JWKSURI:                           p.issuer + "/.well-known/jwks.json",
		EndSessionEndpoint:                p.issuer + "/oauth/logout",
		RevocationEndpoint:                p.issuer + "/oauth/revoke",
		IntrospectionEndpoint:             p.issuer + "/oauth/introspect",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{signingAlg},
		ScopesSupported:                   knownScopes,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{pkceS256},
		ClaimsSupported: []string{"sub", "email", "email_verified", "name", "preferred_username",
			"groups", "metadata", "group_metadata", "is_admin", "updated_at"},
		AuthorizationResponseISSParameterSupported: true,
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, "public, max-age=3600", p.d.Keys.JWKS())
}

// writeJSON writes v as a JSON response with the given status and
// Cache-Control.
func writeJSON(w http.ResponseWriter, status int, cacheControl string, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", cacheControl)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
