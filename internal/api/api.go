// Package api serves the admin REST API under /api/v1 (spec §8): JSON in
// and out, over the same admin service the admin pages use, for service
// accounts that send an API token as "Authorization: Bearer <token>".
//
// Every change goes through admin.Service, with the calling service account
// and token as the actor; handlers may read through the store directly.
// Errors are {"error": "code", "message": "..."}, as fail and writeError
// write them.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"keywell/internal/admin"
	"keywell/internal/model"
	"keywell/internal/ratelimit"
	"keywell/internal/store"
)

// Deps is what the API needs.
type Deps struct {
	Admin *admin.Service
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time // nil = time.Now; also the rate limiter's clock
	// DataDir is the data directory, where app icon files live: deleting an
	// app, or giving it another icon, removes the icon file it owned.
	DataDir string
}

// prefix is the base path; route paths are relative to it.
const prefix = "/api/v1"

// Limits of every request.
const (
	maxBodyBytes      = 1 << 20 // larger bodies get 413 too_large
	requestsPerMinute = 600     // per token; more get 429 rate_limited
)

// route is one endpoint: a method and a path relative to prefix, such as
// "/users/{id}". The path is both the http.ServeMux pattern and the
// OpenAPI path, so its only wildcards are whole segments like {id}.
type route struct {
	method, path string
	serve        func(h *handler, w http.ResponseWriter, r *http.Request)
}

// routes is every endpoint. openapi.json describes exactly these
// (TestOpenAPIMatchesRoutes).
var routes = []route{
	{http.MethodGet, "/openapi.json", (*handler).openAPI}, // public: served before authentication
	{http.MethodGet, "/me", (*handler).me},
	{http.MethodGet, "/users", (*handler).listUsers},
	{http.MethodPost, "/users", (*handler).createUser},
	{http.MethodGet, "/users/{id}", (*handler).getUser},
	{http.MethodPatch, "/users/{id}", (*handler).patchUser},
	{http.MethodDelete, "/users/{id}", (*handler).deleteUser},
	{http.MethodPost, "/users/{id}/reset-email", (*handler).resetEmail},
	{http.MethodPost, "/users/{id}/password", (*handler).setUserPassword},
	{http.MethodPost, "/users/{id}/totp/clear", (*handler).clearUserTOTP},
	{http.MethodPost, "/users/{id}/sessions/revoke", (*handler).revokeUserSessions},
	{http.MethodPut, "/users/{id}/groups", (*handler).setUserGroups},
	{http.MethodPost, "/users/{id}/groups/{group}", (*handler).addUserGroup},
	{http.MethodDelete, "/users/{id}/groups/{group}", (*handler).removeUserGroup},
	{http.MethodGet, "/groups", (*handler).listGroups},
	{http.MethodPost, "/groups", (*handler).createGroup},
	{http.MethodGet, "/groups/{id}", (*handler).getGroup},
	{http.MethodPatch, "/groups/{id}", (*handler).patchGroup},
	{http.MethodDelete, "/groups/{id}", (*handler).deleteGroup},
	{http.MethodGet, "/groups/{id}/members", (*handler).listGroupMembers},
	{http.MethodGet, "/apps", (*handler).listApps},
	{http.MethodPost, "/apps", (*handler).createApp},
	{http.MethodGet, "/apps/{id}", (*handler).getApp},
	{http.MethodPatch, "/apps/{id}", (*handler).patchApp},
	{http.MethodDelete, "/apps/{id}", (*handler).deleteApp},
	{http.MethodPost, "/apps/{id}/rotate-secret", (*handler).rotateAppSecret},
	{http.MethodGet, "/service-accounts", (*handler).listServiceAccounts},
	{http.MethodPost, "/service-accounts", (*handler).createServiceAccount},
	{http.MethodGet, "/service-accounts/{id}", (*handler).getServiceAccount},
	{http.MethodPatch, "/service-accounts/{id}", (*handler).patchServiceAccount},
	{http.MethodDelete, "/service-accounts/{id}", (*handler).deleteServiceAccount},
	{http.MethodGet, "/service-accounts/{id}/tokens", (*handler).listTokens},
	{http.MethodPost, "/service-accounts/{id}/tokens", (*handler).createToken},
	{http.MethodDelete, "/service-accounts/{id}/tokens/{tid}", (*handler).deleteToken},
	{http.MethodGet, "/audit", (*handler).listAudit},
}

// handler holds what the API's handlers share.
type handler struct {
	d       Deps
	limiter *ratelimit.Limiter
}

// New returns the handler for every path under /api/. The middleware, from
// the outside in: recover (with the JSON headers), body limit, the public
// OpenAPI document, bearer authentication, scope, rate limit, router.
// Cookies are never read.
func New(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	h := &handler{d: d, limiter: ratelimit.New(requestsPerMinute, time.Minute)}
	h.limiter.SetClock(d.Now)

	next := h.router()
	next = h.rateLimit(next)
	next = requireScope(next)
	next = h.authenticate(next)
	next = h.publicOpenAPI(next)
	next = limitBody(next)
	return h.recoverJSON(next)
}

// recoverJSON sets the headers every API response has and turns a panic
// into a logged error and a JSON 500, before the outer recoverer can show
// its HTML page.
func (h *handler) recoverJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			h.d.Log.ErrorContext(r.Context(), "api: panic serving request",
				"method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			writeError(w, http.StatusInternalServerError, "internal", msgInternal)
		}()
		next.ServeHTTP(w, r)
	})
}

// limitBody answers 413 too_large, unread, to a request that declares a
// body over maxBodyBytes, and stops reading any other body at the limit
// (decode then answers 413).
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", msgTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// publicOpenAPI serves the OpenAPI document to anyone, with or without a
// token.
func (h *handler) publicOpenAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix+"/openapi.json" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			h.openAPI(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// callerKey is the context key of the request's *admin.Caller.
type callerKey struct{}

// authenticate lets the request through only with a valid API token,
// putting its caller in the context, and otherwise answers 401
// unauthorized. Every kind of bad token gets the same answer.
func (h *handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c *admin.Caller
		if raw, ok := bearerToken(r); ok {
			var err error
			c, err = h.d.Admin.AuthenticateToken(r.Context(), raw)
			if err != nil && !errors.Is(err, admin.ErrBadToken) {
				h.fail(w, r, err)
				return
			}
		}
		if c == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized", msgUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

// bearerToken returns the token of an "Authorization: Bearer <token>"
// header; the scheme is not case-sensitive. ok is false without one.
func bearerToken(r *http.Request) (raw string, ok bool) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	raw = strings.TrimSpace(raw)
	return raw, strings.EqualFold(scheme, "Bearer") && raw != ""
}

// caller is who the request's token stands for. Every handler behind
// authenticate has one.
func caller(r *http.Request) *admin.Caller {
	c, _ := r.Context().Value(callerKey{}).(*admin.Caller)
	return c
}

// actor is the request's caller as the actor of admin changes: the service
// account, with the token's ID for the audit event's detail.token_id.
func actor(r *http.Request) admin.Actor { return caller(r).Actor() }

// requireScope answers 403 forbidden when a token without full admin
// access asks for anything but GET or HEAD, on any path.
func requireScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && caller(r).Token.Scope != model.APITokenScopeAdmin {
			writeError(w, http.StatusForbidden, "forbidden", msgReadOnly)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit answers 429 rate_limited, with Retry-After, to a token that has
// already made requestsPerMinute requests in the last minute.
func (h *handler) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.limiter.Allow(caller(r).Token.ID) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate_limited", msgRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// router serves the routes. A path no route has gets 404 not_found; a
// route's path with a method it does not take gets 405
// method_not_allowed, with Allow naming the methods it takes. (A pattern
// without a method, like the fallback here, would otherwise beat
// ServeMux's own plain-text 405, so the fallback works it out itself.)
func (h *handler) router() http.Handler {
	mux, misses := http.NewServeMux(), http.NewServeMux()
	allowed := map[string][]string{} // path -> methods
	for _, rt := range routes {
		mux.HandleFunc(rt.method+" "+prefix+rt.path, func(w http.ResponseWriter, r *http.Request) { rt.serve(h, w, r) })
		allowed[rt.path] = append(allowed[rt.path], rt.method)
	}
	for path, methods := range allowed {
		if slices.Contains(methods, http.MethodGet) {
			methods = append(methods, http.MethodHead) // a GET pattern also serves HEAD
		}
		allow := strings.Join(methods, ", ")
		misses.HandleFunc(prefix+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", allow)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", fmt.Sprintf(msgMethodFormat, r.Method))
		})
	}
	misses.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", msgNoRoute)
	})
	mux.Handle("/", misses)
	return mux
}
