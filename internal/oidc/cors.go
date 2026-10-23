package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"latch/internal/store"
)

// corsRefresh is how long the set of allowed origins is used before it is
// read from the applications again.
const corsRefresh = time.Minute

// corsOrigins is the set of origins browser apps (public clients) may call
// the token, userinfo and revocation endpoints from: the origins of the
// redirect URIs registered on any application.
type corsOrigins struct {
	store *store.Store
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	origins map[string]bool // nil until loaded
	loaded  time.Time
}

// allowed reports whether origin, as a browser sent it, is the origin of a
// registered redirect URI. A failure to read the applications is logged
// and allows nothing.
func (c *corsOrigins) allowed(ctx context.Context, origin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); c.origins == nil || now.Sub(c.loaded) >= corsRefresh {
		apps, err := c.store.ListApplications(ctx)
		if err != nil {
			c.log.ErrorContext(ctx, "cors: list applications", "error", err)
			return false
		}
		c.origins, c.loaded = map[string]bool{}, now
		for _, app := range apps {
			for _, uri := range app.RedirectURIs {
				if o, ok := originOf(uri); ok {
					c.origins[o] = true
				}
			}
		}
	}
	return c.origins[origin]
}

// originOf returns the origin of an http(s) URL as a browser writes it in
// an Origin header: scheme://host[:port], lower case, without the scheme's
// default port.
func originOf(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, true
	}
	return scheme + "://" + host + ":" + port, true
}

// withCORS lets browser apps at an allowed origin call h: it answers their
// preflight (any OPTIONS request) with 204 and, for an allowed origin, the
// methods and headers they may use; and it names an allowed origin in
// Access-Control-Allow-Origin on h's responses. Other origins get no CORS
// headers. Credentials are never allowed: these endpoints take a client
// secret or bearer token, not cookies.
func (p *Provider) withCORS(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		allowed := origin != "" && p.cors.allowed(r.Context(), origin)
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		if r.Method == http.MethodOptions {
			if allowed {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	})
}
