package web

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"latch/internal/metrics"
)

// contentSecurityPolicy allows forms to post to other origins because OIDC
// redirects carry the browser back to the application.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data: https:; " +
	"style-src 'self' 'unsafe-inline'; form-action 'self' https: http:"

type ctxKey int

const clientIPKey ctxKey = iota

// ClientIP returns the client address resolved by the RealIP middleware,
// falling back to the host part of RemoteAddr.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	return hostOnly(r.RemoteAddr)
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// recoverer turns a panic into a logged error and a generic 500 page.
func recoverer(log *slog.Logger, rd *Renderer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.ErrorContext(r.Context(), "panic serving request",
					"method", r.Method, "path", logPath(r.URL.Path),
					"panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				rd.RenderError(w, r, http.StatusInternalServerError, "Something went wrong",
					"Something went wrong on our side. Please try again in a moment.")
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// proxyRanges are the networks whose X-Forwarded-* headers are believed.
type proxyRanges []netip.Prefix

// parseProxies accepts CIDRs or single addresses; anything else is logged
// and ignored, which leaves that proxy untrusted.
func parseProxies(entries []string, log *slog.Logger) proxyRanges {
	var ranges proxyRanges
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			ranges = append(ranges, p.Masked())
		} else if a, err := netip.ParseAddr(e); err == nil {
			ranges = append(ranges, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else {
			log.Error("ignoring invalid trusted_proxies entry", "entry", e)
		}
	}
	return ranges
}

func (p proxyRanges) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, prefix := range p {
		if prefix.Contains(a) {
			return true
		}
	}
	return false
}

// forwardedFor returns the right-most X-Forwarded-For entry outside the
// trusted ranges: the address the outermost trusted proxy saw. When every
// entry is trusted it returns the last one; "" when there is no usable entry.
func (p proxyRanges) forwardedFor(r *http.Request) string {
	var entries []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for e := range strings.SplitSeq(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	if len(entries) == 0 {
		return ""
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(entries[i])
		if err != nil {
			break
		}
		if !p.contains(a) {
			return a.Unmap().String()
		}
	}
	if a, err := netip.ParseAddr(entries[len(entries)-1]); err == nil {
		return a.Unmap().String()
	}
	return ""
}

// maxWarnedPeers bounds how many untrusted peers realIP remembers having
// warned about; when the set is full it starts again.
const maxWarnedPeers = 64

// warnedPeers is the set of peers realIP has warned about.
type warnedPeers struct {
	mu    sync.Mutex
	peers map[string]struct{}
}

// first reports whether peer is not yet in the set, and adds it.
func (w *warnedPeers) first(peer string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.peers[peer]; ok {
		return false
	}
	if w.peers == nil || len(w.peers) >= maxWarnedPeers {
		w.peers = make(map[string]struct{}, maxWarnedPeers)
	}
	w.peers[peer] = struct{}{}
	return true
}

// realIP resolves the client address. Only when the peer is a trusted proxy
// are X-Forwarded-For and X-Forwarded-Proto believed; then RemoteAddr is
// rewritten to the client address too, so packages that cannot import web
// (session) record the right IP.
//
// Forwarded headers from any other peer are ignored with a warning, once
// per peer: they usually mean the reverse proxy is missing from
// trusted_proxies, which makes every member share its address, so one
// member's failed sign-ins lock everyone out.
func realIP(trusted proxyRanges, log *slog.Logger) func(http.Handler) http.Handler {
	var warned warnedPeers
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, scheme := hostOnly(r.RemoteAddr), ""
			if peer, err := netip.ParseAddr(ip); err == nil && trusted.contains(peer) {
				if fwd := trusted.forwardedFor(r); fwd != "" {
					ip = fwd
				}
				switch proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); proto {
				case "http", "https":
					scheme = proto
				}
			} else if header := forwardedHeader(r); header != "" && warned.first(ip) {
				log.WarnContext(r.Context(), "ignoring "+header+" from untrusted peer "+ip+
					"; add your reverse proxy to trusted_proxies", "peer", ip)
			}
			r = r.WithContext(context.WithValue(r.Context(), clientIPKey, ip))
			if ip != hostOnly(r.RemoteAddr) {
				r.RemoteAddr = ip
			}
			if scheme != "" {
				u := *r.URL
				u.Scheme = scheme
				r.URL = &u
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forwardedHeader names the first of X-Forwarded-For and X-Forwarded-Proto
// that r carries, or "" for neither.
func forwardedHeader(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto"} {
		if r.Header.Get(h) != "" {
			return h
		}
	}
	return ""
}

// statusWriter records the status code a handler sends.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// requestLog logs one line per request. Query strings are never logged
// because they can carry authorization codes.
func requestLog(log *slog.Logger, m *metrics.Registry) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			status := sw.status
			m.CountRequest(status)
			if status == 0 {
				status = http.StatusOK
			}
			log.InfoContext(r.Context(), "request",
				"method", r.Method, "path", logPath(r.URL.Path), "status", status,
				"duration", time.Since(start), "ip", ClientIP(r))
		})
	}
}

// logPath hides the token in /reset/{token} links.
func logPath(p string) string {
	if strings.HasPrefix(p, "/reset/") && len(p) > len("/reset/") {
		return "/reset/[redacted]"
	}
	return p
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// crossOriginProtection rejects cross-site form posts. OAuth and API
// endpoints are called by other servers and are exempt.
func crossOriginProtection(rd *Renderer) *http.CrossOriginProtection {
	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("/oauth/")
	cop.AddInsecureBypassPattern("/api/")
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rd.RenderError(w, r, http.StatusForbidden, "Request blocked",
			"This form was sent from another website, so we ignored it. Go back and try again.")
	}))
	return cop
}
