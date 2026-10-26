package web_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keywell/internal/config"
	"keywell/internal/metrics"
	"keywell/internal/session"
	"keywell/internal/store/storetest"
	"keywell/internal/testenv"
	"keywell/internal/web"
)

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestHealthz(t *testing.T) {
	env := testenv.New(t)
	resp, body := get(t, env.Client(t), env.TS.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if got["status"] != "ok" || got["version"] != testenv.Version {
		t.Fatalf("body %v", got)
	}
}

func TestBrandingRendered(t *testing.T) {
	env := testenv.New(t, testenv.WithConfig(func(c *config.Config) {
		c.Branding.Name = "Northside Hackspace"
		c.Branding.PrimaryColor = "#a1b2c3"
		c.Branding.SupportText = "Need help? Email membership@northside.example"
		c.Branding.Logo = "https://cdn.northside.example/logo.png"
	}))
	resp, body := get(t, env.Client(t), env.TS.URL+"/login")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{
		"Sign in",
		"Northside Hackspace",
		"--primary: #a1b2c3",
		"Need help? Email membership@northside.example",
		`src="/static/logo"`,
		`href="/static/keywell.css"`,
		`action="/login"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy %q", csp)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
		"Content-Type":           "text/html; charset=utf-8",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// mountFunc lets a test register extra routes through Deps.OIDC.
type mountFunc func(*http.ServeMux)

func (f mountFunc) Mount(mux *http.ServeMux) { f(mux) }

// customHandler builds the full web handler (all middleware) with extra
// routes registered by mount. Each change runs on the Deps before New.
func customHandler(t *testing.T, trusted []string, mount mountFunc, changes ...func(*web.Deps)) http.Handler {
	t.Helper()
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "http://keywell.test"
	cfg.TrustedProxies = trusted
	log := slog.New(slog.DiscardHandler)
	rd, err := web.NewRenderer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.OpenTest(t)
	d := web.Deps{
		Cfg:      cfg,
		Store:    st,
		Sessions: session.NewManager(st, time.Hour, 2*time.Hour, false),
		Log:      log,
		Renderer: rd,
		OIDC:     mount,
	}
	for _, change := range changes {
		change(&d)
	}
	return web.New(d)
}

// echoHandler adds /echo, which writes the client IP and scheme the
// middleware resolved.
func echoHandler(t *testing.T, trusted []string) http.Handler {
	t.Helper()
	return customHandler(t, trusted, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /echo", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s|%s", web.ClientIP(r), r.URL.Scheme)
		})
	})
}

func TestPanicRendersGenericError(t *testing.T) {
	h := customHandler(t, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) {
			panic("database password is hunter2")
		})
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Something went wrong") || strings.Contains(body, "hunter2") {
		t.Fatalf("body %q", body)
	}
}

// A panic answered with a 500 is counted and logged like any other
// request.
func TestPanicIsCountedAndLogged(t *testing.T) {
	var logs bytes.Buffer
	reg := metrics.New("test")
	h := customHandler(t, nil, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	}, func(d *web.Deps) {
		d.Log = slog.New(slog.NewTextHandler(&logs, nil))
		d.Metrics = reg
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}

	scrape := httptest.NewRecorder()
	reg.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `keywell_http_requests_total{code="5xx"} 1`+"\n") {
		t.Errorf("panic not counted as 5xx:\n%s", scrape.Body.String())
	}
	var logged bool
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, "msg=request ") && strings.Contains(line, "path=/boom ") &&
			strings.Contains(line, "status=500 ") {
			logged = true
		}
	}
	if !logged {
		t.Errorf("no request line with status 500:\n%s", logs.String())
	}
	// The panic's own log line still shows where it happened.
	if !strings.Contains(logs.String(), "TestPanicIsCountedAndLogged.func1") {
		t.Errorf("panic stack lost the handler that panicked:\n%s", logs.String())
	}
}

func TestRealIPOnlyFromTrustedProxy(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     string
		proto   string
		want    string
	}{
		{"trusted proxy", []string{"10.0.0.0/8"}, "10.0.0.1:5555", "198.51.100.9, 203.0.113.7", "https", "203.0.113.7|https"},
		{"trusted proxy chain", []string{"10.0.0.0/8"}, "10.0.0.1:5555", "203.0.113.7, 10.0.0.2", "", "203.0.113.7|"},
		{"all hops trusted", []string{"10.0.0.0/8"}, "10.0.0.1:5555", "10.9.9.9, 10.0.5.5", "", "10.0.5.5|"},
		{"untrusted peer", []string{"10.0.0.0/8"}, "192.0.2.1:5555", "203.0.113.7", "https", "192.0.2.1|"},
		{"no trusted proxies", nil, "10.0.0.1:5555", "203.0.113.7", "https", "10.0.0.1|"},
		{"trusted proxy without header", []string{"10.0.0.0/8"}, "10.0.0.1:5555", "", "", "10.0.0.1|"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := echoHandler(t, tc.trusted)
			req := httptest.NewRequest(http.MethodGet, "/echo", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Body.String() != tc.want {
				t.Fatalf("status %d body %q, want %q", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	env := testenv.New(t)
	c := env.Client(t)
	post := func(path, fetchSite string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, env.TS.URL+path, strings.NewReader("email=a%40example.org"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", fetchSite)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("/login", "cross-site"); got != http.StatusForbidden {
		t.Errorf("cross-site POST /login: status %d, want 403", got)
	}
	if got := post("/login", "same-origin"); got != http.StatusOK {
		t.Errorf("same-origin POST /login: status %d, want 200", got)
	}
	if got := post("/oauth/token", "cross-site"); got == http.StatusForbidden {
		t.Errorf("cross-site POST /oauth/token was blocked")
	}
}

func TestStaticAndLogo(t *testing.T) {
	env := testenv.New(t)
	c := env.Client(t)
	resp, body := get(t, c, env.TS.URL+"/static/keywell.css")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "--primary") {
		t.Fatalf("keywell.css: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("keywell.css content type %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("keywell.css cache control %q", cc)
	}
	if resp, _ := get(t, c, env.TS.URL+"/static/logo"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("logo without config: status %d, want 404", resp.StatusCode)
	}

	urlEnv := testenv.New(t, testenv.WithConfig(func(c *config.Config) {
		c.Branding.Logo = "https://cdn.example.org/logo.png"
	}))
	resp, _ = get(t, urlEnv.Client(t), urlEnv.TS.URL+"/static/logo")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://cdn.example.org/logo.png" {
		t.Errorf("logo URL: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	logo := filepath.Join(t.TempDir(), "logo.svg")
	svg := `<svg xmlns="http://www.w3.org/2000/svg"/>`
	if err := os.WriteFile(logo, []byte(svg), 0o600); err != nil {
		t.Fatal(err)
	}
	fileEnv := testenv.New(t, testenv.WithConfig(func(c *config.Config) { c.Branding.Logo = logo }))
	resp, body = get(t, fileEnv.Client(t), fileEnv.TS.URL+"/static/logo")
	if resp.StatusCode != http.StatusOK || body != svg {
		t.Errorf("logo file: status %d body %q", resp.StatusCode, body)
	}
}

func TestRendererPages(t *testing.T) {
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	rd, err := web.NewRenderer(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)

	rec := httptest.NewRecorder()
	rd.RenderNoAccess(rec, req, "Members <Wiki>")
	if rec.Code != http.StatusOK {
		t.Fatalf("no access status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"You don't have access to Members &lt;Wiki&gt;.", "Ask an admin", `action="/logout"`} {
		if !strings.Contains(body, want) {
			t.Errorf("no access page missing %q", want)
		}
	}

	rec = httptest.NewRecorder()
	rd.RenderError(rec, req, http.StatusBadRequest, "Unknown application", "The app that sent you here is not registered.")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("error status %d", rec.Code)
	}
	body = rec.Body.String()
	for _, want := range []string{"<h1>Unknown application</h1>", "The app that sent you here is not registered.", "Keywell"} {
		if !strings.Contains(body, want) {
			t.Errorf("error page missing %q", want)
		}
	}
}
