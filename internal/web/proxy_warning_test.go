package web_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/session"
	"github.com/James-Smart/keywell/internal/store/storetest"
	"github.com/James-Smart/keywell/internal/web"
)

// A reverse proxy missing from trusted_proxies makes every member share the
// proxy's address, so one member's failed sign-ins lock everyone out. The
// server says so in its log, once per peer, when forwarded headers arrive
// from a peer it does not trust.
func TestWarnsOnceForForwardedHeadersFromUntrustedPeer(t *testing.T) {
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "http://keywell.test"
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rd, err := web.NewRenderer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.OpenTest(t)
	h := web.New(web.Deps{Cfg: cfg, Store: st, Sessions: session.NewManager(st, time.Hour, 2*time.Hour, false),
		Log: log, Renderer: rd})

	send := func(remote string, headers map[string]string) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = remote
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	warnings := func() []string {
		var got []string
		for line := range strings.Lines(logs.String()) {
			if strings.Contains(line, "untrusted peer") {
				got = append(got, line)
			}
		}
		return got
	}

	xff := map[string]string{"X-Forwarded-For": "198.51.100.7"}
	send("192.0.2.1:5555", xff)
	send("192.0.2.1:6666", xff)                                             // the same peer again
	send("192.0.2.1:7777", nil)                                             // nothing forwarded
	send("10.0.0.1:5555", xff)                                              // a trusted proxy
	send("192.0.2.2:5555", map[string]string{"X-Forwarded-Proto": "https"}) // another peer

	got := warnings()
	if len(got) != 2 {
		t.Fatalf("%d warnings, want 2 (one per untrusted peer):\n%s", len(got), logs.String())
	}
	for i, want := range []string{
		"ignoring X-Forwarded-For from untrusted peer 192.0.2.1; add your reverse proxy to trusted_proxies",
		"ignoring X-Forwarded-Proto from untrusted peer 192.0.2.2; add your reverse proxy to trusted_proxies",
	} {
		if !strings.Contains(got[i], "level=WARN") || !strings.Contains(got[i], want) {
			t.Errorf("warning %d: %s\nwant WARN %q", i+1, got[i], want)
		}
	}
}
