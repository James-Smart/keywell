package web

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"latch/internal/config"
)

func TestTemplateFuncs(t *testing.T) {
	fm := templateFuncs()
	ago := fm["ago"].(func(*time.Time) string)
	date := fm["date"].(func(time.Time) string)
	datetime := fm["datetime"].(func(time.Time) string)
	prettyJSON := fm["prettyJSON"].(func(map[string]any) string)

	if got := ago(nil); got != "Never" {
		t.Errorf("ago(nil) = %q, want Never", got)
	}
	now := time.Now()
	for _, tc := range []struct {
		before time.Duration
		want   string
	}{
		{time.Hour, "Today"},
		{30 * time.Hour, "Yesterday"},
		{5 * 24 * time.Hour, "5 days ago"},
		{70 * 24 * time.Hour, "2 months ago"},
		{800 * 24 * time.Hour, "2 years ago"},
		{31 * 24 * time.Hour, "1 month ago"},
		{400 * 24 * time.Hour, "1 year ago"},
	} {
		at := now.Add(-tc.before)
		if got := ago(&at); got != tc.want {
			t.Errorf("ago(now - %v) = %q, want %q", tc.before, got, tc.want)
		}
	}

	at := time.Date(2026, 10, 3, 14, 5, 0, 0, time.UTC)
	if got := date(at); got != "3 Oct 2026" {
		t.Errorf("date = %q, want 3 Oct 2026", got)
	}
	if got := datetime(at.In(time.FixedZone("BST", 3600))); got != "3 Oct 2026 14:05 UTC" {
		t.Errorf("datetime = %q, want 3 Oct 2026 14:05 UTC", got)
	}

	if got := prettyJSON(map[string]any{"a": 1}); got != "{\n  \"a\": 1\n}" {
		t.Errorf("prettyJSON = %q", got)
	}
	if got := prettyJSON(nil); got != "{}" {
		t.Errorf("prettyJSON(nil) = %q, want {}", got)
	}
	// Shown in a form for editing, so kept as typed: html/template escapes
	// it for the page.
	if got := prettyJSON(map[string]any{"note": "<b>&"}); got != "{\n  \"note\": \"<b>&\"\n}" {
		t.Errorf("prettyJSON escaped HTML: %q", got)
	}
}

// Every _*.html file is in every page's template set, and none is a page.
func TestPartialsInEveryPage(t *testing.T) {
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	rd, err := NewRenderer(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if len(rd.pages) == 0 {
		t.Fatal("no pages")
	}
	for name, set := range rd.pages {
		if strings.HasPrefix(name, "_") {
			t.Errorf("partial file %s is a page", name)
		}
		if set.Lookup("admin-nav") == nil {
			t.Errorf("page %s lacks the admin partials", name)
		}
	}
}
