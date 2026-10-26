package web

import (
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/config"
	"github.com/James-Smart/keywell/internal/store"
)

func TestAdminFailureFor(t *testing.T) {
	fields := map[string]string{"email": "Another member already uses that email address."}
	for _, tc := range []struct {
		name string
		err  error
		want adminFailure
		ok   bool
	}{
		{"validation", &admin.ValidationError{Fields: fields},
			adminFailure{Status: http.StatusUnprocessableEntity, Fields: fields}, true},
		{"refused, wrapped", fmt.Errorf("save: %w", &admin.RefusedError{Message: "You can't disable your own account."}),
			adminFailure{Status: http.StatusConflict, Message: "You can't disable your own account."}, true},
		{"email", &admin.EmailError{Err: errors.New("550 mailbox unavailable")},
			adminFailure{Status: http.StatusBadGateway, Message: msgEmailNotSent}, true},
		{"not found, wrapped", fmt.Errorf("load: %w", store.ErrNotFound),
			adminFailure{Status: http.StatusNotFound}, true},
		{"unexpected", errors.New("database is locked"), adminFailure{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := adminFailureFor(tc.err)
			if ok != tc.ok || got.Status != tc.want.Status || got.Message != tc.want.Message ||
				fmt.Sprint(got.Fields) != fmt.Sprint(tc.want.Fields) {
				t.Errorf("adminFailureFor = %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// adminFailed writes the 404 and 500 pages itself and leaves every other
// failure to the page.
func TestAdminFailed(t *testing.T) {
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	rd, err := NewRenderer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(Deps{Cfg: cfg, Log: log, Renderer: rd})
	fail := func(err error) (*httptest.ResponseRecorder, adminFailure, bool) {
		w := httptest.NewRecorder()
		f, ok := s.adminFailed(w, httptest.NewRequest(http.MethodPost, "/admin/members/x", nil), "members: save", err)
		return w, f, ok
	}

	w, _, ok := fail(fmt.Errorf("load: %w", store.ErrNotFound))
	if ok || w.Code != http.StatusNotFound {
		t.Fatalf("not found: ok %v, status %d; want false, 404", ok, w.Code)
	}
	for _, want := range []string{"Not found",
		html.EscapeString("We couldn't find that. It may have been deleted, or the link may be wrong.")} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("404 page missing %q", want)
		}
	}

	w, _, ok = fail(errors.New("database is locked"))
	if ok || w.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected error: ok %v, status %d; want false, 500", ok, w.Code)
	}
	if strings.Contains(w.Body.String(), "database is locked") {
		t.Error("500 page shows the internal error")
	}
	if !strings.Contains(logs.String(), "members: save") || !strings.Contains(logs.String(), "database is locked") {
		t.Errorf("unexpected error not logged:\n%s", logs.String())
	}

	w, f, ok := fail(&admin.RefusedError{Message: "This is the only admin group."})
	if !ok || f.Status != http.StatusConflict || f.Message != "This is the only admin group." {
		t.Fatalf("refused: %+v, ok %v", f, ok)
	}
	if w.Body.Len() != 0 || w.Code != http.StatusOK { // recorder default: nothing written
		t.Errorf("refused: adminFailed wrote a response (status %d)", w.Code)
	}
}
