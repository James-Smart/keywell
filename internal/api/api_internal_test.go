package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorded decodes a recorded response's body as a JSON object.
func recorded(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("status %d, body is not a JSON object: %v\n%s", rec.Code, err, rec.Body)
	}
	return body
}

// A panic in a handler is logged and answered with JSON, so the outer
// recoverer never shows its HTML page.
func TestRecoverAnswersJSON(t *testing.T) {
	var logged bytes.Buffer
	h := &handler{d: Deps{Log: slog.New(slog.NewTextHandler(&logged, nil))}}
	served := h.recoverJSON(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))

	rec := httptest.NewRecorder()
	served.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	if body := recorded(t, rec); body["error"] != "internal" || body["message"] != msgInternal {
		t.Errorf("body %v, want internal", body)
	}
	if !strings.Contains(logged.String(), "boom") {
		t.Errorf("the panic was not logged: %s", logged.String())
	}
}

func TestDecode(t *testing.T) {
	type input struct {
		Name string `json:"name"`
	}
	for _, tc := range []struct {
		name, body string
		status     int // 0: decoded
		code       string
	}{
		{"object", `{"name": "Door"}`, 0, ""},
		{"empty object", ` {} `, 0, ""},
		{"unknown field", `{"nmae": "Door"}`, http.StatusBadRequest, "invalid_json"},
		{"array", `[1, 2]`, http.StatusBadRequest, "invalid_json"},
		{"string", `"x"`, http.StatusBadRequest, "invalid_json"},
		{"null", `null`, http.StatusBadRequest, "invalid_json"},
		{"number", `42`, http.StatusBadRequest, "invalid_json"},
		{"wrong type", `{"name": 42}`, http.StatusBadRequest, "invalid_json"},
		{"not JSON", `nope`, http.StatusBadRequest, "invalid_json"},
		{"empty", ``, http.StatusBadRequest, "invalid_json"},
		{"two objects", `{} {}`, http.StatusBadRequest, "invalid_json"},
		{"over the limit", `{"name": "` + strings.Repeat("a", maxBodyBytes) + `"}`, http.StatusRequestEntityTooLarge, "too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/x", strings.NewReader(tc.body))
			r.Body = http.MaxBytesReader(rec, r.Body, maxBodyBytes) // as limitBody does
			var in input
			ok := decode(rec, r, &in)
			if tc.status == 0 {
				if !ok {
					t.Fatalf("not decoded: status %d %s", rec.Code, rec.Body)
				}
				return
			}
			if ok {
				t.Fatalf("decoded %+v, want status %d", in, tc.status)
			}
			if body := recorded(t, rec); rec.Code != tc.status || body["error"] != tc.code {
				t.Errorf("status %d, body %v; want %d %s", rec.Code, body, tc.status, tc.code)
			}
		})
	}

	// An unknown field is named in the message.
	rec := httptest.NewRecorder()
	decode(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"nmae": "Door"}`)), &input{})
	if msg, _ := recorded(t, rec)["message"].(string); !strings.Contains(msg, `"nmae"`) {
		t.Errorf("message %q does not name the unknown field", msg)
	}
}

func TestPaging(t *testing.T) {
	for _, tc := range []struct {
		query             string
		page, perPage     int
		badPage, badLimit bool
	}{
		{"", 1, 50, false, false},
		{"page=3&per_page=10", 3, 10, false, false},
		{"per_page=500", 1, 200, false, false},
		{"page=0", 0, 0, true, false},
		{"page=-1&per_page=x", 0, 0, true, true},
		{"per_page=0", 0, 0, false, true},
		{"page=1.5", 0, 0, true, false},
	} {
		rec := httptest.NewRecorder()
		page, perPage, ok := paging(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x?"+tc.query, nil))
		if !tc.badPage && !tc.badLimit {
			if !ok || page != tc.page || perPage != tc.perPage {
				t.Errorf("?%s: %d, %d, %v; want %d, %d", tc.query, page, perPage, ok, tc.page, tc.perPage)
			}
			continue
		}
		body := recorded(t, rec)
		fields, _ := body["fields"].(map[string]any)
		_, gotPage := fields["page"]
		_, gotLimit := fields["per_page"]
		if ok || rec.Code != http.StatusUnprocessableEntity || body["error"] != "invalid" ||
			gotPage != tc.badPage || gotLimit != tc.badLimit {
			t.Errorf("?%s: ok %v, status %d, body %v; want 422 naming page %v, per_page %v",
				tc.query, ok, rec.Code, body, tc.badPage, tc.badLimit)
		}
	}
}

// An empty list is [] in JSON, never null.
func TestListItemsNeverNull(t *testing.T) {
	out, err := json.Marshal(newList[tokenJSON](nil, 1, 50, 0))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"items":[],"page":1,"per_page":50,"total":0}`; string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestPageOf(t *testing.T) {
	nums := []int{1, 2, 3, 4, 5}
	for _, tc := range []struct {
		name          string
		in            []int
		page, perPage int
		want          []int
		total         int
	}{
		{"empty", nil, 1, 50, nil, 0},
		{"first page", nums, 1, 2, []int{1, 2}, 5},
		{"last partial page", nums, 3, 2, []int{5}, 5},
		{"past the end", nums, 4, 2, nil, 5},
		{"max page", nums, maxPage, maxPerPage, nil, 5},
		{"everything", nums, 1, maxPerPage, nums, 5},
	} {
		got, total := pageOf(tc.in, tc.page, tc.perPage)
		if total != tc.total || len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
			t.Errorf("%s: got %v, %d; want %v, %d", tc.name, got, total, tc.want, tc.total)
		}
	}
}
