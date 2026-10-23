package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"latch/internal/admin"
	"latch/internal/model"
	"latch/internal/store"
)

// Error messages, and the field message of a bad page or per_page. The
// message of a 409 refused is the admin service's own.
const (
	msgInvalidJSON        = "Send a JSON object with only the documented fields."
	msgUnknownFieldFormat = "Send a JSON object with only the documented fields. This request doesn't take %s."
	msgUnauthorized       = "Send a valid API token in the Authorization header."
	msgReadOnly           = "This token can only read. Use a token with full admin access to make changes."
	msgNoRoute            = "There is nothing at that address. The OpenAPI document at /api/v1/openapi.json lists every route."
	msgNotFound           = "We couldn't find that. It may have been deleted, or the ID may be wrong."
	msgMethodFormat       = "This address doesn't take %s requests. The Allow header lists the methods it takes."
	msgTooLarge           = "The request body is over the 1 MiB limit."
	msgInvalid            = "Some values can't be saved. The fields object says what to change."
	msgRateLimited        = "This token has made too many requests. Wait a minute, then try again."
	msgEmailFailed        = "The email couldn't be sent. Check the email settings on the Settings page, then try again."
	msgInternal           = "Something went wrong on our side. Please try again in a moment."
	msgWholeNumber        = "Use a whole number of 1 or more."
	msgInviteNotSent      = "The member was added, but the invitation email couldn't be sent. Check the email settings on the Settings page, then send it again with reset-email."
	msgGroupsRequired     = "Send the complete list of groups, as names or IDs."
	msgStatusUnknown      = "Use active, invited, needs_password, disabled, no_2fa or admins."
	msgBadSeconds         = "Use a whole number of seconds, or null for the default."
	msgBadServiceAccount  = "Send a service account ID, or null for none."
	msgBadTime            = "Use a date and time like 2026-03-01T09:00:00Z, or a date like 2026-03-01."
	msgBadExpiry          = "Use a date and time like 2026-03-01T09:00:00Z, or leave it out for no expiry."
)

// errorJSON is the body of every error response.
type errorJSON struct {
	Error   string            `json:"error"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"` // only with invalid
}

// writeJSON writes v as the response body, with status. The JSON headers
// are already set (recoverJSON).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes the error shape: {"error": code, "message": message}.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorJSON{Error: code, Message: message})
}

// writeInvalid writes 422 invalid with a message per field.
func writeInvalid(w http.ResponseWriter, fields map[string]string) {
	writeJSON(w, http.StatusUnprocessableEntity, errorJSON{Error: "invalid", Message: msgInvalid, Fields: fields})
}

// fail answers a request whose admin service call (or store read) returned
// err: 422 invalid with fields for an *admin.ValidationError, 409 refused
// with its message for an *admin.RefusedError, 502 email_failed for an
// *admin.EmailError, 404 not_found for store.ErrNotFound, and otherwise a
// logged 500 internal. An *admin.EmailError is not logged here because its
// text can hold the member's address; the handler logs it without.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var (
		invalid *admin.ValidationError
		refused *admin.RefusedError
		unsent  *admin.EmailError
	)
	switch {
	case errors.As(err, &invalid):
		writeInvalid(w, invalid.Fields)
	case errors.As(err, &refused):
		writeError(w, http.StatusConflict, "refused", refused.Message)
	case errors.As(err, &unsent):
		writeError(w, http.StatusBadGateway, "email_failed", msgEmailFailed)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", msgNotFound)
	default:
		h.d.Log.ErrorContext(r.Context(), "api: request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", msgInternal)
	}
}

// logUnsent logs why an email to member u was not sent, without their
// address, for whoever fixes the email settings. fail and the admin
// service leave this to the handler.
func (h *handler) logUnsent(r *http.Request, what string, u *model.User, err error) {
	h.d.Log.ErrorContext(r.Context(), what, "user_id", u.ID, "error", redactAddress(err.Error(), u.Email))
}

// failUnsent logs why an email to u was not sent, then answers 502
// email_failed.
func (h *handler) failUnsent(w http.ResponseWriter, r *http.Request, what string, u *model.User, err error) {
	h.logUnsent(r, what, u, err)
	h.fail(w, r, err)
}

// redactAddress replaces address in msg, as given or in lower case, with
// "[recipient]".
func redactAddress(msg, address string) string {
	if address == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, address, "[recipient]")
	return strings.ReplaceAll(msg, strings.ToLower(address), "[recipient]")
}

// metadataPatch reads the metadata of a request body: nil when the field
// is absent or null (leave it alone, or use the default), else the object.
// A value that isn't an object is answered 422 invalid, naming metadata,
// and ok is false.
func (h *handler) metadataPatch(w http.ResponseWriter, r *http.Request, raw json.RawMessage) (m *map[string]any, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	parsed, invalid := admin.ParseMetadata(string(raw))
	if invalid != nil {
		h.fail(w, r, invalid)
		return nil, false
	}
	return &parsed, true
}

// decode reads the request body, which must be one JSON object with only
// the fields v has, into v. Otherwise it answers 400 invalid_json (or 413
// too_large past the body limit) and returns false.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", msgTooLarge)
		return false
	}
	// Checked first because Decode accepts null into a struct, leaving it
	// as it was.
	if err != nil || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		writeError(w, http.StatusBadRequest, "invalid_json", msgInvalidJSON)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	err = dec.Decode(v)
	if field, unknown := strings.CutPrefix(fmt.Sprint(err), "json: unknown field "); unknown {
		writeError(w, http.StatusBadRequest, "invalid_json", fmt.Sprintf(msgUnknownFieldFormat, field))
		return false
	}
	if _, tail := dec.Token(); err != nil || tail != io.EOF { // io.EOF: nothing follows the object
		writeError(w, http.StatusBadRequest, "invalid_json", msgInvalidJSON)
		return false
	}
	return true
}

// Paging of list responses.
const (
	defaultPerPage = 50
	maxPerPage     = 200
	maxPage        = 1_000_000 // keeps (page-1)*perPage far from overflowing; no list is this long
)

// listJSON is the body of every list response. Make it with newList.
type listJSON[T any] struct {
	Items   []T `json:"items"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"` // every match, across all pages
}

// newList returns the list body, with items [] rather than null when
// there are none.
func newList[T any](items []T, page, perPage, total int) listJSON[T] {
	if items == nil {
		items = []T{}
	}
	return listJSON[T]{Items: items, Page: page, PerPage: perPage, Total: total}
}

// pageOf returns the given page of s, which is all of a list held in
// memory, and the length of s. A page past the end is empty. page and
// perPage must come from paging, which caps page so the arithmetic here
// cannot overflow.
func pageOf[T any](s []T, page, perPage int) (items []T, total int) {
	total = len(s)
	s = s[min((page-1)*perPage, total):]
	return s[:min(perPage, len(s))], total
}

// paging reads ?page= and ?per_page=, whole numbers of 1 or more: page
// defaults to 1 and per_page to 50, and per_page is capped at 200 and page
// at maxPage (a page past the end of a list is empty). Anything
// else is answered 422 invalid, naming the parameter, and ok is false.
func paging(w http.ResponseWriter, r *http.Request) (page, perPage int, ok bool) {
	q, bad := r.URL.Query(), map[string]string{}
	read := func(name string, def int) int {
		s := q.Get(name)
		if s == "" {
			return def
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			bad[name] = msgWholeNumber
		}
		return n
	}
	page, perPage = read("page", 1), read("per_page", defaultPerPage)
	if len(bad) > 0 {
		writeInvalid(w, bad)
		return 0, 0, false
	}
	return min(page, maxPage), min(perPage, maxPerPage), true
}
