package api

import (
	"net/http"
	"time"

	"github.com/James-Smart/keywell/internal/store"
)

// auditTime reads a ?since= or ?until= value: RFC 3339, or a date
// (YYYY-MM-DD) in UTC. An empty value is the zero time.
func auditTime(s string) (t time.Time, date, ok bool) {
	if s == "" {
		return time.Time{}, false, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, false, true
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, true, true
	}
	return time.Time{}, false, false
}

// listAudit answers GET /audit: raw events, newest first, never collapsed.
// A date for until includes that whole day.
func (h *handler) listAudit(w http.ResponseWriter, r *http.Request) {
	page, perPage, ok := paging(w, r)
	if !ok {
		return
	}
	q, bad := r.URL.Query(), map[string]string{}
	f := store.AuditFilter{
		ActorID: q.Get("actor"), TargetID: q.Get("target"), Query: q.Get("q"), Page: page, PerPage: perPage,
	}
	if a := q.Get("action"); a != "" {
		f.Actions = []string{a}
	}
	var okSince, okUntil, untilIsDate bool
	f.Since, _, okSince = auditTime(q.Get("since"))
	f.Until, untilIsDate, okUntil = auditTime(q.Get("until"))
	if !okSince {
		bad["since"] = msgBadTime
	}
	if !okUntil {
		bad["until"] = msgBadTime
	}
	if len(bad) > 0 {
		writeInvalid(w, bad)
		return
	}
	if untilIsDate {
		f.Until = f.Until.AddDate(0, 0, 1)
	}
	res, err := h.d.Store.ListAuditEvents(r.Context(), f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]auditEventJSON, len(res.Rows))
	for i := range res.Rows {
		out[i] = newAuditEventJSON(&res.Rows[i].AuditEvent)
	}
	writeJSON(w, http.StatusOK, newList(out, res.Page, res.PerPage, res.Total))
}
