package api

import "net/http"

// me answers GET /me: the service account the token belongs to, and the
// token.
func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	row, err := h.serviceAccountRow(r.Context(), c.Account)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ServiceAccount serviceAccountJSON `json:"service_account"`
		Token          tokenJSON          `json:"token"`
	}{newServiceAccountJSON(row), newTokenJSON(c.Token)})
}
