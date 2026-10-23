package api

import (
	_ "embed"
	"net/http"
)

// openAPIDoc is the OpenAPI 3.1 description of the routes, written by
// hand. TestOpenAPIMatchesRoutes keeps it in step with the routes table.
//
//go:embed openapi.json
var openAPIDoc []byte

// openAPI answers GET /openapi.json with the OpenAPI document. It needs no
// token.
func (h *handler) openAPI(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(openAPIDoc)
}
