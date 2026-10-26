package web

import (
	"net/http"
	"os"

	"github.com/James-Smart/keywell/internal/icons"
)

const msgIconRead = "The upload couldn't be read. Try again."

// removeIconFile deletes iconURL's file when appID owns it. A failure is
// logged and otherwise ignored; file contents are never logged.
func (s *Server) removeIconFile(appID, iconURL string) {
	if err := icons.RemoveIfOwned(s.d.Cfg.DataDir, appID, iconURL); err != nil {
		s.d.Log.Warn("icons: remove file", "app_id", appID, "icon", iconURL, "error", err)
	}
}

// serveIcon serves an uploaded icon. It needs no session: tiles are
// plain images, and only names icons.Save could have made are served.
func (s *Server) serveIcon(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	contentType, ok := icons.ContentType(name)
	path, _ := icons.Path(s.d.Cfg.DataDir, name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}
