package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxIconBytes = 256 << 10
	iconPrefix   = "/icons/"

	msgIconType = "Use a PNG, JPEG, GIF or WebP image."
	msgIconSize = "That image is bigger than 256 KB. Use a smaller one."
	msgIconRead = "The upload couldn't be read. Try again."
)

// iconName matches the names saveIcon makes: an app ID, a dash, 12 hex
// digits of the content's hash and the extension.
var iconName = regexp.MustCompile(`^[0-9a-f-]{36}-[0-9a-f]{12}\.(png|jpg|gif|webp)$`)

// iconTypes are the accepted image types, by sniffed type.
var iconTypes = map[string]string{
	"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp",
}

// iconContentType is the Content-Type served for each extension.
var iconContentType = map[string]string{
	"png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
}

// iconExt checks data is an acceptable image and returns its extension.
// Otherwise problem is the message for the upload field.
func iconExt(data []byte) (ext, problem string) {
	if len(data) > maxIconBytes {
		return "", msgIconSize
	}
	ext, ok := iconTypes[http.DetectContentType(data)]
	if !ok {
		return "", msgIconType
	}
	return ext, ""
}

func (s *Server) iconDir() string { return filepath.Join(s.d.Cfg.DataDir, "icons") }

// saveIcon stores data as appID's icon and returns the icon URL. problem
// is a message for the upload field when data is not an acceptable image;
// err is a failure to write it.
func (s *Server) saveIcon(appID string, data []byte) (iconURL string, problem string, err error) {
	ext, problem := iconExt(data)
	if problem != "" {
		return "", problem, nil
	}
	sum := sha256.Sum256(data)
	name := appID + "-" + hex.EncodeToString(sum[:])[:12] + "." + ext
	dir := s.iconDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return "", "", err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmp.Name())
		return "", "", err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return "", "", err
	}
	return iconPrefix + name, "", nil
}

// removeIconFile deletes the file iconURL names, if it names one of ours.
// A failure is logged and otherwise ignored; file contents are never
// logged.
func (s *Server) removeIconFile(iconURL string) {
	name, ok := strings.CutPrefix(iconURL, iconPrefix)
	if !ok || !iconName.MatchString(name) {
		return
	}
	if err := os.Remove(filepath.Join(s.iconDir(), name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.d.Log.Warn("icons: remove file", "name", name, "error", err)
	}
}

// ownIcon reports whether iconURL is a file saved for the app with this
// ID, so that cleanup never touches another app's icon.
func ownIcon(appID, iconURL string) bool {
	return strings.HasPrefix(iconURL, iconPrefix+appID+"-")
}

// serveIcon serves an uploaded icon. It needs no session: tiles are
// plain images, and only names saveIcon could have made are served.
func (s *Server) serveIcon(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !iconName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join(s.iconDir(), name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", iconContentType[name[strings.LastIndexByte(name, '.')+1:]])
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}
