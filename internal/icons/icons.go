// Package icons holds application icon files: where they live, what is
// accepted, how they are written and which of them belong to an app. It
// works on files and URLs only, so the web pages and the API can share it.
package icons

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
	// Prefix starts the URL of every icon this package saves.
	Prefix = "/icons/"
	// MaxBytes is the largest icon accepted.
	MaxBytes = 256 << 10

	// MsgType and MsgSize are the messages for an unusable upload.
	MsgType = "Use a PNG, JPEG, GIF or WebP image."
	MsgSize = "That image is bigger than 256 KB. Use a smaller one."
)

// namePattern matches the names Save makes: an app ID, a dash, 12 hex
// digits of the content's hash and the extension.
var namePattern = regexp.MustCompile(`^[0-9a-f-]{36}-[0-9a-f]{12}\.(png|jpg|gif|webp)$`)

var (
	extByType = map[string]string{
		"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp",
	}
	typeByExt = map[string]string{
		"png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
	}
)

// ValidName reports whether name is a file name Save could have made.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// ContentType is the Content-Type to serve the icon file name with, and
// false when name is not a valid icon name.
func ContentType(name string) (string, bool) {
	if !ValidName(name) {
		return "", false
	}
	return typeByExt[name[strings.LastIndexByte(name, '.')+1:]], true
}

// Dir is the folder icons are kept in.
func Dir(dataDir string) string { return filepath.Join(dataDir, "icons") }

// Path is the file for the icon name, and false when name is not a valid
// icon name (so it can never leave Dir).
func Path(dataDir, name string) (string, bool) {
	if !ValidName(name) {
		return "", false
	}
	return filepath.Join(Dir(dataDir), name), true
}

// Check reports whether data is an acceptable image and returns its file
// extension. Otherwise problem is MsgSize or MsgType.
func Check(data []byte) (ext, problem string) {
	if len(data) > MaxBytes {
		return "", MsgSize
	}
	ext, ok := extByType[http.DetectContentType(data)]
	if !ok {
		return "", MsgType
	}
	return ext, ""
}

// Save stores data as appID's icon and returns its URL. problem is set
// (and nothing written) when data fails Check; err is a failure to write.
// The file is written to a temporary name and renamed into place.
func Save(dataDir, appID string, data []byte) (iconURL, problem string, err error) {
	ext, problem := Check(data)
	if problem != "" {
		return "", problem, nil
	}
	sum := sha256.Sum256(data)
	name := appID + "-" + hex.EncodeToString(sum[:])[:12] + "." + ext
	dir := Dir(dataDir)
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
	return Prefix + name, "", nil
}

// Owns reports whether iconURL is an icon file Save made for the app
// with this ID. Any other URL, including another app's icon, is not.
func Owns(appID, iconURL string) bool {
	name, ok := strings.CutPrefix(iconURL, Prefix)
	if !ok || appID == "" || !ValidName(name) {
		return false
	}
	return name[:strings.LastIndexByte(name, '-')] == appID
}

// RemoveIfOwned deletes the file iconURL names when appID owns it, and
// does nothing for any other URL. A file that is already gone is not an
// error.
func RemoveIfOwned(dataDir, appID, iconURL string) error {
	if !Owns(appID, iconURL) {
		return nil
	}
	path, _ := Path(dataDir, strings.TrimPrefix(iconURL, Prefix))
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
