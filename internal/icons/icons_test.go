package icons_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"latch/internal/icons"
)

const (
	appA = "6b408ea2-1a63-46c5-9c90-73cfd82cfc6c"
	appB = "11111111-1a63-46c5-9c90-73cfd82cfc6c"
)

var pngData = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

func TestValidName(t *testing.T) {
	for _, n := range []string{appA + "-0123456789ab.png", appA + "-0123456789ab.jpg", appA + "-0123456789ab.gif", appA + "-0123456789ab.webp"} {
		if !icons.ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range []string{
		"", "x.svg", "../latch.db", "..%2Flatch.db", "../" + appA + "-0123456789ab.png",
		appA + "-0123456789ab.svg", appA + "-0123456789ab.png/", appA + "-0123456789AB.png",
		appA + "-0123456789a.png", "a/" + appA + "-0123456789ab.png",
	} {
		if icons.ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

func TestSaveAndCheck(t *testing.T) {
	dir := t.TempDir()
	url, problem, err := icons.Save(dir, appA, pngData)
	if err != nil || problem != "" || !strings.HasPrefix(url, icons.Prefix+appA+"-") || !strings.HasSuffix(url, ".png") {
		t.Fatalf("Save = %q, %q, %v", url, problem, err)
	}
	if _, ok := icons.Path(dir, strings.TrimPrefix(url, icons.Prefix)); !ok {
		t.Fatal("saved name is not valid")
	}
	if _, problem, _ := icons.Save(dir, appA, []byte("<svg/>")); problem != icons.MsgType {
		t.Errorf("svg problem = %q", problem)
	}
	if _, problem, _ := icons.Save(dir, appA, append(pngData, make([]byte, icons.MaxBytes)...)); problem != icons.MsgSize {
		t.Errorf("big problem = %q", problem)
	}
	entries, _ := os.ReadDir(icons.Dir(dir))
	if len(entries) != 1 {
		t.Errorf("%d files, want 1", len(entries))
	}
}

func TestOwns(t *testing.T) {
	own := icons.Prefix + appA + "-0123456789ab.png"
	if !icons.Owns(appA, own) {
		t.Error("owner does not own its icon")
	}
	for _, c := range []struct{ app, url string }{
		{appB, own},
		{"", own},
		{appA, ""},
		{appA, "https://example.org/x.png"},
		{appA, appA + "-0123456789ab.png"},
		{appA, icons.Prefix + "../" + appA + "-0123456789ab.png"},
		{appA, icons.Prefix + appA + "-0123456789ab.svg"},
	} {
		if icons.Owns(c.app, c.url) {
			t.Errorf("Owns(%q, %q) = true", c.app, c.url)
		}
	}
}

func TestRemoveIfOwned(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := icons.Save(dir, appA, pngData)
	b, _, _ := icons.Save(dir, appB, pngData)
	if err := icons.RemoveIfOwned(dir, appA, b); err != nil {
		t.Fatal(err)
	}
	pb, _ := icons.Path(dir, strings.TrimPrefix(b, icons.Prefix))
	pa, _ := icons.Path(dir, strings.TrimPrefix(a, icons.Prefix))
	if _, err := os.Stat(pb); err != nil {
		t.Errorf("another app's file removed: %v", err)
	}
	if err := icons.RemoveIfOwned(dir, appA, a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pa); !os.IsNotExist(err) {
		t.Errorf("own file still there: %v", err)
	}
	if err := icons.RemoveIfOwned(dir, appA, a); err != nil {
		t.Errorf("already gone: %v", err)
	}
	// A file outside the icons folder is never touched.
	other := filepath.Join(dir, "latch.db")
	os.WriteFile(other, []byte("db"), 0o600)
	if err := icons.RemoveIfOwned(dir, appA, "/icons/../latch.db"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("latch.db removed: %v", err)
	}
}
