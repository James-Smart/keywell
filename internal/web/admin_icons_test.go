package web_test

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"latch/internal/model"
	"latch/internal/testenv"
)

// pngBytes is a valid PNG of w x 1 pixels.
func pngBytes(t *testing.T, w int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, 1))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// iconApp creates a wiki app and returns it with its edit path.
func iconApp(t *testing.T, env *testenv.Env) (*model.Application, string) {
	t.Helper()
	app := createApp(t, env, model.Application{Name: "Wiki", Slug: "wiki", ClientType: model.ClientTypePublic,
		RedirectURIs: []string{"https://wiki.example.org/cb"}, LaunchURL: "https://wiki.example.org/", ShowTile: true}, "")
	return app, "/admin/apps/" + app.ID
}

// iconForm is the edit form that saves the wiki app unchanged.
func iconForm() url.Values {
	v := appValues("Wiki", "public")
	v.Set("slug", "wiki")
	v.Set("launch_url", "https://wiki.example.org/")
	v.Set("show_tile", "on")
	return v
}

// iconFiles lists the files in the data directory's icons folder.
func iconFiles(t *testing.T, env *testenv.Env) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(env.Cfg.DataDir, "icons"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestUploadIcon(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	app, path := iconApp(t, env)
	data := pngBytes(t, 1)

	resp, _ := env.SubmitMultipart(t, c, path, iconForm(), "icon", "logo.png", data)
	assertRedirect(t, resp, path+"?notice=saved")
	got := storedApp(t, env, "wiki")
	if !regexp.MustCompile(`^/icons/` + app.ID + `-[0-9a-f]{12}\.png$`).MatchString(got.IconURL) {
		t.Fatalf("IconURL = %q", got.IconURL)
	}

	resp, body := env.Page(t, c, got.IconURL)
	assertStatus(t, resp, 200)
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options missing")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if body != string(data) {
		t.Errorf("served bytes differ")
	}

	// No session is needed.
	plain, err := http.Get(env.TS.URL + got.IconURL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, plain.Body)
	plain.Body.Close()
	assertStatus(t, plain, 200)

	_, home := env.Page(t, c, "/")
	assertContains(t, home, `src="`+got.IconURL+`"`)
}

func TestIconRejected(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	_, path := iconApp(t, env)

	big := append(pngBytes(t, 1), make([]byte, 300*1024)...)
	resp, body := env.SubmitMultipart(t, c, path, iconForm(), "icon", "big.png", big)
	assertStatus(t, resp, 422)
	assertContains(t, body, "bigger than 256 KB")

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>`)
	resp, body = env.SubmitMultipart(t, c, path, iconForm(), "icon", "logo.svg", svg)
	assertStatus(t, resp, 422)
	assertContains(t, body, "Use a PNG, JPEG, GIF or WebP image.")

	// A bad icon saves nothing, not even the other fields.
	v := iconForm()
	v.Set("description", "changed")
	resp, _ = env.SubmitMultipart(t, c, path, v, "icon", "logo.svg", svg)
	assertStatus(t, resp, 422)
	got := storedApp(t, env, "wiki")
	if got.IconURL != "" || got.Description != "" {
		t.Errorf("stored icon %q, description %q", got.IconURL, got.Description)
	}
	if files := iconFiles(t, env); len(files) != 0 {
		t.Errorf("files left: %v", files)
	}

	// A good icon with a bad other field leaves no file behind.
	v = iconForm()
	v.Set("access_token_ttl", "soon")
	resp, _ = env.SubmitMultipart(t, c, path, v, "icon", "logo.png", pngBytes(t, 1))
	assertStatus(t, resp, 422)
	if files := iconFiles(t, env); len(files) != 0 {
		t.Errorf("orphan files: %v", files)
	}
}

func TestReplaceAndRemoveIcon(t *testing.T) {
	env := testenv.New(t)
	c, _ := env.AdminClient(t)
	_, path := iconApp(t, env)

	env.SubmitMultipart(t, c, path, iconForm(), "icon", "a.png", pngBytes(t, 1))
	first := storedApp(t, env, "wiki").IconURL

	env.SubmitMultipart(t, c, path, iconForm(), "icon", "b.png", pngBytes(t, 2))
	second := storedApp(t, env, "wiki").IconURL
	if second == first || second == "" {
		t.Fatalf("icon URL %q did not change from %q", second, first)
	}
	files := iconFiles(t, env)
	if len(files) != 1 || "/icons/"+files[0] != second {
		t.Errorf("files = %v, want only %s", files, second)
	}

	// Saving the form as shown, without a file, keeps the icon.
	v := iconForm()
	v.Set("icon_url", second)
	resp, _ := env.Submit(t, c, path, v)
	assertRedirect(t, resp, path+"?notice=saved")
	if got := storedApp(t, env, "wiki").IconURL; got != second {
		t.Errorf("IconURL = %q after a plain save", got)
	}
	if len(iconFiles(t, env)) != 1 {
		t.Errorf("file lost on a plain save")
	}

	v = iconForm()
	v.Set("icon_url", second)
	v.Set("remove_icon", "on")
	resp, _ = env.Submit(t, c, path, v)
	assertRedirect(t, resp, path+"?notice=saved")
	if got := storedApp(t, env, "wiki").IconURL; got != "" {
		t.Errorf("IconURL = %q after remove", got)
	}
	if files := iconFiles(t, env); len(files) != 0 {
		t.Errorf("files after remove: %v", files)
	}

	// Deleting the app removes its icon file.
	env.SubmitMultipart(t, c, path, iconForm(), "icon", "a.png", pngBytes(t, 1))
	if len(iconFiles(t, env)) != 1 {
		t.Fatal("upload missing")
	}
	resp, _ = env.Submit(t, c, path+"/delete", url.Values{"confirm": {"Wiki"}})
	assertRedirect(t, resp, "/admin/apps?notice=deleted")
	if files := iconFiles(t, env); len(files) != 0 {
		t.Errorf("files after delete: %v", files)
	}
}

func TestIconRouteRejectsBadNames(t *testing.T) {
	env := testenv.New(t)
	// Files the guard must refuse to serve: one a traversal reaches, and
	// ones in the icons folder with names saveIcon never makes.
	const svgName = "00000000-0000-0000-0000-000000000000-0123456789ab.svg"
	dir := filepath.Join(env.Cfg.DataDir, "icons")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(env.Cfg.DataDir, "latch.db"): "SQLite format 3 secret",
		filepath.Join(dir, "x.svg"):                `<svg xmlns="http://www.w3.org/2000/svg"></svg>`,
		filepath.Join(dir, svgName):                `<svg xmlns="http://www.w3.org/2000/svg"></svg>`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"..%2Flatch.db",
		"%2e%2e%2flatch.db",
		"x.svg",
		"00000000-0000-0000-0000-000000000000-0123456789ab.png",
		"00000000-0000-0000-0000-000000000000-0123456789ab.svg",
	} {
		resp, err := http.Get(env.TS.URL + "/icons/" + name)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("GET /icons/%s: status %d, want 404", name, resp.StatusCode)
		}
	}
}
