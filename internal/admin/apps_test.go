package admin_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"latch/internal/admin"
	"latch/internal/audit"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// validApp is an application input that passes every rule.
func validApp() admin.AppInput {
	return admin.AppInput{
		Name:         "Members Wiki",
		ClientType:   model.ClientTypeConfidential,
		RedirectURIs: []string{"https://wiki.example.org/callback"},
	}
}

// fieldMessages returns the messages of a *ValidationError, or fails.
func fieldMessages(t *testing.T, err error) map[string]string {
	t.Helper()
	var ve *admin.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v (%T), want *ValidationError", err, err)
	}
	return ve.Fields
}

func TestCreateConfidentialApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)

	app, secret, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 43 || app.ClientSecretHash != secrets.HashToken(secret) {
		t.Errorf("secret %q, hash %q", secret, app.ClientSecretHash)
	}
	if len(app.ClientID) != 24 || app.Slug != "members-wiki" || app.SubjectMode != model.SubjectModeID {
		t.Errorf("app %+v", app)
	}
	got, err := st.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecretHash != app.ClientSecretHash || got.ClientID != app.ClientID {
		t.Errorf("stored %+v", got)
	}

	ev := oneEvent(t, st, audit.AppCreate)
	if ev.TargetType != "application" || ev.TargetID != app.ID || ev.ActorID != ada.ID {
		t.Errorf("event %+v", ev)
	}
	if ev.Detail["slug"] != "members-wiki" || ev.Detail["client_type"] != "confidential" {
		t.Errorf("detail %v", ev.Detail)
	}
	for k, v := range ev.Detail {
		if strings.Contains(fmt.Sprint(v), secret) || strings.Contains(fmt.Sprint(v), app.ClientSecretHash) {
			t.Errorf("detail %s holds the secret", k)
		}
	}
}

func TestCreatePublicApp(t *testing.T) {
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	in := validApp()
	in.ClientType = model.ClientTypePublic

	app, secret, err := svc.CreateApp(context.Background(), actorFor(ada), in)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || app.ClientSecretHash != "" {
		t.Errorf("secret %q hash %q", secret, app.ClientSecretHash)
	}
}

func TestAppValidation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	member := mkMember(t, st, "Bo Member", "bo@example.org")
	if _, _, err := svc.CreateApp(ctx, actorFor(ada), validApp()); err != nil { // takes "members-wiki"
		t.Fatal(err)
	}

	tooMany := make([]string, 21)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("https://a.example.org/%d", i)
	}
	tests := []struct {
		name  string
		edit  func(*admin.AppInput)
		field string
		want  string // "" = any message
	}{
		{"empty name", func(in *admin.AppInput) { in.Name = " " }, "name", ""},
		{"long name", func(in *admin.AppInput) { in.Name = strings.Repeat("n", 101) }, "name", ""},
		{"bad slug", func(in *admin.AppInput) { in.Slug = "Bad Slug!" }, "slug", "Use lower-case letters, numbers and hyphens."},
		{"taken slug", func(in *admin.AppInput) { in.Slug = "members-wiki" }, "slug", "Another app already uses that short name."},
		{"taken derived slug", func(in *admin.AppInput) {}, "slug", "Another app already uses that short name."},
		{"client type", func(in *admin.AppInput) { in.ClientType = "weird" }, "client_type", "Choose whether the app keeps a secret."},
		{"subject mode", func(in *admin.AppInput) { in.SubjectMode = "guess" }, "subject_mode", "Choose how the app identifies people."},
		{"relative redirect", func(in *admin.AppInput) { in.RedirectURIs = []string{"/callback"} }, "redirect_uris", "Line 1"},
		{"javascript redirect", func(in *admin.AppInput) { in.RedirectURIs = []string{"javascript:alert(1)"} }, "redirect_uris", "Line 1"},
		{"userinfo redirect", func(in *admin.AppInput) { in.RedirectURIs = []string{"https://user:pw@a/cb"} }, "redirect_uris", "Line 1"},
		{"fragment redirect", func(in *admin.AppInput) { in.RedirectURIs = []string{"https://a/cb#x"} }, "redirect_uris", "Line 1 can't contain a # part."},
		{"bad logout", func(in *admin.AppInput) { in.PostLogoutRedirectURIs = []string{"ftp://a/out"} }, "post_logout_redirect_uris", "Line 1 isn't a full web address starting with https:// or http://."},
		{"too many redirects", func(in *admin.AppInput) { in.RedirectURIs = tooMany }, "redirect_uris", "Add at most 20 addresses."},
		{"access ttl", func(in *admin.AppInput) { in.AccessTokenTTL = 25 * time.Hour }, "access_token_ttl", "Use a time between 1m and 24h, like 1h."},
		{"short access ttl", func(in *admin.AppInput) { in.AccessTokenTTL = 30 * time.Second }, "access_token_ttl", "Use a time between 1m and 24h, like 1h."},
		{"id ttl", func(in *admin.AppInput) { in.IDTokenTTL = 25 * time.Hour }, "id_token_ttl", "Use a time between 1m and 24h, like 1h."},
		{"refresh ttl", func(in *admin.AppInput) { in.RefreshTokenTTL = 2161 * time.Hour }, "refresh_token_ttl", "Use a time between 1m and 90d."},
		{"launch url", func(in *admin.AppInput) { in.LaunchURL = "ftp://x" }, "launch_url", ""},
		{"icon http", func(in *admin.AppInput) { in.IconURL = "http://x/i.png" }, "icon_url", ""},
		{"icon path", func(in *admin.AppInput) { in.IconURL = "/static/i.png" }, "icon_url", ""},
		{"service account on public app", func(in *admin.AppInput) {
			in.ClientType = model.ClientTypePublic
			in.ServiceAccountID = "anything"
		}, "service_account_id", "Only apps that keep a secret can sign in by themselves."},
		{"member as service account", func(in *admin.AppInput) { in.ServiceAccountID = member.ID }, "service_account_id", "Choose a service account."},
		{"unknown service account", func(in *admin.AppInput) { in.ServiceAccountID = "nope" }, "service_account_id", "Choose a service account."},
		{"unknown group", func(in *admin.AppInput) { in.AllowedGroupIDs = []string{"nope"} }, "allowed_groups", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := validApp()
			tc.edit(&in)
			_, _, err := svc.CreateApp(ctx, actorFor(ada), in)
			msg := fieldMessages(t, err)[tc.field]
			if msg == "" || (tc.want != "" && !strings.Contains(msg, tc.want)) || (tc.want != "" && strings.HasSuffix(tc.want, ".") && msg != tc.want) {
				t.Errorf("%s: message %q, want %q (all: %v)", tc.field, msg, tc.want, err)
			}
		})
	}
}

func TestAppValidAccepted(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, adminGroup := mkAdmin(t, st)
	sa := mkServiceAccount(t, st, "Robot", "robot")

	in := validApp()
	in.Name = "Everything"
	in.Slug = "everything"
	in.SubjectMode = model.SubjectModeEmail
	in.AllowedGroupIDs = []string{adminGroup.ID, adminGroup.ID}
	in.PostLogoutRedirectURIs = []string{"http://localhost:3000/"}
	in.AccessTokenTTL, in.IDTokenTTL, in.RefreshTokenTTL = time.Minute, 24*time.Hour, 2160*time.Hour
	in.LaunchURL = "https://wiki.example.org/"
	in.IconURL = "/icons/wiki.svg"
	in.ShowTile = true
	in.ServiceAccountID = sa.ID
	app, _, err := svc.CreateApp(ctx, actorFor(ada), in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.AllowedGroupIDs, []string{adminGroup.ID}) || got.ServiceAccountID != sa.ID ||
		got.SubjectMode != model.SubjectModeEmail || got.RefreshTokenTTL != 2160*time.Hour || !got.ShowTile {
		t.Errorf("stored %+v", got)
	}

	in = validApp()
	in.Name, in.IconURL = "Secure icon", "https://cdn.example.org/i.png"
	if _, _, err := svc.CreateApp(ctx, actorFor(ada), in); err != nil {
		t.Errorf("https icon: %v", err)
	}
}

func TestSlugDerivation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	for name, want := range map[string]string{
		"  Café -- Bar!! ":      "caf-bar",
		"???":                   "app",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		in := validApp()
		in.Name = name
		app, _, err := svc.CreateApp(ctx, actorFor(ada), in)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if app.Slug != want {
			t.Errorf("%q: slug %q, want %q", name, app.Slug, want)
		}
	}
}

func TestRedirectURICleanup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)

	in := validApp()
	in.RedirectURIs = []string{"  https://a/cb ", "", "https://a/cb", "\r", "https://b/cb"}
	app, _, err := svc.CreateApp(ctx, actorFor(ada), in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://a/cb", "https://b/cb"}; !reflect.DeepEqual(got.RedirectURIs, want) {
		t.Errorf("stored %q, want %q", got.RedirectURIs, want)
	}

	in = validApp()
	in.Slug = "other"
	in.RedirectURIs = []string{"https://a/cb", "", "/x"}
	_, _, err = svc.CreateApp(ctx, actorFor(ada), in)
	if msg := fieldMessages(t, err)["redirect_uris"]; msg != "Line 3 isn't a full web address starting with https:// or http://." {
		t.Errorf("message %q", msg)
	}
}

func TestUpdateApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	app, _, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}
	other := validApp()
	other.Name, other.Slug = "Other", "other"
	otherApp, _, err := svc.CreateApp(ctx, actorFor(ada), other)
	if err != nil {
		t.Fatal(err)
	}

	name, ttl, uris := "Renamed Wiki", 2*time.Hour, []string{"https://new.example.org/cb"}
	got, secret, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{Name: &name, AccessTokenTTL: &ttl, RedirectURIs: &uris})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || got.Name != name || got.Slug != "members-wiki" || got.AccessTokenTTL != ttl ||
		got.ClientSecretHash != app.ClientSecretHash || got.ClientID != app.ClientID {
		t.Errorf("updated %+v", got)
	}
	ev := oneEvent(t, st, audit.AppUpdate)
	changed, _ := ev.Detail["changed"].(map[string]any)
	if len(changed) != 3 || changed["name"] == nil || changed["access_token_ttl"] == nil || changed["redirect_uris"] == nil {
		t.Errorf("changed %v", changed)
	}

	// No change, no event.
	if _, _, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if n := len(events(t, st, audit.AppUpdate)); n != 1 {
		t.Errorf("%d update events, want 1", n)
	}

	// A taken slug, and an invalid value in the patch, are field messages; nothing is saved.
	taken := "other"
	_, _, err = svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{Slug: &taken})
	if msg := fieldMessages(t, err)["slug"]; msg != "Another app already uses that short name." {
		t.Errorf("slug message %q", msg)
	}
	// Renaming to the app's own slug is fine.
	own := "members-wiki"
	if _, _, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{Slug: &own}); err != nil {
		t.Errorf("own slug: %v", err)
	}
	// A blank slug is made from the name.
	blank := ""
	got, _, err = svc.UpdateApp(ctx, actorFor(ada), otherApp.ID, admin.AppPatch{Slug: &blank})
	if err != nil || got.Slug != "other" {
		t.Errorf("blank slug: %+v, %v", got, err)
	}
	bad := 48 * time.Hour
	_, _, err = svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{IDTokenTTL: &bad})
	fieldMessages(t, err)

	if _, _, err := svc.UpdateApp(ctx, actorFor(ada), "missing", admin.AppPatch{Name: &name}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing app: %v", err)
	}
}

func TestUpdateAppRevalidatesWholeApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	sa := mkServiceAccount(t, st, "Robot", "robot")
	in := validApp()
	in.ServiceAccountID = sa.ID
	app, _, err := svc.CreateApp(ctx, actorFor(ada), in)
	if err != nil {
		t.Fatal(err)
	}
	// Going public while a service account is set is refused.
	public := model.ClientTypePublic
	_, _, err = svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ClientType: &public})
	if _, ok := fieldMessages(t, err)["service_account_id"]; !ok {
		t.Errorf("error %v", err)
	}
	none := ""
	if _, _, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ClientType: &public, ServiceAccountID: &none}); err != nil {
		t.Errorf("public with the account cleared: %v", err)
	}
}

// Ruling 18: a tile on the members' home page needs a link; without one it
// would never show, and nobody could tell why.
func TestTileNeedsLaunchURL(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	const msg = "Add a link to open the app, or untick Show on members' home page."

	in := validApp()
	in.ShowTile = true
	before := countEvents(t, st)
	if got := fieldMessages(t, errOf3(svc.CreateApp(ctx, actorFor(ada), in)))["launch_url"]; got != msg {
		t.Errorf("create: launch_url message %q", got)
	}
	in.LaunchURL = "   "
	if got := fieldMessages(t, errOf3(svc.CreateApp(ctx, actorFor(ada), in)))["launch_url"]; got != msg {
		t.Errorf("create with a blank link: launch_url message %q", got)
	}
	if countEvents(t, st) != before {
		t.Error("events recorded for a refused create")
	}

	// Without a tile, no link is needed; ticking it later needs one.
	app, _, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}
	tile := true
	if got := fieldMessages(t, errOf3(svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ShowTile: &tile})))["launch_url"]; got != msg {
		t.Errorf("update: launch_url message %q", got)
	}
	link := "https://wiki.example.org/"
	if _, _, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ShowTile: &tile, LaunchURL: &link}); err != nil {
		t.Errorf("tile with a link: %v", err)
	}
	// Taking the link away from a tile is refused too.
	none := ""
	if got := fieldMessages(t, errOf3(svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{LaunchURL: &none})))["launch_url"]; got != msg {
		t.Errorf("remove link: launch_url message %q", got)
	}
}

func TestUpdateAppClientTypeSwitch(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	app, _, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}

	public := model.ClientTypePublic
	got, secret, err := svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ClientType: &public})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" || got.ClientSecretHash != "" || got.ClientType != model.ClientTypePublic {
		t.Errorf("to public: secret %q app %+v", secret, got)
	}
	stored, err := st.GetApplication(ctx, app.ID)
	if err != nil || stored.ClientSecretHash != "" {
		t.Errorf("stored after public: %+v, %v", stored, err)
	}

	confidential := model.ClientTypeConfidential
	got, secret, err = svc.UpdateApp(ctx, actorFor(ada), app.ID, admin.AppPatch{ClientType: &confidential})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 43 || got.ClientSecretHash != secrets.HashToken(secret) {
		t.Errorf("to confidential: secret %q hash %q", secret, got.ClientSecretHash)
	}
	stored, err = st.GetApplication(ctx, app.ID)
	if err != nil || stored.ClientSecretHash != secrets.HashToken(secret) {
		t.Errorf("stored after confidential: %+v, %v", stored, err)
	}

	for _, ev := range events(t, st, audit.AppUpdate) {
		if strings.Contains(fmt.Sprint(ev.Detail), secret) || strings.Contains(fmt.Sprint(ev.Detail), got.ClientSecretHash) {
			t.Errorf("event holds the secret: %v", ev.Detail)
		}
	}
	if n := len(events(t, st, audit.AppUpdate)); n != 2 {
		t.Errorf("%d update events, want 2", n)
	}
}

func TestRotateAppSecret(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	app, oldSecret, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}

	newSecret, err := svc.RotateAppSecret(ctx, actorFor(ada), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newSecret == oldSecret || len(newSecret) != 43 || stored.ClientSecretHash != secrets.HashToken(newSecret) ||
		stored.ClientSecretHash == secrets.HashToken(oldSecret) {
		t.Errorf("old %q new %q hash %q", oldSecret, newSecret, stored.ClientSecretHash)
	}
	ev := oneEvent(t, st, audit.AppSecretRotate)
	if ev.TargetID != app.ID || strings.Contains(fmt.Sprint(ev.Detail), newSecret) || strings.Contains(ev.Summary, newSecret) {
		t.Errorf("event %+v", ev)
	}

	in := validApp()
	in.Name, in.ClientType = "Public app", model.ClientTypePublic
	pub, _, err := svc.CreateApp(ctx, actorFor(ada), in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RotateAppSecret(ctx, actorFor(ada), pub.ID)
	var refused *admin.RefusedError
	if !errors.As(err, &refused) || refused.Message != "This app doesn't use a secret." {
		t.Errorf("public app: %v", err)
	}
	if _, err := svc.RotateAppSecret(ctx, actorFor(ada), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing app: %v", err)
	}
}

func TestDeleteApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	app, _, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.DeleteApp(ctx, actorFor(ada), app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetApplication(ctx, app.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("app still there: %v", err)
	}
	ev := oneEvent(t, st, audit.AppDelete)
	if ev.TargetID != app.ID || ev.Detail["name"] != app.Name || ev.Detail["slug"] != app.Slug || ev.Detail["client_id"] != app.ClientID {
		t.Errorf("event %+v", ev)
	}
	if err := svc.DeleteApp(ctx, actorFor(ada), app.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestResolveApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	app, _, err := svc.CreateApp(ctx, actorFor(ada), validApp())
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{app.ID, "slug:members-wiki"} {
		got, err := svc.ResolveApp(ctx, ref)
		if err != nil || got.ID != app.ID {
			t.Errorf("%s: %+v, %v", ref, got, err)
		}
	}
	for _, ref := range []string{"missing", "slug:missing", "members-wiki"} {
		if _, err := svc.ResolveApp(ctx, ref); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: %v", ref, err)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                            "",
		90 * 24 * time.Hour:          "90d",
		24 * time.Hour:               "1d",
		36 * time.Hour:               "36h",
		time.Hour:                    "1h",
		90 * time.Minute:             "90m",
		time.Minute:                  "1m",
		time.Minute + 30*time.Second: "1m30s",
		time.Hour + time.Millisecond: "1h0m0.001s",
	} {
		if got := admin.FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

// CheckApp applies the app pages' rules to an app made elsewhere, such as
// by the importer.
func TestCheckApp(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)

	app := &model.Application{Name: "  Members Wiki ", ClientType: model.ClientTypeConfidential,
		RedirectURIs: []string{" https://wiki.example.org/cb ", "", "https://wiki.example.org/cb"}}
	if err := svc.CheckApp(ctx, app); err != nil {
		t.Fatalf("valid app: %v", err)
	}
	if app.Name != "Members Wiki" || app.Slug != "members-wiki" || app.SubjectMode != model.SubjectModeID ||
		!reflect.DeepEqual(app.RedirectURIs, []string{"https://wiki.example.org/cb"}) {
		t.Errorf("not tidied: %+v", app)
	}

	taken := &model.Application{Name: "Door", Slug: "door", ClientID: "door-client-id"}
	if err := st.CreateApplication(ctx, taken); err != nil {
		t.Fatal(err)
	}
	other := &model.Application{Name: "Door Booking", Slug: "door", ClientType: model.ClientTypePublic}
	if msg := fieldMessages(t, svc.CheckApp(ctx, other))["slug"]; msg != "Another app already uses that short name." {
		t.Errorf("slug message %q", msg)
	}
	// An app's own slug is not taken.
	self := *taken
	self.Name = "Door renamed"
	if err := svc.CheckApp(ctx, &self); err != nil {
		t.Errorf("own slug: %v", err)
	}

	if got := admin.SlugFromName("Door_Booking"); got != "door-booking" {
		t.Errorf("SlugFromName = %q", got)
	}
}
