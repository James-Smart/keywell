package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"latch/internal/model"
)

func sortedIDs(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

func mkGroup(t *testing.T, s *Store, name string) *model.Group {
	t.Helper()
	g := &model.Group{Name: name}
	if err := s.CreateGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	return g
}

func mkUser(t *testing.T, s *Store, email string) *model.User {
	t.Helper()
	u := &model.User{Name: email, Email: email, IsActive: true}
	if err := s.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestApplicationRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	g1, g2, g3 := mkGroup(t, s, "g1"), mkGroup(t, s, "g2"), mkGroup(t, s, "g3")
	svc := &model.User{Name: "svc", Type: model.UserTypeService, IsActive: true}
	if err := s.CreateUser(ctx, svc); err != nil {
		t.Fatal(err)
	}
	pk := int64(42)
	a := &model.Application{
		Name: "Wiki", Slug: "wiki", ClientID: "wiki-client", ClientSecretHash: "abc",
		RedirectURIs:           []string{"https://wiki/cb", "https://wiki/cb2"},
		PostLogoutRedirectURIs: []string{"https://wiki/bye"},
		AllowedGroupIDs:        []string{g2.ID, g1.ID},
		AccessTokenTTL:         5 * time.Minute, IDTokenTTL: 10 * time.Minute,
		LaunchURL: "https://wiki", ShowTile: true, ServiceAccountID: svc.ID, AuthentikProviderPK: &pk,
	}
	if err := s.CreateApplication(ctx, a); err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.CreatedAt.IsZero() || a.SubjectMode != model.SubjectModeID || a.ClientType != model.ClientTypeConfidential {
		t.Fatalf("defaults not filled: %+v", a)
	}
	got, err := s.GetApplication(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.RedirectURIs, a.RedirectURIs) || !reflect.DeepEqual(got.PostLogoutRedirectURIs, a.PostLogoutRedirectURIs) {
		t.Fatalf("uris: %+v", got)
	}
	if want := sortedIDs(g1.ID, g2.ID); !reflect.DeepEqual(got.AllowedGroupIDs, want) {
		t.Fatalf("groups %v want %v", got.AllowedGroupIDs, want)
	}
	if got.AccessTokenTTL != 5*time.Minute || got.RefreshTokenTTL != 0 || got.IDTokenTTL != 10*time.Minute {
		t.Fatalf("ttls %v %v %v", got.AccessTokenTTL, got.RefreshTokenTTL, got.IDTokenTTL)
	}
	if got.ServiceAccountID != svc.ID || got.AuthentikProviderPK == nil || *got.AuthentikProviderPK != 42 || !got.ShowTile {
		t.Fatalf("fields: %+v", got)
	}
	var nulls int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications WHERE refresh_token_ttl IS NULL`).Scan(&nulls); err != nil || nulls != 1 {
		t.Fatalf("0 TTL should be NULL: %d %v", nulls, err)
	}
	if byCID, err := s.GetApplicationByClientID(ctx, "wiki-client"); err != nil || byCID.ID != a.ID {
		t.Fatalf("by client id: %v %v", byCID, err)
	}
	if bySlug, err := s.GetApplicationBySlug(ctx, "wiki"); err != nil || bySlug.ID != a.ID {
		t.Fatalf("by slug: %v %v", bySlug, err)
	}
	if _, err := s.GetApplication(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// Empty slices read back non-nil.
	b := &model.Application{Name: "B", Slug: "b", ClientID: "b", ClientType: model.ClientTypePublic}
	if err := s.CreateApplication(ctx, b); err != nil {
		t.Fatal(err)
	}
	gb, _ := s.GetApplication(ctx, b.ID)
	if gb.RedirectURIs == nil || gb.PostLogoutRedirectURIs == nil || gb.AllowedGroupIDs == nil || len(gb.RedirectURIs) != 0 {
		t.Fatalf("want empty non-nil slices: %+v", gb)
	}
	if gb.ServiceAccountID != "" || gb.AuthentikProviderPK != nil || gb.ClientType != model.ClientTypePublic {
		t.Fatalf("b: %+v", gb)
	}

	// Update replaces group set.
	got.AllowedGroupIDs = []string{g3.ID}
	got.Name = "Wiki2"
	got.AccessTokenTTL = 0
	if err := s.UpdateApplication(ctx, got); err != nil {
		t.Fatal(err)
	}
	up, _ := s.GetApplication(ctx, a.ID)
	if up.Name != "Wiki2" || up.AccessTokenTTL != 0 || !reflect.DeepEqual(up.AllowedGroupIDs, []string{g3.ID}) {
		t.Fatalf("update: %+v", up)
	}
	if err := s.UpdateApplication(ctx, &model.Application{ID: "missing", Slug: "m", ClientID: "m"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	all, err := s.ListApplications(ctx)
	if err != nil || len(all) != 2 || len(all[0].AllowedGroupIDs)+len(all[1].AllowedGroupIDs) != 1 {
		t.Fatalf("list: %+v %v", all, err)
	}
	if err := s.CreateApplication(ctx, &model.Application{Name: "dup", Slug: "wiki", ClientID: "z"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

func TestListTileApplicationsForUser(t *testing.T) {
	ctx := context.Background()
	s := OpenTest(t)
	u := mkUser(t, s, "u@example.org")
	g := mkGroup(t, s, "G")
	mk := func(slug, launch string, tile bool, groups ...string) {
		t.Helper()
		a := &model.Application{Name: slug, Slug: slug, ClientID: slug, LaunchURL: launch, ShowTile: tile, AllowedGroupIDs: groups}
		if err := s.CreateApplication(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "https://a", true)
	mk("b", "https://b", true, g.ID)
	mk("c", "https://c", false)
	mk("d", "", true)
	names := func() []string {
		t.Helper()
		apps, err := s.ListTileApplicationsForUser(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, a := range apps {
			out = append(out, a.Slug)
		}
		return out
	}
	if got := names(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("before membership: %v", got)
	}
	if err := s.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if got := names(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("after membership: %v", got)
	}
	apps, _ := s.ListTileApplicationsForUser(ctx, u.ID)
	if len(apps[1].AllowedGroupIDs) != 1 {
		t.Fatalf("group ids not loaded: %+v", apps[1])
	}
}
