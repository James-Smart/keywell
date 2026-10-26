package admin_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"keywell/internal/admin"
	"keywell/internal/audit"
	"keywell/internal/model"
	"keywell/internal/secrets"
	"keywell/internal/store"
)

// errOf3 drops the first and second of three results.
func errOf3[T any](_ T, _ string, err error) error { return err }

func TestServiceAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	a := actorFor(ada)
	laser := mkGroup(t, st, "Laser", false)

	if got := fields(t, errOf(svc.CreateServiceAccount(ctx, a, admin.ServiceAccountInput{Name: "Door"})))["username"]; got != "Enter a username." {
		t.Errorf("username message %q", got)
	}
	if got := fields(t, errOf(svc.CreateServiceAccount(ctx, a, admin.ServiceAccountInput{Name: "", Username: "d e"}))); got["name"] != "Enter a name." || got["username"] != "Usernames can't contain spaces." {
		t.Errorf("fields %v", got)
	}
	if n := countEvents(t, st); n != 0 {
		t.Fatalf("%d events after failures", n)
	}

	sa, err := svc.CreateServiceAccount(ctx, a, admin.ServiceAccountInput{Name: "Door", Username: "door", Description: "Opens",
		GroupIDs: []string{laser.ID}, Metadata: map[string]any{"k": 1}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUser(ctx, sa.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != model.UserTypeService || got.Description != "Opens" || !got.IsActive || got.PasswordHash != "" || got.LegacyPasswordHash != "" {
		t.Errorf("stored %+v", got)
	}
	if names := groupNames(t, st, sa.ID); len(names) != 1 || names[0] != "Laser" {
		t.Errorf("groups %v", names)
	}
	if ev := oneEvent(t, st, audit.ServiceAccountCreate); ev.TargetType != "service_account" || ev.TargetID != sa.ID {
		t.Errorf("create event %+v", ev)
	}
	if ev := oneEvent(t, st, audit.GroupMemberAdd); ev.TargetID != sa.ID || ev.Detail["group_id"] != laser.ID ||
		ev.Summary != "Added Door to Laser" {
		t.Errorf("group.member.add on create: %+v", ev)
	}

	if got := fields(t, errOf(svc.CreateServiceAccount(ctx, a, admin.ServiceAccountInput{Name: "Other", Username: "door"})))["username"]; got != "That username is taken." {
		t.Errorf("taken message %q", got)
	}

	up, err := svc.UpdateServiceAccount(ctx, a, sa.ID, admin.ServiceAccountPatch{Name: ptr("Front door"), Description: ptr("Opens it"),
		GroupIDs: ptr([]string{})})
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "Front door" || up.Description != "Opens it" || up.Username != "door" {
		t.Errorf("updated %+v", up)
	}
	changed, _ := oneEvent(t, st, audit.ServiceAccountUpdate).Detail["changed"].(map[string]any)
	if changed["name"] == nil || changed["description"] == nil || len(changed) != 2 {
		t.Errorf("changed %v", changed)
	}
	if len(events(t, st, audit.GroupMemberRemove)) != 1 {
		t.Error("no group.member.remove")
	}
	if got := fields(t, errOf(svc.UpdateServiceAccount(ctx, a, sa.ID, admin.ServiceAccountPatch{Username: ptr("")})))["username"]; got != "Enter a username." {
		t.Errorf("empty username on update: %q", got)
	}
	member := mkMember(t, st, "Alex", "alex@example.org")
	if _, err := svc.UpdateServiceAccount(ctx, a, member.ID, admin.ServiceAccountPatch{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("update member: %v", err)
	}

	r, err := svc.ResolveServiceAccount(ctx, "username:door")
	if err != nil || r.ID != sa.ID {
		t.Errorf("resolve: %+v %v", r, err)
	}
	if r, err = svc.ResolveServiceAccount(ctx, sa.ID); err != nil || r.ID != sa.ID {
		t.Errorf("resolve id: %+v %v", r, err)
	}
	if _, err := svc.ResolveServiceAccount(ctx, member.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("resolve member: %v", err)
	}

	if err := svc.DeleteServiceAccount(ctx, a, member.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete member: %v", err)
	}
	if err := svc.DeleteServiceAccount(ctx, a, sa.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUser(ctx, sa.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("still there: %v", err)
	}
	ev := oneEvent(t, st, audit.ServiceAccountDelete)
	if ev.Detail["username"] != "door" || ev.Detail["name"] != "Front door" {
		t.Errorf("delete event %+v", ev)
	}
}

func inFuture(d time.Duration) *time.Time { t := time.Now().Add(d); return &t }

func TestCreateToken(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	a := actorFor(ada)
	sa := mkServiceAccount(t, st, "Door", "door")

	tok, raw, err := svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "CI", Scope: model.APITokenScopeRead, ExpiresAt: inFuture(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "keywell_") || len(raw) != 51 {
		t.Errorf("raw token %q", raw)
	}
	stored, err := st.GetAPITokenByHash(ctx, secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != tok.ID || stored.Scope != model.APITokenScopeRead || stored.CreatedByUserID != ada.ID ||
		stored.ServiceAccountID != sa.ID || stored.Label != "CI" || stored.TokenHash != secrets.HashToken(raw) {
		t.Errorf("stored %+v", stored)
	}
	ev := oneEvent(t, st, audit.APITokenCreate)
	if ev.TargetType != "api_token" || ev.TargetID != tok.ID || ev.Detail["label"] != "CI" || ev.Detail["scope"] != "read" ||
		ev.Summary != "Made read-only API token CI for Door" {
		t.Errorf("event %+v", ev)
	}
	if s := fmt.Sprint(ev); strings.Contains(s, raw) || strings.Contains(s, secrets.HashToken(raw)) {
		t.Error("event contains the token")
	}

	// No expiry is allowed. The summary says when a token can change things.
	if _, _, err := svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "Forever", Scope: model.APITokenScopeAdmin}); err != nil {
		t.Error(err)
	}
	summaries := map[any]string{}
	for _, ev := range events(t, st, audit.APITokenCreate) {
		summaries[ev.Detail["label"]] = ev.Summary
	}
	if got := summaries["Forever"]; got != "Made full admin API token Forever for Door" {
		t.Errorf("full admin summary %q", got)
	}
	before := countEvents(t, st)
	for field, in := range map[string]admin.NewToken{
		"label":      {Label: " ", Scope: model.APITokenScopeRead},
		"scope":      {Label: "x", Scope: "write"},
		"expires_at": {Label: "x", Scope: model.APITokenScopeRead, ExpiresAt: inFuture(-24 * time.Hour)},
	} {
		_, raw, err := svc.CreateToken(ctx, a, sa.ID, in)
		if raw != "" || fields(t, err)[field] == "" {
			t.Errorf("%s: raw %q err %v", field, raw, err)
		}
	}
	msgs := fields(t, errOf3(svc.CreateToken(ctx, a, sa.ID, admin.NewToken{})))
	if msgs["label"] != "Enter a label so you can tell tokens apart." || msgs["scope"] != "Choose full admin or read only." {
		t.Errorf("messages %v", msgs)
	}
	if got := fields(t, errOf3(svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "x", Scope: "read", ExpiresAt: inFuture(-time.Hour)})))["expires_at"]; got != "Choose a date in the future." {
		t.Errorf("expiry message %q", got)
	}
	if countEvents(t, st) != before {
		t.Error("events recorded for failures")
	}
	member := mkMember(t, st, "Alex", "alex@example.org")
	if _, _, err := svc.CreateToken(ctx, a, member.ID, admin.NewToken{Label: "x", Scope: "read"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token for a member: %v", err)
	}
}

func TestAuthenticateToken(t *testing.T) {
	ctx := context.Background()
	clock := newClock(time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC))
	svc, st, _ := newService(t, withNow(clock.Now))
	ada, _ := mkAdmin(t, st)
	a := actorFor(ada)
	sa := mkServiceAccount(t, st, "Door", "door")
	exp := clock.Now().Add(time.Hour)
	tok, raw, err := svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "CI", Scope: model.APITokenScopeAdmin, ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}

	c, err := svc.AuthenticateToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Account.ID != sa.ID || c.Token.ID != tok.ID {
		t.Errorf("caller %+v %+v", c.Account, c.Token)
	}
	if got := c.Actor(); got != (admin.Actor{Type: model.ActorServiceAccount, ID: sa.ID, TokenID: tok.ID}) {
		t.Errorf("actor %+v", got)
	}

	lastUsed := func() *time.Time {
		toks, err := st.ListAPITokens(ctx, sa.ID)
		if err != nil || len(toks) == 0 {
			t.Fatal(toks, err)
		}
		return toks[len(toks)-1].LastUsedAt // the oldest token, the one under test
	}
	first := lastUsed()
	if first == nil || !first.Equal(clock.Now()) {
		t.Fatalf("first use: %v", first)
	}
	clock.Advance(30 * time.Second)
	if _, err := svc.AuthenticateToken(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(*first) {
		t.Errorf("after 30s: %v, want unchanged", got)
	}
	clock.Advance(31 * time.Second)
	if _, err := svc.AuthenticateToken(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if got := lastUsed(); !got.Equal(clock.Now()) {
		t.Errorf("after 61s: %v, want %v", got, clock.Now())
	}

	bad := func(name, raw string) {
		t.Helper()
		c, err := svc.AuthenticateToken(ctx, raw)
		if c != nil || !errors.Is(err, admin.ErrBadToken) {
			t.Errorf("%s: %v %v", name, c, err)
		}
	}
	bad("unknown", "keywell_nope")
	bad("empty", "")

	// Expired exactly now.
	clock.Advance(time.Hour - 61*time.Second)
	bad("expired", raw)

	// Revoked.
	tok2, raw2, err := svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "two", Scope: model.APITokenScopeRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateToken(ctx, raw2); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeToken(ctx, a, sa.ID, tok2.ID); err != nil {
		t.Fatal(err)
	}
	bad("revoked", raw2)

	// Inactive account, then deleted account.
	_, raw3, err := svc.CreateToken(ctx, a, sa.ID, admin.NewToken{Label: "three", Scope: model.APITokenScopeRead})
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser(ctx, sa.ID)
	if err != nil {
		t.Fatal(err)
	}
	u.IsActive = false
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	bad("inactive", raw3)
	u.IsActive = true
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateToken(ctx, raw3); err != nil {
		t.Errorf("reactivated: %v", err)
	}
	if err := svc.DeleteServiceAccount(ctx, a, sa.ID); err != nil {
		t.Fatal(err)
	}
	bad("account deleted", raw3)
}

func TestRevokeToken(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newService(t)
	ada, _ := mkAdmin(t, st)
	a := actorFor(ada)
	door := mkServiceAccount(t, st, "Door", "door")
	lamp := mkServiceAccount(t, st, "Lamp", "lamp")
	tok, raw, err := svc.CreateToken(ctx, a, door.ID, admin.NewToken{Label: "CI", Scope: model.APITokenScopeAdmin})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RevokeToken(ctx, a, lamp.ID, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other account: %v", err)
	}
	if _, err := svc.AuthenticateToken(ctx, raw); err != nil {
		t.Errorf("token lost: %v", err)
	}
	if len(events(t, st, audit.APITokenRevoke)) != 0 {
		t.Error("event for refused revoke")
	}
	if err := svc.RevokeToken(ctx, a, door.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateToken(ctx, raw); !errors.Is(err, admin.ErrBadToken) {
		t.Errorf("after revoke: %v", err)
	}
	ev := oneEvent(t, st, audit.APITokenRevoke)
	if ev.TargetType != "api_token" || ev.TargetID != tok.ID || ev.Detail["label"] != "CI" {
		t.Errorf("event %+v", ev)
	}
	if err := svc.RevokeToken(ctx, a, door.ID, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second revoke: %v", err)
	}
}
