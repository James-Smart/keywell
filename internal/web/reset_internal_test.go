package web

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/mail"
	"latch/internal/model"
	"latch/internal/secrets"
	"latch/internal/store"
)

// SendReset with purpose invite mails the invitation, with a link that
// lasts seven days, and records the request. (The full stack in web_test
// has no route that sends invites yet.)
func TestSendResetInvite(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Load("", func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "https://id.example.org"
	cfg.Branding.Name = "Makerspace"
	cfg.Branding.SupportText = "Ask at the front desk."
	st, db := store.OpenTestDB(t)
	log := slog.New(slog.DiscardHandler)
	mailer := &mail.Memory{}
	s := newServer(Deps{Cfg: cfg, Store: st, Mailer: mailer, Audit: audit.New(st, log), Log: log})
	u := &model.User{Name: "New Member", Email: "new@example.org", IsActive: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	if err := s.SendReset(ctx, u, model.ResetPurposeInvite); err != nil {
		t.Fatal(err)
	}
	msg, ok := mailer.Last()
	if !ok || msg.To != "new@example.org" || msg.Subject != "Set up your Makerspace account" ||
		!strings.Contains(msg.Text, "7 days") || !strings.Contains(msg.Text, "Ask at the front desk.") {
		t.Fatalf("email %+v", msg)
	}
	m := regexp.MustCompile(`https://id\.example\.org/reset/([A-Za-z0-9_-]{43})\b`).FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no invite link in:\n%s", msg.Text)
	}
	tok, err := st.PeekResetToken(ctx, secrets.HashToken(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(tok.ExpiresAt); tok.UserID != u.ID || tok.Purpose != model.ResetPurposeInvite ||
		d < InviteTokenTTL-time.Minute || d > InviteTokenTTL {
		t.Fatalf("token %+v lasts %v", tok, d)
	}
	if ok, err := st.HasActiveInviteToken(ctx, u.ID); err != nil || !ok {
		t.Fatalf("HasActiveInviteToken = %v, %v", ok, err)
	}

	var action, actorID, targetID, detail string
	if err := db.QueryRow(`SELECT action, actor_id, target_id, detail FROM audit_events`).
		Scan(&action, &actorID, &targetID, &detail); err != nil {
		t.Fatal(err)
	}
	if action != audit.PasswordResetRequested || actorID != u.ID || targetID != u.ID || detail != `{"purpose":"invite"}` {
		t.Fatalf("audit event %s %s %s %s", action, actorID, targetID, detail)
	}
}
