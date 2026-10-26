package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/mail"
	"github.com/James-Smart/keywell/internal/model"
)

// KeyRetireAfter is how long a signing key stays published after a newer
// one replaces it, so apps can still check the tokens it signed.
const KeyRetireAfter = 90 * 24 * time.Hour

// SendTestEmail sends a test email to the member to and records
// settings.smtp_test with whether it was sent. The mailer's error is
// returned as it is.
func (s *Service) SendTestEmail(ctx context.Context, a Actor, to *model.User) error {
	brand := mail.Brand{Name: s.d.Cfg.Branding.Name, SupportText: s.d.Cfg.Branding.SupportText, PublicURL: s.d.Cfg.Issuer()}
	msg := mail.TestEmail(brand)
	msg.To = to.Email
	err := s.d.Mailer.Send(ctx, msg)
	summary := "Sent a test email to " + displayName(to)
	if err != nil {
		summary = "Test email to " + displayName(to) + " failed"
	}
	s.record(ctx, a, audit.SMTPTest, targetUser, to.ID, summary, map[string]any{"sent": err == nil})
	return err
}

// RotateKeys makes a new signing key active, recording the rotation as
// made by a, and retires the keys that were replaced more than
// KeyRetireAfter ago. It returns the new key's ID and how many keys it
// retired.
func (s *Service) RotateKeys(ctx context.Context, a Actor) (string, int, error) {
	kid, err := s.d.Keys.RotateAs(ctx, a.Type, a.ID)
	if err != nil {
		return "", 0, fmt.Errorf("admin: rotate keys: %w", err)
	}
	retired, err := s.d.Keys.RetireOlderThan(ctx, KeyRetireAfter)
	if err != nil {
		return kid, 0, fmt.Errorf("admin: retire old keys: %w", err)
	}
	return kid, retired, nil
}
