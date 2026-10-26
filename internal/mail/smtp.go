package mail

import (
	"context"
	"fmt"

	gomail "github.com/wneessen/go-mail"

	"keywell/internal/config"
)

// SMTP delivers messages through an SMTP server.
type SMTP struct{ cfg config.SMTPConfig }

// NewSMTP validates cfg and returns an SMTP mailer.
func NewSMTP(cfg config.SMTPConfig) (*SMTP, error) {
	switch cfg.TLS {
	case "starttls", "tls", "none":
	default:
		return nil, fmt.Errorf("mail: smtp tls must be starttls, tls or none, got %q", cfg.TLS)
	}
	return &SMTP{cfg: cfg}, nil
}

// Send delivers m, opening a fresh connection for each message.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	opts := []gomail.Option{gomail.WithPort(s.cfg.Port)}
	switch s.cfg.TLS {
	case "starttls":
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	case "tls":
		opts = append(opts, gomail.WithSSL())
	case "none":
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	}
	if s.cfg.Username != "" {
		opts = append(opts,
			gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(s.cfg.Username),
			gomail.WithPassword(s.cfg.Password),
		)
	}
	client, err := gomail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("mail: new client: %w", err)
	}

	msg := gomail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return fmt.Errorf("mail: from address: %w", err)
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("mail: to address: %w", err)
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(gomail.TypeTextPlain, m.Text)
	msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("mail: send: %w", err)
	}
	return nil
}
