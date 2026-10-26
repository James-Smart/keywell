package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/James-Smart/keywell/internal/admin"
	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/mail"
	"github.com/James-Smart/keywell/internal/oidc"
	"github.com/James-Smart/keywell/internal/secrets"
)

// failingMailer fails every send with err.
type failingMailer struct{ err error }

func (m failingMailer) Send(context.Context, mail.Message) error { return m.err }

func TestSendTestEmail(t *testing.T) {
	ctx := context.Background()
	var mailer mail.Memory
	svc, st, _ := newService(t, withDeps(func(d *admin.Deps) {
		d.Cfg.Branding.Name = "Make Space"
		d.Mailer = &mailer
	}))
	ada, _ := mkAdmin(t, st)

	if err := svc.SendTestEmail(ctx, actorFor(ada), ada); err != nil {
		t.Fatal(err)
	}
	msg, ok := mailer.Last()
	if !ok || msg.To != ada.Email || msg.Subject != "Test email from Make Space" {
		t.Errorf("sent %+v", msg)
	}
	ev := oneEvent(t, st, audit.SMTPTest)
	if ev.Detail["sent"] != true || ev.ActorID != ada.ID {
		t.Errorf("event %+v", ev)
	}
}

func TestSendTestEmailFailure(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("connection refused")
	svc, st, _ := newService(t, withDeps(func(d *admin.Deps) { d.Mailer = failingMailer{boom} }))
	ada, _ := mkAdmin(t, st)

	if err := svc.SendTestEmail(ctx, actorFor(ada), ada); !errors.Is(err, boom) {
		t.Errorf("error %v, want %v", err, boom)
	}
	if ev := oneEvent(t, st, audit.SMTPTest); ev.Detail["sent"] != false {
		t.Errorf("event %+v", ev)
	}
}

func TestRotateKeys(t *testing.T) {
	ctx := context.Background()
	var keys *oidc.KeyManager
	svc, st, _ := newService(t, withDeps(func(d *admin.Deps) {
		enc, err := secrets.NewEncryptor(secrets.GenerateKey())
		if err != nil {
			t.Fatal(err)
		}
		if keys, err = oidc.NewKeyManager(ctx, d.Store, enc); err != nil {
			t.Fatal(err)
		}
		d.Keys = keys.WithAudit(d.Audit)
	}))
	ada, _ := mkAdmin(t, st)
	before := keys.ActiveKID()

	kid, retired, err := svc.RotateKeys(ctx, actorFor(ada))
	if err != nil {
		t.Fatal(err)
	}
	if kid == before || kid != keys.ActiveKID() || retired != 0 {
		t.Errorf("kid %q before %q active %q retired %d", kid, before, keys.ActiveKID(), retired)
	}
	ev := oneEvent(t, st, audit.KeyRotated)
	if ev.ActorType != "user" || ev.ActorID != ada.ID || ev.TargetID != kid {
		t.Errorf("event %+v", ev)
	}
}
