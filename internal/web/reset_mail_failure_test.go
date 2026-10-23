package web_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"latch/internal/mail"
	"latch/internal/testenv"
)

// failingMailer refuses every message with an error that echoes the
// recipient, as SMTP servers do, in the case given and in lower case.
type failingMailer struct{}

func (failingMailer) Send(_ context.Context, m mail.Message) error {
	return errors.New("550 5.1.1 <" + m.To + ">: mailbox unavailable (" + strings.ToLower(m.To) + ")")
}

// A reset email that fails in the background is logged with its cause, so
// the operator can fix the mail settings, but without the address.
func TestFailedResetEmailLoggedWithRedactedCause(t *testing.T) {
	var logs logBuffer
	env := testenv.New(t,
		testenv.WithLog(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))),
		testenv.WithMailer(func(*mail.Memory) mail.Mailer { return failingMailer{} }))
	u := env.CreateUser(t, "Alex.Member@Example.org", testPW)

	post(t, env, env.Client(t), "/reset", url.Values{"email": {"alex.member@example.org"}})
	env.WaitMail(t)

	got := logs.String()
	if !strings.Contains(got, "send reset email failed") || !strings.Contains(got, u.ID) {
		t.Fatalf("no failure logged for the user:\n%s", got)
	}
	if !strings.Contains(got, "550 5.1.1 <[recipient]>: mailbox unavailable ([recipient])") {
		t.Errorf("log does not carry the redacted cause:\n%s", got)
	}
	if strings.Contains(strings.ToLower(got), "alex.member@example.org") {
		t.Errorf("log contains the recipient's address:\n%s", got)
	}
}
