package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/James-Smart/keywell/internal/audit"
	"github.com/James-Smart/keywell/internal/model"
	"github.com/James-Smart/keywell/internal/password"
	"github.com/James-Smart/keywell/internal/store"
	"github.com/James-Smart/keywell/internal/web"
)

// adminGroup is the group whose members administer Keywell.
const adminGroup = "Admin"

// errServiceAccount refuses to make a service account an admin or give it
// a reset link: it cannot use the login pages.
var errServiceAccount = errors.New("that is a service account, which cannot sign in")

func cmdCreateAdmin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./keywell.yaml", "path to the config file")
	email := flags.String("email", "", "the admin's email address (required)")
	pw := flags.String("password", "", "password for a new account (prompted for when omitted)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case flags.NArg() > 0:
		return usageError(stderr, "create-admin", "unexpected argument %q", flags.Arg(0))
	case *email == "":
		return usageError(stderr, "create-admin", "--email is required")
	case !strings.Contains(*email, "@"):
		return usageError(stderr, "create-admin", "--email must be an email address")
	}
	ctx := context.Background()
	cfg, st, conn, err := openInstall(ctx, *configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer conn.Close()
	created, err := makeAdmin(ctx, st, *email, func() (string, error) {
		return adminPassword(*pw, *email, cfg.Password.MinLength, stdin, stderr)
	})
	if err != nil {
		return fail(stderr, err)
	}
	if created {
		fmt.Fprintf(stdout, "Created %s in the %s group.\n", *email, adminGroup)
	} else {
		fmt.Fprintf(stdout, "Added %s to the %s group. Their password is unchanged.\n", *email, adminGroup)
	}
	fmt.Fprintln(stdout, "They'll be asked to set up two-step sign in when they next sign in, if they haven't already.")
	return 0
}

// makeAdmin adds the user with email to the Admin group, creating the group
// if it is missing and the account, with the password getPassword returns,
// if there is none. It reports whether it created the account. A service
// account or a deactivated account is refused: neither could sign in.
func makeAdmin(ctx context.Context, st *store.Store, email string, getPassword func() (string, error)) (created bool, err error) {
	user, err := st.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		user = nil
	case err != nil:
		return false, err
	case user.Type != model.UserTypeMember:
		return false, errServiceAccount
	case !user.IsActive:
		return false, errors.New("that account is deactivated")
	}
	group, err := ensureAdminGroup(ctx, st)
	if err != nil {
		return false, err
	}
	if user == nil {
		pw, err := getPassword()
		if err != nil {
			return false, err
		}
		phc, err := password.Hash(pw)
		if err != nil {
			return false, err
		}
		user = &model.User{Email: email, PasswordHash: phc, IsActive: true}
		if err := st.CreateUser(ctx, user); err != nil {
			return false, err
		}
		created = true
	}
	return created, st.AddMember(ctx, user.ID, group.ID)
}

// ensureAdminGroup returns the Admin group, first creating it, as an admin
// group that requires two-step sign in, if it is missing.
func ensureAdminGroup(ctx context.Context, st *store.Store) (*model.Group, error) {
	g, err := st.GetGroupByName(ctx, adminGroup)
	if errors.Is(err, store.ErrNotFound) {
		g = &model.Group{Name: adminGroup, IsAdmin: true, RequireTOTP: true}
		err = st.CreateGroup(ctx, g)
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

// adminPassword returns the password for a new admin account: given, if it
// is not empty; otherwise typed twice at the terminal when stdin is one, or
// else read as one line from stdin. It must pass the password policy.
func adminPassword(given, email string, minLength int, stdin io.Reader, stderr io.Writer) (string, error) {
	pw := given
	if pw == "" {
		var err error
		if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			pw, err = promptPassword(int(f.Fd()), email, stderr)
		} else {
			pw, err = readLine(stdin)
		}
		if err != nil {
			return "", err
		}
	}
	err := password.CheckPolicy(pw, minLength)
	var short password.ErrTooShort
	switch {
	case errors.As(err, &short):
		return "", fmt.Errorf("the password must have at least %d characters", short.Min)
	case err != nil: // password.ErrCommon
		return "", errors.New("that password is too common; pick something less guessable")
	}
	return pw, nil
}

// promptPassword asks for a password twice at the terminal fd, without
// echoing it.
func promptPassword(fd int, email string, stderr io.Writer) (string, error) {
	read := func(prompt string) (string, error) {
		fmt.Fprint(stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(b), nil
	}
	pw, err := read("Password for " + email + ": ")
	if err != nil {
		return "", err
	}
	again, err := read("Type it again: ")
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("the passwords don't match")
	}
	return pw, nil
}

// readLine reads one line from r, without its line ending.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	switch {
	case errors.Is(err, io.EOF) && line == "":
		return "", errors.New("no password given: pass it with a flag or on standard input")
	case err != nil && !errors.Is(err, io.EOF):
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func cmdResetPassword(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./keywell.yaml", "path to the config file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		return usageError(stderr, "reset-password", "give one email address: keywell reset-password [--config PATH] EMAIL")
	}
	ctx := context.Background()
	cfg, st, conn, err := openInstall(ctx, *configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer conn.Close()
	user, err := st.GetUserByEmail(ctx, flags.Arg(0))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fail(stderr, errors.New("no account with that email"))
	case err != nil:
		return fail(stderr, err)
	case user.Type != model.UserTypeMember:
		return fail(stderr, errServiceAccount)
	case !user.IsActive:
		return fail(stderr, errors.New("that account is deactivated, so a reset link would not work"))
	}
	link, err := web.IssueResetLink(ctx, st, cfg.Issuer(), user.ID, model.ResetPurposeReset)
	if err != nil {
		return fail(stderr, err)
	}
	audit.New(st, cliLogger(stderr)).Record(ctx, model.AuditEvent{
		ActorType: audit.ActorSystem, Action: audit.PasswordResetRequested,
		TargetType: "user", TargetID: user.ID,
		Summary: "Issued a password reset link from the command line",
		Detail:  map[string]any{"purpose": string(model.ResetPurposeReset)},
	})
	fmt.Fprintln(stdout, link)
	return 0
}
