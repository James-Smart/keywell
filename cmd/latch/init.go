package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"latch/internal/config"
	"latch/internal/oidc"
	"latch/internal/secrets"
)

// cmdInit sets up a new installation: the config file, the database, the
// Admin group, a signing key and, when --admin-email is given, the first
// admin. Everything that can be refused (flags, an existing config or
// database, the admin's password) is checked before anything is written.
// LATCH_* environment variables are ignored: the database is set up as the
// written file describes.
func cmdInit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./latch.yaml", "where to write the config file")
	dataDir := flags.String("data-dir", "./data", "directory for the database")
	publicURL := flags.String("public-url", "", "the address members use to reach Latch, e.g. https://login.example.org (required)")
	adminEmail := flags.String("admin-email", "", "email address of the first admin")
	adminPW := flags.String("admin-password", "", "the first admin's password (prompted for when omitted)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case flags.NArg() > 0:
		return usageError(stderr, "init", "unexpected argument %q", flags.Arg(0))
	case *publicURL == "":
		return usageError(stderr, "init", "--public-url is required")
	case *adminPW != "" && *adminEmail == "":
		return usageError(stderr, "init", "--admin-password needs --admin-email")
	case *adminEmail != "" && !strings.Contains(*adminEmail, "@"):
		return usageError(stderr, "init", "--admin-email must be an email address")
	}
	if _, err := os.Stat(*configPath); err == nil {
		return fail(stderr, fmt.Errorf("%s already exists", *configPath))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fail(stderr, err)
	}

	issuer := strings.TrimSuffix(*publicURL, "/")
	key := secrets.GenerateKey()
	defaults, err := config.Load("", noEnv)
	if err != nil {
		return fail(stderr, err)
	}
	defaults.PublicURL, defaults.EncryptionKey, defaults.DataDir = issuer, key, *dataDir
	if err := defaults.Validate(); err != nil {
		return usageError(stderr, "init", "%v", err)
	}
	// Its secrets are sealed with the lost config's key; a new key would
	// make them unreadable.
	if _, err := os.Stat(defaults.DBPath()); err == nil {
		return fail(stderr, fmt.Errorf("a database already exists at %s; restore your config file instead of running init again",
			defaults.DBPath()))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fail(stderr, err)
	}
	var pw string
	if *adminEmail != "" {
		if pw, err = adminPassword(*adminPW, *adminEmail, defaults.Password.MinLength, stdin, stderr); err != nil {
			return fail(stderr, err)
		}
	}

	text, err := configFromExample(config.ExampleYAML, issuer, *dataDir, key)
	if err != nil {
		return fail(stderr, err)
	}
	if err := writeNewFile(*configPath, text); err != nil {
		return fail(stderr, err)
	}
	cfg, err := config.Load(*configPath, noEnv)
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		return fail(stderr, err)
	}
	if err := setUp(cfg, *adminEmail, pw); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, "Wrote %s and set up the database in %s.\n", *configPath, cfg.DataDir)
	if *adminEmail != "" {
		fmt.Fprintf(stdout, "%s is in the %s group.\n", *adminEmail, adminGroup)
	}
	fmt.Fprintf(stdout, "\nNext steps:\n")
	fmt.Fprintf(stdout, "  - Edit %s to set your branding and email (smtp) settings.\n", *configPath)
	if *adminEmail == "" {
		fmt.Fprintf(stdout, "  - Add an admin: latch create-admin --config %s --email you@example.org\n", *configPath)
	}
	fmt.Fprintf(stdout, "  - Start the server: latch serve --config %s\n", *configPath)
	fmt.Fprintf(stdout, "  - Sign in at %s as the admin. You'll be asked to set up two-step sign in first, because the %s group requires it.\n",
		cfg.Issuer(), adminGroup)
	return 0
}

// noEnv is an environment with no variables set.
func noEnv(string) string { return "" }

// setUp creates the data directory and database, the Admin group, a
// signing key and, when email is not empty, the admin with password pw.
func setUp(cfg *config.Config, email, pw string) error {
	ctx := context.Background()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, conn, err := openStore(ctx, cfg.DBPath())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := ensureAdminGroup(ctx, st); err != nil {
		return err
	}
	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("encryption_key: %w", err)
	}
	// NewKeyManager generates a signing key when there is none.
	if _, err := oidc.NewKeyManager(ctx, st, enc); err != nil {
		return err
	}
	if email == "" {
		return nil
	}
	_, err = makeAdmin(ctx, st, email, func() (string, error) { return pw, nil })
	return err
}

// writeNewFile writes text to a new file at path, readable by its owner
// only, creating the directory it goes in if needed. It never replaces an
// existing file.
func writeNewFile(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return fmt.Errorf("write config: %w", err)
	}
	return f.Close()
}

// configFromExample returns the example config with public_url, data_dir
// and encryption_key set and branding.logo commented out (a new
// installation has no logo file yet). Each key's line is replaced, keeping
// its comment; encryption_key's line is uncommented.
func configFromExample(example, publicURL, dataDir, key string) (string, error) {
	lines := strings.SplitAfter(example, "\n")
	for _, set := range []struct{ key, value string }{
		{"public_url", publicURL},
		{"data_dir", dataDir},
		{"encryption_key", key},
	} {
		if err := setLine(lines, set.key, set.value); err != nil {
			return "", err
		}
	}
	found := false
	for i, line := range lines {
		if rest, ok := strings.CutPrefix(line, "  logo:"); ok {
			lines[i], found = "  # logo:"+rest, true
		}
	}
	if !found {
		return "", errors.New("example config has no branding.logo line")
	}
	return strings.Join(lines, ""), nil
}

// setLine replaces the value on the top-level line for key, commented out
// or not, keeping the line's trailing comment in the same column.
func setLine(lines []string, key, value string) error {
	quoted, err := yamlScalar(value)
	if err != nil {
		return err
	}
	for i, line := range lines {
		body, ok := strings.CutPrefix(line, key+":")
		if !ok {
			body, ok = strings.CutPrefix(line, "# "+key+":")
		}
		if !ok {
			continue
		}
		newLine := key + ": " + quoted
		if at := strings.Index(body, " #"); at >= 0 {
			comment := strings.TrimRight(body[at+1:], "\n")
			column := len(line) - len(body) + at + 1 // where the comment started
			newLine += strings.Repeat(" ", max(2, column-len(newLine))) + comment
		}
		lines[i] = newLine + "\n"
		return nil
	}
	return fmt.Errorf("example config has no %s line", key)
}

// yamlScalar returns s as a YAML scalar, quoted only if it must be.
func yamlScalar(s string) (string, error) {
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("encode %q: %w", s, err)
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}
