package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"latch/internal/config"
	"latch/internal/db"
	"latch/internal/model"
	"latch/internal/oidc"
	"latch/internal/password"
	"latch/internal/secrets"
	"latch/internal/store"
)

const (
	testPW    = "correct horse battery staple"
	publicURL = "https://login.example.org"
)

// latch runs the command line in-process with stdin, returning the exit
// code and what it wrote.
func latch(stdin string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// initInstall runs latch init in a fresh directory with an admin
// admin@example.org and returns the config file's path.
func initInstall(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "latch.yaml")
	code, _, stderr := latch("", "init", "--config", cfgPath, "--data-dir", filepath.Join(dir, "data"),
		"--public-url", publicURL, "--admin-email", "admin@example.org", "--admin-password", testPW)
	if code != 0 {
		t.Fatalf("init: exit %d, stderr %q", code, stderr)
	}
	return cfgPath
}

// openInstallation loads the config at cfgPath, without environment
// overrides, and opens its database.
func openInstallation(t *testing.T, cfgPath string) (*config.Config, *store.Store) {
	t.Helper()
	cfg, err := config.Load(cfgPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return cfg, store.New(conn)
}

// groupNames returns the names of the groups u is in.
func groupNames(t *testing.T, st *store.Store, u *model.User) []string {
	t.Helper()
	groups, err := st.ListGroupsForUser(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return names
}

// checkPassword fails the test unless u's password is pw.
func checkPassword(t *testing.T, u *model.User, pw string) {
	t.Helper()
	if ok, err := password.Verify(pw, u.PasswordHash); err != nil || !ok {
		t.Fatalf("%s: password does not verify (%v)", u.Email, err)
	}
}

func TestVersionSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dev") {
		t.Fatalf("stdout %q", stdout.String())
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"frobnicate"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if code := run(nil, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("no subcommand: exit %d, want 2", code)
	}
}

func TestInitCreatesConfigDBAdminAndKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "latch.yaml")
	dataDir := filepath.Join(dir, "data")
	args := []string{"init", "--config", cfgPath, "--data-dir", dataDir, "--public-url", publicURL,
		"--admin-email", "admin@example.org", "--admin-password", testPW}
	code, stdout, stderr := latch("", args...)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"latch serve --config " + cfgPath, "two-step sign in"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}

	// The config file: private, valid, with the given values and a fresh key.
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode %v, want 0600", perm)
	}
	written, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^encryption_key: \S{44} +# `).Match(written) {
		t.Errorf("no uncommented encryption_key line:\n%s", written)
	}
	cfg, st := openInstallation(t, cfgPath)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.EncryptionKey) != 44 || cfg.PublicURL != publicURL || cfg.DataDir != dataDir {
		t.Errorf("config: encryption_key %q, public_url %q, data_dir %q", cfg.EncryptionKey, cfg.PublicURL, cfg.DataDir)
	}
	if cfg.Branding.Logo != "" {
		t.Errorf("branding.logo = %q, want unset (no logo file yet)", cfg.Branding.Logo)
	}
	if fi, err := os.Stat(dataDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("data dir: %v, err %v; want mode 0700", fi.Mode(), err)
	}

	// The admin, in an Admin group that is admin and requires two-step sign in.
	admin, err := st.GetUserByEmail(ctx, "admin@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !admin.IsActive {
		t.Error("admin is not active")
	}
	checkPassword(t, admin, testPW)
	if names := groupNames(t, st, admin); len(names) != 1 || names[0] != "Admin" {
		t.Errorf("admin groups %v, want [Admin]", names)
	}
	group, err := st.GetGroupByName(ctx, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if !group.IsAdmin || !group.RequireTOTP {
		t.Errorf("Admin group: IsAdmin %v, RequireTOTP %v", group.IsAdmin, group.RequireTOTP)
	}

	// One signing key, sealed with the key in the config.
	keys, err := st.ListSigningKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d signing keys, want 1", len(keys))
	}
	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	km, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		t.Fatalf("signing key does not open with the configured key: %v", err)
	}
	if km.ActiveKID() != keys[0].KID {
		t.Errorf("active kid %q, want %q", km.ActiveKID(), keys[0].KID)
	}

	// A second init leaves everything alone.
	code, _, stderr = latch("", args...)
	if code != 1 || stderr != "latch: "+cfgPath+" already exists\n" {
		t.Fatalf("second init: exit %d, stderr %q", code, stderr)
	}
	again, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, written) {
		t.Error("second init changed the config file")
	}
}

// Values with ports, colons, # and quotes survive the substitution: each
// loads back exactly as given.
func TestConfigFromExampleSubstitutesValues(t *testing.T) {
	for _, tc := range []struct{ name, publicURL, dataDir string }{
		{"port", "https://login.example.org:8443", "./data"},
		{"# in public_url", "https://login.example.org/#top", "./data"},
		{"# in data_dir", publicURL, "./data#2"},
		{"comment-like data_dir", publicURL, `my data #1: "x"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := secrets.GenerateKey()
			text, err := configFromExample(config.ExampleYAML, tc.publicURL, tc.dataDir, key)
			if err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(t.TempDir(), "latch.yaml")
			if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(cfgPath, func(string) string { return "" })
			if err != nil {
				t.Fatalf("%v\n%s", err, text)
			}
			if cfg.PublicURL != tc.publicURL || cfg.DataDir != tc.dataDir || cfg.EncryptionKey != key {
				t.Errorf("public_url %q, data_dir %q, encryption_key %q\n%s", cfg.PublicURL, cfg.DataDir, cfg.EncryptionKey, text)
			}
		})
	}
}

// An operator who lost their config must not get a new encryption key over
// a database whose secrets were sealed with the old one.
func TestInitRefusesExistingDatabase(t *testing.T) {
	cfgPath := initInstall(t)
	dataDir := filepath.Join(filepath.Dir(cfgPath), "data")
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := latch("", "init", "--config", cfgPath, "--data-dir", dataDir, "--public-url", publicURL,
		"--admin-email", "admin@example.org", "--admin-password", testPW)
	want := "latch: a database already exists at " + filepath.Join(dataDir, "latch.db") +
		"; restore your config file instead of running init again\n"
	if code != 1 || stdout != "" || stderr != want {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1, %q", code, stdout, stderr, want)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("config file written (stat: %v)", err)
	}
}

func TestInitAcceptsEmptyDataDir(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "latch.yaml")
	const portURL = "https://login.example.org:8443"
	code, _, stderr := latch("", "init", "--config", cfgPath, "--data-dir", dataDir, "--public-url", portURL)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	cfg, st := openInstallation(t, cfgPath)
	if cfg.PublicURL != portURL || cfg.DataDir != dataDir {
		t.Errorf("public_url %q, data_dir %q", cfg.PublicURL, cfg.DataDir)
	}
	if keys, err := st.ListSigningKeys(context.Background()); err != nil || len(keys) != 1 {
		t.Errorf("%d signing keys (err %v), want 1", len(keys), err)
	}
}

// init sets up the database the file describes, whatever LATCH_*
// variables happen to be set.
func TestInitIgnoresEnvironment(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	t.Setenv("LATCH_DATA_DIR", elsewhere)
	t.Setenv("LATCH_ENCRYPTION_KEY", secrets.GenerateKey())
	cfgPath := filepath.Join(dir, "latch.yaml")
	dataDir := filepath.Join(dir, "data")
	code, _, stderr := latch("", "init", "--config", cfgPath, "--data-dir", dataDir, "--public-url", publicURL)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(elsewhere); !os.IsNotExist(err) {
		t.Errorf("LATCH_DATA_DIR used (stat: %v)", err)
	}
	cfg, st := openInstallation(t, cfgPath) // the file's data_dir and key
	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oidc.NewKeyManager(context.Background(), st, enc); err != nil {
		t.Fatalf("signing key not sealed with the file's key: %v", err)
	}
}

func TestInitReadsPasswordFromStdin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "latch.yaml")
	code, _, stderr := latch(testPW+"\n", "init", "--config", cfgPath, "--data-dir", filepath.Join(dir, "data"),
		"--public-url", publicURL, "--admin-email", "admin@example.org")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	_, st := openInstallation(t, cfgPath)
	admin, err := st.GetUserByEmail(context.Background(), "admin@example.org")
	if err != nil {
		t.Fatal(err)
	}
	checkPassword(t, admin, testPW)
}

func TestInitRefusesBadInputBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"no public url", nil, 2, "--public-url is required"},
		{"bad public url", []string{"--public-url", "login.example.org"}, 2, "public_url must be an absolute http(s) URL"},
		{"password without email", []string{"--public-url", publicURL, "--admin-password", testPW}, 2, "--admin-password needs --admin-email"},
		{"short password", []string{"--public-url", publicURL, "--admin-email", "a@example.org", "--admin-password", "short"}, 1, "at least 10 characters"},
		{"common password", []string{"--public-url", publicURL, "--admin-email", "a@example.org", "--admin-password", "password123"}, 1, "too common"},
		{"no password on stdin", []string{"--public-url", publicURL, "--admin-email", "a@example.org"}, 1, "no password given"},
		{"stray argument", []string{"--public-url", publicURL, "extra"}, 2, `unexpected argument "extra"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "latch.yaml")
			args := append([]string{"init", "--config", cfgPath, "--data-dir", filepath.Join(dir, "data")}, tc.args...)
			code, _, stderr := latch("", args...)
			if code != tc.code || !strings.Contains(stderr, tc.stderr) || strings.Count(stderr, "\n") != 1 {
				t.Fatalf("exit %d, stderr %q; want exit %d and one line with %q", code, stderr, tc.code, tc.stderr)
			}
			if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
				t.Errorf("config file written (stat: %v)", err)
			}
		})
	}
}

func TestCreateAdmin(t *testing.T) {
	ctx := context.Background()
	cfgPath := initInstall(t)
	_, st := openInstallation(t, cfgPath)

	// A new account.
	code, stdout, stderr := latch("", "create-admin", "--config", cfgPath, "--email", "sam@example.org", "--password", testPW)
	if code != 0 || stderr != "" {
		t.Fatalf("create: exit %d, stderr %q", code, stderr)
	}
	sam, err := st.GetUserByEmail(ctx, "sam@example.org")
	if err != nil {
		t.Fatal(err)
	}
	checkPassword(t, sam, testPW)
	if names := groupNames(t, st, sam); len(names) != 1 || names[0] != "Admin" {
		t.Errorf("sam's groups %v, want [Admin]", names)
	}
	if !strings.Contains(stdout, "sam@example.org") {
		t.Errorf("stdout %q", stdout)
	}

	// An existing member is promoted, password unchanged.
	hash, err := password.Hash("an existing passphrase")
	if err != nil {
		t.Fatal(err)
	}
	kim := &model.User{Email: "kim@example.org", IsActive: true, PasswordHash: hash}
	if err := st.CreateUser(ctx, kim); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = latch("", "create-admin", "--config", cfgPath, "--email", "KIM@example.org")
	if code != 0 || stderr != "" {
		t.Fatalf("promote: exit %d, stderr %q", code, stderr)
	}
	kim, err = st.GetUser(ctx, kim.ID)
	if err != nil {
		t.Fatal(err)
	}
	checkPassword(t, kim, "an existing passphrase")
	if names := groupNames(t, st, kim); len(names) != 1 || names[0] != "Admin" {
		t.Errorf("kim's groups %v, want [Admin]", names)
	}

	if code, _, _ := latch("", "create-admin", "--config", cfgPath); code != 2 {
		t.Errorf("no --email: exit %d, want 2", code)
	}
}

func TestResetPasswordPrintsLink(t *testing.T) {
	ctx := context.Background()
	cfgPath := initInstall(t)
	_, st := openInstallation(t, cfgPath)

	code, stdout, stderr := latch("", "reset-password", "--config", cfgPath, "admin@example.org")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	m := regexp.MustCompile(`^` + regexp.QuoteMeta(publicURL) + `/reset/([A-Za-z0-9_-]{43})\n$`).FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("stdout %q is not a reset link alone", stdout)
	}
	tok, err := st.PeekResetToken(ctx, secrets.HashToken(m[1]))
	if err != nil {
		t.Fatalf("token not stored: %v", err)
	}
	admin, err := st.GetUserByEmail(ctx, "admin@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if tok.UserID != admin.ID || tok.Purpose != model.ResetPurposeReset {
		t.Errorf("token for %q purpose %q", tok.UserID, tok.Purpose)
	}

	code, stdout, stderr = latch("", "reset-password", "--config", cfgPath, "nobody@example.org")
	if code != 1 || stdout != "" || stderr != "latch: no account with that email\n" {
		t.Errorf("unknown email: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// A link for a deactivated account would only show "link expired".
	admin.IsActive = false
	if err := st.UpdateUser(ctx, admin); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = latch("", "reset-password", "--config", cfgPath, "admin@example.org")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "deactivated") {
		t.Errorf("deactivated: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, _, _ := latch("", "reset-password", "--config", cfgPath); code != 2 {
		t.Errorf("no email: exit %d, want 2", code)
	}
}

func TestRotateKeys(t *testing.T) {
	ctx := context.Background()
	cfgPath := initInstall(t)
	_, st := openInstallation(t, cfgPath)

	code, stdout, stderr := latch("", "rotate-keys", "--config", cfgPath)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	keys, err := st.ListSigningKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].RetiredAt != nil || keys[1].RetiredAt != nil {
		t.Fatalf("after rotate: %d keys, want 2 unretired", len(keys))
	}
	for _, want := range []string{"New signing key: " + keys[0].KID, "Retired 0 older keys.", "within 5 minutes"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}

	// Retiring at once leaves only the new key published.
	code, stdout, stderr = latch("", "rotate-keys", "--config", cfgPath, "--retire-after", "0d")
	if code != 0 || stderr != "" {
		t.Fatalf("retire: exit %d, stderr %q", code, stderr)
	}
	if keys, err = st.ListSigningKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0].RetiredAt != nil || keys[1].RetiredAt == nil || keys[2].RetiredAt == nil {
		t.Fatalf("after rotate --retire-after 0d: %d keys, want 3 with the 2 older retired", len(keys))
	}
	if !strings.Contains(stdout, "Retired 2 older keys.") {
		t.Errorf("stdout %q", stdout)
	}

	for _, bad := range []string{"soon", "-1d"} {
		if code, _, _ := latch("", "rotate-keys", "--config", cfgPath, "--retire-after", bad); code != 2 {
			t.Errorf("--retire-after %s: exit %d, want 2", bad, code)
		}
	}
}

func TestCommandsNeedAnExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "latch.yaml")
	cfg := "public_url: " + publicURL + "\ndata_dir: " + filepath.Join(dir, "data") +
		"\nencryption_key: " + secrets.GenerateKey() + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := latch("", "rotate-keys", "--config", cfgPath)
	if code != 1 || !strings.Contains(stderr, "run latch init first") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Errorf("data dir created (stat: %v)", err)
	}
}
