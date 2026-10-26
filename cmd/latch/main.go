// Command latch is the Latch identity provider.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"latch/internal/audit"
	"latch/internal/config"
	"latch/internal/db"
	"latch/internal/mail"
	"latch/internal/metrics"
	"latch/internal/oidc"
	"latch/internal/secrets"
	"latch/internal/session"
	"latch/internal/store"
	"latch/internal/web"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

const usage = `usage: latch <command> [flags]

commands:
  init              write a config file, set up the database and the first admin
  serve             run the web server
  create-admin      add someone to the Admin group, creating their account if needed
  reset-password    print a one-time link for choosing a new password
  rotate-keys       make a new token signing key and retire old ones
  import-authentik  copy members, groups and apps from an Authentik database
  version           print the version

Every command but version takes --config PATH (default ./latch.yaml).
Run latch <command> -h for its flags.
`

// command runs one subcommand and returns the process exit code.
type command func(args []string, stdin io.Reader, stdout, stderr io.Writer) int

var commands = map[string]command{
	"init":             cmdInit,
	"serve":            cmdServe,
	"create-admin":     cmdCreateAdmin,
	"reset-password":   cmdResetPassword,
	"rotate-keys":      cmdRotateKeys,
	"import-authentik": cmdImportAuthentik,
	"version":          cmdVersion,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "latch: unknown command %q\n%s", args[0], usage)
		return 2
	}
	return cmd(args[1:], stdin, stdout, stderr)
}

// fail reports err on one line and returns exit code 1.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "latch: %v\n", err)
	return 1
}

// usageError reports, on one line, a mistake in how command was called and
// returns exit code 2.
func usageError(stderr io.Writer, command, format string, args ...any) int {
	fmt.Fprintf(stderr, "latch %s: %s\n", command, fmt.Sprintf(format, args...))
	return 2
}

// loadConfig reads the config file at path, applies LATCH_* overrides from
// the environment and validates the result.
func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path, os.Getenv)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// openStore opens the database at path, creating it if needed, and applies
// any pending migrations. The caller closes the returned connection.
func openStore(ctx context.Context, path string) (*store.Store, *sql.DB, error) {
	conn, err := db.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := db.Migrate(ctx, conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return store.New(conn), conn, nil
}

// openInstall loads the config at configPath and opens its database, which
// latch init must already have made. The caller closes the connection.
func openInstall(ctx context.Context, configPath string) (*config.Config, *store.Store, *sql.DB, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := os.Stat(cfg.DBPath()); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("no database at %s; run latch init first", cfg.DBPath())
	}
	st, conn, err := openStore(ctx, cfg.DBPath())
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, st, conn, nil
}

// cliLogger logs warnings and errors (such as a failed audit write) to
// stderr; the commands report their own progress on stdout.
func cliLogger(stderr io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func cmdVersion(_ []string, _ io.Reader, stdout, _ io.Writer) int {
	fmt.Fprintf(stdout, "latch %s\n", Version)
	return 0
}

func cmdServe(args []string, _ io.Reader, _, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./latch.yaml", "path to the config file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fail(stderr, err)
	}
	log, err := newLogger(cfg.Log, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("serve failed", "error", err)
		return 1
	}
	return 0
}

func newLogger(c config.LogConfig, w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Level)); err != nil {
		return nil, fmt.Errorf("log.level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(c.Format) {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("log.format must be json or text, got %q", c.Format)
	}
}

// serve opens the database, builds the handler and runs the HTTP server
// until ctx is cancelled, then shuts down gracefully.
func serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	conn, err := db.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer conn.Close()
	applied, err := db.Migrate(ctx, conn)
	if err != nil {
		return err
	}
	if len(applied) > 0 {
		log.Info("applied migrations", "migrations", applied)
	}
	st := store.New(conn)

	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("encryption_key: %w", err)
	}
	mailer, err := mail.NewSMTP(cfg.SMTP)
	if err != nil {
		return err
	}
	rend, err := web.NewRenderer(cfg, log)
	if err != nil {
		return err
	}
	reg := metrics.New(Version)
	rec := audit.New(st, log).WithObserver(reg.ObserveAudit)
	keys, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		return err
	}
	keys.WithAudit(rec)
	sessions := session.NewManager(st, cfg.Sessions.Idle, cfg.Sessions.Absolute, cfg.SecureCookies())
	prov := oidc.NewProvider(oidc.Deps{
		Cfg: cfg, Store: st, Keys: keys, Audit: rec, Log: log, Renderer: rend, Sessions: sessions,
	})
	// Emails already under way (each bounded by its own timeout) and the
	// periodic jobs finish before the database closes, however serve
	// returns.
	var background sync.WaitGroup
	defer background.Wait()
	// Deferred after Wait, so it runs first: the jobs stop on any return,
	// not only when ctx ends.
	jobsCtx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	background.Go(func() { runEvery(jobsCtx, cleanupInterval, janitor(st, log)) })
	background.Go(func() { runEvery(jobsCtx, keyReloadInterval, keyReloader(keys, log)) })
	handler := web.New(web.Deps{
		Cfg:        cfg,
		Store:      st,
		Sessions:   sessions,
		Mailer:     mailer,
		Audit:      rec,
		Enc:        enc,
		Log:        log,
		Renderer:   rend,
		Limits:     web.NewLimiters(time.Now),
		Metrics:    reg,
		OIDC:       prov,
		Keys:       keys,
		Background: &background,
		Version:    Version,
	})

	newServer := func(addr string, h http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
	}
	srv := newServer(cfg.Listen, handler)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "issuer", cfg.Issuer(), "version", Version)

	// Metrics are served on their own listener, never the public one.
	var msrv *http.Server
	merrc := make(chan error, 1)
	if cfg.Metrics.Listen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", reg.Handler())
		msrv = newServer(cfg.Metrics.Listen, mux)
		go func() { merrc <- msrv.ListenAndServe() }()
		log.Info("serving metrics", "addr", cfg.Metrics.Listen)
	}

	select {
	case err := <-errc:
		if msrv != nil {
			msrv.Close()
		}
		return err
	case err := <-merrc:
		srv.Close()
		return fmt.Errorf("metrics listener: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if msrv != nil {
		if err := msrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown metrics: %w", err)
		}
		if err := <-merrc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
