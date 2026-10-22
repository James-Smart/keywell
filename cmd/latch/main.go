// Command latch is the Latch identity provider.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
  serve     run the web server (--config PATH, default ./latch.yaml)
  version   print the version
`

// command runs one subcommand and returns the process exit code.
type command func(args []string, stdin io.Reader, stdout, stderr io.Writer) int

var commands = map[string]command{
	"serve":   cmdServe,
	"version": cmdVersion,
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

func cmdVersion(_ []string, _ io.Reader, stdout, _ io.Writer) int {
	fmt.Fprintf(stdout, "latch %s\n", Version)
	return 0
}

func cmdServe(args []string, _ io.Reader, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "./latch.yaml", "path to the config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath, os.Getenv)
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		fmt.Fprintf(stderr, "latch: %v\n", err)
		return 1
	}
	log, err := newLogger(cfg.Log, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "latch: %v\n", err)
		return 1
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
	rec := audit.New(st, log)
	keys, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		return err
	}
	keys.WithAudit(rec)
	prov := oidc.NewProvider(oidc.Deps{Cfg: cfg, Store: st, Keys: keys, Audit: rec, Log: log, Renderer: rend})
	// Emails already under way (each bounded by its own timeout) finish
	// before the database closes, however serve returns.
	var background sync.WaitGroup
	defer background.Wait()
	handler := web.New(web.Deps{
		Cfg:        cfg,
		Store:      st,
		Sessions:   session.NewManager(st, cfg.Sessions.Idle, cfg.Sessions.Absolute, cfg.SecureCookies()),
		Mailer:     mailer,
		Audit:      rec,
		Enc:        enc,
		Log:        log,
		Renderer:   rend,
		Limits:     web.NewLimiters(time.Now),
		OIDC:       prov,
		Background: &background,
		Version:    Version,
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "issuer", cfg.Issuer(), "version", Version)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
