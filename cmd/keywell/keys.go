package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"keywell/internal/audit"
	"keywell/internal/config"
	"keywell/internal/oidc"
	"keywell/internal/secrets"
)

// cmdRotateKeys makes a new active signing key, then retires the keys
// superseded at least --retire-after ago.
func cmdRotateKeys(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("rotate-keys", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./keywell.yaml", "path to the config file")
	retireAfter := 90 * 24 * time.Hour
	flags.Func("retire-after", "retire older keys once they have been superseded this long, e.g. 90d or 0d (default 90d)",
		func(s string) error {
			d, err := config.ParseDuration(s) // refuses negative durations
			retireAfter = d
			return err
		})
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		return usageError(stderr, "rotate-keys", "unexpected argument %q", flags.Arg(0))
	}
	ctx := context.Background()
	cfg, st, conn, err := openInstall(ctx, *configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer conn.Close()
	enc, err := secrets.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return fail(stderr, fmt.Errorf("encryption_key: %w", err))
	}
	keys, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		return fail(stderr, err)
	}
	keys.WithAudit(audit.New(st, cliLogger(stderr)))
	kid, err := keys.Rotate(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "New signing key: %s\n", kid)
	retired, err := keys.RetireOlderThan(ctx, retireAfter)
	if err != nil {
		return fail(stderr, fmt.Errorf("the new key is active, but retiring older keys failed: %w", err))
	}
	noun := "keys"
	if retired == 1 {
		noun = "key"
	}
	fmt.Fprintf(stdout, "Retired %d older %s.\n", retired, noun)
	fmt.Fprintln(stdout, "A running server picks up the new key within 5 minutes.")
	return 0
}
