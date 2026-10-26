package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"keywell/internal/audit"
	"keywell/internal/authentik"
	"keywell/internal/importer"
	"keywell/internal/secrets"
)

// readAuthentik reads the Authentik database; tests replace it.
var readAuthentik = authentik.Read

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return fmt.Sprint([]string(*l)) }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// cmdImportAuthentik copies members, groups and apps from an Authentik
// database into Keywell, or with --dry-run says what it would copy.
func cmdImportAuthentik(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("import-authentik", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "./keywell.yaml", "path to the config file")
	from := flags.String("from", "", "connection string for Authentik's Postgres database (required); the password can be set in PGPASSWORD instead")
	dryRun := flags.Bool("dry-run", false, "show what would be imported, and save nothing")
	var dropKeys stringList
	flags.Var(&dropKeys, "drop-key", "leave this member or group metadata key out (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case flags.NArg() > 0:
		// Never echo the arguments: an unquoted keyword DSN leaves its
		// password here.
		return usageError(stderr, "import-authentik", "unexpected arguments; put the --from value in quotes if it has spaces")
	case *from == "":
		return usageError(stderr, "import-authentik", "--from is required")
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
	snap, err := readAuthentik(ctx, *from)
	if err != nil {
		return fail(stderr, err)
	}
	rep, err := importer.Run(ctx, importer.Deps{
		Store: st, Enc: enc, Cfg: cfg, Audit: audit.New(st, cliLogger(stderr)),
	}, snap, importer.Options{DryRun: *dryRun, DropKeys: dropKeys, Source: authentik.Source(*from)})
	if rep != nil {
		if werr := rep.WriteText(stdout); werr != nil && err == nil {
			err = werr
		}
	}
	if errors.Is(err, importer.ErrBlocked) {
		return 1
	}
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}
