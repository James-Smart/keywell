package main

import (
	"context"
	"strings"
	"testing"

	"latch/internal/audit"
	"latch/internal/authentik"
	"latch/internal/model"
	"latch/internal/store"
)

const importDSN = "postgres://reader:s3cret@db.internal:5432/authentik"

// fakeAuthentik replaces readAuthentik with a snapshot of two members, one
// with the metadata keys member_number and door, and restores it afterwards.
func fakeAuthentik(t *testing.T, users ...authentik.User) {
	t.Helper()
	old := readAuthentik
	t.Cleanup(func() { readAuthentik = old })
	readAuthentik = func(_ context.Context, dsn string) (*authentik.Snapshot, error) {
		return &authentik.Snapshot{InstallID: "install-1", Users: users}, nil
	}
}

func akUser(pk int64, username, email string, attrs map[string]any) authentik.User {
	if attrs == nil {
		attrs = map[string]any{}
	}
	return authentik.User{PK: pk, UUID: username + "-uuid", Username: username, Name: username, Email: email,
		IsActive: true, Type: "internal", Attributes: attrs}
}

func importRunCount(t *testing.T, st *store.Store) int {
	t.Helper()
	if _, err := st.LastImportRun(context.Background()); err != nil {
		if err == store.ErrNotFound {
			return 0
		}
		t.Fatal(err)
	}
	return 1
}

func TestImportCommand(t *testing.T) {
	ctx := context.Background()
	users := []authentik.User{
		akUser(1, "alex", "alex@example.org", map[string]any{"member_number": 42, "door": "yes"}),
		akUser(2, "sam", "sam@example.org", nil),
	}

	t.Run("dry run", func(t *testing.T) {
		cfgPath := initInstall(t)
		_, st := openInstallation(t, cfgPath)
		fakeAuthentik(t, users...)
		code, stdout, stderr := latch("", "import-authentik", "--config", cfgPath, "--from", importDSN, "--dry-run")
		if code != 0 || stderr != "" {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if !strings.Contains(stdout, "Dry run of an import from db.internal:5432/authentik") ||
			!strings.Contains(stdout, "Members: 2 added") {
			t.Errorf("stdout %q", stdout)
		}
		if importRunCount(t, st) != 0 {
			t.Error("a dry run stored an import run")
		}
		if _, err := st.GetUserByEmail(ctx, "alex@example.org"); err == nil {
			t.Error("a dry run added a member")
		}
	})

	t.Run("real run", func(t *testing.T) {
		cfgPath := initInstall(t)
		_, st := openInstallation(t, cfgPath)
		fakeAuthentik(t, users...)
		code, stdout, stderr := latch("", "import-authentik", "--config", cfgPath, "--from", importDSN)
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		run, err := st.LastImportRun(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for name, s := range map[string]string{"stdout": stdout, "stderr": stderr, "report": run.Report} {
			if strings.Contains(s, "s3cret") {
				t.Errorf("%s has the password: %q", name, s)
			}
		}
		if run.Source != "db.internal:5432/authentik" {
			t.Errorf("source %q", run.Source)
		}
		page, err := st.ListAuditEvents(ctx, store.AuditFilter{Actions: []string{audit.ImportRun}})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) != 1 {
			t.Fatalf("%d import.run events, want 1", len(page.Rows))
		}
		ev := page.Rows[0]
		want := "Imported from Authentik: 2 members added, 0 updated, 0 skipped; 0 groups added, 0 updated, 0 skipped; 0 apps added, 0 updated, 0 skipped"
		if ev.ActorType != model.ActorImporter || ev.Summary != want {
			t.Errorf("event actor %q summary %q; want importer and %q", ev.ActorType, ev.Summary, want)
		}
		u, err := st.GetUserByEmail(ctx, "alex@example.org")
		if err != nil {
			t.Fatal(err)
		}
		if u.Metadata["member_number"] == nil || u.Metadata["door"] == nil {
			t.Errorf("metadata %v", u.Metadata)
		}
	})

	t.Run("drop keys", func(t *testing.T) {
		cfgPath := initInstall(t)
		_, st := openInstallation(t, cfgPath)
		fakeAuthentik(t, users...)
		code, _, stderr := latch("", "import-authentik", "--config", cfgPath, "--from", importDSN,
			"--drop-key", "member_number", "--drop-key", "door")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		u, err := st.GetUserByEmail(ctx, "alex@example.org")
		if err != nil {
			t.Fatal(err)
		}
		if len(u.Metadata) != 0 {
			t.Errorf("metadata %v, want none", u.Metadata)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		cfgPath := initInstall(t)
		_, st := openInstallation(t, cfgPath)
		fakeAuthentik(t, akUser(1, "alex", "Alex@example.org", nil), akUser(2, "alex2", "alex@example.org", nil))
		code, stdout, _ := latch("", "import-authentik", "--config", cfgPath, "--from", importDSN)
		if code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		if !strings.Contains(stdout, "Nothing was imported from db.internal:5432/authentik. Fix these first:") ||
			!strings.Contains(stdout, "have the same email address apart from capitals") {
			t.Errorf("stdout %q", stdout)
		}
		if importRunCount(t, st) != 0 {
			t.Error("a blocked import stored a run")
		}
	})

	t.Run("no --from", func(t *testing.T) {
		code, stdout, stderr := latch("", "import-authentik", "--config", initInstall(t))
		if code != 2 || stdout != "" || stderr != "latch import-authentik: --from is required\n" {
			t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}
