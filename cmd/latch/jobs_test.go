package main

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"latch/internal/config"
	"latch/internal/db"
	"latch/internal/model"
	"latch/internal/oidc"
	"latch/internal/secrets"
	"latch/internal/store"
)

// within bounds each wait in these tests, so a broken loop fails the test
// instead of hanging it.
const within = 5 * time.Second

// waitFor fails the test unless ch is closed or receives within the bound.
func waitFor[T any](t *testing.T, ch <-chan T, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("%s: nothing after %v", what, within)
	}
}

func TestRunEveryCallsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var calls atomic.Int32
	first, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runEvery(ctx, time.Hour, func(context.Context) {
			if calls.Add(1) == 1 {
				close(first)
			}
		})
	}()
	waitFor(t, first, "first call")
	cancel()
	waitFor(t, done, "runEvery returning")
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d calls within the first hour, want 1", n)
	}
}

func TestRunEveryRepeatsUntilContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls, done := make(chan struct{}, 10), make(chan struct{})
	go func() {
		defer close(done)
		runEvery(ctx, 5*time.Millisecond, func(context.Context) { calls <- struct{}{} })
	}()
	for range 3 {
		waitFor(t, calls, "repeat call")
	}
	cancel()
	waitFor(t, done, "runEvery returning")
}

// A job still running when the context ends sees it end too, so shutdown
// does not wait out the job.
func TestRunEveryPassesItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runEvery(ctx, time.Hour, func(jobCtx context.Context) {
			close(started)
			<-jobCtx.Done()
		})
	}()
	waitFor(t, started, "job starting")
	cancel()
	waitFor(t, done, "runEvery returning")
}

// debugLog returns a text logger at debug level and the buffer it writes
// to. Only one goroutine may log to it.
func debugLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// addSession stores a session for userID that expires at expires.
func addSession(t *testing.T, st *store.Store, userID string, expires time.Time) string {
	t.Helper()
	now := time.Now().UTC()
	sess := &model.Session{ID: secrets.NewID(), UserID: userID, CreatedAt: now, LastSeenAt: now, ExpiresAt: expires}
	if err := st.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess.ID
}

// sessionIDs lists the IDs of every stored session, expired or not.
func sessionIDs(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT id FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestSessionJanitorDeletesExpiredSessions(t *testing.T) {
	ctx := context.Background()
	st, conn := store.OpenTestDB(t)
	u := &model.User{Email: "alex@example.org", IsActive: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	addSession(t, st, u.ID, time.Now().Add(-time.Minute))
	live := addSession(t, st, u.ID, time.Now().Add(time.Hour))
	log, logs := debugLog()

	sessionJanitor(st, log)(ctx)
	if ids := sessionIDs(t, conn); len(ids) != 1 || ids[0] != live {
		t.Fatalf("sessions left %v, want only the live one %s", ids, live)
	}
	if out := logs.String(); !strings.Contains(out, `level=DEBUG msg="deleted expired sessions" count=1`) {
		t.Fatalf("log:\n%s", out)
	}
}

// keyReloader picks up a key that latch rotate-keys, in another process,
// made active.
func TestKeyReloaderPicksUpRotation(t *testing.T) {
	ctx := context.Background()
	st := store.OpenTest(t)
	enc, err := secrets.NewEncryptor(secrets.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	serving, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		t.Fatal(err)
	}
	other, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := other.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if serving.ActiveKID() == kid {
		t.Fatal("the serving manager has the new key before reloading")
	}
	log, logs := debugLog()

	keyReloader(serving, log)(ctx)
	if serving.ActiveKID() != kid {
		t.Fatalf("active key %s, want the rotated key %s", serving.ActiveKID(), kid)
	}
	if logs.Len() != 0 {
		t.Fatalf("log:\n%s", logs)
	}
}

// A job that fails logs a warning and returns; the next run tries again.
func TestJobsWarnOnFailure(t *testing.T) {
	ctx := context.Background()
	st, conn := store.OpenTestDB(t)
	enc, err := secrets.NewEncryptor(secrets.GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := oidc.NewKeyManager(ctx, st, enc)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	log, logs := debugLog()

	sessionJanitor(st, log)(ctx)
	keyReloader(keys, log)(ctx)
	out := logs.String()
	for _, want := range []string{`level=WARN msg="delete expired sessions"`, `level=WARN msg="reload signing keys"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

// serveInstall makes an installation with latch init and returns its
// config, set to listen on addr, and a connection to its database.
func serveInstall(t *testing.T, addr string) (*config.Config, *store.Store, *sql.DB) {
	t.Helper()
	cfg, err := config.Load(initInstall(t), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = addr
	conn, err := db.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return cfg, store.New(conn), conn
}

// serve deletes expired sessions as it starts, and stops its background
// jobs and returns when its context ends.
func TestServeCleansSessionsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cfg, st, conn := serveInstall(t, "127.0.0.1:0")
	admin, err := st.GetUserByEmail(ctx, "admin@example.org")
	if err != nil {
		t.Fatal(err)
	}
	addSession(t, st, admin.ID, time.Now().Add(-time.Minute))

	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, cfg, slog.New(slog.DiscardHandler)) }()
	deadline := time.Now().Add(within)
	for len(sessionIDs(t, conn)) > 0 {
		if time.Now().After(deadline) {
			cancel()
			<-errc
			t.Fatalf("expired session still stored after %v", within)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(within):
		t.Fatalf("serve still running %v after its context ended", within)
	}
}

// When the server cannot listen, serve stops its background jobs and
// returns the error rather than waiting for them forever.
func TestServeReturnsWhenListenFails(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	cfg, _, _ := serveInstall(t, taken.Addr().String())

	errc := make(chan error, 1)
	go func() { errc <- serve(t.Context(), cfg, slog.New(slog.DiscardHandler)) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("serve: %v, want address already in use", err)
		}
	case <-time.After(within):
		t.Fatalf("serve still running %v after failing to listen", within)
	}
}
