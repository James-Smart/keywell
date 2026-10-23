package main

import (
	"context"
	"log/slog"
	"time"

	"latch/internal/oidc"
	"latch/internal/store"
)

// How often serve runs its background jobs.
const (
	cleanupInterval = time.Hour
	// latch rotate-keys tells the operator a running server picks up a new
	// key within this long.
	keyReloadInterval = 5 * time.Minute
)

// runEvery calls fn at once and then every d until ctx is done, passing
// ctx on so a call under way when ctx ends can stop early. It returns when
// ctx is done.
func runEvery(ctx context.Context, d time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for ctx.Err() == nil {
		fn(ctx)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

// janitor returns a job that deletes rows that can no longer be used:
// expired sessions, used or expired authorization codes and reset links,
// and refresh tokens past their absolute lifetime or long revoked. A
// failure is logged as a warning, unless it came from ctx ending, and the
// next kind of row is tried.
func janitor(st *store.Store, log *slog.Logger) func(context.Context) {
	cleanups := []struct {
		what string
		run  func(context.Context) (int64, error)
	}{
		{"expired sessions", st.DeleteExpiredSessions},
		{"used or expired authorization codes", st.DeleteSpentAuthCodes},
		{"expired or long-revoked refresh tokens", st.DeleteDeadRefreshTokens},
		{"used or expired reset links", st.DeleteSpentResetTokens},
	}
	return func(ctx context.Context) {
		for _, c := range cleanups {
			if ctx.Err() != nil {
				return
			}
			n, err := c.run(ctx)
			if err != nil {
				if ctx.Err() == nil {
					log.WarnContext(ctx, "delete "+c.what, "error", err)
				}
				continue
			}
			log.DebugContext(ctx, "deleted "+c.what, "count", n)
		}
	}
}

// keyReloader returns a job that re-reads the signing keys, so a rotation
// made by latch rotate-keys in another process takes effect. A failure is
// logged as a warning, unless it came from ctx ending; the keys already
// loaded stay in use.
func keyReloader(keys *oidc.KeyManager, log *slog.Logger) func(context.Context) {
	return func(ctx context.Context) {
		if err := keys.Reload(ctx); err != nil && ctx.Err() == nil {
			log.WarnContext(ctx, "reload signing keys", "error", err)
		}
	}
}
