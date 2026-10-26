package web

import (
	"time"

	"keywell/internal/ratelimit"
)

// Limiters are the attempt limits on sign-in and password reset requests,
// each counted per account and per client IP, and on wrong second-factor
// codes, counted per account.
type Limiters struct {
	LoginAccount, LoginIP *ratelimit.Limiter
	ResetAccount, ResetIP *ratelimit.Limiter
	// TOTPAccount spans sessions: a correct password resets LoginAccount
	// and starts a session with a fresh count of wrong codes.
	TOTPAccount *ratelimit.Limiter
}

// NewLimiters returns the production limits: failed sign-ins 10 per account
// and 50 per IP per 15 minutes (the login handler forgives successful ones);
// reset requests 3 per account and 20 per IP per hour; wrong second-factor
// codes 10 per account per 15 minutes (a correct code resets the count).
// now is their time source (time.Now outside tests).
func NewLimiters(now func() time.Time) Limiters {
	limit := func(n int, window time.Duration) *ratelimit.Limiter {
		l := ratelimit.New(n, window)
		l.SetClock(now)
		return l
	}
	return Limiters{
		LoginAccount: limit(10, 15*time.Minute),
		LoginIP:      limit(50, 15*time.Minute),
		ResetAccount: limit(3, time.Hour),
		ResetIP:      limit(20, time.Hour),
		TOTPAccount:  limit(10, 15*time.Minute),
	}
}
