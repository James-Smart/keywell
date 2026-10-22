package web

import (
	"time"

	"latch/internal/ratelimit"
)

// Limiters are the attempt limits on sign-in and password reset requests,
// each counted per account and per client IP.
type Limiters struct {
	LoginAccount, LoginIP *ratelimit.Limiter
	ResetAccount, ResetIP *ratelimit.Limiter
}

// NewLimiters returns the production limits: sign-in 10 per account and 50
// per IP per 15 minutes; reset 3 per account and 20 per IP per hour. now is
// their time source (time.Now outside tests).
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
	}
}
