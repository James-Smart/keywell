// Package ratelimit is an in-memory sliding-window attempt limiter.
package ratelimit

import (
	"sync"
	"time"
)

// sweepEvery is how many Allow calls pass between full sweeps of idle keys.
const sweepEvery = 1000

// Limiter permits at most limit attempts per key within a sliding window.
type Limiter struct {
	mu     sync.Mutex
	events map[string][]time.Time
	limit  int
	window time.Duration
	now    func() time.Time
	calls  int
}

// New returns a Limiter allowing limit attempts per key per window.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		events: make(map[string][]time.Time),
		limit:  limit,
		window: window,
		now:    time.Now,
	}
}

// SetClock replaces the time source. It exists for tests only.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Allow reports whether key may make another attempt. The attempt is
// recorded only when Allow returns true.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.calls++
	if l.calls%sweepEvery == 0 {
		l.sweep(now)
	}

	kept := l.prune(l.events[key], now)
	if len(kept) >= l.limit {
		l.store(key, kept)
		return false
	}
	l.store(key, append(kept, now))
	return true
}

// Forgive removes key's newest recorded attempt, e.g. to give back the
// attempt Allow counted once it turns out to have succeeded. It does
// nothing when key has no attempts.
func (l *Limiter) Forgive(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.events[key]
	if len(ts) == 0 {
		return
	}
	l.store(key, ts[:len(ts)-1])
}

// Reset forgets all attempts for key, e.g. after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.events, key)
}

// prune drops events at or before the start of the window.
func (l *Limiter) prune(ts []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

func (l *Limiter) store(key string, ts []time.Time) {
	if len(ts) == 0 {
		delete(l.events, key)
		return
	}
	l.events[key] = ts
}

func (l *Limiter) sweep(now time.Time) {
	for k, ts := range l.events {
		l.store(k, l.prune(ts, now))
	}
}
