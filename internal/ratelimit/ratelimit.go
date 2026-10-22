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

	now := l.tick()
	kept := l.prune(l.events[key], now)
	if len(kept) >= l.limit {
		l.store(key, kept)
		return false
	}
	l.store(key, append(kept, now))
	return true
}

// Peek reports whether key is under the limit, without recording an
// attempt. Use it with Record when only some attempts (e.g. failed sign-ins)
// should count.
func (l *Limiter) Peek(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.tick()
	kept := l.prune(l.events[key], now)
	l.store(key, kept)
	return len(kept) < l.limit
}

// Record counts an attempt by key whether or not it is over the limit. Only
// the newest limit attempts are kept: they decide when key is next under it.
func (l *Limiter) Record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.tick()
	kept := append(l.prune(l.events[key], now), now)
	if len(kept) > l.limit {
		kept = kept[len(kept)-l.limit:]
	}
	l.store(key, kept)
}

// tick returns the current time and sweeps idle keys every sweepEvery
// calls. l.mu must be held.
func (l *Limiter) tick() time.Time {
	now := l.now()
	l.calls++
	if l.calls%sweepEvery == 0 {
		l.sweep(now)
	}
	return now
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
