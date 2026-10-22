package ratelimit

import (
	"testing"
	"time"
)

func TestAllowUpToLimit(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("fourth attempt should be denied")
	}
}

func TestWindowSlides(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := New(2, time.Minute)
	l.SetClock(func() time.Time { return now })
	l.Allow("a")
	now = now.Add(30 * time.Second)
	l.Allow("a")
	if l.Allow("a") {
		t.Fatal("should be limited inside the window")
	}
	now = now.Add(31 * time.Second) // first event is now 61s old
	if !l.Allow("a") {
		t.Fatal("oldest event should have left the window")
	}
	if l.Allow("a") {
		t.Fatal("window holds two events again, third must be denied")
	}
}

func TestResetClears(t *testing.T) {
	l := New(1, time.Minute)
	l.Allow("a")
	if l.Allow("a") {
		t.Fatal("should be limited")
	}
	l.Reset("a")
	if !l.Allow("a") {
		t.Fatal("reset should clear the key")
	}
}

func TestKeysIndependent(t *testing.T) {
	l := New(1, time.Minute)
	l.Allow("a")
	if !l.Allow("b") {
		t.Fatal("key b should be unaffected by key a")
	}
}

func TestSweepPrunesIdleKeys(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := New(5, time.Minute)
	l.SetClock(func() time.Time { return now })
	for i := 0; i < 10; i++ {
		l.Allow(string(rune('a' + i)))
	}
	now = now.Add(2 * time.Minute)
	for i := 0; i < sweepEvery; i++ {
		l.Allow("hot")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) != 1 {
		t.Fatalf("expected only the hot key to remain, got %d keys", len(l.events))
	}
}

func TestForgiveGivesBackOneAttempt(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("fourth attempt should be denied")
	}
	l.Forgive("a")
	if !l.Allow("a") {
		t.Fatal("forgiven attempt should be available again")
	}
	if l.Allow("a") {
		t.Fatal("only one attempt was forgiven")
	}
}

func TestForgiveEmptyKeyIsNoop(t *testing.T) {
	l := New(1, time.Minute)
	l.Forgive("a")
	l.mu.Lock()
	_, present := l.events["a"]
	l.mu.Unlock()
	if present {
		t.Fatal("Forgive created an entry for an unknown key")
	}
	if !l.Allow("a") {
		t.Fatal("first attempt should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("Forgive on an empty key must not give extra attempts")
	}
}
