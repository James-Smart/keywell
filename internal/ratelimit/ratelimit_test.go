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

func TestSweepRunsForPeekAndRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := New(5, time.Minute)
	l.SetClock(func() time.Time { return now })
	for i := 0; i < 10; i++ {
		l.Record(string(rune('a' + i)))
	}
	now = now.Add(2 * time.Minute)
	for i := 0; i < sweepEvery; i++ {
		l.Peek("hot")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) != 0 {
		t.Fatalf("expected idle keys to be swept, got %d keys", len(l.events))
	}
}

func TestPeekRecordsNothing(t *testing.T) {
	l := New(2, time.Minute)
	for i := 0; i < 5; i++ {
		if !l.Peek("a") {
			t.Fatalf("peek %d: want under the limit", i+1)
		}
	}
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("peeks used up attempts")
	}
}

func TestRecordCountsTowardLimit(t *testing.T) {
	l := New(2, time.Minute)
	l.Record("a")
	if !l.Peek("a") {
		t.Fatal("one attempt recorded, limit 2: want under the limit")
	}
	l.Record("a")
	if l.Peek("a") {
		t.Fatal("two attempts recorded, limit 2: want limited")
	}
	if l.Allow("a") {
		t.Fatal("Allow should agree with Peek")
	}
	if !l.Peek("b") {
		t.Fatal("key b should be unaffected by key a")
	}
}

func TestRecordedAttemptsLeaveWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := New(2, time.Minute)
	l.SetClock(func() time.Time { return now })
	// Attempts at +0s, +10s, +20s, +30s: more than the limit, and only the
	// newest two matter.
	for i := 0; i < 4; i++ {
		l.Record("a")
		now = now.Add(10 * time.Second)
	}
	l.mu.Lock()
	kept := len(l.events["a"])
	l.mu.Unlock()
	if kept != 2 {
		t.Fatalf("kept %d attempts, want the limit (2)", kept)
	}
	now = now.Add(40 * time.Second) // +80s: the +20s attempt has left the window
	if !l.Peek("a") {
		t.Fatal("oldest kept attempt should have left the window")
	}
	l.Record("a")
	if l.Peek("a") {
		t.Fatal("+30s and +80s are inside the window: want limited")
	}
}
