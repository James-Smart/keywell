package store

import (
	"testing"
	"time"
)

func TestFormatTimeIsFixedWidthAndSortable(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC)
	t1 := t0.Add(500 * time.Millisecond)
	s0, s1 := formatTime(t0), formatTime(t1)
	if len(s0) != len(s1) {
		t.Fatalf("lengths differ: %q %q", s0, s1)
	}
	if !(s0 < s1) {
		t.Fatalf("not lexically ordered: %q !< %q", s0, s1)
	}
	for _, in := range []time.Time{t0, t1} {
		got, err := parseTime(formatTime(in))
		if err != nil || !got.Equal(in) {
			t.Fatalf("round trip %v -> %v (%v)", in, got, err)
		}
	}
}
