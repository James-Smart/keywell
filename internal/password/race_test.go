//go:build race

package password_test

// raceEnabled reports whether the race detector is on. Its instrumentation
// slows hashing several times over, so timings mean nothing under it.
const raceEnabled = true
