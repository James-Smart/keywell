package web

import (
	"strconv"
	"testing"
)

// The peers warned about are remembered, but never more than
// maxWarnedPeers of them, however many send forwarded headers.
func TestWarnedPeersBounded(t *testing.T) {
	var w warnedPeers
	if !w.first("192.0.2.1") || w.first("192.0.2.1") {
		t.Fatal("first: want true once, then false")
	}
	for i := range 10 * maxWarnedPeers {
		w.first("peer-" + strconv.Itoa(i))
		if len(w.peers) > maxWarnedPeers {
			t.Fatalf("%d peers remembered, want at most %d", len(w.peers), maxWarnedPeers)
		}
	}
}
