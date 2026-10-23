package web

import (
	"context"
	"log/slog"
	"testing"

	"latch/internal/store/storetest"
)

func TestSafeNext(t *testing.T) {
	const authorize = "/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fwiki.example.org%2Fcb"
	for _, tc := range []struct{ raw, want string }{
		{"/account", "/account"},
		{"/", "/"},
		{authorize, authorize},
		{"https://evil.example", "/"},
		{"http://evil.example/account", "/"},
		{"//evil.example", "/"},
		{"///evil.example", "/"},
		{"/\\evil", "/"},
		{"\\\\evil.example", "/"},
		{"/account\\..\\..\\evil", "/"},
		{"/\t/evil.example", "/"},
		{"javascript:alert(1)", "/"},
		{"account", "/"},
		{"", "/"},
	} {
		if got := safeNext(tc.raw); got != tc.want {
			t.Errorf("safeNext(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The dummy hash stands in for missing users; its password must not let
// anyone in.
func TestAuthenticateUnknownEmailWithDummyPassword(t *testing.T) {
	s := newServer(Deps{Store: storetest.OpenTest(t), Log: slog.New(slog.DiscardHandler)})
	u, ok, err := s.authenticate(context.Background(), "nobody@example.org", dummyPassword)
	if u != nil || ok || err != nil {
		t.Fatalf("authenticate = %v, %v, %v; want nil, false, nil", u, ok, err)
	}
}
