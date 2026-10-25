package authentik_test

import (
	"strings"
	"testing"
	"time"

	"latch/internal/authentik"
)

func TestParseValidity(t *testing.T) {
	ok := []struct {
		in   string
		want time.Duration
	}{
		{"hours=1", time.Hour},
		{"minutes=5", 5 * time.Minute},
		{"days=30", 720 * time.Hour},
		{"weeks=20", 3360 * time.Hour},
		{"hours=1;minutes=30", 90 * time.Minute},
		{"HOURS=2", 2 * time.Hour},
		{"seconds=1.5", 1500 * time.Millisecond},
		{"hours=1;bogus=3", time.Hour},
	}
	for _, c := range ok {
		got, err := authentik.ParseValidity(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseValidity(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{"", "hours", "bogus=1", "hours=x", "hours=-1"} {
		if got, err := authentik.ParseValidity(in); err == nil {
			t.Errorf("ParseValidity(%q) = %v, nil; want an error", in, got)
		}
	}
	if _, err := authentik.ParseValidity("bogus=1"); err == nil || !strings.Contains(err.Error(), "no valid keys") {
		t.Errorf("bogus=1 error = %v; want it to say \"no valid keys\"", err)
	}
}

func TestHashedUserID(t *testing.T) {
	// A value Authentik itself returned for user 6.
	const want = "9ddc5c9119d9167a4f7d5c6516bfaa6da909f0c1b69a107562f7951b1dac8051"
	if got := authentik.HashedUserID(6, "c8b87056-95de-45d3-aed6-2c27cb4271ec"); got != want {
		t.Errorf("HashedUserID = %s, want %s", got, want)
	}
}

func TestSource(t *testing.T) {
	for _, c := range []struct{ dsn, want string }{
		{"postgres://authentik:s3cret@db.internal:5432/authentik?sslmode=disable", "db.internal:5432/authentik"},
		{"postgres://u:p@localhost/ak", "localhost:5432/ak"},
		{"host=db user=u password=p dbname=ak", "db:5432/ak"},
		{"::not a dsn::", "an Authentik database"},
	} {
		got := authentik.Source(c.dsn)
		if got != c.want {
			t.Errorf("Source(%q) = %q, want %q", c.dsn, got, c.want)
		}
		if strings.Contains(got, "s3cret") || strings.Contains(got, "password") {
			t.Errorf("Source(%q) = %q leaks a password", c.dsn, got)
		}
	}
}
