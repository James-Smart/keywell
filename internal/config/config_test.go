package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load("", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:8080" {
		t.Errorf("Listen = %q", c.Listen)
	}
	if c.DataDir != "./data" {
		t.Errorf("DataDir = %q", c.DataDir)
	}
	if c.Sessions.Idle != 336*time.Hour || c.Sessions.Absolute != 720*time.Hour {
		t.Errorf("sessions = %+v", c.Sessions)
	}
	if c.Tokens.Access != time.Hour || c.Tokens.ID != time.Hour ||
		c.Tokens.Refresh != 720*time.Hour || c.Tokens.RefreshAbsolute != 2160*time.Hour {
		t.Errorf("tokens = %+v", c.Tokens)
	}
	if c.Password.MinLength != 10 {
		t.Errorf("MinLength = %d", c.Password.MinLength)
	}
	if c.Log.Level != "info" || c.Log.Format != "json" {
		t.Errorf("log = %+v", c.Log)
	}
	if c.SMTP.TLS != "starttls" || c.SMTP.Port != 587 {
		t.Errorf("smtp = %+v", c.SMTP)
	}
	if c.Branding.PrimaryColor != "#2c6e49" || c.Branding.Name != "Latch" {
		t.Errorf("branding = %+v", c.Branding)
	}
}

func TestLoadYAMLAndEnvOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "latch.yaml")
	y := "public_url: https://x\nsmtp:\n  host: a\n  port: 25\nsessions:\n  absolute: 30d\ntrusted_proxies: [10.0.0.0/8]\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, mapEnv(map[string]string{
		"LATCH_SMTP_HOST":                                 "b",
		"LATCH_TOKENS_ACCESS":                             "30m",
		"LATCH_SESSIONS_IDLE":                             "7d",
		"LATCH_BRANDING_PRIMARY_COLOR":                    "#112233",
		"LATCH_TOKENS_REQUIRE_OFFLINE_ACCESS_FOR_REFRESH": "true",
		"LATCH_TRUSTED_PROXIES":                           "192.168.0.0/16, 172.16.0.0/12",
		"LATCH_PASSWORD_MIN_LENGTH":                       "12",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://x" {
		t.Errorf("PublicURL = %q", c.PublicURL)
	}
	if c.SMTP.Host != "b" || c.SMTP.Port != 25 {
		t.Errorf("smtp = %+v", c.SMTP)
	}
	if c.Tokens.Access != 30*time.Minute {
		t.Errorf("access = %v", c.Tokens.Access)
	}
	if c.Sessions.Idle != 168*time.Hour || c.Sessions.Absolute != 720*time.Hour {
		t.Errorf("sessions = %+v", c.Sessions)
	}
	if c.Branding.PrimaryColor != "#112233" || !c.Tokens.RequireOfflineAccessForRefresh || c.Password.MinLength != 12 {
		t.Errorf("cfg = %+v", c)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[1] != "172.16.0.0/12" {
		t.Errorf("proxies = %v", c.TrustedProxies)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load("/nonexistent/latch.yaml", noEnv); err == nil {
		t.Error("missing file: want error")
	}
	_, err := Load("", mapEnv(map[string]string{"LATCH_TOKENS_ACCESS": "soon"}))
	if err == nil || !strings.Contains(err.Error(), "LATCH_TOKENS_ACCESS") {
		t.Errorf("bad duration err = %v", err)
	}
}

func valid(t *testing.T) *Config {
	t.Helper()
	c, err := Load("", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicURL = "https://login.example.org"
	c.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	return c
}

func TestValidate(t *testing.T) {
	if err := valid(t).Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	cases := []struct {
		key    string
		mutate func(*Config)
	}{
		{"public_url", func(c *Config) { c.PublicURL = "" }},
		{"public_url", func(c *Config) { c.PublicURL = "ftp://x" }},
		{"public_url", func(c *Config) { c.PublicURL = "https://x/path" }},
		{"public_url", func(c *Config) { c.PublicURL = "https://x?q=1" }},
		{"public_url", func(c *Config) { c.PublicURL = "https://x#f" }},
		{"public_url", func(c *Config) { c.PublicURL = "/relative" }},
		{"encryption_key", func(c *Config) { c.EncryptionKey = "" }},
		{"encryption_key", func(c *Config) { c.EncryptionKey = "!!!notbase64" }},
		{"encryption_key", func(c *Config) { c.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 16)) }},
		{"smtp.tls", func(c *Config) { c.SMTP.TLS = "foo" }},
		{"branding.primary_color", func(c *Config) { c.Branding.PrimaryColor = "red" }},
		// The common-password list only holds passwords of 10 or more
		// characters, so a shorter minimum would let common ones through.
		{"password.min_length", func(c *Config) { c.Password.MinLength = 9 }},
		{"password.min_length", func(c *Config) { c.Password.MinLength = 0 }},
		{"sessions.idle", func(c *Config) { c.Sessions.Idle = 0 }},
		{"sessions.absolute", func(c *Config) { c.Sessions.Absolute = -time.Hour }},
		{"tokens.access", func(c *Config) { c.Tokens.Access = 0 }},
		{"tokens.id", func(c *Config) { c.Tokens.ID = -time.Second }},
		{"tokens.refresh", func(c *Config) { c.Tokens.Refresh = 0 }},
		{"tokens.refresh_absolute", func(c *Config) { c.Tokens.RefreshAbsolute = 0 }},
		// Retired signing keys verify tokens for only 24 hours.
		{"tokens.access", func(c *Config) { c.Tokens.Access = 24*time.Hour + time.Second }},
		{"tokens.id", func(c *Config) { c.Tokens.ID = 25 * time.Hour }},
		{"tokens.refresh_absolute", func(c *Config) { c.Tokens.RefreshAbsolute = c.Tokens.Refresh - time.Second }},
		{"trusted_proxies", func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8", "proxy.internal"} }},
		{"trusted_proxies", func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/33"} }},
		{"trusted_proxies", func(c *Config) { c.TrustedProxies = []string{""} }},
	}
	for _, tc := range cases {
		c := valid(t)
		tc.mutate(c)
		err := c.Validate()
		if err == nil || !strings.HasPrefix(err.Error(), tc.key+" ") {
			t.Errorf("%s: err = %v", tc.key, err)
		}
	}
}

// Values at the limits, and every form of trusted proxy, are accepted.
func TestValidateAcceptsLimits(t *testing.T) {
	c := valid(t)
	c.Password.MinLength = 10
	c.Tokens.Access, c.Tokens.ID = 24*time.Hour, 24*time.Hour
	c.Tokens.RefreshAbsolute = c.Tokens.Refresh
	c.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.10", "fd00::/8", "::1"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDerived(t *testing.T) {
	c := valid(t)
	c.PublicURL = "https://x/"
	c.DataDir = "/var/lib/latch"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Issuer() != "https://x" {
		t.Errorf("Issuer = %q", c.Issuer())
	}
	if !c.SecureCookies() {
		t.Error("SecureCookies want true")
	}
	c.PublicURL = "http://x"
	if c.SecureCookies() {
		t.Error("SecureCookies want false")
	}
	if c.DBPath() != "/var/lib/latch/latch.db" {
		t.Errorf("DBPath = %q", c.DBPath())
	}
}

func TestExampleFileLoads(t *testing.T) {
	c, err := Load("../../latch.example.yaml", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	c.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The repo-root latch.example.yaml is a copy of example.yaml, the source
// that latch init writes configs from.
func TestRootExampleMatchesEmbedded(t *testing.T) {
	root, err := os.ReadFile("../../latch.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(root) != ExampleYAML {
		t.Fatal("latch.example.yaml differs from internal/config/example.yaml; copy example.yaml over it")
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d":  90 * 24 * time.Hour,
		"1.5d": 36 * time.Hour,
		"0d":   0,
		"30m":  30 * time.Minute,
	} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "soon", "xd", "5 days",
		"infd", "+Infd", "nand", "NaNd", "-1d", "-0.5d", "-30m", "1e300d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q): no error", in)
		}
	}
}
