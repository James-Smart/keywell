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

// A misspelt key is an error naming it, not silently ignored (which would
// leave, say, trusted_proxies at its default).
func TestLoadRejectsUnknownKeys(t *testing.T) {
	for _, tc := range []struct{ yaml, key string }{
		{"public_url: https://x\ntrusted_proxy: [10.0.0.0/8]\n", "trusted_proxy"},
		{"smtp:\n  hostname: mail.example.org\n", "hostname"},
		{"sessions:\n  idle: 7d\n  absolut: 30d\n", "absolut"},
	} {
		p := filepath.Join(t.TempDir(), "latch.yaml")
		if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(p, noEnv)
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("Load(%q) err = %v, want one naming %s", tc.yaml, err, tc.key)
		}
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
	// The scheme is case-insensitive: Validate writes it in lower case, so
	// cookies are still Secure and the issuer is what clients expect.
	c.PublicURL = "HTTPS://login.example.org/"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.SecureCookies() || c.Issuer() != "https://login.example.org" {
		t.Errorf("HTTPS:// public_url: SecureCookies %v, Issuer %q; want true, https://login.example.org",
			c.SecureCookies(), c.Issuer())
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
	// No proxy is trusted until the operator names theirs: a guessed range
	// would let anyone inside it choose their address.
	if len(c.TrustedProxies) != 0 {
		t.Errorf("example trusted_proxies %v, want none", c.TrustedProxies)
	}
	if !strings.Contains(ExampleYAML, "trusted_proxies: []") || !strings.Contains(ExampleYAML, "172.16.0.0/12") {
		t.Error("example config should set trusted_proxies: [] and explain what to list, with the Docker range")
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

func TestMetricsListen(t *testing.T) {
	c, err := Load("", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metrics.Listen != "" {
		t.Errorf("default Metrics.Listen = %q", c.Metrics.Listen)
	}
	c, err = Load("", mapEnv(map[string]string{"LATCH_METRICS_LISTEN": "127.0.0.1:9100"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Metrics.Listen != "127.0.0.1:9100" {
		t.Errorf("Metrics.Listen = %q", c.Metrics.Listen)
	}
	for _, ok := range []string{"", "127.0.0.1:9100", ":9100"} {
		c := valid(t)
		c.Metrics.Listen = ok
		if err := c.Validate(); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"localhost", "127.0.0.1:x", "127.0.0.1:", "127.0.0.1:70000", "127.0.0.1:0", ":0"} {
		c := valid(t)
		c.Metrics.Listen = bad
		want := "metrics.listen must be host:port, got \"" + bad + "\""
		if err := c.Validate(); err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want %q", bad, err, want)
		}
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
