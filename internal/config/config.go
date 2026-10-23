// Package config loads and validates Latch's configuration from a YAML file
// with LATCH_* environment overrides.
package config

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ExampleYAML is the annotated example configuration. latch init writes new
// config files from it; latch.example.yaml at the repository root is a copy.
//
//go:embed example.yaml
var ExampleYAML string

type BrandingConfig struct {
	Name         string
	Logo         string
	PrimaryColor string `yaml:"primary_color"`
	SupportText  string `yaml:"support_text"`
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // starttls | tls | none
}

type SessionsConfig struct {
	Idle     time.Duration
	Absolute time.Duration
}

type TokensConfig struct {
	Access                         time.Duration
	ID                             time.Duration
	Refresh                        time.Duration
	RefreshAbsolute                time.Duration `yaml:"refresh_absolute"`
	RequireOfflineAccessForRefresh bool          `yaml:"require_offline_access_for_refresh"`
}

type PasswordConfig struct {
	MinLength int `yaml:"min_length"`
}

type LogConfig struct {
	Level  string
	Format string
}

type Config struct {
	PublicURL      string   `yaml:"public_url"`
	Listen         string   `yaml:"listen"`
	DataDir        string   `yaml:"data_dir"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	EncryptionKey  string   `yaml:"encryption_key"`
	Branding       BrandingConfig
	SMTP           SMTPConfig
	Sessions       SessionsConfig
	Tokens         TokensConfig
	Password       PasswordConfig
	Log            LogConfig
}

func defaults() *Config {
	return &Config{
		Listen:   "0.0.0.0:8080",
		DataDir:  "./data",
		Branding: BrandingConfig{Name: "Latch", PrimaryColor: "#2c6e49"},
		SMTP:     SMTPConfig{Port: 587, TLS: "starttls"},
		Sessions: SessionsConfig{Idle: 336 * time.Hour, Absolute: 720 * time.Hour},
		Tokens: TokensConfig{
			Access:          time.Hour,
			ID:              time.Hour,
			Refresh:         720 * time.Hour,
			RefreshAbsolute: 2160 * time.Hour,
		},
		Password: PasswordConfig{MinLength: 10},
		Log:      LogConfig{Level: "info", Format: "json"},
	}
}

// durationPaths are the YAML key paths holding durations.
var durationPaths = [][]string{
	{"sessions", "idle"}, {"sessions", "absolute"},
	{"tokens", "access"}, {"tokens", "id"}, {"tokens", "refresh"}, {"tokens", "refresh_absolute"},
}

// ParseDuration is time.ParseDuration plus a "d" suffix meaning 24h
// (whole or fractional days, e.g. "30d"). Negative durations are refused.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		if n < 0 {
			return 0, fmt.Errorf("duration %q must not be negative", s)
		}
		ns := n * float64(24*time.Hour)
		if ns >= math.MaxInt64 {
			return 0, fmt.Errorf("duration %q is too long", s)
		}
		return time.Duration(ns), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", s)
	}
	return d, nil
}

// Load reads path (if non-empty) over the defaults, then applies LATCH_*
// overrides from env.
func Load(path string, env func(string) string) (*Config, error) {
	c := defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if doc.Kind != 0 {
			if err := normalizeDurations(&doc); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			if err := doc.Decode(c); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
		}
	}
	if err := applyEnv(c, env); err != nil {
		return nil, err
	}
	return c, nil
}

// normalizeDurations rewrites "Nd" scalars at the known duration paths into
// hour strings that yaml.v3 can decode into time.Duration.
func normalizeDurations(doc *yaml.Node) error {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	for _, p := range durationPaths {
		n := root
		for _, k := range p {
			n = mapValue(n, k)
			if n == nil {
				break
			}
		}
		if n == nil || n.Kind != yaml.ScalarNode {
			continue
		}
		d, err := ParseDuration(n.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", strings.Join(p, "."), err)
		}
		n.Tag, n.Value = "!!str", d.String()
	}
	return nil
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func applyEnv(c *Config, env func(string) string) error {
	str := func(key string, dst *string) {
		if v := env(key); v != "" {
			*dst = v
		}
	}
	var err error
	dur := func(key string, dst *time.Duration) {
		if v := env(key); v != "" && err == nil {
			d, e := ParseDuration(v)
			if e != nil {
				err = fmt.Errorf("%s: %w", key, e)
				return
			}
			*dst = d
		}
	}
	num := func(key string, dst *int) {
		if v := env(key); v != "" && err == nil {
			n, e := strconv.Atoi(v)
			if e != nil {
				err = fmt.Errorf("%s: invalid integer %q", key, v)
				return
			}
			*dst = n
		}
	}
	boolean := func(key string, dst *bool) {
		if v := env(key); v != "" && err == nil {
			b, e := strconv.ParseBool(v)
			if e != nil {
				err = fmt.Errorf("%s: invalid boolean %q", key, v)
				return
			}
			*dst = b
		}
	}

	str("LATCH_PUBLIC_URL", &c.PublicURL)
	str("LATCH_LISTEN", &c.Listen)
	str("LATCH_DATA_DIR", &c.DataDir)
	if v := env("LATCH_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.TrustedProxies = append(c.TrustedProxies, p)
			}
		}
	}
	str("LATCH_ENCRYPTION_KEY", &c.EncryptionKey)
	str("LATCH_BRANDING_NAME", &c.Branding.Name)
	str("LATCH_BRANDING_LOGO", &c.Branding.Logo)
	str("LATCH_BRANDING_PRIMARY_COLOR", &c.Branding.PrimaryColor)
	str("LATCH_BRANDING_SUPPORT_TEXT", &c.Branding.SupportText)
	str("LATCH_SMTP_HOST", &c.SMTP.Host)
	num("LATCH_SMTP_PORT", &c.SMTP.Port)
	str("LATCH_SMTP_USERNAME", &c.SMTP.Username)
	str("LATCH_SMTP_PASSWORD", &c.SMTP.Password)
	str("LATCH_SMTP_FROM", &c.SMTP.From)
	str("LATCH_SMTP_TLS", &c.SMTP.TLS)
	dur("LATCH_SESSIONS_IDLE", &c.Sessions.Idle)
	dur("LATCH_SESSIONS_ABSOLUTE", &c.Sessions.Absolute)
	dur("LATCH_TOKENS_ACCESS", &c.Tokens.Access)
	dur("LATCH_TOKENS_ID", &c.Tokens.ID)
	dur("LATCH_TOKENS_REFRESH", &c.Tokens.Refresh)
	dur("LATCH_TOKENS_REFRESH_ABSOLUTE", &c.Tokens.RefreshAbsolute)
	boolean("LATCH_TOKENS_REQUIRE_OFFLINE_ACCESS_FOR_REFRESH", &c.Tokens.RequireOfflineAccessForRefresh)
	num("LATCH_PASSWORD_MIN_LENGTH", &c.Password.MinLength)
	str("LATCH_LOG_LEVEL", &c.Log.Level)
	str("LATCH_LOG_FORMAT", &c.Log.Format)
	return err
}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Validate checks required keys and formats; errors name the offending key.
func (c *Config) Validate() error {
	u, err := url.Parse(c.PublicURL)
	switch {
	case c.PublicURL == "":
		return fmt.Errorf("public_url is required")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return fmt.Errorf("public_url must be an absolute http(s) URL, got %q", c.PublicURL)
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return fmt.Errorf("public_url must not have a path, query or fragment, got %q", c.PublicURL)
	}
	key, err := base64.StdEncoding.DecodeString(c.EncryptionKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("encryption_key must be standard base64 of exactly 32 bytes")
	}
	switch c.SMTP.TLS {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("smtp.tls must be starttls, tls or none, got %q", c.SMTP.TLS)
	}
	if !colorRE.MatchString(c.Branding.PrimaryColor) {
		return fmt.Errorf("branding.primary_color must be #rrggbb, got %q", c.Branding.PrimaryColor)
	}
	// The common-password list holds only passwords of 10 or more
	// characters; a lower minimum would let shorter common ones through.
	if c.Password.MinLength < 10 {
		return fmt.Errorf("password.min_length must be at least 10, got %d", c.Password.MinLength)
	}
	for _, d := range []struct {
		key string
		val time.Duration
	}{
		{"sessions.idle", c.Sessions.Idle},
		{"sessions.absolute", c.Sessions.Absolute},
		{"tokens.access", c.Tokens.Access},
		{"tokens.id", c.Tokens.ID},
		{"tokens.refresh", c.Tokens.Refresh},
		{"tokens.refresh_absolute", c.Tokens.RefreshAbsolute},
	} {
		if d.val <= 0 {
			return fmt.Errorf("%s must be more than 0, got %v", d.key, d.val)
		}
	}
	// A retired signing key verifies tokens for only 24 hours after it is
	// retired (oidc.RetiredKeyGrace), so no token may outlive that.
	if c.Tokens.Access > maxTokenLifetime {
		return fmt.Errorf("tokens.access must be at most 24h, got %v", c.Tokens.Access)
	}
	if c.Tokens.ID > maxTokenLifetime {
		return fmt.Errorf("tokens.id must be at most 24h, got %v", c.Tokens.ID)
	}
	if c.Tokens.RefreshAbsolute < c.Tokens.Refresh {
		return fmt.Errorf("tokens.refresh_absolute must be at least tokens.refresh (%v), got %v",
			c.Tokens.Refresh, c.Tokens.RefreshAbsolute)
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(p); err != nil {
			return fmt.Errorf("trusted_proxies entries must be CIDR ranges or IP addresses, got %q", p)
		}
	}
	return nil
}

// maxTokenLifetime caps tokens.access and tokens.id; it matches
// oidc.RetiredKeyGrace.
const maxTokenLifetime = 24 * time.Hour

// Issuer is PublicURL with any trailing slash stripped.
func (c *Config) Issuer() string { return strings.TrimSuffix(c.PublicURL, "/") }

func (c *Config) SecureCookies() bool { return strings.HasPrefix(c.PublicURL, "https://") }

func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "latch.db") }
