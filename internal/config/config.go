// Package config loads and validates Scout's configuration.
//
// Precedence (lowest to highest): built-in defaults < YAML file < environment
// variables. A zero-config launch is fully functional: Scout runs in
// default-allow mode with a built-in dangerous-command denylist.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/57ajay/scout/internal/yamllite"
)

// Duration is a time.Duration parsed from human strings like "300s".
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the top-level configuration object.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Auth       AuthConfig       `yaml:"auth"`
	Policy     PolicyConfig     `yaml:"policy"`
	Filesystem FilesystemConfig `yaml:"filesystem"`
	Limits     LimitsConfig     `yaml:"limits"`
	Approvals  ApprovalsConfig  `yaml:"approvals"`
	Audit      AuditConfig      `yaml:"audit"`
	Exec       ExecConfig       `yaml:"exec"`
}

type ServerConfig struct {
	Bind     string `yaml:"bind"`
	Port     string `yaml:"port"`
	TLSCert  string `yaml:"tls_cert"`
	TLSKey   string `yaml:"tls_key"`
	BasePath string `yaml:"base_path"` // e.g. "/scout" when behind a proxy sub-path
}

type AuthConfig struct {
	// Tokens are bearer tokens accepted by the API. If empty, one is generated
	// on startup and printed to logs.
	Tokens []string `yaml:"tokens"`
	// AllowedIPs, when non-empty, restricts access to these CIDRs / IPs.
	AllowedIPs []string `yaml:"allowed_ips"`
}

type RuleConfig struct {
	// Pattern is a Go regular expression matched against the full command
	// string (for exec) or resolved path (for fs operations).
	Pattern string `yaml:"pattern"`
	// Action is one of: allow, ask, deny.
	Action string `yaml:"action"`
	// Reason is shown to the human approver and in audit logs.
	Reason string `yaml:"reason"`
}

type PolicyConfig struct {
	// Default action for commands not matched by any rule: allow | ask | deny.
	Default string `yaml:"default"`
	// Rules are evaluated in order; first match wins. They override built-ins.
	Rules []RuleConfig `yaml:"rules"`
	// UseBuiltinDangerous enables the built-in dangerous-command denylist
	// (routes destructive commands to human approval). Default true.
	UseBuiltinDangerous *bool `yaml:"use_builtin_dangerous"`
	// ProtectedPaths are globs (** supported); touching them escalates to ask.
	ProtectedPaths []string `yaml:"protected_paths"`
}

type FilesystemConfig struct {
	// Roots confine all filesystem endpoints and cwd to these directories.
	// Empty or ["/"] means unrestricted (full VM access).
	Roots []string `yaml:"roots"`
}

type LimitsConfig struct {
	Timeout         Duration `yaml:"timeout"`           // per-command timeout
	MaxOutputBytes  int      `yaml:"max_output_bytes"`  // cap on buffered output
	RateLimit       int      `yaml:"rate_limit"`        // requests per minute (0 = off)
	MaxRequestBytes int64    `yaml:"max_request_bytes"` // cap on request body size
}

type ApprovalsConfig struct {
	WaitTimeout   Duration `yaml:"wait_timeout"`   // how long exec?wait=true blocks
	TTL           Duration `yaml:"ttl"`            // how long a pending approval lives
	NotifyWebhook string   `yaml:"notify_webhook"` // optional POST on new approval
}

type AuditConfig struct {
	File      string `yaml:"file"`       // JSONL audit log path ("" disables file)
	MaxMemory int    `yaml:"max_memory"` // in-memory entries for dashboard/API
}

type ExecConfig struct {
	// Shell is the argv used to run commands, e.g. ["/bin/bash","-lc"].
	Shell []string `yaml:"shell"`
	// WorkingDir is the default cwd when a request omits one.
	WorkingDir string `yaml:"working_dir"`
}

// Default returns a fully-populated config with safe, capable defaults.
func Default() Config {
	useBuiltin := true
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/"
	}
	return Config{
		Server: ServerConfig{
			Bind: "0.0.0.0",
			Port: "7711",
		},
		Auth: AuthConfig{},
		Policy: PolicyConfig{
			Default:             "allow",
			UseBuiltinDangerous: &useBuiltin,
			ProtectedPaths: []string{
				"**/.ssh/**",
				"**/.aws/**",
				"**/.gnupg/**",
				"**/.kube/config",
				"**/*.pem",
				"**/*.key",
				"**/id_rsa*",
				"**/.env",
				"**/.env.*",
				"/etc/shadow",
				"/etc/sudoers",
				"/etc/sudoers.d/**",
			},
		},
		Filesystem: FilesystemConfig{
			Roots: []string{"/"}, // unrestricted; narrow this to sandbox
		},
		Limits: LimitsConfig{
			Timeout:         Duration(5 * time.Minute),
			MaxOutputBytes:  10 * 1024 * 1024, // 10 MB
			RateLimit:       240,
			MaxRequestBytes: 128 * 1024 * 1024, // 128 MB
		},
		Approvals: ApprovalsConfig{
			WaitTimeout: Duration(90 * time.Second),
			TTL:         Duration(1 * time.Hour),
		},
		Audit: AuditConfig{
			File:      "", // disabled unless set
			MaxMemory: 500,
		},
		Exec: ExecConfig{
			Shell:      detectShell(),
			WorkingDir: home,
		},
	}
}

func detectShell() []string {
	for _, sh := range []string{"/bin/bash", "/usr/bin/bash"} {
		if _, err := os.Stat(sh); err == nil {
			return []string{sh, "-lc"}
		}
	}
	return []string{"/bin/sh", "-c"}
}

// Load reads defaults, overlays a YAML file (if path != "" and it exists),
// then applies environment overrides.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return cfg, fmt.Errorf("reading config %q: %w", path, err)
			}
			// Missing file is fine — defaults + env only.
		} else {
			tree, err := yamllite.Parse(data)
			if err != nil {
				return cfg, fmt.Errorf("parsing config %q: %w", path, err)
			}
			if err := mapTree(&cfg, tree); err != nil {
				return cfg, fmt.Errorf("config %q: %w", path, err)
			}
		}
	}

	applyEnv(&cfg)

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SCOUT_BIND"); v != "" {
		cfg.Server.Bind = v
	}
	if v := os.Getenv("PORT"); v != "" {
		cfg.Server.Port = v
	}
	if v := os.Getenv("SCOUT_PORT"); v != "" {
		cfg.Server.Port = v
	}
	if v := os.Getenv("AUTH_TOKEN"); v != "" {
		cfg.Auth.Tokens = append(cfg.Auth.Tokens, splitList(v)...)
	}
	if v := os.Getenv("SCOUT_TOKENS"); v != "" {
		cfg.Auth.Tokens = append(cfg.Auth.Tokens, splitList(v)...)
	}
	if v := os.Getenv("SCOUT_ALLOWED_IPS"); v != "" {
		cfg.Auth.AllowedIPs = splitList(v)
	}
	if v := os.Getenv("SCOUT_POLICY_DEFAULT"); v != "" {
		cfg.Policy.Default = v
	}
	if v := os.Getenv("WORKSPACE"); v != "" {
		cfg.Exec.WorkingDir = v
		cfg.Filesystem.Roots = []string{v}
	}
	if v := os.Getenv("SCOUT_WORKING_DIR"); v != "" {
		cfg.Exec.WorkingDir = v
	}
	if v := os.Getenv("SCOUT_ROOTS"); v != "" {
		cfg.Filesystem.Roots = splitList(v)
	}
	if v := os.Getenv("SCOUT_AUDIT_FILE"); v != "" {
		cfg.Audit.File = v
	}
	if v := os.Getenv("SCOUT_NOTIFY_WEBHOOK"); v != "" {
		cfg.Approvals.NotifyWebhook = v
	}
	if v := os.Getenv("SCOUT_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Limits.RateLimit = n
		}
	}
	if v := os.Getenv("SCOUT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Limits.Timeout = Duration(d)
		}
	}
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c *Config) validate() error {
	switch c.Policy.Default {
	case "allow", "ask", "deny":
	case "":
		c.Policy.Default = "allow"
	default:
		return fmt.Errorf("policy.default must be allow|ask|deny, got %q", c.Policy.Default)
	}
	for i, r := range c.Policy.Rules {
		switch r.Action {
		case "allow", "ask", "deny":
		default:
			return fmt.Errorf("policy.rules[%d].action must be allow|ask|deny, got %q", i, r.Action)
		}
	}
	if len(c.Exec.Shell) == 0 {
		c.Exec.Shell = detectShell()
	}
	if c.Limits.MaxOutputBytes <= 0 {
		c.Limits.MaxOutputBytes = 10 * 1024 * 1024
	}
	if c.Limits.Timeout.Std() <= 0 {
		c.Limits.Timeout = Duration(5 * time.Minute)
	}
	if c.Approvals.WaitTimeout.Std() <= 0 {
		c.Approvals.WaitTimeout = Duration(90 * time.Second)
	}
	if c.Approvals.TTL.Std() <= 0 {
		c.Approvals.TTL = Duration(time.Hour)
	}
	if c.Audit.MaxMemory <= 0 {
		c.Audit.MaxMemory = 500
	}
	return nil
}

// UseBuiltinDangerous reports whether the built-in denylist is enabled.
func (p PolicyConfig) UseBuiltin() bool {
	return p.UseBuiltinDangerous == nil || *p.UseBuiltinDangerous
}
