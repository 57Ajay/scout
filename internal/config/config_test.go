package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFullConfig(t *testing.T) {
	yaml := `
server:
  bind: "127.0.0.1"
  port: "9000"
auth:
  tokens:
    - tok-one
    - tok-two
  allowed_ips: ["10.0.0.0/8"]
policy:
  default: ask
  use_builtin_dangerous: false
  rules:
    - { pattern: "^ls", action: allow, reason: "listing is fine" }
    - pattern: "^git push"
      action: deny
      reason: "no push"
  protected_paths:
    - "**/.env"
filesystem:
  roots: ["/home/me/projects", "/tmp"]
limits:
  timeout: 2m
  max_output_bytes: 5000
  rate_limit: 100
  max_request_bytes: 1048576
approvals:
  wait_timeout: 30s
  ttl: 10m
  notify_webhook: "https://example.com/hook"
audit:
  file: /var/log/scout.log
  max_memory: 200
exec:
  shell: ["/bin/sh", "-c"]
  working_dir: /home/me/projects
`
	dir := t.TempDir()
	path := filepath.Join(dir, "scout.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Bind != "127.0.0.1" || cfg.Server.Port != "9000" {
		t.Errorf("server: %+v", cfg.Server)
	}
	if len(cfg.Auth.Tokens) != 2 || cfg.Auth.Tokens[0] != "tok-one" {
		t.Errorf("tokens: %+v", cfg.Auth.Tokens)
	}
	if len(cfg.Auth.AllowedIPs) != 1 || cfg.Auth.AllowedIPs[0] != "10.0.0.0/8" {
		t.Errorf("allowed_ips: %+v", cfg.Auth.AllowedIPs)
	}
	if cfg.Policy.Default != "ask" {
		t.Errorf("default: %q", cfg.Policy.Default)
	}
	if cfg.Policy.UseBuiltin() {
		t.Error("expected use_builtin_dangerous false")
	}
	if len(cfg.Policy.Rules) != 2 {
		t.Fatalf("rules: %+v", cfg.Policy.Rules)
	}
	if cfg.Policy.Rules[0].Pattern != "^ls" || cfg.Policy.Rules[0].Action != "allow" {
		t.Errorf("rule0: %+v", cfg.Policy.Rules[0])
	}
	if cfg.Policy.Rules[1].Pattern != "^git push" || cfg.Policy.Rules[1].Action != "deny" {
		t.Errorf("rule1: %+v", cfg.Policy.Rules[1])
	}
	if len(cfg.Filesystem.Roots) != 2 {
		t.Errorf("roots: %+v", cfg.Filesystem.Roots)
	}
	if cfg.Limits.Timeout.Std() != 2*time.Minute {
		t.Errorf("timeout: %v", cfg.Limits.Timeout.Std())
	}
	if cfg.Limits.MaxOutputBytes != 5000 || cfg.Limits.RateLimit != 100 {
		t.Errorf("limits: %+v", cfg.Limits)
	}
	if cfg.Limits.MaxRequestBytes != 1048576 {
		t.Errorf("max_request_bytes: %d", cfg.Limits.MaxRequestBytes)
	}
	if cfg.Approvals.WaitTimeout.Std() != 30*time.Second || cfg.Approvals.TTL.Std() != 10*time.Minute {
		t.Errorf("approvals: %+v", cfg.Approvals)
	}
	if cfg.Approvals.NotifyWebhook != "https://example.com/hook" {
		t.Errorf("webhook: %q", cfg.Approvals.NotifyWebhook)
	}
	if cfg.Audit.File != "/var/log/scout.log" || cfg.Audit.MaxMemory != 200 {
		t.Errorf("audit: %+v", cfg.Audit)
	}
	if len(cfg.Exec.Shell) != 2 || cfg.Exec.Shell[0] != "/bin/sh" {
		t.Errorf("shell: %+v", cfg.Exec.Shell)
	}
	if cfg.Exec.WorkingDir != "/home/me/projects" {
		t.Errorf("working_dir: %q", cfg.Exec.WorkingDir)
	}
}

func TestLoadDefaultsWhenMissing(t *testing.T) {
	cfg, err := Load("/nonexistent/scout.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Policy.Default != "allow" {
		t.Errorf("expected default allow, got %q", cfg.Policy.Default)
	}
	if !cfg.Policy.UseBuiltin() {
		t.Error("expected builtin dangerous enabled by default")
	}
	if cfg.Server.Port != "7711" {
		t.Errorf("expected default port, got %q", cfg.Server.Port)
	}
}

// Regression: a policy block whose rules are all commented out must not error
// and must keep the default protected paths.
func TestLoadConfigWithCommentedRules(t *testing.T) {
	yaml := `
policy:
  default: allow
  use_builtin_dangerous: true
  rules:
    # - { pattern: "x", action: allow }
  protected_paths:
    - "**/.ssh/**"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "scout.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Policy.Rules) != 0 {
		t.Errorf("expected no rules, got %+v", cfg.Policy.Rules)
	}
	if cfg.Policy.Default != "allow" || !cfg.Policy.UseBuiltin() {
		t.Errorf("policy: %+v", cfg.Policy)
	}
	if len(cfg.Policy.ProtectedPaths) != 1 {
		t.Errorf("protected paths: %+v", cfg.Policy.ProtectedPaths)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SCOUT_POLICY_DEFAULT", "deny")
	t.Setenv("SCOUT_PORT", "8888")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.Default != "deny" {
		t.Errorf("env default not applied: %q", cfg.Policy.Default)
	}
	if cfg.Server.Port != "8888" {
		t.Errorf("env port not applied: %q", cfg.Server.Port)
	}
}
