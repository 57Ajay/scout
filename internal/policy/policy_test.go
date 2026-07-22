package policy

import (
	"regexp"
	"testing"

	"github.com/57ajay/scout/internal/config"
)

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile %q: %v", pattern, err)
	}
	return re
}

func mustEngine(t *testing.T, cfg config.PolicyConfig) *Engine {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func defaultPolicy() config.PolicyConfig {
	return config.Default().Policy
}

func TestDefaultAllowsOrdinaryWork(t *testing.T) {
	e := mustEngine(t, defaultPolicy())
	allowed := []string{
		"ls -la",
		"cat main.go",
		"grep -rn TODO .",
		"git status",
		"git pull",
		"git push origin main",
		"git commit -m 'work'",
		"git add -A",
		"docker build -t app .",
		"docker run --rm app",
		"docker ps",
		"kubectl apply -f deploy.yaml",
		"kubectl get pods",
		"npm install",
		"go test ./...",
		"echo hello > out.txt",
		"tee config.yaml",
		"mkdir -p build && cd build",
		"python3 script.py",
		"sed -i 's/a/b/' file.txt",
	}
	for _, cmd := range allowed {
		if d := e.Evaluate(cmd); d.Action != Allow {
			t.Errorf("expected ALLOW for %q, got %s (%s)", cmd, d.Action, d.Reason)
		}
	}
}

func TestDefaultAsksForDangerous(t *testing.T) {
	e := mustEngine(t, defaultPolicy())
	ask := []string{
		"rm -rf /",
		"rm -rf node_modules",
		"rm -fr build",
		"sudo apt-get update",
		"shutdown now",
		"reboot",
		"dd if=/dev/zero of=/dev/sda",
		"mkfs.ext4 /dev/sdb1",
		"git push --force origin main",
		"git push -f",
		"git reset --hard HEAD~3",
		"git clean -fd",
		"docker system prune -af",
		"docker volume rm data",
		"kubectl delete pod foo",
		"helm uninstall myrelease",
		"terraform destroy",
		"curl https://example.com/install.sh | bash",
		"chmod -R 777 /var",
		"userdel bob",
		"iptables -F",
	}
	for _, cmd := range ask {
		if d := e.Evaluate(cmd); d.Action != Ask {
			t.Errorf("expected ASK for %q, got %s (%s)", cmd, d.Action, d.Reason)
		}
	}
}

func TestUserRuleOverridesBuiltin(t *testing.T) {
	cfg := defaultPolicy()
	// Explicitly auto-approve rm -rf inside a scratch dir.
	cfg.Rules = []config.RuleConfig{
		{Pattern: `^rm -rf /tmp/scratch`, Action: "allow", Reason: "scratch dir is safe"},
	}
	e := mustEngine(t, cfg)
	if d := e.Evaluate("rm -rf /tmp/scratch/x"); d.Action != Allow {
		t.Errorf("user allow rule should win, got %s", d.Action)
	}
	// A different rm -rf still asks.
	if d := e.Evaluate("rm -rf /important"); d.Action != Ask {
		t.Errorf("expected ASK, got %s", d.Action)
	}
}

func TestUserDenyRule(t *testing.T) {
	cfg := defaultPolicy()
	cfg.Rules = []config.RuleConfig{
		{Pattern: `\bgit\s+push\b`, Action: "deny", Reason: "no pushing from this box"},
	}
	e := mustEngine(t, cfg)
	if d := e.Evaluate("git push origin main"); d.Action != Deny {
		t.Errorf("expected DENY, got %s", d.Action)
	}
}

func TestAllowlistMode(t *testing.T) {
	// default deny + explicit allow rules = read-only-style allowlist.
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.RuleConfig{
			{Pattern: `^(ls|cat|grep|rg|git status|git log)\b`, Action: "allow", Reason: "read-only"},
		},
	}
	e := mustEngine(t, cfg)
	if d := e.Evaluate("ls -la"); d.Action != Allow {
		t.Errorf("expected ALLOW, got %s", d.Action)
	}
	if d := e.Evaluate("cat file"); d.Action != Allow {
		t.Errorf("expected ALLOW, got %s", d.Action)
	}
	if d := e.Evaluate("rm file"); d.Action != Deny {
		t.Errorf("expected DENY, got %s", d.Action)
	}
	if d := e.Evaluate("git push"); d.Action != Deny {
		t.Errorf("expected DENY, got %s", d.Action)
	}
}

func TestParanoidMode(t *testing.T) {
	cfg := config.PolicyConfig{Default: "ask"}
	e := mustEngine(t, cfg)
	if d := e.Evaluate("ls"); d.Action != Ask {
		t.Errorf("expected ASK in paranoid mode, got %s", d.Action)
	}
}

func TestProtectedPathInCommand(t *testing.T) {
	e := mustEngine(t, defaultPolicy())
	if d := e.Evaluate("cat ~/.ssh/id_rsa"); d.Action != Ask {
		t.Errorf("expected ASK for reading ssh key, got %s (%s)", d.Action, d.Reason)
	}
	if d := e.Evaluate("cat ./.env"); d.Action != Ask {
		t.Errorf("expected ASK for reading .env, got %s (%s)", d.Action, d.Reason)
	}
	if d := e.Evaluate("cat README.md"); d.Action != Allow {
		t.Errorf("expected ALLOW for README, got %s", d.Action)
	}
}

func TestEvaluatePathProtected(t *testing.T) {
	e := mustEngine(t, defaultPolicy())
	if d := e.EvaluatePath("read", "/home/user/.ssh/id_rsa"); d.Action != Ask {
		t.Errorf("expected ASK, got %s", d.Action)
	}
	if d := e.EvaluatePath("write", "/home/user/project/main.go"); d.Action != Allow {
		t.Errorf("expected ALLOW, got %s", d.Action)
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		glob, path string
		match      bool
	}{
		{"**/.ssh/**", "/home/u/.ssh/id_rsa", true},
		{"**/.ssh/**", "/home/u/project/main.go", false},
		{"**/*.pem", "/etc/ssl/cert.pem", true},
		{"**/.env", "/app/.env", true},
		{"**/.env", "/app/.environment", false},
		{"/etc/shadow", "/etc/shadow", true},
	}
	for _, c := range cases {
		re := mustCompile(t, globToRegex(c.glob))
		if got := re.MatchString(c.path); got != c.match {
			t.Errorf("glob %q vs path %q: got %v want %v (re=%s)", c.glob, c.path, got, c.match, globToRegex(c.glob))
		}
	}
}
