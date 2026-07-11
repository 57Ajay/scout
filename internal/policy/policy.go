// Package policy decides whether a command may run automatically, must be
// approved by a human, or is denied outright.
//
// Model: default-allow. Everything runs unless a rule says otherwise. A
// built-in denylist routes destructive/irreversible commands to human
// approval ("ask"). Users layer their own allow/ask/deny rules on top, and
// can flip the default to "ask" (paranoid) or "deny" (allowlist-only).
//
// Evaluation order (first match wins):
//  1. user rules, in declared order
//  2. built-in dangerous patterns  -> ask
//  3. protected-path touch          -> ask
//  4. policy.default                -> allow | ask | deny
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/57ajay/scout/internal/config"
)

type Action string

const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

// Decision is the outcome of evaluating a command or path.
type Decision struct {
	Action Action
	Reason string
	// Source identifies which rule fired: "user", "builtin", "protected-path",
	// or "default".
	Source string
}

type rule struct {
	re     *regexp.Regexp
	action Action
	reason string
	source string
}

// Engine evaluates commands against the configured policy.
type Engine struct {
	def       Action
	userRules []rule
	builtin   []rule
	protected []*regexp.Regexp
	protRaw   []string
}

// New builds an Engine from policy configuration.
func New(cfg config.PolicyConfig) (*Engine, error) {
	e := &Engine{def: Action(cfg.Default)}
	if e.def == "" {
		e.def = Allow
	}

	for i, rc := range cfg.Rules {
		re, err := regexp.Compile(rc.Pattern)
		if err != nil {
			return nil, fmt.Errorf("policy.rules[%d]: invalid pattern %q: %w", i, rc.Pattern, err)
		}
		reason := rc.Reason
		if reason == "" {
			reason = "matched user policy rule"
		}
		e.userRules = append(e.userRules, rule{re: re, action: Action(rc.Action), reason: reason, source: "user"})
	}

	if cfg.UseBuiltin() {
		for _, d := range builtinDangerous {
			re, err := regexp.Compile(d.pattern)
			if err != nil {
				return nil, fmt.Errorf("builtin pattern %q: %w", d.pattern, err)
			}
			e.builtin = append(e.builtin, rule{re: re, action: Ask, reason: d.reason, source: "builtin"})
		}
	}

	for _, g := range cfg.ProtectedPaths {
		re, err := regexp.Compile(globToRegex(g))
		if err != nil {
			return nil, fmt.Errorf("protected_path %q: %w", g, err)
		}
		e.protected = append(e.protected, re)
		e.protRaw = append(e.protRaw, g)
	}

	return e, nil
}

// Evaluate decides what to do with a shell command string.
func (e *Engine) Evaluate(command string) Decision {
	norm := normalize(command)

	// 1. user rules, first match wins
	for _, r := range e.userRules {
		if r.re.MatchString(norm) {
			return Decision{Action: r.action, Reason: r.reason, Source: r.source}
		}
	}

	// 2. built-in dangerous patterns
	for _, r := range e.builtin {
		if r.re.MatchString(norm) {
			return Decision{Action: Ask, Reason: r.reason, Source: r.source}
		}
	}

	// 3. protected-path touch anywhere in the command
	if reason, hit := e.touchesProtected(command); hit {
		// If the default is already stricter than ask, keep it stricter.
		if e.def == Deny {
			return Decision{Action: Deny, Reason: reason, Source: "protected-path"}
		}
		return Decision{Action: Ask, Reason: reason, Source: "protected-path"}
	}

	// 4. default
	return Decision{Action: e.def, Reason: "policy default (" + string(e.def) + ")", Source: "default"}
}

// EvaluatePath decides what to do with a filesystem operation against a path.
// op is a short label like "read", "write", "edit".
func (e *Engine) EvaluatePath(op, path string) Decision {
	// User rules can also match bare paths (handy for e.g. "/etc/.*").
	for _, r := range e.userRules {
		if r.re.MatchString(path) {
			return Decision{Action: r.action, Reason: r.reason, Source: r.source}
		}
	}
	for _, re := range e.protected {
		if re.MatchString(path) {
			reason := fmt.Sprintf("%s touches a protected path (%s)", op, path)
			if e.def == Deny {
				return Decision{Action: Deny, Reason: reason, Source: "protected-path"}
			}
			return Decision{Action: Ask, Reason: reason, Source: "protected-path"}
		}
	}
	if e.def == Deny {
		return Decision{Action: Deny, Reason: "policy default (deny)", Source: "default"}
	}
	// Reads/writes of non-protected paths are allowed even in ask-default mode,
	// so an agent can work with files without a prompt per file. Commands still
	// go through Evaluate(); this is only the fs endpoints.
	return Decision{Action: Allow, Reason: "path not protected", Source: "default"}
}

func (e *Engine) touchesProtected(command string) (string, bool) {
	if len(e.protected) == 0 {
		return "", false
	}
	for _, tok := range tokenizeLoose(command) {
		for i, re := range e.protected {
			if re.MatchString(tok) {
				return fmt.Sprintf("command references a protected path (%s ~ %s)", tok, e.protRaw[i]), true
			}
		}
	}
	return "", false
}

// ProtectedGlobs returns the configured protected path globs (for display).
func (e *Engine) ProtectedGlobs() []string { return append([]string(nil), e.protRaw...) }

// Default returns the fallthrough action (for display).
func (e *Engine) Default() Action { return e.def }

// RuleCount returns the number of user + builtin rules (for display).
func (e *Engine) RuleCount() (user, builtin int) { return len(e.userRules), len(e.builtin) }

func normalize(s string) string {
	s = strings.TrimSpace(s)
	// collapse runs of whitespace to single spaces so patterns are simpler
	return strings.Join(strings.Fields(s), " ")
}

// tokenizeLoose splits on whitespace and common shell separators so that
// protected-path scanning catches paths regardless of surrounding operators.
func tokenizeLoose(s string) []string {
	f := func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '|', ';', '&', '(', ')', '<', '>', '"', '\'', '=', ',':
			return true
		}
		return false
	}
	return strings.FieldsFunc(s, f)
}

// globToRegex converts a shell-style glob (supporting ** and *) to a regexp
// anchored to match a full path substring.
func globToRegex(glob string) string {
	var b strings.Builder
	b.WriteString("(?:^|/)?") // allow matching relative or absolute forms
	i := 0
	for i < len(glob) {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				// ** matches across path separators
				b.WriteString(".*")
				i += 2
				// swallow a following slash so "**/" behaves naturally
				if i < len(glob) && glob[i] == '/' {
					b.WriteString("/?")
					i++
				}
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
			i++
		case '[':
			// pass character classes through
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	b.WriteString("$")
	return b.String()
}

// dangerous is a built-in pattern that requires human approval.
type dangerous struct {
	pattern string
	reason  string
}

// builtinDangerous is the default denylist. These do not block — they route to
// a human, who decides. Tuned so ordinary agent work (git push/pull, docker
// build/run, kubectl apply, writing files) flows without prompts, while
// destructive or irreversible actions pause for a human.
var builtinDangerous = []dangerous{
	// ---- catastrophic filesystem deletion ----
	{`\brm\b[^|;&]*\s-[a-zA-Z]*r[a-zA-Z]*f|\brm\b[^|;&]*\s-[a-zA-Z]*f[a-zA-Z]*r`, "recursive force delete (rm -rf)"},
	{`\brm\b[^|;&]*\s-[a-zA-Z]*f[a-zA-Z]*\s+/(\s|$|\*)`, "force delete at filesystem root"},
	{`\bshred\b`, "shred securely erases files"},
	{`\bfind\b[^|]*-delete\b`, "find -delete removes files"},
	{`\bfind\b[^|]*-exec\b[^|]*\brm\b`, "find -exec rm removes files"},
	{`\btruncate\b\s+-s\s*0`, "truncate empties a file"},
	{`>\s*/dev/sd[a-z]`, "writing directly to a block device"},

	// ---- disk / partition / filesystem ----
	{`\bdd\b[^|]*\bof=/dev/`, "dd writing to a device wipes data"},
	{`\bmkfs(\.\w+)?\b`, "mkfs formats a filesystem"},
	{`\bfdisk\b|\bparted\b|\bgdisk\b|\bsgdisk\b`, "partition table manipulation"},
	{`\bwipefs\b|\bblkdiscard\b`, "wiping filesystem signatures"},
	{`\bmkswap\b|\bswapoff\b`, "swap manipulation"},

	// ---- system power / init ----
	{`\b(shutdown|reboot|halt|poweroff)\b`, "system power control"},
	{`\binit\s+[06]\b|\btelinit\s+[06]\b`, "changing runlevel (halt/reboot)"},
	{`\bsystemctl\s+(stop|disable|mask)\b`, "stopping/disabling a system service"},
	{`\bservice\s+\S+\s+stop\b`, "stopping a system service"},

	// ---- users / permissions / privilege ----
	{`\bsudo\b`, "privilege escalation (sudo)"},
	{`\bsu\s`, "switching users (su)"},
	{`\bchmod\b[^|]*\s-R\b|\bchown\b[^|]*\s-R\b`, "recursive permission/ownership change"},
	{`\bchmod\b[^|]*\s0*00?0\b`, "removing all permissions (chmod 000)"},
	{`\b(passwd|useradd|userdel|usermod|groupadd|groupdel)\b`, "user/group account change"},
	{`\bvisudo\b|/etc/sudoers`, "editing sudoers"},

	// ---- firewall / network destructive ----
	{`\biptables\b[^|]*\s-F\b|\biptables\b[^|]*\s--flush\b`, "flushing firewall rules"},
	{`\bnft\b\s+flush\b`, "flushing nftables ruleset"},
	{`\bufw\s+(disable|reset)\b`, "disabling/resetting the firewall"},
	{`\bip\s+link\s+set\s+\S+\s+down\b`, "bringing a network interface down"},

	// ---- package removal / system-wide changes ----
	{`\bapt(-get)?\s+(remove|purge|autoremove)\b`, "removing system packages"},
	{`\b(yum|dnf)\s+(remove|erase)\b`, "removing system packages"},
	{`\bpacman\s+-R`, "removing system packages"},
	{`\bapk\s+del\b`, "removing system packages"},
	{`\bbrew\s+uninstall\b`, "removing packages"},
	{`\bnpm\s+(uninstall|rm)\s+-g\b`, "removing global npm packages"},

	// ---- git destructive / history-rewriting ----
	{`\bgit\s+push\b[^|]*(--force\b|--force-with-lease\b|\s-f\b)`, "force push rewrites remote history"},
	{`\bgit\s+push\b[^|]*--delete\b|\bgit\s+push\b[^|]*\s:\S`, "deleting a remote branch/ref"},
	{`\bgit\s+reset\s+--hard\b`, "git reset --hard discards local work"},
	{`\bgit\s+clean\b[^|]*\s-[a-zA-Z]*f`, "git clean deletes untracked files"},
	{`\bgit\s+branch\s+-D\b`, "force-deleting a git branch"},
	{`\bgit\s+filter-branch\b|\bgit\s+filter-repo\b`, "rewriting git history"},

	// ---- docker destructive ----
	{`\bdocker\s+system\s+prune\b`, "docker prune deletes unused data"},
	{`\bdocker\s+(volume\s+(rm|prune)|image\s+prune)\b`, "removing docker volumes/images"},
	{`\bdocker\s+rm\b[^|]*\s-f|\bdocker\s+rmi\b[^|]*\s-f`, "force-removing containers/images"},
	{`\bdocker\s+(compose\s+)?down\b[^|]*(-v|--volumes)`, "compose down -v deletes volumes"},

	// ---- kubernetes destructive ----
	{`\bkubectl\s+delete\b`, "kubectl delete removes cluster resources"},
	{`\bkubectl\s+drain\b`, "draining a node evicts pods"},
	{`\bkubectl\s+cordon\b`, "cordoning a node"},
	{`\b(helm)\s+(uninstall|delete)\b`, "helm uninstall removes a release"},

	// ---- terraform / infra ----
	{`\bterraform\s+destroy\b`, "terraform destroy tears down infrastructure"},
	{`\bterraform\s+apply\b[^|]*-auto-approve\b`, "unattended terraform apply"},

	// ---- remote-code execution via pipe to shell ----
	{`\b(curl|wget)\b[^|]*\|[^|]*\b(sudo\s+)?(ba)?sh\b`, "piping a downloaded script straight into a shell"},

	// ---- fork bomb ----
	{`:\(\)\s*\{\s*:\s*\|\s*:`, "fork bomb"},

	// ---- mass process kill ----
	{`\bkill\b[^|]*\s-9\s+-1\b|\bkill\b\s+-1\b`, "killing all processes"},
	{`\bkillall\b|\bpkill\b\s+-9`, "mass process termination"},
}
