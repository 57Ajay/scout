package config

import (
	"fmt"
	"time"
)

// mapTree overlays a parsed YAML tree onto cfg. Only present keys are applied,
// so the file overrides defaults field by field.
func mapTree(cfg *Config, tree map[string]any) error {
	if srv, ok := subMap(tree, "server"); ok {
		applyString(srv, "bind", &cfg.Server.Bind)
		applyStringLoose(srv, "port", &cfg.Server.Port)
		applyString(srv, "tls_cert", &cfg.Server.TLSCert)
		applyString(srv, "tls_key", &cfg.Server.TLSKey)
		applyString(srv, "base_path", &cfg.Server.BasePath)
	}

	if auth, ok := subMap(tree, "auth"); ok {
		// A present-but-nil value (e.g. an all-commented block) is treated as
		// "not set" and keeps defaults. Use an explicit [] to clear a list.
		if v, ok := auth["tokens"]; ok && v != nil {
			cfg.Auth.Tokens = toStringList(v)
		}
		if v, ok := auth["allowed_ips"]; ok && v != nil {
			cfg.Auth.AllowedIPs = toStringList(v)
		}
	}

	if pol, ok := subMap(tree, "policy"); ok {
		applyString(pol, "default", &cfg.Policy.Default)
		applyBoolPtr(pol, "use_builtin_dangerous", &cfg.Policy.UseBuiltinDangerous)
		if v, ok := pol["protected_paths"]; ok && v != nil {
			cfg.Policy.ProtectedPaths = toStringList(v)
		}
		if v, ok := pol["rules"]; ok && v != nil {
			rules, err := toRules(v)
			if err != nil {
				return err
			}
			cfg.Policy.Rules = rules
		}
	}

	if fs, ok := subMap(tree, "filesystem"); ok {
		if v, ok := fs["roots"]; ok && v != nil {
			cfg.Filesystem.Roots = toStringList(v)
		}
	}

	if lim, ok := subMap(tree, "limits"); ok {
		if err := applyDuration(lim, "timeout", &cfg.Limits.Timeout); err != nil {
			return err
		}
		applyInt(lim, "max_output_bytes", &cfg.Limits.MaxOutputBytes)
		applyInt(lim, "rate_limit", &cfg.Limits.RateLimit)
		applyInt64(lim, "max_request_bytes", &cfg.Limits.MaxRequestBytes)
	}

	if ap, ok := subMap(tree, "approvals"); ok {
		if err := applyDuration(ap, "wait_timeout", &cfg.Approvals.WaitTimeout); err != nil {
			return err
		}
		if err := applyDuration(ap, "ttl", &cfg.Approvals.TTL); err != nil {
			return err
		}
		applyString(ap, "notify_webhook", &cfg.Approvals.NotifyWebhook)
	}

	if au, ok := subMap(tree, "audit"); ok {
		applyString(au, "file", &cfg.Audit.File)
		applyInt(au, "max_memory", &cfg.Audit.MaxMemory)
	}

	if ex, ok := subMap(tree, "exec"); ok {
		if v, ok := ex["shell"]; ok {
			if list := toStringList(v); len(list) > 0 {
				cfg.Exec.Shell = list
			}
		}
		applyString(ex, "working_dir", &cfg.Exec.WorkingDir)
	}

	return nil
}

func subMap(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false
	}
	sm, ok := v.(map[string]any)
	return sm, ok
}

func applyString(m map[string]any, key string, dst *string) {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			*dst = s
		}
	}
}

// applyStringLoose accepts a string or number (e.g. port: 7711).
func applyStringLoose(m map[string]any, key string, dst *string) {
	if v, ok := m[key]; ok && v != nil {
		*dst = toString(v)
	}
}

func applyBoolPtr(m map[string]any, key string, dst **bool) {
	if v, ok := m[key]; ok && v != nil {
		b := toBool(v)
		*dst = &b
	}
}

func applyInt(m map[string]any, key string, dst *int) {
	if v, ok := m[key]; ok && v != nil {
		if n, ok := toInt(v); ok {
			*dst = n
		}
	}
}

func applyInt64(m map[string]any, key string, dst *int64) {
	if v, ok := m[key]; ok && v != nil {
		if n, ok := toInt(v); ok {
			*dst = int64(n)
		}
	}
}

func applyDuration(m map[string]any, key string, dst *Duration) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	s := toString(v)
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%s: invalid duration %q", key, s)
	}
	*dst = Duration(d)
	return nil
}

func toRules(v any) ([]RuleConfig, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("policy.rules must be a list")
	}
	var out []RuleConfig
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("policy.rules[%d] must be a mapping", i)
		}
		out = append(out, RuleConfig{
			Pattern: toString(m["pattern"]),
			Action:  toString(m["action"]),
			Reason:  toString(m["reason"]),
		})
	}
	return out, nil
}

func toStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if e != nil {
				out = append(out, toString(e))
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case nil:
		return nil
	default:
		return []string{toString(v)}
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	default:
		return 0, false
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := t
		return s == "true" || s == "yes" || s == "on" || s == "1"
	default:
		return false
	}
}
