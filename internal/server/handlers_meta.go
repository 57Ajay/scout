package server

import (
	"net/http"
	"time"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "scout",
		"uptime":  time.Since(s.startedAt).Truncate(time.Second).String(),
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	userRules, builtinRules := s.policy.RuleCount()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"default":         string(s.policy.Default()),
		"user_rules":      userRules,
		"builtin_rules":   builtinRules,
		"protected_paths": s.policy.ProtectedGlobs(),
		"roots":           s.cfg.Filesystem.Roots,
		"shell":           s.exec.Shell(),
		"working_dir":     s.cfg.Exec.WorkingDir,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	n := queryInt(r, "n", 100)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": s.audit.Recent(n)})
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, helpDoc)
}

// helpDoc is a machine-readable API guide returned by GET /api/help. It is
// written for an AI agent discovering Scout at runtime.
var helpDoc = map[string]any{
	"service": "scout",
	"summary": "Remote VM control plane for AI agents. Full shell, file ops, background processes, and streaming, with a human-approval gate for dangerous commands.",
	"auth":    "Send token as ?token=... or 'Authorization: Bearer ...' on every call except /api/health.",
	"endpoints": map[string]any{
		"GET  /api/health":                 "Liveness. No auth.",
		"GET  /api/help":                   "This document.",
		"GET  /api/policy":                 "Current policy: default action, rule counts, protected paths, roots, shell.",
		"GET  /api/audit?n=100":            "Recent audited operations.",
		"GET|POST /api/exec":               "Run a shell command. Params: cmd|command, cwd, env(POST), timeout, stream, wait, session.",
		"GET  /api/fs/read":                "Read a file. Params: path, start, end (1-indexed line range), stream.",
		"POST /api/fs/write":               "Write a file. Body: path, content, mode(overwrite|append|create), base64, mkdirs.",
		"POST /api/fs/edit":                "Search/replace edit. Body: path, edits:[{old,new,replace_all}].",
		"GET  /api/fs/list":                "List a directory. Params: path, recursive, depth.",
		"GET  /api/fs/stat":                "Stat a path. Params: path.",
		"POST /api/proc/start":             "Start a background process. Body: command, cwd, env.",
		"GET  /api/proc":                   "List background processes.",
		"GET  /api/proc/{id}":              "Get one process.",
		"GET  /api/proc/{id}/logs":         "Tail process output. Params: since (offset), stream.",
		"POST /api/proc/{id}/stop":         "Stop a process (SIGTERM then SIGKILL).",
		"POST /api/proc/{id}/remove":       "Forget a finished process.",
		"GET  /api/approvals?status=":      "List approvals (status: pending|completed|denied|expired|failed).",
		"GET  /api/approvals/{id}":         "Poll one approval. When status=completed, 'result' holds the command output.",
		"POST /api/approvals/{id}/approve": "Human approves a parked command (runs it).",
		"POST /api/approvals/{id}/deny":    "Human denies a parked command.",
	},
	"policy_model": map[string]any{
		"default_allow": "Most commands run immediately (git push/pull, docker, kubectl apply, writing files).",
		"ask":           "Destructive/irreversible commands return 202 with an approval_id and are parked for a human.",
		"deny":          "Commands matching a deny rule return 403.",
		"wait":          "exec/fs default to wait=true: they block up to the approval wait window, then return the result or a pending handle.",
		"streaming":     "Add stream=true to /api/exec or /api/fs/read for newline-delimited JSON / chunked output on long or large results.",
	},
	"agent_tips": []string{
		"Prefer /api/fs/read, /api/fs/write, /api/fs/edit over shell redirection — they avoid quoting bugs and stream large files.",
		"For a 5000-line file, read with start/end line ranges or stream=true instead of catting it whole.",
		"Long-running or big-output commands: add stream=true to /api/exec and read events as they arrive.",
		"Servers and watchers (npm run dev, kubectl port-forward): use /api/proc/start, then /api/proc/{id}/logs.",
		"If you get 202 pending_approval, poll GET /api/approvals/{id} until status != pending; result appears on completion.",
		"Use a stable 'session' value to keep cwd and env across exec calls.",
	},
}
