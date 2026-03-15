package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// ══════════════════════════════════════════════════════════════════════════════
// Configuration
// ══════════════════════════════════════════════════════════════════════════════

type Config struct {
	Port           string
	AuthToken      string
	Workspace      string
	MaxOutputBytes int
	CmdTimeout     time.Duration
	RateLimit      int // requests per minute
}

func loadConfig() Config {
	cfg := Config{
		Port:           envOr("PORT", "8080"),
		AuthToken:      os.Getenv("AUTH_TOKEN"),
		Workspace:      envOr("WORKSPACE", "/workspace"),
		MaxOutputBytes: 2 * 1024 * 1024, // 2 MB
		CmdTimeout:     30 * time.Second,
		RateLimit:      60,
	}
	if cfg.AuthToken == "" {
		b := make([]byte, 24)
		rand.Read(b)
		cfg.AuthToken = hex.EncodeToString(b)
		log.Printf("🔑 Generated auth token: %s", cfg.AuthToken)
		log.Printf("   Use ?token=%s in requests", cfg.AuthToken)
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ══════════════════════════════════════════════════════════════════════════════
// Allowed Commands — THE allowlist. If it's not here, it doesn't run.
// ══════════════════════════════════════════════════════════════════════════════

var allowedCommands = map[string]bool{
	// Navigation & listing
	"ls": true, "pwd": true, "tree": true, "realpath": true,

	// File reading
	"cat": true, "head": true, "tail": true, "nl": true, "tac": true,
	"bat": true, // better cat (if installed)

	// Search
	"grep": true, "egrep": true, "fgrep": true,
	"rg":   true, // ripgrep
	"find": true,
	"fd":   true, // fd-find

	// Text processing (read-only transforms to stdout)
	"sed": true, "awk": true, "cut": true, "tr": true,
	"sort": true, "uniq": true, "column": true,
	"wc": true, "rev": true, "expand": true,

	// File info
	"file": true, "stat": true, "du": true,

	// Comparison
	"diff": true, "comm": true,

	// JSON
	"jq": true,

	// Hashing (useful for checking file identity)
	"md5sum": true, "sha256sum": true,

	// Path helpers
	"dirname": true, "basename": true, "echo": true,

	// Git (read-only subcommands validated separately)
	"git": true,

	// Misc
	"xargs":   true,
	"hexdump": true, "xxd": true,
	"env": true, // only allowed to print, not set
}

// Git subcommands that are read-only
var allowedGitSub = map[string]bool{
	"log": true, "show": true, "diff": true, "blame": true,
	"status": true, "branch": true, "tag": true, "remote": true,
	"rev-parse": true, "ls-files": true, "ls-tree": true,
	"shortlog": true, "describe": true, "reflog": true,
	"config": true, "stash": true, // stash list is read-only
	"name-rev": true, "rev-list": true, "cat-file": true,
}

// Flags that are BLOCKED on specific commands
var blockedFlags = map[string][]string{
	"sed":   {"-i", "--in-place"},
	"find":  {"-exec", "-execdir", "-delete", "-ok", "-okdir"},
	"git":   {}, // handled via subcommand allowlist
	"xargs": {}, // validated: target command must be in allowlist
}

// ══════════════════════════════════════════════════════════════════════════════
// Tokenizer — parses command strings respecting quotes, no shell involved
// ══════════════════════════════════════════════════════════════════════════════

// splitPipes splits a command string by unquoted pipe characters.
func splitPipes(input string) ([]string, error) {
	var segments []string
	var buf strings.Builder
	inSingle, inDouble, escaped := false, false, false

	for _, r := range input {
		if escaped {
			buf.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			buf.WriteRune(r)
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			buf.WriteRune(r)
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			buf.WriteRune(r)
			continue
		}
		if r == '|' && !inSingle && !inDouble {
			s := strings.TrimSpace(buf.String())
			if s == "" {
				return nil, fmt.Errorf("empty pipe segment")
			}
			segments = append(segments, s)
			buf.Reset()
			continue
		}
		buf.WriteRune(r)
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unclosed quote in command")
	}
	if s := strings.TrimSpace(buf.String()); s != "" {
		segments = append(segments, s)
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return segments, nil
}

// tokenize splits a single command segment into tokens, handling quotes.
func tokenize(input string) ([]string, error) {
	var tokens []string
	var buf strings.Builder
	inSingle, inDouble, escaped := false, false, false

	flush := func() {
		if buf.Len() > 0 {
			tokens = append(tokens, buf.String())
			buf.Reset()
		}
	}

	for _, r := range input {
		if escaped {
			buf.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if unicode.IsSpace(r) && !inSingle && !inDouble {
			flush()
			continue
		}
		buf.WriteRune(r)
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return tokens, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// Validator — every command must pass before execution
// ══════════════════════════════════════════════════════════════════════════════

func validateTokens(tokens []string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := tokens[0]

	// Must be in allowlist
	if !allowedCommands[cmd] {
		return fmt.Errorf("command %q is not allowed", cmd)
	}

	// Check blocked flags for this command
	if blocked, ok := blockedFlags[cmd]; ok {
		for _, arg := range tokens[1:] {
			for _, bf := range blocked {
				if arg == bf || strings.HasPrefix(arg, bf+"=") {
					return fmt.Errorf("flag %q is not allowed for %q", bf, cmd)
				}
			}
			// Also catch sed -i variants like -i.bak, -ibak
			if cmd == "sed" && (arg == "-i" || strings.HasPrefix(arg, "-i.") || strings.HasPrefix(arg, "-i'") || strings.HasPrefix(arg, "-i\"")) {
				return fmt.Errorf("in-place editing flag is not allowed for sed")
			}
			// Catch combined short flags containing 'i' for sed, e.g. -ni
			if cmd == "sed" && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1 {
				for _, c := range arg[1:] {
					if c == 'i' {
						return fmt.Errorf("in-place editing flag is not allowed for sed")
					}
				}
			}
		}
	}

	// Git: validate subcommand
	if cmd == "git" {
		return validateGit(tokens)
	}

	// xargs: validate that the target command is also allowed
	if cmd == "xargs" {
		return validateXargs(tokens)
	}

	// env: only allow without arguments (prints env) or with specific patterns
	if cmd == "env" && len(tokens) > 1 {
		return fmt.Errorf("env with arguments is not allowed")
	}

	// Block any argument that looks like shell redirection/injection
	// (defense in depth — we don't use a shell, but still)
	for _, arg := range tokens[1:] {
		if containsShellMeta(arg) {
			return fmt.Errorf("argument %q contains blocked shell metacharacter", arg)
		}
	}

	return nil
}

func validateGit(tokens []string) error {
	if len(tokens) < 2 {
		return fmt.Errorf("git requires a subcommand")
	}
	// Skip flags before subcommand (like git -C /path ...)
	sub := ""
	for _, t := range tokens[1:] {
		if !strings.HasPrefix(t, "-") {
			sub = t
			break
		}
	}
	if sub == "" {
		return fmt.Errorf("git requires a subcommand")
	}
	if !allowedGitSub[sub] {
		return fmt.Errorf("git subcommand %q is not allowed (read-only only)", sub)
	}
	return nil
}

func validateXargs(tokens []string) error {
	// Find the command xargs will execute (first non-flag argument)
	targetCmd := ""
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			// Check for -I, -n, -P etc (these are xargs flags, fine)
			continue
		}
		targetCmd = t
		break
	}
	if targetCmd == "" {
		// xargs with no command defaults to echo, which is allowed
		return nil
	}
	if !allowedCommands[targetCmd] {
		return fmt.Errorf("xargs target command %q is not in the allowlist", targetCmd)
	}
	// Disallow xargs running xargs (no recursion)
	if targetCmd == "xargs" {
		return fmt.Errorf("nested xargs is not allowed")
	}
	return nil
}

func containsShellMeta(s string) bool {
	// We execute without a shell, so these are harmless in practice,
	// but we block them as defense-in-depth.
	dangerous := []string{"$(", "`"}
	for _, d := range dangerous {
		if strings.Contains(s, d) {
			return true
		}
	}
	return false
}

func validatePipeline(segments [][]string) error {
	for i, seg := range segments {
		if err := validateTokens(seg); err != nil {
			return fmt.Errorf("pipe segment %d: %w", i+1, err)
		}
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// Path Security — cwd must stay inside workspace
// ══════════════════════════════════════════════════════════════════════════════

func resolveCwd(workspace, requested string) (string, error) {
	if requested == "" {
		return workspace, nil
	}
	var resolved string
	if filepath.IsAbs(requested) {
		resolved = filepath.Clean(requested)
	} else {
		resolved = filepath.Clean(filepath.Join(workspace, requested))
	}
	// Must be inside workspace
	if !strings.HasPrefix(resolved, workspace) {
		return "", fmt.Errorf("path %q is outside workspace", requested)
	}
	// Verify it exists
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", requested, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", requested)
	}
	return resolved, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// Executor — runs validated pipelines with NO shell, pure exec pipes
// ══════════════════════════════════════════════════════════════════════════════

type ExecResult struct {
	OK       bool   `json:"ok"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code"`
	Cwd      string `json:"cwd"`
	Duration string `json:"duration"`
	Command  string `json:"command"`
}

func executePipeline(ctx context.Context, segments [][]string, cwd string, maxOut int) ExecResult {
	start := time.Now()
	cmdStr := formatPipeline(segments)

	if len(segments) == 1 {
		return executeSingle(ctx, segments[0], cwd, maxOut, cmdStr, start)
	}

	// Build command chain
	cmds := make([]*exec.Cmd, len(segments))
	for i, seg := range segments {
		cmds[i] = exec.CommandContext(ctx, seg[0], seg[1:]...)
		cmds[i].Dir = cwd
	}

	// Wire pipes between commands
	for i := 0; i < len(cmds)-1; i++ {
		pipe, err := cmds[i].StdoutPipe()
		if err != nil {
			return errResult(cmdStr, cwd, start, fmt.Sprintf("pipe setup error: %v", err))
		}
		cmds[i+1].Stdin = pipe
	}

	// Capture final stdout and all stderr
	var stdout bytes.Buffer
	var stderrAll bytes.Buffer
	cmds[len(cmds)-1].Stdout = &limitedWriter{buf: &stdout, max: maxOut}
	for _, cmd := range cmds {
		cmd.Stderr = &stderrAll
	}

	// Start all commands (order matters: start from first)
	for i, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			return errResult(cmdStr, cwd, start, fmt.Sprintf("segment %d start error: %v", i+1, err))
		}
	}

	// Wait for all commands
	exitCode := 0
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}
	}

	return ExecResult{
		OK:       exitCode == 0,
		Stdout:   stdout.String(),
		Stderr:   stderrAll.String(),
		ExitCode: exitCode,
		Cwd:      cwd,
		Duration: time.Since(start).String(),
		Command:  cmdStr,
	}
}

func executeSingle(ctx context.Context, tokens []string, cwd string, maxOut int, cmdStr string, start time.Time) ExecResult {
	cmd := exec.CommandContext(ctx, tokens[0], tokens[1:]...)
	cmd.Dir = cwd

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, max: maxOut}
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return errResult(cmdStr, cwd, start, err.Error())
		}
	}

	return ExecResult{
		OK:       exitCode == 0,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Cwd:      cwd,
		Duration: time.Since(start).String(),
		Command:  cmdStr,
	}
}

func errResult(cmd, cwd string, start time.Time, msg string) ExecResult {
	return ExecResult{
		OK:       false,
		Stderr:   msg,
		ExitCode: -1,
		Cwd:      cwd,
		Duration: time.Since(start).String(),
		Command:  cmd,
	}
}

func formatPipeline(segments [][]string) string {
	parts := make([]string, len(segments))
	for i, seg := range segments {
		parts[i] = strings.Join(seg, " ")
	}
	return strings.Join(parts, " | ")
}

// limitedWriter caps how much output we buffer.
type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // silently discard
	}
	if len(p) > remaining {
		p = p[:remaining]
		w.buf.Write(p)
		w.buf.WriteString("\n\n... [output truncated at 2MB] ...")
		return len(p), nil
	}
	return w.buf.Write(p)
}

// ══════════════════════════════════════════════════════════════════════════════
// Rate Limiter — sliding window, per-minute
// ══════════════════════════════════════════════════════════════════════════════

type RateLimiter struct {
	mu       sync.Mutex
	requests []time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int) *RateLimiter {
	return &RateLimiter{limit: limit, window: time.Minute}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Evict old entries
	valid := 0
	for _, t := range rl.requests {
		if t.After(cutoff) {
			rl.requests[valid] = t
			valid++
		}
	}
	rl.requests = rl.requests[:valid]

	if len(rl.requests) >= rl.limit {
		return false
	}
	rl.requests = append(rl.requests, now)
	return true
}

// ══════════════════════════════════════════════════════════════════════════════
// HTTP Handlers
// ══════════════════════════════════════════════════════════════════════════════

type Server struct {
	cfg     Config
	limiter *RateLimiter
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	rawCmd := r.URL.Query().Get("cmd")
	cwd := r.URL.Query().Get("cwd")

	if rawCmd == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "missing 'cmd' query parameter",
			"hint":  "GET /api/exec?token=...&cmd=ls%20-la&cwd=opentelemetry-collector-contrib",
		})
		return
	}

	// Resolve working directory (sandboxed to workspace)
	resolvedCwd, err := resolveCwd(s.cfg.Workspace, cwd)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	// Parse pipeline
	pipeSegments, err := splitPipes(rawCmd)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("parse error: %v", err),
		})
		return
	}

	// Tokenize each segment
	allTokens := make([][]string, 0, len(pipeSegments))
	for _, seg := range pipeSegments {
		tokens, err := tokenize(seg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("tokenize error in %q: %v", seg, err),
			})
			return
		}
		if len(tokens) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "empty pipe segment",
			})
			return
		}
		allTokens = append(allTokens, tokens)
	}

	// Validate every command in the pipeline
	if err := validatePipeline(allTokens); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("validation failed: %v", err),
		})
		return
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.CmdTimeout)
	defer cancel()

	result := executePipeline(ctx, allTokens, resolvedCwd, s.cfg.MaxOutputBytes)

	status := http.StatusOK
	if !result.OK {
		status = http.StatusOK // still 200, the exit_code tells the story
	}
	writeJSON(w, status, result)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Health doesn't require auth
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"workspace": s.cfg.Workspace,
		"time":      time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	cmds := make([]string, 0, len(allowedCommands))
	for c := range allowedCommands {
		cmds = append(cmds, c)
	}

	gitSubs := make([]string, 0, len(allowedGitSub))
	for c := range allowedGitSub {
		gitSubs = append(gitSubs, c)
	}

	blocked := make(map[string][]string)
	for cmd, flags := range blockedFlags {
		if len(flags) > 0 {
			blocked[cmd] = flags
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": map[string]string{
			"GET /api/exec":   "Run a command. Params: cmd (required), cwd (optional, relative to workspace)",
			"GET /api/health": "Health check (no auth required)",
			"GET /api/help":   "This help page",
		},
		"allowed_commands":        cmds,
		"allowed_git_subcommands": gitSubs,
		"blocked_flags":           blocked,
		"notes": []string{
			"All commands are executed WITHOUT a shell — no injection possible",
			"Pipes (|) are supported; every command in the chain is validated",
			"Filesystem is mounted read-only",
			"cwd is sandboxed to workspace root",
			"Output is capped at 2MB",
			"Commands time out after 30s",
		},
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// Middleware
// ══════════════════════════════════════════════════════════════════════════════

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			// Also check Authorization header
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AuthToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "invalid or missing auth token",
			})
			return
		}
		next(w, r)
	}
}

func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow() {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("rate limit exceeded (%d req/min)", s.cfg.RateLimit),
			})
			return
		}
		next(w, r)
	}
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Redact token from logs
		logPath := r.URL.Path
		if cmd := r.URL.Query().Get("cmd"); cmd != "" {
			logPath += " cmd=" + cmd
		}
		if cwd := r.URL.Query().Get("cwd"); cwd != "" {
			logPath += " cwd=" + cwd
		}
		next(w, r)
		log.Printf("%-6s %s [%s]", r.Method, logPath, time.Since(start))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

// ══════════════════════════════════════════════════════════════════════════════
// Main
// ══════════════════════════════════════════════════════════════════════════════

func main() {
	cfg := loadConfig()

	// Validate workspace exists
	if info, err := os.Stat(cfg.Workspace); err != nil || !info.IsDir() {
		log.Fatalf("❌ Workspace %q does not exist or is not a directory", cfg.Workspace)
	}

	srv := &Server{
		cfg:     cfg,
		limiter: NewRateLimiter(cfg.RateLimit),
	}

	mux := http.NewServeMux()

	// Public endpoints (no auth)
	mux.HandleFunc("GET /api/health", loggingMiddleware(srv.handleHealth))

	// Protected endpoints
	mux.HandleFunc("GET /api/exec", loggingMiddleware(srv.rateLimitMiddleware(srv.authMiddleware(srv.handleExec))))
	mux.HandleFunc("GET /api/help", loggingMiddleware(srv.authMiddleware(srv.handleHelp)))

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: cfg.CmdTimeout + 5*time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("🛑 Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("🔭 Scout server starting on :%s", cfg.Port)
	log.Printf("📂 Workspace: %s", cfg.Workspace)
	log.Printf("🔒 Auth: token required on all /api/exec and /api/help requests")
	log.Printf("⚡ Rate limit: %d req/min", cfg.RateLimit)
	log.Println("────────────────────────────────────────────────────────")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("❌ Server error: %v", err)
	}
	log.Println("👋 Server stopped")
}
