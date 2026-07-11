// Package server wires the policy engine, executor, filesystem, process
// manager, approval queue, and audit log behind an HTTP API plus a web
// dashboard.
package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/57ajay/scout/internal/approval"
	"github.com/57ajay/scout/internal/audit"
	"github.com/57ajay/scout/internal/config"
	"github.com/57ajay/scout/internal/executor"
	"github.com/57ajay/scout/internal/fsops"
	"github.com/57ajay/scout/internal/policy"
	"github.com/57ajay/scout/internal/procs"
)

// Server holds all runtime dependencies.
type Server struct {
	cfg       config.Config
	policy    *policy.Engine
	exec      *executor.Executor
	fs        *fsops.FS
	procs     *procs.Manager
	approvals *approval.Store
	audit     *audit.Log
	limiter   *rateLimiter
	tokens    [][]byte
	sessions  *sessionStore
	startedAt time.Time
}

// New constructs a Server from configuration.
func New(cfg config.Config) (*Server, error) {
	pol, err := policy.New(cfg.Policy)
	if err != nil {
		return nil, err
	}
	aud, err := audit.New(cfg.Audit.File, cfg.Audit.MaxMemory)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		policy:    pol,
		exec:      executor.New(cfg.Exec.Shell, cfg.Limits.MaxOutputBytes, cfg.Limits.Timeout.Std()),
		fs:        fsops.New(cfg.Filesystem.Roots),
		procs:     procs.New(cfg.Exec.Shell),
		audit:     aud,
		limiter:   newRateLimiter(cfg.Limits.RateLimit),
		sessions:  newSessionStore(),
		startedAt: time.Now(),
	}
	s.approvals = approval.New(cfg.Approvals.TTL.Std(), s.onNewApproval)
	for _, t := range cfg.Auth.Tokens {
		s.tokens = append(s.tokens, []byte(t))
	}
	return s, nil
}

// Handler builds the routed HTTP handler with middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public — no auth.
	mux.HandleFunc("GET /api/health", s.mwLog(s.handleHealth))

	// Protected API.
	protected := func(h http.HandlerFunc) http.HandlerFunc {
		return s.mwLog(s.mwRateLimit(s.mwIPAllow(s.mwAuth(h))))
	}

	mux.HandleFunc("GET /api/help", protected(s.handleHelp))
	mux.HandleFunc("GET /api/policy", protected(s.handlePolicy))
	mux.HandleFunc("GET /api/audit", protected(s.handleAudit))

	mux.HandleFunc("GET /api/exec", protected(s.handleExec))
	mux.HandleFunc("POST /api/exec", protected(s.handleExec))

	mux.HandleFunc("GET /api/fs/read", protected(s.handleFSRead))
	mux.HandleFunc("POST /api/fs/write", protected(s.handleFSWrite))
	mux.HandleFunc("POST /api/fs/edit", protected(s.handleFSEdit))
	mux.HandleFunc("GET /api/fs/list", protected(s.handleFSList))
	mux.HandleFunc("GET /api/fs/stat", protected(s.handleFSStat))

	mux.HandleFunc("POST /api/proc/start", protected(s.handleProcStart))
	mux.HandleFunc("GET /api/proc", protected(s.handleProcList))
	mux.HandleFunc("GET /api/proc/{id}", protected(s.handleProcGet))
	mux.HandleFunc("GET /api/proc/{id}/logs", protected(s.handleProcLogs))
	mux.HandleFunc("POST /api/proc/{id}/stop", protected(s.handleProcStop))
	mux.HandleFunc("POST /api/proc/{id}/remove", protected(s.handleProcRemove))

	mux.HandleFunc("GET /api/approvals", protected(s.handleApprovalsList))
	mux.HandleFunc("GET /api/approvals/{id}", protected(s.handleApprovalGet))
	mux.HandleFunc("POST /api/approvals/{id}/approve", protected(s.handleApprovalApprove))
	mux.HandleFunc("POST /api/approvals/{id}/deny", protected(s.handleApprovalDeny))

	// Dashboard (auth via ?token=).
	mux.HandleFunc("GET /", s.mwLog(s.mwIPAllow(s.handleDashboard)))

	return mux
}

// ---- shared helpers ----

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func queryBool(r *http.Request, key string) bool {
	v := r.URL.Query().Get(key)
	return v == "1" || v == "true" || v == "yes"
}

// resolveCwd resolves a requested working directory to an absolute path inside
// the configured roots, defaulting to the configured working dir.
func (s *Server) resolveCwd(requested string) (string, error) {
	if requested == "" {
		return s.cfg.Exec.WorkingDir, nil
	}
	return s.fs.Resolve(requested, s.cfg.Exec.WorkingDir)
}

func (s *Server) commandTimeout(raw string) time.Duration {
	if raw == "" {
		return s.cfg.Limits.Timeout.Std()
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	return s.cfg.Limits.Timeout.Std()
}

// onNewApproval fires when a command is parked for approval: it optionally
// posts to a notification webhook.
func (s *Server) onNewApproval(a *approval.Approval) {
	url := s.cfg.Approvals.NotifyWebhook
	if url == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"text":    "Scout: command needs approval — " + a.Reason,
		"id":      a.ID,
		"command": a.Command,
		"cwd":     a.Cwd,
		"kind":    a.Kind,
		"reason":  a.Reason,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// ---- minimal session store: persists cwd + env across calls ----

type sessionState struct {
	cwd string
	env map[string]string
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]*sessionState
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]*sessionState)}
}

func (s *sessionStore) get(id string) *sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[id]
	if !ok {
		st = &sessionState{env: map[string]string{}}
		s.m[id] = st
	}
	return st
}

func (s *sessionStore) update(id, cwd string, env map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[id]
	if !ok {
		st = &sessionState{env: map[string]string{}}
		s.m[id] = st
	}
	if cwd != "" {
		st.cwd = cwd
	}
	for k, v := range env {
		st.env[k] = v
	}
}
