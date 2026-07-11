// Scout — a remote VM control plane for AI agents.
//
// Full shell, structured file operations, background processes, and streaming
// over HTTP, gated by a policy engine that routes dangerous commands to a human
// for approval.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/57ajay/scout/internal/config"
	"github.com/57ajay/scout/internal/server"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "2.0.0"

func main() {
	var (
		configPath  = flag.String("config", envOr("SCOUT_CONFIG", ""), "path to scout.yaml (optional)")
		showVersion = flag.Bool("version", false, "print version and exit")
		genConfig   = flag.Bool("gen-config", false, "print a sample scout.yaml and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("scout %s\n", version)
		return
	}
	if *genConfig {
		fmt.Print(sampleConfig)
		return
	}

	// Default config path: ./scout.yaml if present.
	if *configPath == "" {
		if _, err := os.Stat("scout.yaml"); err == nil {
			*configPath = "scout.yaml"
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("❌ config: %v", err)
	}

	// Ensure at least one auth token exists.
	if len(cfg.Auth.Tokens) == 0 {
		tok := genToken()
		cfg.Auth.Tokens = []string{tok}
		log.Printf("🔑 No token configured — generated one:")
		log.Printf("   %s", tok)
		log.Printf("   Pass it as ?token=%s or 'Authorization: Bearer %s'", tok, tok)
	}

	// Verify working dir exists.
	if info, err := os.Stat(cfg.Exec.WorkingDir); err != nil || !info.IsDir() {
		log.Fatalf("❌ working_dir %q does not exist or is not a directory", cfg.Exec.WorkingDir)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("❌ init: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              querySafeAddr(cfg.Server.Bind, cfg.Server.Port),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// No global write timeout: streaming and long-running commands need
		// open-ended responses. Per-command timeouts bound execution instead.
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("🛑 shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	banner(cfg)

	tls := cfg.Server.TLSCert != "" && cfg.Server.TLSKey != ""
	if tls {
		err = httpSrv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("❌ server: %v", err)
	}
	log.Println("👋 stopped")
}

func banner(cfg config.Config) {
	log.Printf("🔭 scout %s", version)
	log.Printf("🌐 listening on %s:%s", cfg.Server.Bind, cfg.Server.Port)
	log.Printf("📂 working dir: %s", cfg.Exec.WorkingDir)
	log.Printf("🐚 shell: %s", strings.Join(cfg.Exec.Shell, " "))
	log.Printf("🛡  policy default: %s (built-in dangerous guard: %v)", cfg.Policy.Default, cfg.Policy.UseBuiltin())
	if len(cfg.Filesystem.Roots) == 1 && cfg.Filesystem.Roots[0] == "/" {
		log.Printf("🗂  filesystem: UNRESTRICTED (whole VM). Narrow filesystem.roots to sandbox.")
	} else {
		log.Printf("🗂  filesystem roots: %s", strings.Join(cfg.Filesystem.Roots, ", "))
	}
	log.Printf("🧭 dashboard: http://%s:%s/?token=…", displayHost(cfg.Server.Bind), cfg.Server.Port)
	log.Println("────────────────────────────────────────────────────────")
}

func displayHost(bind string) string {
	if bind == "0.0.0.0" || bind == "" {
		return "YOUR_HOST"
	}
	return bind
}

func querySafeAddr(bind, port string) string {
	if bind == "" {
		bind = "0.0.0.0"
	}
	return bind + ":" + port
}

func genToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const sampleConfig = `# scout.yaml — Scout configuration (all fields optional; these are the defaults)
server:
  bind: "0.0.0.0"
  port: "7711"
  # tls_cert: /etc/scout/cert.pem
  # tls_key:  /etc/scout/key.pem

auth:
  # Bearer tokens accepted by the API. If empty, one is generated at startup.
  tokens:
    - "change-me-to-a-long-random-string"
  # Optional: restrict callers to these IPs/CIDRs.
  # allowed_ips: ["10.0.0.0/8", "203.0.113.7"]

policy:
  # Fallthrough action for commands no rule matches: allow | ask | deny
  default: allow
  # Keep the built-in dangerous-command guard (routes destructive ops to a human)
  use_builtin_dangerous: true
  # Your own overrides — first match wins, evaluated before the built-ins.
  rules:
    # - { pattern: "^git\\s+push",       action: allow, reason: "pushing is fine here" }
    # - { pattern: "\\bterraform\\b",    action: ask,   reason: "review infra changes" }
    # - { pattern: "\\bdocker\\s+login", action: deny,  reason: "no registry logins" }
  # Touching any of these escalates to human approval.
  protected_paths:
    - "**/.ssh/**"
    - "**/.aws/**"
    - "**/.env"
    - "**/*.pem"

filesystem:
  # Confine file endpoints + cwd. ["/"] means the whole VM. Narrow to sandbox.
  roots: ["/"]

limits:
  timeout: 5m
  max_output_bytes: 10485760   # 10 MB
  rate_limit: 240              # requests/minute (0 = unlimited)
  max_request_bytes: 134217728 # 128 MB

approvals:
  wait_timeout: 90s            # how long exec?wait=true blocks for a decision
  ttl: 1h                      # how long a pending approval lives
  # notify_webhook: "https://hooks.slack.com/services/…"  # POSTed on new approval

audit:
  # file: /var/log/scout/audit.log   # JSONL audit trail ("" disables file)
  max_memory: 500

exec:
  shell: ["/bin/bash", "-lc"]
  # working_dir: /home/you        # default cwd (defaults to $HOME)
`
