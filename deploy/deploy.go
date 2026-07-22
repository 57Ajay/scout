package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

const scoutServiceTemplate = `[Unit]
Description=Scout — remote VM control plane for AI agents
Documentation=https://github.com/57ajay/scout
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.Group}}
Environment=HOME={{.Home}}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:{{.Home}}/.local/bin
ExecStart=/usr/local/bin/scout --config /etc/scout/scout.yaml
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
KillMode=mixed

[Install]
WantedBy=multi-user.target
`

func main() {
	log.SetFlags(0)
	log.Println("▶ Starting Scout Native Go Installer")

	// 1. Check Root Privileges
	if os.Geteuid() != 0 {
		log.Fatal("✗ Error: This installer must be run with root privileges (sudo).")
	}

	// 2. Load .env config
	env := loadEnv()
	port := env["SCOUT_PORT"]
	if port == "" {
		port = "7711"
	}
	bind := env["SCOUT_BIND"]
	if bind == "" {
		bind = "0.0.0.0"
	}
	domain := env["DOMAIN_NAME"]

	// 3. Resolve Target User
	runUser := env["SCOUT_USER"]
	if runUser == "" {
		runUser = os.Getenv("SUDO_USER")
	}
	if runUser == "" {
		runUser = os.Getenv("USER")
	}
	if runUser == "" || runUser == "root" {
		runUser = "ubuntu" // reasonable fallback on many cloud VMs
		log.Printf("⚠ Warning: Could not detect sudo user, falling back to: %s\n", runUser)
	}

	u, err := user.Lookup(runUser)
	if err != nil {
		log.Fatalf("✗ Error: Target user %q does not exist: %v\n", runUser, err)
	}

	log.Printf("  Target user : %s (%s)\n", u.Username, u.Gid)
	log.Printf("  Home        : %s\n", u.HomeDir)
	log.Printf("  Bind address: %s:%s\n", bind, port)

	// 4. Build Scout Binary
	log.Println("▶ Building Scout binary...")
	cmdBuild := exec.Command("go", "build", "-ldflags=-s -w", "-o", "/usr/local/bin/scout", ".")
	cmdBuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmdBuild.Stdout = os.Stdout
	cmdBuild.Stderr = os.Stderr
	if err := cmdBuild.Run(); err != nil {
		log.Fatalf("✗ Error: Failed to build Scout binary: %v\n", err)
	}
	if err := os.Chmod("/usr/local/bin/scout", 0755); err != nil {
		log.Fatalf("✗ Error: Failed to set binary permissions: %v\n", err)
	}
	log.Println("  Installed /usr/local/bin/scout successfully.")

	// 5. Setup Scout Configuration Directory and File
	if err := os.MkdirAll("/etc/scout", 0755); err != nil {
		log.Fatalf("✗ Error: Failed to create /etc/scout directory: %v\n", err)
	}

	scoutConfigPath := "/etc/scout/scout.yaml"
	var finalToken string

	if _, err := os.Stat(scoutConfigPath); os.IsNotExist(err) {
		log.Println("▶ Generating new Scout configuration...")
		// Run scout --gen-config to generate default YAML content
		cmdGen := exec.Command("/usr/local/bin/scout", "--gen-config")
		output, err := cmdGen.Output()
		if err != nil {
			log.Fatalf("✗ Error: Failed to generate default config: %v\n", err)
		}

		// Parse/generate auth token
		finalToken = env["AUTH_TOKEN"]
		if finalToken == "" {
			bytes := make([]byte, 24)
			if _, err := rand.Read(bytes); err != nil {
				log.Fatalf("✗ Error: Failed to generate random token: %v\n", err)
			}
			finalToken = hex.EncodeToString(bytes)
		}

		// Replace placeholders
		configContent := string(output)
		configContent = strings.ReplaceAll(configContent, "change-me-to-a-long-random-string", finalToken)
		
		// Let's replace port and bind (using regex-like or simple logic)
		lines := strings.Split(configContent, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "  port:") {
				lines[i] = fmt.Sprintf("  port: %q", port)
			} else if strings.HasPrefix(line, "  bind:") {
				lines[i] = fmt.Sprintf("  bind: %q", bind)
			}
		}
		configContent = strings.Join(lines, "\n")

		if err := os.WriteFile(scoutConfigPath, []byte(configContent), 0600); err != nil {
			log.Fatalf("✗ Error: Failed to write /etc/scout/scout.yaml: %v\n", err)
		}

		// Change ownership of config file to the running user
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		if err := os.Chown(scoutConfigPath, uid, gid); err != nil {
			log.Printf("⚠ Warning: Failed to set ownership on %s: %v\n", scoutConfigPath, err)
		}
		log.Println("  Configuration file /etc/scout/scout.yaml written.")
	} else {
		log.Println("  Keeping existing configuration file at /etc/scout/scout.yaml")
		// Parse token from existing config if possible
		finalToken = parseTokenFromConfig(scoutConfigPath)
	}

	// 6. Install systemd service
	log.Println("▶ Installing Scout systemd service...")
	serviceContent := strings.ReplaceAll(scoutServiceTemplate, "{{.User}}", u.Username)
	serviceContent = strings.ReplaceAll(serviceContent, "{{.Group}}", u.Username) // Or look up group name, but username usually matches group on Ubuntu/Debian
	serviceContent = strings.ReplaceAll(serviceContent, "{{.Home}}", u.HomeDir)

	servicePath := "/etc/systemd/system/scout.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		log.Fatalf("✗ Error: Failed to write systemd service file: %v\n", err)
	}

	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "enable", "scout")
	if err := runCommand("systemctl", "restart", "scout"); err != nil {
		log.Fatalf("✗ Error: Failed to restart scout service: %v\n", err)
	}
	log.Println("  Scout systemd service is active and enabled.")

	// 7. Setup Caddy (Reverse Proxy + TLS) if Domain is specified
	if domain != "" {
		log.Printf("▶ Configuring Caddy for domain: %s\n", domain)
		if !commandExists("caddy") {
			log.Println("  Caddy is not installed. Installing Caddy from official debian repository...")
			installCaddy()
		} else {
			log.Println("  Caddy is already installed.")
		}

		caddyfilePath := "/etc/caddy/Caddyfile"
		caddyfileContent := fmt.Sprintf(`%s {
	reverse_proxy 127.0.0.1:%s {
		flush_interval -1
	}

	header {
		X-Content-Type-Options "nosniff"
		X-Frame-Options         "DENY"
		Referrer-Policy         "no-referrer"
		Cache-Control           "no-store"
		-Server
	}
}
`, domain, port)

		if err := os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0644); err != nil {
			log.Fatalf("✗ Error: Failed to write Caddyfile: %v\n", err)
		}
		log.Println("  Caddyfile configured.")

		runCommand("systemctl", "enable", "caddy")
		if err := runCommand("systemctl", "reload", "caddy"); err != nil {
			log.Println("  Reload failed, attempting restart...")
			if err := runCommand("systemctl", "restart", "caddy"); err != nil {
				log.Printf("⚠ Warning: Failed to reload/restart Caddy: %v\n", err)
			}
		}
		log.Println("  Caddy reverse proxy configured and active.")
	} else {
		log.Println("ℹ Skipping Caddy setup: DOMAIN_NAME is not set in .env.")
	}

	// 8. Print Summary
	log.Println("\n✓ Scout installation completed successfully!")
	log.Printf("  Scout Service  : Running natively under systemd\n")
	log.Printf("  Local Port     : http://127.0.0.1:%s\n", port)
	if domain != "" {
		log.Printf("  Public HTTPS   : https://%s\n", domain)
		log.Printf("  Dashboard      : https://%s/?token=%s\n", domain, finalToken)
	} else {
		log.Printf("  Dashboard      : http://localhost:%s/?token=%s\n", port, finalToken)
	}
	if finalToken != "" {
		log.Println("\n  ┌────────────────────────────────────────────────────────────")
		log.Printf("  │ AUTH TOKEN: %s\n", finalToken)
		log.Println("  │ Share this token and URL with your AI agent.")
		log.Println("  └────────────────────────────────────────────────────────────\n")
	}
}

// Helper: loadEnv parses simple KEY=VALUE from .env file at repo root.
func loadEnv() map[string]string {
	env := make(map[string]string)
	file, err := os.Open(".env")
	if err != nil {
		// Try to read .env.example as fallback for defaults
		file, err = os.Open(".env.example")
		if err != nil {
			return env
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Strip optional quotes
			if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
				val = val[1 : len(val)-1]
			} else if strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'") {
				val = val[1 : len(val)-1]
			}
			env[key] = val
		}
	}
	return env
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runShellCommand(command string) error {
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func installCaddy() {
	log.Println("  [1/4] Installing debian dependencies...")
	if err := exec.Command("apt-get", "install", "-y", "debian-keyring", "debian-archive-keyring", "apt-transport-https", "curl").Run(); err != nil {
		log.Printf("⚠ Warning: failed apt-get install of keyring/curl dependencies: %v\n", err)
	}

	log.Println("  [2/4] Adding Caddy stable GPG key...")
	if err := runShellCommand("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"); err != nil {
		log.Printf("⚠ Warning: failed to add Caddy GPG key: %v\n", err)
	}

	log.Println("  [3/4] Adding Caddy apt source list...")
	if err := runShellCommand("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list"); err != nil {
		log.Printf("⚠ Warning: failed to add Caddy apt source list: %v\n", err)
	}

	log.Println("  [4/4] Updating packages and installing Caddy...")
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		log.Printf("⚠ Warning: apt-get update failed: %v\n", err)
	}
	if err := exec.Command("apt-get", "install", "-y", "caddy").Run(); err != nil {
		log.Fatalf("✗ Error: Failed to install Caddy: %v\n", err)
	}
}

// parseTokenFromConfig tries to extract the token from /etc/scout/scout.yaml
func parseTokenFromConfig(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inTokensSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "tokens:") {
			inTokensSection = true
			continue
		}
		if inTokensSection {
			if strings.HasPrefix(line, "-") {
				token := strings.TrimSpace(strings.TrimPrefix(line, "-"))
				// remove quotes
				token = strings.Trim(token, `"'`)
				return token
			}
			// If we hit any other key-value pair, tokens section is over
			if line != "" && !strings.HasPrefix(line, "-") && strings.Contains(line, ":") {
				break
			}
		}
	}
	return ""
}
