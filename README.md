# Scout

**A remote VM control plane for AI agents.** Give an AI model one URL and a token, and it can drive your machine the way you would — read and write files, run any shell command, use git, Docker, and Kubernetes, start long-running processes, and stream large output back in real time. Dangerous commands are gated: Scout pauses them and asks a human to approve or deny, from a built-in web dashboard.

Scout used to be a read-only codebase explorer. It is now a full control plane. Everything runs through a single Go binary with **zero third-party dependencies** — build it once, drop it on a VM, and point any agent at it.

```
   AI agent  ──HTTP──▶  Scout  ──▶  bash · files · git · docker · kubectl
                          │
                          └─ dangerous command?  ─▶  human approves in dashboard
```

---

## Table of contents

- [Why Scout](#why-scout)
- [Security model at a glance](#security-model-at-a-glance)
- [Quick start (native)](#quick-start-native)
- [Quick start (Docker)](#quick-start-docker)
- [Core concepts](#core-concepts)
- [🤖 The agent playbook](#-the-agent-playbook) — *hand this to your AI*
- [API reference](#api-reference)
- [Policy & privacy](#policy--privacy)
- [Configuration reference](#configuration-reference)
- [Deployment](#deployment)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## Why Scout

An AI coding agent is only as useful as its reach. Copy-pasting files into a chat, or giving it read-only access, means it can *suggest* but not *do*. Scout closes that gap safely:

- **Full shell.** Commands run through `bash -lc`, so pipes, redirects, `&&`, subshells, environment variables, and every CLI you have installed just work.
- **Structured file ops.** Dedicated read / write / edit / list / stat endpoints avoid shell-quoting bugs and stream large files in chunks.
- **Live processes.** Start a dev server or a log tail in the background, stream its output, stop it later.
- **Streaming.** Long commands and big files stream back as newline-delimited JSON instead of arriving all at once.
- **Human-in-the-loop.** Default-allow, but destructive commands (`rm -rf`, `git push --force`, `kubectl delete`, `docker system prune`, `sudo`, …) are parked for a human to approve.
- **Configurable.** Flip to a paranoid "approve everything" mode, or a locked "allowlist only" mode, or add your own allow/ask/deny rules.

---

## Security model at a glance

Scout is powerful by design. Treat the token like a root password and read this section before exposing it.

| Layer | What it does |
|---|---|
| **Auth token** | Every endpoint except `/api/health` needs a bearer token (constant-time compared). |
| **Policy engine** | Default-allow, but a built-in denylist routes ~50 dangerous command patterns to human approval. Fully configurable. |
| **Protected paths** | Touching `.ssh`, `.env`, `*.pem`, `/etc/shadow`, etc. escalates to approval — even for reads. |
| **Filesystem roots** | Confine all file endpoints and working directories to specific directories. |
| **IP allowlist** | Optionally restrict callers to specific IPs / CIDRs. |
| **Audit log** | Every command, decision, and approval is recorded (JSONL + in-memory), tokens redacted. |
| **Rate limiting** | Sliding-window request cap. |
| **TLS** | First-class via the bundled Caddy reverse proxy, or Scout's own `tls_cert`/`tls_key`. |

> ⚠️ With `filesystem.roots: ["/"]` (the default) and default-allow policy, an approved agent can do anything you can. For sensitive machines: narrow `filesystem.roots`, set `allowed_ips`, use a strong token over TLS, and consider `policy.default: ask`.

---

## Quick start (native)

The most capable setup — Scout runs as *you*, with your real access to files, Docker, and Kubernetes.

```bash
git clone https://github.com/57ajay/scout && cd scout

# One-shot install: builds the binary, writes /etc/scout/scout.yaml with a
# strong random token, and starts a systemd service running as your user.
sudo ./deploy/install.sh
```

The installer prints your token. Verify:

```bash
curl http://127.0.0.1:7711/api/health
curl "http://127.0.0.1:7711/api/exec?token=YOUR_TOKEN&cmd=uname%20-a"
```

Open the dashboard at `http://YOUR_HOST:7711/?token=YOUR_TOKEN`, then hand the base URL + token to your AI.

**Manual build** (no systemd):

```bash
go build -o scout .
./scout --gen-config > scout.yaml    # edit it: set a token
./scout --config scout.yaml
```

Scout needs Go 1.23+ to build. It has no dependencies, so the build works offline.

---

## Quick start (Docker)

A containerized control plane with the Docker CLI and `kubectl` baked in.

```bash
git clone https://github.com/57ajay/scout && cd scout
cp .env.example .env
# edit .env: set AUTH_TOKEN (openssl rand -hex 24) and HOST_MOUNT=/path/to/projects

docker compose up -d --build
curl "http://localhost:7711/api/exec?token=YOUR_TOKEN&cmd=ls%20-la"
```

The compose file mounts your `HOST_MOUNT` read-write at `/work`, plus the host Docker socket and (optionally) your kubeconfig, so the agent can build images and drive your cluster. For TLS, set `DOMAIN_NAME` and run `docker compose --profile tls up -d`.

> The Docker option with the socket mounted is root-equivalent on the host. For a smaller blast radius, prefer the native install or comment out the `docker.sock` volume.

---

## Core concepts

### The policy decision

Every command gets one of three verdicts:

- **allow** — runs immediately.
- **ask** — parked for a human; the agent gets an `approval_id` to poll (or waits inline).
- **deny** — rejected outright.

The default is **allow**, with a built-in guard that turns destructive commands into **ask**. You can add rules, change the default, or turn the guard off. See [Policy & privacy](#policy--privacy).

### Approvals

When a command is parked, Scout returns HTTP `202` with an `approval_id`. A human resolves it in the dashboard (`/?token=…`) or via the API. On approval the command **executes server-side** and the result is attached to the approval record — so whether the agent waited inline or polls later, it gets the output. Pending approvals expire after `approvals.ttl`.

By default exec/fs calls **wait inline** (`wait=true`) up to `approvals.wait_timeout`, so a quick human approval returns the result in the same request. Pass `wait=false` to get the pending handle immediately and poll.

### Streaming

Add `stream=true` to `/api/exec` (or `/api/fs/read`) and Scout streams output as it is produced:

- `/api/exec?...&stream=true` → **newline-delimited JSON** events: one `meta`, many `stdout`/`stderr`, one `exit`.
- `/api/fs/read?...&stream=true` → the raw file, chunked.

Use this for commands that take a while or produce megabytes, and for reading large files without buffering them whole.

### Sessions

Pass a stable `session` string across exec calls to persist the working directory and environment variables between commands — a lightweight substitute for an interactive shell.

---

## 🤖 The agent playbook

**This section is written for the AI.** If you are an assistant that has been handed a Scout `BASE_URL` and `TOKEN`, this is how to use it to its fullest.

### Golden rules

1. **You are driving a real machine.** Files you write persist. Commands you run have effects. Prefer reversible steps and check your work (`git status`, `git diff`, re-read files after writing).
2. **Send the token on every call** as `?token=TOKEN` or header `Authorization: Bearer TOKEN`. Only `/api/health` is unauthenticated.
3. **Prefer the file endpoints over shell redirection** for reading and writing — they avoid quoting bugs and stream large content.
4. **When you get `202 pending_approval`, a human must approve.** Poll `GET /api/approvals/{id}` until `status != "pending"`. Don't retry the command — it's already queued.
5. **Stream anything big.** For a 5,000-line file or a slow build, use `stream=true` instead of pulling it all at once.

### Recipes

**Run a command**

```
GET  {BASE_URL}/api/exec?token=TOKEN&cmd=<url-encoded command>
POST {BASE_URL}/api/exec     {"command": "...", "cwd": "...", "env": {...}}
```

```bash
curl -G "$BASE/api/exec" --data-urlencode "token=$T" \
     --data-urlencode "cmd=cd myrepo && npm run build"
```

Response: `{ ok, stdout, stderr, exit_code, cwd, duration_ms }`. `ok` is true only when `exit_code == 0`.

**Read a file (whole, a line range, or streamed)**

```bash
# whole file
curl -G "$BASE/api/fs/read" --data-urlencode "token=$T" --data-urlencode "path=src/main.go"
# lines 100–200 only
curl -G "$BASE/api/fs/read" --data-urlencode "token=$T" --data-urlencode "path=src/main.go" \
     --data-urlencode "start=100" --data-urlencode "end=200"
# stream a huge file
curl -N -G "$BASE/api/fs/read" --data-urlencode "token=$T" --data-urlencode "path=big.log" \
     --data-urlencode "stream=true"
```

Binary files come back base64-encoded (`encoding: "base64"`).

**Write a file**

```bash
curl -X POST "$BASE/api/fs/write?token=$T" -H 'Content-Type: application/json' -d '{
  "path": "src/new.go",
  "content": "package main\n\nfunc main() {}\n",
  "mode": "overwrite",          // or "append", or "create" (fail if exists)
  "mkdirs": true
}'
```

For binary content set `"base64": true` and send base64 in `content`.

**Edit a file (surgical search/replace)**

```bash
curl -X POST "$BASE/api/fs/edit?token=$T" -H 'Content-Type: application/json' -d '{
  "path": "config.yaml",
  "edits": [
    { "old": "port: 8080", "new": "port: 9090" },
    { "old": "  debug: false", "new": "  debug: true", "replace_all": false }
  ]
}'
```

A non-`replace_all` edit requires its `old` string to be **unique** in the file (0 or >1 matches is an error) — include surrounding context to disambiguate, exactly like a careful human editor.

**Explore the filesystem**

```bash
curl -G "$BASE/api/fs/list" --data-urlencode "token=$T" --data-urlencode "path=." \
     --data-urlencode "recursive=true" --data-urlencode "depth=2"
curl -G "$BASE/api/fs/stat" --data-urlencode "token=$T" --data-urlencode "path=go.mod"
```

**Stream a long command**

```bash
curl -N -G "$BASE/api/exec" --data-urlencode "token=$T" --data-urlencode "stream=true" \
     --data-urlencode "cmd=go test ./... -v"
# → {"type":"meta",...}
#   {"type":"stdout","data":"=== RUN   TestFoo\n"}
#   ...
#   {"type":"exit","exit_code":0,"duration_ms":8123}
```

**Run something in the background** (dev servers, watchers, port-forwards)

```bash
# start
curl -X POST "$BASE/api/proc/start?token=$T" -H 'Content-Type: application/json' \
     -d '{"command":"npm run dev","cwd":"myapp"}'          # → {"process":{"id":"proc_…"}}
# tail its output (offset-based; pass the returned offset next time)
curl -G "$BASE/api/proc/proc_XXXX/logs" --data-urlencode "token=$T"
# or stream it live
curl -N "$BASE/api/proc/proc_XXXX/logs?token=$T&stream=true"
# stop it
curl -X POST "$BASE/api/proc/proc_XXXX/stop?token=$T"
```

**Handle an approval**

```bash
# A dangerous command returns 202:
curl -G "$BASE/api/exec" --data-urlencode "token=$T" --data-urlencode "cmd=rm -rf build" \
     --data-urlencode "wait=false"
# → {"status":"pending_approval","approval_id":"ap_123","reason":"recursive force delete (rm -rf)"}

# Poll until resolved:
curl "$BASE/api/approvals/ap_123?token=$T"
# → status: "pending" → keep polling
# → status: "completed" → read approval.result.stdout / exit_code
# → status: "denied"    → the human said no; do not retry, ask them why
```

If you'd rather block, omit `wait` (defaults to true): the call holds until the human decides or the wait window elapses, then returns the result or a pending handle.

**Keep a working directory across calls**

```bash
curl -G "$BASE/api/exec" --data-urlencode "token=$T" --data-urlencode "session=job1" \
     --data-urlencode "cwd=/home/me/project" --data-urlencode "cmd=pwd"
# later calls with session=job1 default to that cwd and remember env vars
```

### A ready-made instruction block

You can paste this into an agent's system prompt:

> You have a tool called **Scout** at `BASE_URL` with token `TOKEN`. It lets you control a Linux machine over HTTP. Send the token on every request. Use `GET/POST {BASE_URL}/api/exec` to run shell commands (`cmd` or JSON `command`), and the `/api/fs/*` endpoints to read, write, and edit files. Start long-running processes with `/api/proc/start` and stream big output or slow commands with `stream=true`. Most commands run immediately; destructive ones return `202 pending_approval` with an `approval_id` — a human must approve them, so poll `GET {BASE_URL}/api/approvals/{id}` until the status changes, then use the attached result. Read `GET {BASE_URL}/api/help` for the full API. Work carefully: your changes are real and persistent.

---

## API reference

All responses are JSON unless streaming. Auth is required on every endpoint except `/api/health`, via `?token=` or `Authorization: Bearer`.

### Meta

| Endpoint | Description |
|---|---|
| `GET /api/health` | Liveness. No auth. |
| `GET /api/help` | Machine-readable API guide (for agents). |
| `GET /api/policy` | Current policy: default action, rule counts, protected paths, roots, shell. |
| `GET /api/audit?n=100` | Recent audited operations. |

### Exec

`GET`/`POST /api/exec`

| Param | Where | Description |
|---|---|---|
| `cmd` / `command` | query / body | The shell command (required). |
| `cwd` | query / body | Working directory (absolute, or relative to `working_dir`). |
| `env` | body | `{ "KEY": "value" }` environment overrides. |
| `timeout` | query / body | e.g. `30s`, `5m`. Defaults to `limits.timeout`. |
| `stream` | query / body | `true` → NDJSON event stream. |
| `wait` | query / body | For dangerous commands: `true` (default) blocks for approval; `false` returns a pending handle. |
| `session` | query / body | Persist cwd + env across calls. |

Buffered result: `{ ok, stdout, stderr, exit_code, cwd, command, duration_ms, timed_out, truncated_stdout }`.
Stream events: `{type:"meta",cwd,command}`, `{type:"stdout"|"stderr",data}`, `{type:"exit",exit_code,duration_ms,timed_out}`.

### Filesystem

| Endpoint | Body / params | Description |
|---|---|---|
| `GET /api/fs/read` | `path`, `start`, `end`, `stream` | Read a file or line range; stream large ones. |
| `POST /api/fs/write` | `path`, `content`, `mode`, `base64`, `mkdirs` | Write a file. `mode`: `overwrite`\|`append`\|`create`. |
| `POST /api/fs/edit` | `path`, `edits:[{old,new,replace_all}]` | Search/replace edits. |
| `GET /api/fs/list` | `path`, `recursive`, `depth` | Directory listing (dirs first). |
| `GET /api/fs/stat` | `path` | File metadata. |

### Processes

| Endpoint | Description |
|---|---|
| `POST /api/proc/start` | Start a background process. Body: `command`, `cwd`, `env`. Returns `{process:{id,…}}`. |
| `GET /api/proc` | List processes. |
| `GET /api/proc/{id}` | One process snapshot. |
| `GET /api/proc/{id}/logs?since=N` | Output from offset `N`. Add `stream=true` for live output. |
| `POST /api/proc/{id}/stop` | Stop (SIGTERM, then SIGKILL) the process group. |
| `POST /api/proc/{id}/remove` | Forget a finished process. |

### Approvals

| Endpoint | Description |
|---|---|
| `GET /api/approvals?status=pending` | List approvals (`pending`\|`completed`\|`denied`\|`expired`\|`failed`). |
| `GET /api/approvals/{id}` | Poll one. On `completed`, `result` holds the command output. |
| `POST /api/approvals/{id}/approve?by=name` | Approve and run. |
| `POST /api/approvals/{id}/deny?by=name` | Deny. |

---

## Policy & privacy

Scout evaluates each command in order — **first match wins**:

1. **Your rules** (from config), top to bottom.
2. **Built-in dangerous guard** → `ask` (unless disabled).
3. **Protected-path touch** → `ask` (or `deny` if the default is `deny`).
4. **`policy.default`** → `allow` | `ask` | `deny`.

### What the built-in guard catches

Destructive/irreversible commands are routed to a human by default, including: `rm -rf`, `shred`, `find -delete`, `dd of=/dev/…`, `mkfs`, `fdisk`, `shutdown`/`reboot`, `systemctl stop/disable`, `sudo`, `chmod -R`, `userdel`/`passwd`, firewall flushes, `apt/yum/dnf remove`, `git push --force`, `git reset --hard`, `git clean -f`, `docker system prune`, `docker volume rm`, `kubectl delete`, `kubectl drain`, `helm uninstall`, `terraform destroy`, `curl … | bash`, fork bombs, and mass `kill`/`killall`.

Ordinary work is **not** interrupted: `git push`/`pull`/`commit`, `docker build`/`run`, `kubectl apply`/`get`, package installs, builds, tests, and file writes all run immediately.

### Shaping the policy

Three example postures, all set in `scout.yaml`:

```yaml
# 1) Default (capable): run everything, pause the dangerous stuff.
policy:
  default: allow
  use_builtin_dangerous: true

# 2) Paranoid: approve every command.
policy:
  default: ask

# 3) Locked allowlist: deny everything except explicit allows.
policy:
  default: deny
  rules:
    - { pattern: "^(ls|cat|rg|grep|git status|git log)\\b", action: allow, reason: "read-only" }
```

Add your own overrides (evaluated before the built-ins):

```yaml
policy:
  rules:
    - { pattern: "^rm -rf /tmp/scratch", action: allow, reason: "scratch is disposable" }
    - { pattern: "\\bterraform\\b",       action: ask,   reason: "review all infra changes" }
    - { pattern: "\\bdocker\\s+login\\b", action: deny,  reason: "no registry logins here" }
```

`pattern` is a Go regular expression matched against the whole command string.

### Protecting secrets

`policy.protected_paths` are globs (with `**`) that escalate any command or file operation touching them — reads included. Defaults cover `.ssh`, `.aws`, `.gnupg`, kubeconfig, `*.pem`, `*.key`, `id_rsa*`, `.env*`, `/etc/shadow`, and sudoers. Add your own.

### Sandboxing the filesystem

`filesystem.roots` confines every file endpoint and working directory. Set it to your project directory to keep the agent out of the rest of the machine:

```yaml
filesystem:
  roots: ["/home/me/projects"]
```

---

## Configuration reference

Config is optional — Scout runs with sensible defaults and zero config. Provide `scout.yaml` (auto-loaded from the working directory, or via `--config`), or use environment variables. Precedence: **defaults < file < env**.

Generate a fully-commented starter:

```bash
scout --gen-config > scout.yaml
```

| Section | Key | Default | Meaning |
|---|---|---|---|
| `server` | `bind` / `port` | `0.0.0.0` / `7711` | Listen address. |
| | `tls_cert` / `tls_key` | — | Enable built-in HTTPS. |
| `auth` | `tokens` | *(generated)* | Accepted bearer tokens. |
| | `allowed_ips` | — | Restrict callers (IPs/CIDRs). |
| `policy` | `default` | `allow` | Fallthrough: `allow`\|`ask`\|`deny`. |
| | `use_builtin_dangerous` | `true` | Enable the dangerous-command guard. |
| | `rules` | — | Your allow/ask/deny overrides. |
| | `protected_paths` | *(secrets)* | Globs that escalate to approval. |
| `filesystem` | `roots` | `["/"]` | Confine file ops + cwd. |
| `limits` | `timeout` | `5m` | Per-command timeout. |
| | `max_output_bytes` | `10MB` | Cap on buffered output. |
| | `rate_limit` | `240` | Requests/minute (`0` = off). |
| `approvals` | `wait_timeout` | `90s` | How long `wait=true` blocks. |
| | `ttl` | `1h` | Pending approval lifetime. |
| | `notify_webhook` | — | POSTed when a command needs approval. |
| `audit` | `file` | — | JSONL audit path (`""` = memory only). |
| `exec` | `shell` | `[/bin/bash,-lc]` | Command interpreter. |
| | `working_dir` | `$HOME` | Default cwd. |

**Environment overrides:** `SCOUT_TOKENS`, `SCOUT_PORT`, `SCOUT_BIND`, `SCOUT_POLICY_DEFAULT`, `SCOUT_ROOTS`, `SCOUT_WORKING_DIR`, `SCOUT_ALLOWED_IPS`, `SCOUT_AUDIT_FILE`, `SCOUT_NOTIFY_WEBHOOK`, `SCOUT_RATE_LIMIT`, `SCOUT_TIMEOUT`, `AUTH_TOKEN`.

### Notifications

Set `approvals.notify_webhook` (or `SCOUT_NOTIFY_WEBHOOK`) to get a JSON POST whenever a command is parked — wire it to Slack, Discord, or [ntfy](https://ntfy.sh):

```json
{ "text": "Scout: command needs approval — recursive force delete (rm -rf)",
  "id": "ap_…", "command": "rm -rf build", "reason": "…" }
```

---

## Deployment

### Native (systemd)

`sudo ./deploy/install.sh` builds the binary, writes `/etc/scout/scout.yaml` with a random token, and installs a service running as your user. Then:

```bash
systemctl status scout
journalctl -u scout -f
sudo nano /etc/scout/scout.yaml && sudo systemctl restart scout
```

Uninstall: `sudo systemctl disable --now scout && sudo rm /etc/systemd/system/scout.service /usr/local/bin/scout`.

### Docker

`docker compose up -d --build`. Configure via `.env` (token, `HOST_MOUNT`, kubeconfig, domain). The image ships bash, git, `jq`, `ripgrep`, the Docker CLI, and `kubectl`. Add TLS with `--profile tls`.

### TLS

Either terminate TLS at the bundled Caddy proxy (set `DOMAIN_NAME`, run the `tls` profile — the Caddyfile is already tuned to flush streaming responses), or give Scout `tls_cert`/`tls_key` directly. Never expose a plaintext token to the public internet.

---

## Architecture

```
scout/
├── main.go                     entrypoint, flags, graceful shutdown
├── internal/
│   ├── config/                 layered config (defaults < yaml < env)
│   ├── yamllite/               tiny dependency-free YAML parser
│   ├── policy/                 allow/ask/deny engine + dangerous denylist
│   ├── executor/               bash -lc runner (buffered + NDJSON streaming)
│   ├── fsops/                  read/write/edit/list/stat, root-confined
│   ├── procs/                  background process manager
│   ├── approval/               human-in-the-loop queue
│   ├── audit/                  JSONL + in-memory audit log
│   └── server/                 HTTP routing, middleware, handlers, dashboard
├── deploy/                     systemd unit + installer
├── Dockerfile · docker-compose.yaml · Caddyfile
└── scout.example.yaml
```

Commands run through a real shell (`bash -lc`), each in its own process group so timeouts and stops clean up the whole tree. Streaming uses HTTP chunked transfer with `Flusher`. No `Math.random`/global state that would surprise you; IDs use `crypto/rand`. Nothing leaves the box except optional approval webhooks.

---

## Troubleshooting

**`command denied by policy`** — a rule (or the `deny` default) blocked it. Check `GET /api/policy` and your `rules`.

**`202 pending_approval` and it never resolves** — no human approved it. Open the dashboard (`/?token=…`) or `POST /api/approvals/{id}/approve`. Pending approvals expire after `approvals.ttl`.

**`path is outside the configured roots`** — the path is outside `filesystem.roots`. Widen the roots or use a path inside them.

**`server has no auth tokens configured`** — set `auth.tokens`, `AUTH_TOKEN`, or let Scout generate one (printed at startup).

**Streaming arrives all at once** — a proxy is buffering. Behind Caddy, the bundled config sets `flush_interval -1`; behind nginx, disable `proxy_buffering`.

**Docker/kubectl "command not found" (container)** — they're in the image; make sure `/var/run/docker.sock` and your kubeconfig are mounted (see `docker-compose.yaml`).

**Build fails fetching modules** — it shouldn't; Scout has zero dependencies. Ensure you're on Go 1.23+ and building from the repo root.

---

## License

MIT — use it however you want.
