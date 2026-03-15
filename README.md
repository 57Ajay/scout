# Scout

**Secure, read-only codebase explorer for AI-assisted development.**

Scout gives Claude (or any LLM) live, read-only access to your local codebase through a simple HTTP API. Instead of copy-pasting files into chat or fighting GitHub's rate limits, you start Scout once, hand Claude the endpoint URL and auth token, and it can browse your project structure, read files, search code, check git history — all without being able to modify a single byte.

---

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Claude Integration Guide](#claude-integration-guide)
- [Command Reference](#command-reference)
- [Pipes](#pipes)
- [Security Model](#security-model)
- [Real-World Workflow Examples](#real-world-workflow-examples)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
git clone https://github.com/57ajay/scout && cd scout
cp .env.example .env
```

Edit `.env`:

```env
HOST_PROJECTS=~/Projects       # where your repos live on the host
SCOUT_PORT=7711                # port exposed on localhost
AUTH_TOKEN=                    # leave empty to auto-generate
DOMAIN_NAME=
```

Build and start:

```bash
docker compose up -d --build
```

Grab the auth token from logs (only needed if you left `AUTH_TOKEN` empty):

```bash
docker compose logs scout | grep "Generated auth token"
```

Verify it's running:

```bash
curl "http://localhost:7711/api/health"
# {"status":"ok","workspace":"/workspace","time":"..."}

curl "http://localhost:7711/api/exec?token=YOUR_TOKEN&cmd=ls"
# Lists all projects in your workspace
```

Done. Give Claude the base URL (`http://YOUR_IP:7711`) and token.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  Your Machine                                                │
│                                                              │
│  ~/Projects/                                                 │
│  ├── opentelemetry-collector-contrib/                        │
│  ├── opentelemetry-collector/                                │
│  └── scout/                                                  │
│       │                                                      │
│       │ mounted read-only (:ro)                              │
│       ▼                                                      │
│  ┌─────────────────────────── Docker ──────────────────────┐ │
│  │                                                         │ │
│  │  scout-server (:8080)                                   │ │
│  │  ├── Parses command string (no shell)                   │ │
│  │  ├── Validates every command against allowlist          │ │
│  │  ├── Validates every pipe segment independently         │ │
│  │  ├── Executes via os/exec (direct syscall, no sh -c)    │ │
│  │  └── Returns JSON result                                │ │
│  │       │                                                 │ │
│  │       │ internal docker network                         │ │
│  │       ▼                                                 │ │
│  │  scout-caddy (:80 → host :7711)                         │ │
│  │  └── Reverse proxy + security headers                   │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│       │                                                      │
│       │ http://localhost:7711                                │
│       ▼                                                      │
│  Claude (via web_fetch or curl)                              │
└──────────────────────────────────────────────────────────────┘
```

Key principle: **your filesystem is mounted read-only, the container itself is read-only, and every command is validated against a hardcoded allowlist before execution.** There is no shell involved at any point — commands are tokenized in Go and executed via direct syscalls.

---

## Configuration

All configuration is via environment variables in `.env` (or set directly in `docker-compose.yml`).

| Variable | Default | Description |
|---|---|---|
| `HOST_PROJECTS` | `~/Projects` | Path on your host machine to mount as the workspace. This is what Scout can see. |
| `SCOUT_PORT` | `7711` | Port exposed on the host (Caddy listens here). |
| `AUTH_TOKEN` | *(auto-generated)* | Bearer token for API access. If empty, a random 48-char hex token is generated on startup and printed to logs. |

Internal (set in `docker-compose.yml`, rarely need changing):

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Internal port the Go server listens on (inside Docker). |
| `WORKSPACE` | `/workspace` | Mount point inside the container. Must match the volume target. |

Hardcoded defaults in `main.go` (edit source to change):

| Setting | Value |
|---|---|
| Max output size | 2 MB |
| Command timeout | 30 seconds |
| Rate limit | 60 requests/minute |

---

## API Reference

### Base URL

```
http://YOUR_HOST:7711
```

All responses are JSON with `Content-Type: application/json`.

---

### `GET /api/health`

Health check. **No authentication required.**

```
GET /api/health
```

Response:
```json
{
  "status": "ok",
  "workspace": "/workspace",
  "time": "2026-03-15T12:00:00Z"
}
```

---

### `GET /api/exec`

Execute a read-only command. **Authentication required.**

#### Parameters

| Param | Required | Description |
|---|---|---|
| `token` | Yes | Auth token (can also be sent as `Authorization: Bearer <token>` header) |
| `cmd` | Yes | The command to execute (URL-encoded). Pipes (`\|`) are supported. |
| `cwd` | No | Working directory, **relative to the workspace root**. E.g., `opentelemetry-collector-contrib`. If omitted, defaults to workspace root. |

#### Example Request

```
GET /api/exec?token=abc123&cmd=ls%20-la&cwd=opentelemetry-collector-contrib
```

#### Success Response

```json
{
  "ok": true,
  "stdout": "total 1234\ndrwxr-xr-x  45 root root 4096 ...\n...",
  "stderr": "",
  "exit_code": 0,
  "cwd": "/workspace/opentelemetry-collector-contrib",
  "duration": "12.345ms",
  "command": "ls -la"
}
```

#### Error Response (validation failure)

```json
{
  "ok": false,
  "error": "validation failed: command \"rm\" is not allowed"
}
```

#### Error Response (command failed but was allowed)

```json
{
  "ok": false,
  "stdout": "",
  "stderr": "cat: nosuchfile.go: No such file or directory",
  "exit_code": 1,
  "cwd": "/workspace/opentelemetry-collector-contrib",
  "duration": "3.21ms",
  "command": "cat nosuchfile.go"
}
```

---

### `GET /api/help`

Returns the full list of allowed commands, git subcommands, blocked flags, and usage notes. **Authentication required.**

```
GET /api/help?token=abc123
```

---

## Claude Integration Guide

**This section is for Claude (the AI) — a reference on how to use Scout effectively via `web_fetch`.**

### Setup

When the user provides a Scout endpoint, Claude receives two things:

1. **Base URL** — e.g., `http://1.2.3.4:7711`
2. **Auth token** — e.g., `a1b2c3d4e5...`

Claude uses the `web_fetch` tool to make GET requests:

```
web_fetch: http://BASE_URL/api/exec?token=TOKEN&cmd=URL_ENCODED_COMMAND&cwd=RELATIVE_PATH
```

### How to URL-Encode Commands

Spaces become `%20`, pipes become `%20%7C%20`, quotes become `%27` (single) or `%22` (double).

Examples:
- `ls -la` → `ls%20-la`
- `cat main.go` → `cat%20main.go`
- `grep -rn 'func Coalesce' .` → `grep%20-rn%20%27func%20Coalesce%27%20.`
- `rg TODO | head -20` → `rg%20TODO%20%7C%20head%20-20`

### Step-by-Step: Exploring a New Issue

Here is the recommended workflow when a user asks Claude to work on an issue in a project:

**Step 1 — List available projects:**

```
GET /api/exec?token=TOKEN&cmd=ls
```

This lists all directories under `~/Projects` on the user's machine.

**Step 2 — Navigate into the project and understand structure:**

```
GET /api/exec?token=TOKEN&cmd=ls%20-la&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=tree%20-L%202%20-d&cwd=opentelemetry-collector-contrib/processor/transformprocessor
```

**Step 3 — Read specific files:**

```
GET /api/exec?token=TOKEN&cmd=cat%20config.go&cwd=opentelemetry-collector-contrib/processor/transformprocessor
```

For large files, use `head` first to check size:

```
GET /api/exec?token=TOKEN&cmd=wc%20-l%20config.go&cwd=opentelemetry-collector-contrib/processor/transformprocessor
```

Then read specific sections:

```
GET /api/exec?token=TOKEN&cmd=head%20-100%20config.go&cwd=...
GET /api/exec?token=TOKEN&cmd=sed%20-n%20'50,120p'%20config.go&cwd=...
```

**Step 4 — Search for patterns across the project:**

```
GET /api/exec?token=TOKEN&cmd=rg%20'func%20Coalesce'%20--type%20go&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=rg%20-l%20'transformprocessor'%20--type%20go&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=grep%20-rn%20'Dropped'%20.&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor
```

**Step 5 — Check git context:**

```
GET /api/exec?token=TOKEN&cmd=git%20log%20--oneline%20-20&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=git%20branch%20-a&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=git%20diff%20HEAD~3%20--%20processor/transformprocessor/&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=git%20blame%20config.go&cwd=opentelemetry-collector-contrib/processor/transformprocessor
```

**Step 6 — Understand dependencies and structure:**

```
GET /api/exec?token=TOKEN&cmd=cat%20go.mod%20%7C%20grep%20opentelemetry&cwd=opentelemetry-collector-contrib
GET /api/exec?token=TOKEN&cmd=find%20.%20-name%20'metadata.yaml'%20-path%20'*/transformprocessor/*'&cwd=opentelemetry-collector-contrib
```

### Response Parsing

Every response is JSON. The key fields are:

- **`ok`** (`bool`) — `true` if exit code was 0.
- **`stdout`** (`string`) — command output. This is what you're usually interested in.
- **`stderr`** (`string`) — error output, if any. Non-empty stderr doesn't always mean failure (e.g., `grep` with no matches returns exit code 1 but is not an error per se).
- **`exit_code`** (`int`) — process exit code. 0 = success.
- **`cwd`** (`string`) — the resolved absolute path the command ran in.
- **`command`** (`string`) — the full command string that was executed (useful for debugging).

### Tips for Claude

1. **Start broad, then narrow.** `tree -L 2 -d` before `cat` individual files.
2. **Use `rg` (ripgrep) for searching.** It's faster than `grep -r` and has better output. `rg 'pattern' --type go -l` to list files, `rg 'pattern' --type go -C 3` for context.
3. **Use `wc -l` before `cat` on unknown files.** If a file is 5000 lines, read it in chunks with `sed -n '1,100p'` or `head -n 100`.
4. **Use `fd` instead of `find` for simpler syntax.** `fd 'config\.go' processor/` finds all `config.go` files under `processor/`.
5. **Chain commands with pipes.** `rg -l 'TODO' --type go | head -10` or `cat go.mod | grep opentelemetry`.
6. **Use git context.** `git log --oneline -10 -- path/to/file` shows recent changes to a specific file. `git blame file.go` shows who changed each line and when.
7. **The `cwd` parameter is your friend.** Instead of long paths in every command, set `cwd` to the deepest relevant directory.
8. **Output is capped at 2 MB.** If you're reading huge generated files, use `head`/`tail`/`sed -n` to grab what you need.
9. **Don't guess file contents.** Always verify by reading the actual file. One `web_fetch` call is cheaper than a wrong solution.
10. **Use `jq` for JSON files.** `cat config.json | jq '.exporters'` to extract specific sections.

---

## Command Reference

### Navigation & Listing

| Command | Description | Example |
|---|---|---|
| `ls` | List directory contents | `ls -la`, `ls -lh processor/` |
| `pwd` | Print working directory | `pwd` |
| `tree` | Show directory tree | `tree -L 3 -d`, `tree -I node_modules` |
| `realpath` | Resolve file path | `realpath ../collector` |

### File Reading

| Command | Description | Example |
|---|---|---|
| `cat` | Print entire file | `cat main.go` |
| `head` | Print first N lines | `head -50 main.go` |
| `tail` | Print last N lines | `tail -30 main.go` |
| `nl` | Print with line numbers | `nl -ba main.go` |
| `tac` | Print file in reverse | `tac changelog.md` |
| `bat` | Pretty print with syntax highlight | `bat config.go` |
| `sed -n` | Print line range | `sed -n '100,200p' parser.go` |

### Search

| Command | Description | Example |
|---|---|---|
| `grep` | Search text in files | `grep -rn 'func Parse' .` |
| `egrep` | Extended grep (regex) | `egrep -rn 'func (Parse\|Eval)' .` |
| `rg` | Ripgrep (fast search) | `rg 'Coalesce' --type go -C 3` |
| `rg -l` | List files with matches | `rg -l 'TODO' --type go` |
| `find` | Find files by name/path | `find . -name '*.go' -path '*/ottl/*'` |
| `fd` | Modern find alternative | `fd 'config\.go' processor/` |

### Text Processing

| Command | Description | Example |
|---|---|---|
| `sed` | Stream editor (read-only) | `sed -n '50,100p' file.go` |
| `awk` | Pattern processing | `awk '/^func / {print NR": "$0}' main.go` |
| `cut` | Extract columns | `cut -d: -f1 /etc/passwd` |
| `tr` | Translate characters | `cat file \| tr '[:upper:]' '[:lower:]'` |
| `sort` | Sort lines | `sort -u`, `sort -t, -k2 -n` |
| `uniq` | Deduplicate lines | `sort file \| uniq -c \| sort -rn` |
| `wc` | Count lines/words/chars | `wc -l *.go` |
| `column` | Format into columns | `cat data.tsv \| column -t` |
| `jq` | Process JSON | `cat config.json \| jq '.receivers'` |

### File Information

| Command | Description | Example |
|---|---|---|
| `file` | Identify file type | `file binary.exe` |
| `stat` | File metadata | `stat main.go` |
| `du` | Disk usage | `du -sh */`, `du -sh --max-depth=1` |
| `md5sum` | MD5 hash | `md5sum config.go` |
| `sha256sum` | SHA256 hash | `sha256sum config.go` |

### Comparison

| Command | Description | Example |
|---|---|---|
| `diff` | Compare files | `diff old.go new.go`, `diff -u a.go b.go` |
| `comm` | Compare sorted files | `comm -12 list1.txt list2.txt` |

### Git (Read-Only)

| Subcommand | Description | Example |
|---|---|---|
| `git log` | Commit history | `git log --oneline -20`, `git log --oneline -- path/to/file` |
| `git show` | Show commit details | `git show HEAD`, `git show abc123:path/file.go` |
| `git diff` | Diff between refs | `git diff HEAD~5`, `git diff main..feature-branch -- dir/` |
| `git blame` | Line-by-line authorship | `git blame config.go` |
| `git status` | Working tree status | `git status --short` |
| `git branch` | List branches | `git branch -a`, `git branch --contains abc123` |
| `git tag` | List tags | `git tag -l 'v0.100*'` |
| `git ls-files` | List tracked files | `git ls-files '*.go'` |
| `git ls-tree` | List tree contents | `git ls-tree -r --name-only HEAD processor/` |
| `git remote` | List remotes | `git remote -v` |
| `git rev-parse` | Parse git refs | `git rev-parse HEAD` |
| `git shortlog` | Summarize commits | `git shortlog -sn --no-merges` |
| `git reflog` | Ref history | `git reflog -20` |
| `git cat-file` | Inspect objects | `git cat-file -t HEAD` |
| `git config` | Read config | `git config --list` |
| `git describe` | Describe relative to tags | `git describe --tags` |
| `git rev-list` | List commit objects | `git rev-list --count HEAD` |
| `git stash` | List stashes | `git stash list` |

### Utility

| Command | Description | Example |
|---|---|---|
| `echo` | Print text | `echo hello` |
| `dirname` | Extract directory path | `dirname /path/to/file.go` |
| `basename` | Extract filename | `basename /path/to/file.go .go` |
| `xargs` | Build commands from stdin | `rg -l 'TODO' \| xargs wc -l` |
| `hexdump` | Hex dump | `hexdump -C binary.dat \| head -20` |
| `xxd` | Hex dump / reverse | `xxd -l 64 binary.dat` |
| `env` | Print environment (no args) | `env` |

---

## Pipes

Pipes are fully supported. Every command in the pipeline is independently validated against the allowlist.

```
rg -l 'OTTL' --type go | head -10
cat go.mod | grep opentelemetry | sort
find . -name '*.go' -path '*/ottl/*' | xargs wc -l | sort -rn | head -20
git log --oneline -50 | grep -i 'coalesce'
awk '/^func / {print $0}' parser.go | sort | nl
```

**What's blocked in pipes:**

Every segment is validated independently. If even one command in the chain is not in the allowlist, the entire pipeline is rejected.

```
cat file.go | rm -rf /           → BLOCKED: "rm" is not allowed
ls -la | bash                    → BLOCKED: "bash" is not allowed
cat file.go | sed -i 's/a/b/' x → BLOCKED: sed -i is blocked
find . -exec rm {} \;            → BLOCKED: -exec flag is blocked for find
```

---

## Security Model

Scout implements defense-in-depth. Even if one layer fails, others prevent damage.

### Layer 1: Read-Only Filesystem Mount

Your `~/Projects` directory is mounted with Docker's `:ro` flag. The Linux kernel enforces this — no process inside the container can write to it regardless of what commands run.

### Layer 2: Read-Only Container

The `read_only: true` setting in docker-compose makes the entire container filesystem immutable. Combined with a `tmpfs` at `/tmp` for commands that need scratch space, this means even container-escape scenarios can't write anywhere persistent.

### Layer 3: Command Allowlist

A hardcoded Go `map[string]bool` of ~40 commands. If a command isn't in this map, it is rejected before any execution attempt. There is no way to add commands at runtime — you must edit `main.go` and rebuild.

### Layer 4: Every Pipe Segment Validated

The command `cat file.go | ls` validates **both** `cat` and `ls` independently. You can't sneak an unauthorized command into any position of a pipeline.

### Layer 5: Dangerous Flag Blocking

Even for allowed commands, certain flags are blocked:
- `sed -i` / `sed --in-place` (writes to files)
- `find -exec` / `find -execdir` / `find -delete` (arbitrary execution or deletion)
- `git` write subcommands (`push`, `commit`, `checkout`, `reset`, `merge`, etc.)

### Layer 6: xargs Target Validation

If `xargs` is used, the target command it would execute is also validated against the allowlist. `rg -l pattern | xargs cat` works (both `rg` and `cat` are allowed), but `rg -l pattern | xargs rm` fails (`rm` is not allowed).

### Layer 7: No Shell Execution

Commands are **never** passed through `sh -c` or `bash -c`. The Go server tokenizes the command string itself (handling quotes, escapes, pipes) and calls `os/exec.Command(binary, args...)` directly. This means shell injection is structurally impossible — characters like `;`, `&&`, `||`, `$()`, backticks have no special meaning.

### Layer 8: Shell Metacharacter Blocking (Defense-in-Depth)

Even though no shell is used, arguments containing `$(` or backticks are rejected as an extra precaution.

### Layer 9: Path Sandboxing

The `cwd` parameter is resolved and validated to ensure it stays within the workspace root. Paths like `../../etc/` are rejected. Symlinks that point outside the workspace will resolve to their target, which is then checked against the workspace boundary.

### Layer 10: Authentication

Every request to `/api/exec` and `/api/help` requires a valid auth token (via `?token=` query parameter or `Authorization: Bearer` header). Token comparison uses constant-time comparison to prevent timing attacks.

### Layer 11: Rate Limiting

60 requests per minute, sliding window. Prevents runaway usage.

### Layer 12: Output & Timeout Caps

- Output is capped at 2 MB (excess is silently truncated with a marker).
- Commands time out after 30 seconds.

### Layer 13: Non-Root User

The scout binary runs as user `scout` (UID 1000) inside the container, not as root.

### Layer 14: No Privilege Escalation

Docker's `no-new-privileges` security option prevents any process from gaining additional privileges via setuid/setgid binaries.

---

## Real-World Workflow Examples

### Investigating an OTTL Issue

User says: *"I need to add a `Coalesce` converter to OTTL in opentelemetry-collector-contrib."*

Claude's Scout calls:

```
# 1. Find the OTTL package
cmd=fd%20'ottl'%20-t%20d%20--max-depth%203&cwd=opentelemetry-collector-contrib

# 2. Understand OTTL structure
cmd=tree%20-L%202&cwd=opentelemetry-collector-contrib/pkg/ottl

# 3. See existing converters for the pattern to follow
cmd=ls%20-la&cwd=opentelemetry-collector-contrib/pkg/ottl/ottlfuncs

# 4. Read an existing converter as a template
cmd=cat%20func_concat.go&cwd=opentelemetry-collector-contrib/pkg/ottl/ottlfuncs

# 5. Check how converters are registered
cmd=rg%20'createFactory'%20--type%20go%20-C%205&cwd=opentelemetry-collector-contrib/pkg/ottl/ottlfuncs

# 6. Check the functions registry
cmd=cat%20functions.go&cwd=opentelemetry-collector-contrib/pkg/ottl/ottlfuncs

# 7. Read the grammar to understand the type system
cmd=cat%20grammar.go&cwd=opentelemetry-collector-contrib/pkg/ottl

# 8. Check test patterns
cmd=fd%20'func_concat_test'%20--type%20f&cwd=opentelemetry-collector-contrib/pkg/ottl
cmd=cat%20func_concat_test.go&cwd=opentelemetry-collector-contrib/pkg/ottl/ottlfuncs

# 9. Check recent branch work
cmd=git%20branch%20-a%20%7C%20grep%20coalesce&cwd=opentelemetry-collector-contrib

# 10. Check .chloggen format
cmd=ls%20.chloggen&cwd=opentelemetry-collector-contrib
cmd=cat%20.chloggen/.tmpl.yaml&cwd=opentelemetry-collector-contrib
```

### Debugging a Processor Bug

User says: *"The tailsamplingprocessor is logging a warning for dropped decisions."*

```
# 1. Find the processor
cmd=tree%20-L%201&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor

# 2. Search for the warning message
cmd=rg%20'dropped'%20--type%20go%20-i%20-C%205&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor

# 3. Read the sampling decision logic
cmd=rg%20'NotSampled'%20--type%20go%20-C%2010&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor

# 4. Read the policy types
cmd=rg%20'Dropped'%20--type%20go&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor

# 5. Check test file for patterns
cmd=rg%20-l%20'TestSampling'%20--type%20go&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor
cmd=cat%20processor_test.go&cwd=opentelemetry-collector-contrib/processor/tailsamplingprocessor

# 6. Check recent git history for this file
cmd=git%20log%20--oneline%20-10%20--%20processor/tailsamplingprocessor/&cwd=opentelemetry-collector-contrib
```

### Reviewing a PR Before Submitting

```
# 1. See what branch we're on and uncommitted changes
cmd=git%20status%20--short&cwd=opentelemetry-collector-contrib
cmd=git%20branch%20--show-current&cwd=opentelemetry-collector-contrib

# 2. See the full diff of what's being submitted
cmd=git%20diff%20main&cwd=opentelemetry-collector-contrib

# 3. Check for lint issues (just read what files changed)
cmd=git%20diff%20main%20--name-only&cwd=opentelemetry-collector-contrib

# 4. Read each changed file
cmd=cat%20pkg/ottl/ottlfuncs/func_coalesce.go&cwd=opentelemetry-collector-contrib
cmd=cat%20pkg/ottl/ottlfuncs/func_coalesce_test.go&cwd=opentelemetry-collector-contrib

# 5. Make sure the changelog entry is correct
cmd=fd%20'coalesce'%20.chloggen/&cwd=opentelemetry-collector-contrib
```

### Understanding Unfamiliar Code

```
# 1. Get a high-level map
cmd=tree%20-L%201%20-d&cwd=opentelemetry-collector-contrib/exporter/awss3exporter

# 2. Count lines per file to know what's big
cmd=find%20.%20-name%20'*.go'%20-not%20-name%20'*_test.go'%20%7C%20xargs%20wc%20-l%20%7C%20sort%20-rn&cwd=opentelemetry-collector-contrib/exporter/awss3exporter

# 3. Find all exported types
cmd=rg%20'^(type|func) [A-Z]'%20--type%20go%20--no-filename&cwd=opentelemetry-collector-contrib/exporter/awss3exporter

# 4. Read the README
cmd=cat%20README.md&cwd=opentelemetry-collector-contrib/exporter/awss3exporter

# 5. Read the config struct
cmd=cat%20config.go&cwd=opentelemetry-collector-contrib/exporter/awss3exporter
```

---

## Troubleshooting

**"command X is not allowed"**
The command isn't in the allowlist. Edit `allowedCommands` in `main.go` and rebuild with `docker compose up -d --build`.

**"path X is outside workspace"**
The `cwd` parameter resolved to a path outside your mounted workspace. Use paths relative to the workspace root.

**Output is empty but `ok: true`**
The command succeeded but produced no output. This is normal for commands like `grep` with no matches (though `grep` returns exit code 1 for no matches).

**"rate limit exceeded"**
You've exceeded 60 requests/minute. Wait a moment and retry.

**"output truncated at 2MB"**
The output exceeded the 2 MB cap. Use `head`, `tail`, or `sed -n` to read smaller chunks.

**Container can't see my files**
Check that `HOST_PROJECTS` in `.env` points to the right directory on your host. Run `docker compose exec scout ls /workspace` to verify the mount.

**Permission denied errors**
The scout process runs as UID 1000. If your host files have restrictive permissions, the container user may not be able to read them. Ensure files are world-readable or owned by UID 1000.

---

## Stopping Scout

```bash
docker compose down
```

To rebuild after editing `main.go`:

```bash
docker compose up -d --build
```

---

## License

MIT — use it however you want.
