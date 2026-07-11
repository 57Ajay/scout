#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Scout native installer (Linux + systemd).
#
# Builds the binary, installs config to /etc/scout, and sets up a systemd
# service that runs Scout as your user (full docker/kubectl/file access).
#
#   sudo ./deploy/install.sh
#
# Env overrides:
#   SCOUT_USER=alice      # run-as user (default: $SUDO_USER or current user)
#   SCOUT_PORT=7711
#   SCOUT_BIND=0.0.0.0
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo: sudo ./deploy/install.sh" >&2
    exit 1
fi

RUN_USER="${SCOUT_USER:-${SUDO_USER:-$(whoami)}}"
RUN_GROUP="$(id -gn "$RUN_USER")"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
PORT="${SCOUT_PORT:-7711}"
BIND="${SCOUT_BIND:-0.0.0.0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "▶ Installing Scout"
echo "  run-as user : $RUN_USER ($RUN_GROUP)"
echo "  home        : $RUN_HOME"
echo "  bind        : $BIND:$PORT"

# ── 1. Build ────────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1; then
    echo "✗ Go toolchain not found. Install Go 1.23+ and retry." >&2
    exit 1
fi
echo "▶ Building binary…"
(cd "$REPO_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/scout .)
chmod 0755 /usr/local/bin/scout
echo "  installed /usr/local/bin/scout ($(/usr/local/bin/scout --version))"

# ── 2. Config ───────────────────────────────────────────────────
mkdir -p /etc/scout
if [[ ! -f /etc/scout/scout.yaml ]]; then
    /usr/local/bin/scout --gen-config >/etc/scout/scout.yaml
    TOKEN="$(openssl rand -hex 24 2>/dev/null || head -c24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    # Replace the placeholder token with a strong random one.
    sed -i "s/change-me-to-a-long-random-string/${TOKEN}/" /etc/scout/scout.yaml
    sed -i "s/^  port: .*/  port: \"${PORT}\"/" /etc/scout/scout.yaml
    sed -i "s/^  bind: .*/  bind: \"${BIND}\"/" /etc/scout/scout.yaml
    chown "$RUN_USER:$RUN_GROUP" /etc/scout/scout.yaml
    chmod 0600 /etc/scout/scout.yaml
    echo "  wrote /etc/scout/scout.yaml"
    echo ""
    echo "  ┌────────────────────────────────────────────────────────────"
    echo "  │ AUTH TOKEN: ${TOKEN}"
    echo "  │ Give this to your AI along with the base URL."
    echo "  └────────────────────────────────────────────────────────────"
    echo ""
else
    echo "  keeping existing /etc/scout/scout.yaml"
fi

# ── 3. systemd unit ─────────────────────────────────────────────
echo "▶ Installing systemd service…"
sed -e "s|__USER__|$RUN_USER|g" \
    -e "s|__GROUP__|$RUN_GROUP|g" \
    -e "s|__HOME__|$RUN_HOME|g" \
    "$SCRIPT_DIR/scout.service" >/etc/systemd/system/scout.service

systemctl daemon-reload
systemctl enable scout >/dev/null 2>&1 || true
systemctl restart scout

sleep 1
echo ""
systemctl --no-pager --lines=0 status scout || true
echo ""
echo "✓ Scout is running."
echo "  Health : curl http://127.0.0.1:${PORT}/api/health"
echo "  Logs   : journalctl -u scout -f"
echo "  Config : /etc/scout/scout.yaml   (edit, then: sudo systemctl restart scout)"
echo "  Dash   : http://YOUR_HOST:${PORT}/?token=YOUR_TOKEN"
