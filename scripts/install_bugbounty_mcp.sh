#!/usr/bin/env bash
# Install a pinned upstream MCP server into the user's OpenCode directory.
set -euo pipefail

MCP_REPOSITORY="https://github.com/gokulapap/bugbounty-mcp-server.git"
MCP_COMMIT="47b096fe7d18ffa2cf257d20a1a87ec0abebca20"
MCP_DIR="${1:?usage: install_bugbounty_mcp.sh <OpenCode MCP install directory>}"

command -v git >/dev/null 2>&1 || { echo "[!] git is required to install BugBounty MCP." >&2; exit 2; }

if [ -e "$MCP_DIR" ]; then
  if ! git -C "$MCP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[!] Refusing to overwrite non-git MCP directory: $MCP_DIR" >&2
    exit 2
  fi
  origin="$(git -C "$MCP_DIR" remote get-url origin 2>/dev/null || true)"
  current="$(git -C "$MCP_DIR" rev-parse HEAD 2>/dev/null || true)"
  if [ "$origin" != "$MCP_REPOSITORY" ] || [ "$current" != "$MCP_COMMIT" ]; then
    echo "[!] Existing MCP checkout differs from the pinned upstream; leaving it untouched." >&2
    echo "    Expected $MCP_REPOSITORY at $MCP_COMMIT" >&2
    exit 2
  fi
else
  mkdir -p "$(dirname "$MCP_DIR")"
  git clone --filter=blob:none --no-checkout "$MCP_REPOSITORY" "$MCP_DIR"
  git -C "$MCP_DIR" checkout --detach "$MCP_COMMIT"
fi

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "[!] BugBounty MCP requires Python 3.10+. Install it, then rerun setup." >&2
  exit 2
fi

if [ ! -x "$MCP_DIR/.venv/bin/python" ]; then
  python3 -m venv "$MCP_DIR/.venv"
fi
"$MCP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -e "$MCP_DIR"

STATE_DIR="${HOME}/.local/share/opencode/bugbounty-mcp"
mkdir -p "$STATE_DIR/data" "$STATE_DIR/output"
chmod 700 "$STATE_DIR" "$STATE_DIR/data" "$STATE_DIR/output"

# Validate without inheriting any target scope from a caller's shell or .env.
SAFE_MODE=true \
ALLOWED_TARGETS= \
BLOCKED_TARGETS= \
ALLOW_PRIVATE_TARGETS=false \
ENABLE_NUCLEI=false \
ENABLED_EXTERNAL_TOOLS= \
"$MCP_DIR/.venv/bin/bugbounty-mcp" validate-config
echo "[✓] BugBounty MCP installed at pinned commit $MCP_COMMIT (network scope empty)."
