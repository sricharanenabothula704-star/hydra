#!/usr/bin/env bash
# ==============================================================
# 🐉 HYDRA — AI BUG BOUNTY SYSTEM · one-command setup
# Guided setup: checks prerequisites, backs up existing config,
# asks before installing OpenCode or replacing an existing config.
#
# Non-interactive mode:
#   bash setup.sh --handle YOURNAME --email you@example.com
#   bash setup.sh --handle YOURNAME --email you@example.com --install-opencode
# ==============================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OC_DIR="$HOME/.config/opencode"
HANDLE=""; EMAIL=""; INSTALL_OPENCODE=0; REPLACE_CONFIG=0

# ---------- parse flags (non-interactive mode) -----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --handle) [[ $# -ge 2 ]] || { echo "[!] --handle needs a value"; exit 2; }; HANDLE="$2"; shift 2 ;;
    --email)  [[ $# -ge 2 ]] || { echo "[!] --email needs a value"; exit 2; }; EMAIL="$2"; shift 2 ;;
    --install-opencode) INSTALL_OPENCODE=1; shift ;;
    --replace-config) REPLACE_CONFIG=1; shift ;;
    *) echo "[!] Unknown option: $1"; exit 1 ;;
  esac
done

echo "==============================================="
echo "   🐉 HYDRA — AI BUG BOUNTY SYSTEM SETUP"

# ---------- optional glamour (gum) ----------
if command -v gum >/dev/null 2>&1 && [ -t 0 ]; then
  h_title(){ gum style --foreground "#2EE6A8" --bold "$1"; }
  h_step(){ printf "[*] %s\n" "$1"; }
  h_ok(){ gum style --foreground "#2EE6A8" "✓ $1"; }
else
  h_title(){ echo "$1"; }
  h_step(){ printf "[*] %s\n" "$1"; }
  h_ok(){ echo "[✓] $1"; }
fi

echo "==============================================="

# ---------- identity -------------------------------------------
if [ -z "$HANDLE" ]; then read -rp "Reporter handle / username [YOUR_HANDLE]: " HANDLE; fi
if [ -z "$EMAIL"  ]; then read -rp "Testing email [you@example.com]: "      EMAIL;  fi
HANDLE="${HANDLE:-YOUR_HANDLE}"
EMAIL="${EMAIL:-you@example.com}"
if [[ ! "$HANDLE" =~ ^[A-Za-z0-9_.-]{1,39}$ ]]; then
  echo "[!] Handle must use only letters, numbers, dot, underscore or hyphen (max 39 chars)."
  exit 2
fi
if [[ ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
  echo "[!] Email format is invalid."
  exit 2
fi

# ---------- step 1: opencode (auto-install, zero touch) --------
fix_path() {
  # opencode installs to ~/.opencode/bin (or ~/.local/bin on some setups)
  export PATH="$HOME/.opencode/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
}

fix_path
if command -v opencode >/dev/null 2>&1; then
  echo "[✓] opencode found: $(command -v opencode)"
else
  if [ "$INSTALL_OPENCODE" -ne 1 ]; then
    if [ -t 0 ]; then
      read -rp "OpenCode is missing. Download and run its official installer? [y/N] " answer
      [[ "$answer" =~ ^[Yy]$ ]] || { echo "[!] Stopped. Re-run with --install-opencode to approve installation."; exit 2; }
    else
      echo "[!] OpenCode is missing. Review the installer, then re-run with --install-opencode to approve it."
      exit 2
    fi
  fi
  command -v curl >/dev/null 2>&1 || { echo "[!] curl is required to download the OpenCode installer."; exit 2; }
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "[!] sha256sum or shasum is required to display the installer digest."
    exit 2
  fi
  echo "[*] Downloading the official OpenCode installer to a temporary file..."
  INSTALLER=$(mktemp)
  trap 'rm -f "$INSTALLER"' EXIT
  curl -fsSL https://opencode.ai/install -o "$INSTALLER"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "    installer sha256: $(sha256sum "$INSTALLER" | cut -d' ' -f1)"
  else
    echo "    installer sha256: $(shasum -a 256 "$INSTALLER" | cut -d' ' -f1)"
  fi
  echo "    Review the installer at: $INSTALLER"
  if [ -t 0 ] && [ "$INSTALL_OPENCODE" -eq 1 ]; then
    read -rp "Run this downloaded installer now? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { echo "[!] Installer not run. HYDRA setup stopped."; exit 2; }
  fi
  bash "$INSTALLER"
  rm -f "$INSTALLER"
  trap - EXIT
  fix_path
  if command -v opencode >/dev/null 2>&1; then
    echo "[✓] opencode installed: $(opencode --version 2>/dev/null || echo ok)"
  else
    echo "[!] Installer ran but binary not on PATH yet."
    echo "    It was added to ~/.bashrc — run:  source ~/.bashrc"
    echo "    Continuing with the rest of the setup..."
  fi
fi

# ---------- step 2: install config ------------------------------
mkdir -p "$OC_DIR"
if [ -n "$(find "$OC_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]; then
  BACKUP_ROOT="$HOME/.hydra_backups"
  BACKUP_DIR="$BACKUP_ROOT/opencode-$(date +%Y%m%d-%H%M%S)"
  umask 077
  mkdir -p "$BACKUP_DIR"
  cp -a "$OC_DIR/." "$BACKUP_DIR/"
  echo "[✓] Existing OpenCode config backed up to: $BACKUP_DIR"
  if [ "$REPLACE_CONFIG" -ne 1 ] && [ -t 0 ]; then
    read -rp "Merge HYDRA files into this existing OpenCode config? Some matching files may be replaced. [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { echo "[!] Existing config left unchanged. Re-run with --replace-config to approve the merge."; exit 2; }
  elif [ "$REPLACE_CONFIG" -ne 1 ]; then
    echo "[!] Existing OpenCode files left unchanged. Review the backup, then re-run with --replace-config to approve the merge."
    exit 2
  fi
fi

h_step "Installing agents, skills, methodology"
cp -r "$REPO_DIR/agents"    "$OC_DIR/"
cp -r "$REPO_DIR/skills"    "$OC_DIR/"
cp -r "$REPO_DIR/common"    "$OC_DIR/"
cp -r "$REPO_DIR/templates" "$OC_DIR/"

h_step "Rendering your identity into config"
sed -e "s|__HOME__|$HOME|g" \
    -e "s|__HANDLE__|$HANDLE|g" \
    -e "s|__EMAIL__|$EMAIL|g" \
    "$REPO_DIR/opencode.jsonc.template" > "$OC_DIR/opencode.jsonc"

# Install the repository-backed hydra command without copying the repo itself.
mkdir -p "$HOME/.local/bin"
chmod +x "$REPO_DIR/dist/bin/hydra"
ln -sf "$REPO_DIR/dist/bin/hydra" "$HOME/.local/bin/hydra"

# ---------- step 3: workspace dirs -------------------------------
h_step "Creating recon workspace"
mkdir -p "$HOME/scripts" \
         "$HOME/recon_reports/companies" \
         "$HOME/recon_reports/verified_findings" \
         "$HOME/recon_reports/rejected_findings" \
         "$HOME/recon_reports/bugbase_reports" \
         "$HOME/recon_reports/plans" \
         "$HOME/recon_reports/docs" \
         "$HOME/payloads"

# ---------- step 4: helper scripts -------------------------------
h_step "Installing helper scripts"
cp "$REPO_DIR/scripts/"* "$HOME/scripts/" 2>/dev/null || true
chmod +x "$HOME/scripts/"*.sh "$HOME/scripts/"*.py 2>/dev/null || true

# ---------- step 4b: scope policy gate default ----------
mkdir -p "$OC_DIR"
[ -f "$OC_DIR/SCOPE_ALLOWLIST.txt" ] || cat > "$OC_DIR/SCOPE_ALLOWLIST.txt" <<'EOL'
# Your authorized program domains, one per line. Wildcards allowed.
# Examples:
#   example.com          <- covers all subdomains
#   *.example.dev
localhost
EOL

# ---------- step 5: memory seeds ----------------------------------
mkdir -p "$OC_DIR/agent_memory"
for m in hunter verifier reporter plan debug auditor recon; do
  agent_title="$(printf '%s' "$m" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
  [ -f "$OC_DIR/agent_memory/$m.md" ] || printf '# %s Agent Memory\n\n## What I Learned\n- Initialized %s\n' "$agent_title" "$(date +%F)" > "$OC_DIR/agent_memory/$m.md"
done

# ---------- done ---------------------------------------------------
echo ""
echo "==============================================="
echo " ✅ HYDRA IS INSTALLED"
echo "==============================================="
if command -v opencode >/dev/null 2>&1; then
  echo " Launch OpenCode with: opencode"
else
  echo " OpenCode is not on PATH yet; review its installer and rerun setup with --install-opencode."
fi
echo ""
echo " Optional env keys:"
echo "   export OPENROUTER_API_KEY=sk-or-...   (or NVIDIA_NIM_API_KEY=...)"
echo " Add authorized domains to: $OC_DIR/SCOPE_ALLOWLIST.txt"
echo " If hydra is not on PATH, run: export PATH=\"\$HOME/.local/bin:\$PATH\""
echo " Preflight: hydra doctor (or $HOME/.local/bin/hydra doctor)"
echo "   export VIRUSTOTAL_API_KEY=... URLSCAN_API_KEY=..."
echo " Optional tooling:  bash $REPO_DIR/install-tools.sh"
echo "==============================================="
