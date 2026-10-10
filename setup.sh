#!/usr/bin/env bash
# ==============================================================
# 🐉 HYDRA — AI BUG BOUNTY SYSTEM · one-command setup
# FULLY AUTOMATED: installs opencode if missing, fixes PATH,
# renders your config, installs skills/agents/scripts.
#
# Non-interactive mode:
#   bash setup.sh --handle YOURNAME --email you@example.com
# ==============================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OC_DIR="$HOME/.config/opencode"
HANDLE=""; EMAIL=""

# ---------- parse flags (non-interactive mode) -----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --handle) HANDLE="$2"; shift 2 ;;
    --email)  EMAIL="$2";  shift 2 ;;
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

# ---------- step 1: opencode (auto-install, zero touch) --------
fix_path() {
  # opencode installs to ~/.opencode/bin (or ~/.local/bin on some setups)
  export PATH="$HOME/.opencode/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
}

if command -v opencode >/dev/null 2>&1; then
  echo "[✓] opencode found: $(command -v opencode)"
else
  echo "[*] opencode not found — installing automatically..."
  INSTALLER=$(mktemp)
  curl -fsSL https://opencode.ai/install -o "$INSTALLER"
  echo "    installer sha256: $(sha256sum "$INSTALLER" | cut -d' ' -f1)"
  bash "$INSTALLER"; rm -f "$INSTALLER"
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
h_step "Installing agents, skills, methodology"
mkdir -p "$OC_DIR"
cp -r "$REPO_DIR/agents"    "$OC_DIR/"
cp -r "$REPO_DIR/skills"    "$OC_DIR/"
cp -r "$REPO_DIR/common"    "$OC_DIR/"
cp -r "$REPO_DIR/templates" "$OC_DIR/"

h_step "Rendering your identity into config"
sed -e "s|__HOME__|$HOME|g" \
    -e "s|__HANDLE__|$HANDLE|g" \
    -e "s|__EMAIL__|$EMAIL|g" \
    "$REPO_DIR/opencode.jsonc.template" > "$OC_DIR/opencode.jsonc"

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
  [ -f "$OC_DIR/agent_memory/$m.md" ] || printf '# %s Agent Memory\n\n## What I Learned\n- Initialized %s\n' "$(echo $m | sed 's/^./\U&/')" "$(date +%F)" > "$OC_DIR/agent_memory/$m.md"
done

# ---------- done ---------------------------------------------------
echo ""
echo "==============================================="
echo " ✅ HYDRA IS INSTALLED"
echo "==============================================="
command -v opencode >/dev/null 2>&1 && \
  echo " Launch it:   opencode        → then type:  /hunt example.com" || \
  echo " Activate:    source ~/.bashrc && opencode"
echo ""
echo " Optional env keys:"
echo "   export OPENROUTER_API_KEY=sk-or-...   (or NVIDIA_NIM_API_KEY=...)"
echo "   export VIRUSTOTAL_API_KEY=... URLSCAN_API_KEY=..."
echo " Optional tooling:  bash $REPO_DIR/install-tools.sh"
echo "==============================================="
