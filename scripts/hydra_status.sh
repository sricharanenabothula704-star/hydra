#!/usr/bin/env bash
# hydra_status.sh — live right-side dashboard (pair with opencode in tmux)
# usage: watch -cn2 bash hydra_status.sh   |   or via: hydra dash
C=$'\033[38;5;79m'; Y=$'\033[33m'; R=$'\033[91m'; G=$'\033[0m'; B=$'\033[2m'
line(){ printf "${C}%s${G}\n" "$(printf '─%.0s' $(seq 1 34))"; }
hdr(){ printf "\n${C} %s${G}\n" "$1"; line; }

printf "\n${C}  🐉 HYDRA DASHBOARD${G}\n"; line

# ---- LOOP STATE ----
HB="$HOME/.hydra_loop/heartbeat.txt"
if [ -f "$HB" ]; then
  AGE=$(( $(date +%s) - $(cat "$HB") ))
  CYCLE=$(grep -c "cycle start" "$HOME/.hydra_loop/loop.log" 2>/dev/null || echo 0)
  if [ $AGE -lt 150 ]; then printf "  LOOP   \033[32m● RUNNING\033[0m  cycle %s (%ss ago)\n" "$CYCLE" "$AGE"
  else printf "  LOOP   \033[33m○ IDLE\033[0m  last run %ss ago\n" "$AGE"; fi
else printf "  LOOP   ○ never started\n"; fi

# ---- FINDINGS ----
LEADS=$(find ~/recon_reports/companies/*/unreported -type f 2>/dev/null | wc -l)
VER=$(ls ~/recon_reports/verified_findings/READY_* 2>/dev/null | wc -l)
REJ=$(ls ~/recon_reports/rejected_findings/* 2>/dev/null | wc -l)
REP=$(ls ~/recon_reports/bugbase_reports/BUGBASE_* 2>/dev/null | wc -l)
hdr " FINDINGS"
printf "  leads %-4s verified %-4s rejected\n" "$LEADS" "$VER"
printf "  reports %s\n" "$REP"

# ---- SKILLS ----
SK=$(ls -d "$HOME/.config/opencode/skills/"*/ 2>/dev/null | wc -l)
hdr " ARSENAL"
printf "  skills %s · scripts %s\n" "$SK" "$(ls ~/scripts/* 2>/dev/null | wc -l)"

# ---- MCPS ----
hdr " MCP SERVERS"
CFG="$HOME/.config/opencode/opencode.jsonc"
if [ -f "$CFG" ]; then
  python3 - "$CFG" <<'PY' 2>/dev/null
import json,re,sys
t=re.sub(r'^\s*//.*$','',open(sys.argv[1]).read(),flags=re.M)
try: cfg=json.loads(t)
except Exception: sys.exit()
for name,m in cfg.get("mcp",{}).items():
    st="🟢" if m.get("enabled",True) else "⚪ off"
    print(f"  {st} {name}")
if not cfg.get("mcp"): print("  (none configured)")
PY
fi

# ---- SCOPE ----
hdr " SCOPE ALLOWLIST"
grep -vE '^#|^\s*$' "$HOME/.config/opencode/SCOPE_ALLOWLIST.txt" 2>/dev/null | head -4 | sed 's/^/  🔒 /'

# ---- MODEL ----
hdr " BRAIN"
[ -n "${OPENROUTER_API_KEY:-}" ] && printf "  🟢 openrouter\n"
[ -n "${NVIDIA_NIM_API_KEY:-}" ] && printf "  🟢 nvidia-nim\n"
[ -z "${OPENROUTER_API_KEY:-}${NVIDIA_NIM_API_KEY:-}" ] && printf "  ${R}🔴 no key in shell${G}\n"
printf "\n${B}  q=quit · updates every 2s${G}\n"
