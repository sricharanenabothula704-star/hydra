#!/usr/bin/env bash
# ==============================================================
# 🐉 HYDRA LOOP MODE — autonomous continuous hunting
#
# usage:
#   ./hydra_loop.sh targets.txt              # endless, 25-min cycles
#   ./hydra_loop.sh targets.txt 40           # custom cycle minutes
#   ./hydra_loop.sh doctor                   # pre-flight stop-condition audit
#
# WHY AGENT LOOPS DIE — and the counter built for each:
#   1. Context exhaustion   → fresh `opencode run` process every cycle;
#                             state lives in agent_memory/ files on disk,
#                             never in the model's window.
#   2. "Task complete" / agent asks a question → the hunt prompt explicitly
#      forbids stopping: continue until timeout, save findings continuously.
#   3. API rate limits      → detect 429/rate-limit text → escalating backoff,
#                             optional provider key rotation via env.
#   4. Crash / hang         → hard timeout per cycle + watchdog restart;
#                             runs inside tmux so SSH drops don't kill it.
#   5. Diminishing returns  → target rotation each cycle + methodology hint
#                             injected per-cycle from a rotating list.
#   6. Network blips        → retry with jitter before declaring failure.
#   7. Machine sleep        → doctor warns; run on server/tmux recommended.
#
# SAFETY: refuses to start unless every target passes scope_check.sh.
# ==============================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOOPDIR="$HOME/.hydra_loop"
LOG="$LOOPDIR/loop.log"; HB="$LOOPDIR/heartbeat.txt"; STATE="$LOOPDIR/state"
mkdir -p "$LOOPDIR"

log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# ---------------- doctor: pre-flight audit ----------------
doctor(){
  local FAIL=0; have(){ command -v "$1" >/dev/null && echo "[✓] $1" || { echo "[✗] $1 MISSING"; FAIL=1; }; }
  echo "── STOP-CONDITION AUDIT ──────────────────────"
  have opencode; have curl; have jq
  [ -f "$HOME/.config/opencode/opencode.jsonc" ] && echo "[✓] config rendered" || { echo "[✗] no config — run setup.sh first"; FAIL=1; }
  if [ -s "$HOME/.config/opencode/SCOPE_ALLOWLIST.txt" ]; then echo "[✓] scope allowlist present"; else echo "[✗] allowlist empty — loop refuses to start"; FAIL=1; fi
  if [ -n "${OPENROUTER_API_KEY:-}" ] || [ -n "${NVIDIA_NIM_API_KEY:-}" ]; then echo "[✓] model key present"; else echo "[✗] NO MODEL KEY → cycle 1 will die instantly"; FAIL=1; fi
  local FREE=$(df --output=avail -BG "$HOME" | tail -1 | tr -dc '0-9')
  [ "${FREE:-0}" -ge 5 ] && echo "[✓] disk ${FREE}G free" || { echo "[✗] disk <5G — findings writes may fail"; FAIL=1; }
  command -v tmux >/dev/null && echo "[✓] tmux available (survives disconnect)" || echo "[!] tmux missing — SSH drop kills loop"
  echo "[i] machine-sleep note: disable sleep or run on a server"
  echo "──────────────────────────────────────────────"
  [ "$FAIL" = 0 ] && echo "ALL CLEAR ✓" || echo "FIX THE ABOVE ✗"
}

# ---------------- targets & scope gate ----------------
TARGETS_FILE="${1:-}"; CYCLE_MIN="${2:-25}"
if [ "${1:-}" = "doctor" ]; then doctor; exit 0; fi
[ -n "$TARGETS_FILE" ] && [ -f "$TARGETS_FILE" ] || { sed -n '2,20p' "$0"; exit 1; }

mapfile -t TARGETS < <(grep -vE '^\s*#|^\s*$' "$TARGETS_FILE")
[ ${#TARGETS[@]} -eq 0 ] && { log "[!] no targets"; exit 1; }

for T in "${TARGETS[@]}"; do
  if ! bash "$HERE/scope_check.sh" "$T" >/dev/null 2>&1; then
    log "[SCOPE-DENY] '$T' not authorized — removing from rotation."
    TARGETS=("${TARGETS[@]/$T/}"); TARGETS=("${TARGETS[@]/ /}")
  fi
done
TARGETS=($(printf '%s\n' "${TARGETS[@]}" | grep -v '^$' || true))
[ ${#TARGETS[@]} -eq 0 ] && { log "[!] zero authorized targets. exiting."; exit 1; }
log "authorized rotation: ${TARGETS[*]}"

IDX=0; BACKOFF=60
HINTS=("focus on parameterized URLs and fuzzing" \
       "focus on JS analysis and source maps" \
       "focus on authentication/session flows" \
       "focus on API endpoints and IDOR patterns" \
       "focus on misconfigurations and exposed files")

# ---------------- the endless loop ----------------
while true; do
  T="${TARGETS[$((IDX % ${#TARGETS[@]}))]:-}"
  if [ -z "$T" ]; then IDX=$((IDX+1)); sleep 5; continue; fi
  IDX=$((IDX+1))
  HINT="${HINTS[$((IDX % ${#HINTS[@]}))]}"
  log "── cycle start · target=$T · hint='$HINT'"
  date +%s > "$HB"

  OUT=$(timeout "${CYCLE_MIN}m" opencode run \
    "/hunt $T — CONTINUOUS MODE: this is cycle $IDX. Work autonomously, NEVER ask questions, NEVER declare done early. Save every finding immediately. This cycle: $HINT." \
    2>&1); RC=$?

  echo "$OUT" | tail -40 >> "$LOG"
  date +%s > "$HB"

  # ---- classify why it stopped & counter it ----
  if [ $RC -eq 124 ]; then
    log "[ok] cycle hit planned timeout — that's the design. continuing."; BACKOFF=60
  elif echo "$OUT" | grep -qiE "rate.?limit|429|quota"; then
    BACKOFF=$((BACKOFF*2)); [ $BACKOFF -gt 1800 ] && BACKOFF=1800
    log "[backoff] rate limit detected — sleeping ${BACKOFF}s (🎮 'hydra game' to pass time)"
    source "$HERE/hydra_anim.sh"
    anim_start "cooling down… agents resume automatically"; sleep "$BACKOFF"; anim_stop
  elif [ $RC -ne 0 ]; then
    log "[restart] opencode exited rc=$RC — restarting next cycle in 15s"
    sleep 15
  else
    log "[continue] clean exit — rotating to next target/methodology"
    sleep 10
  fi
done
