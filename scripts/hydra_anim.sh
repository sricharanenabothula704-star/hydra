#!/usr/bin/env bash
# hydra_anim.sh — source this to get HYDRA-branded animations
# usage:
#   source hydra_anim.sh
#   anim_start "hunting subdomains…" ; sleep 3 ; anim_stop
#   hydra_progress 7 10 "verifying"

ANIM_PID=""
FRAMES=('🐍' '🐉' '🥚' '🐉')
DOTS=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

anim_start(){
  local msg="${1:-working}"; local i=0
  (
    trap 'exit 0' TERM INT
    while true; do
      printf "\r\033[K  %s %s" "${FRAMES[$((i % 4))]}" "$msg"
      i=$((i+1)); sleep 0.18
    done
  ) & ANIM_PID=$!
}
anim_stop(){
  [ -n "$ANIM_PID" ] && kill "$ANIM_PID" 2>/dev/null
  wait "$ANIM_PID" 2>/dev/null
  printf "\r\033[K"; ANIM_PID=""
}

# progress bar: hydra_progress <current> <total> <label>
hydra_progress(){
  local cur=$1 tot=$2 label="${3:-}"
  local pct=$(( cur * 100 / (tot>0?tot:1) ))
  local filled=$(( pct / 5 ))
  local bar=""; for ((b=0;b<filled;b++)) do bar+="█"; done
  for ((b=filled;b<20;b++)) do bar+="░"; done
  printf "\r  🐉 [%s] %3d%%  %s" "$bar" "$pct" "$label"
}
