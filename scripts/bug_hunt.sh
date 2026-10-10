#!/usr/bin/env bash
# 🎮 bug_hunt — play while your agents grind.
# Snake, but you're the hunter eating bugs. Pure bash + ANSI.
# usage: hydra game   |   ./bug_hunt.sh
set -uo pipefail

W=28; H=16; DELAY=0.12
PX=$((W/2)); PY=$((H/2)); VX=1; VY=0; LEN=5; SCORE=0; BEST=0
[[ -f ~/.hydra_snake_best ]] && BEST=$(cat ~/.hydra_snake_best)
declare -a BODY_X BODY_Y
for ((i=0;i<LEN;i++)) do BODY_X[$i]=$((PX-i)); BODY_Y[$i]=$PY; done
spawn_food(){ FX=$((RANDOM % (W-2) + 1)); FY=$((RANDOM % (H-2) + 1)); }
spawn_food

draw(){
  printf "\033[H\033[2J"
  printf "\033[1;36m🐉 BUG HUNT\033[0m  score:\033[1;33m%3d\033[0m  best:%3d  [arrows/wasd · q quit]\n" "$SCORE" "$BEST"
  printf "┌%s┐\n" "$(printf '─%.0s' $(seq $W))"
  for ((y=0;y<H;y++)); do
    printf "│"
    for ((x=0;x<W;x++)); do
      if [[ $x -eq FX && $y -eq FY ]]; then printf "\033[1;31m🐛\033[0m"
      else
        hit=""
        for ((i=0;i<${#BODY_X[@]};i++)); do
          [[ ${BODY_X[$i]} -eq x && ${BODY_Y[$i]} -eq y ]] && { if [ $i -eq 0 ]; then printf "\033[1;32m◆\033[0m"; else printf "\033[32mo\033[0m"; fi; hit=1; break; }
        done
        [ -z "${hit:-}" ] && printf " "
      fi
    done
    printf "│\n"
  done
  printf "└%s┘\n" "$(printf '─%.0s' $(seq $W))"
}

step(){
  PX=$((PX+VX)); PY=$((PY+VY))
  [[ $PX -lt 0 || $PX -ge W || $PY -lt 0 || $PY -ge H ]] && return 1
  for ((i=0;i<${#BODY_X[@]};i++)); do
    [[ ${BODY_X[$i]} -eq PX && ${BODY_Y[$i]} -eq PY ]] && return 1
  done
  if [[ $PX -eq FX && $PY -eq FY ]]; then
    SCORE=$((SCORE+10))
    LAST=${#BODY_X[@]}
    BODY_X[LAST]=${BODY_X[LAST-1]}; BODY_Y[LAST]=${BODY_Y[LAST-1]}
    spawn_food
  else
    for ((i=${#BODY_X[@]}-1;i>0;i--)); do
      BODY_X[$i]=${BODY_X[$((i-1))]} ; BODY_Y[$i]=${BODY_Y[$((i-1))]}
    done
    BODY_X[0]=$PX; BODY_Y[0]=$PY
  fi
  return 0
}

printf "\033[?25l"; trap 'printf "\033[?25h\033[0m"; exit' INT TERM
draw
while true; do
  read -rsn1 -t "$DELAY" k || { step || break; draw; continue; }
  case "$k" in
    q|Q) break;;
    w|W|A) [ "$VY" != "1" ] && VX=0 && VY=-1 ;;
    s|S) [ "$VY" != "-1" ] && VX=0 && VY=1 ;;
    a|A|D) [ "$VX" != "1" ] && VX=-1 && VY=0 ;;
    d) [ "$VX" != "-1" ] && VX=1 && VY=0 ;;
    $'\e') read -rsn2 -t 0.01 r; case "$r" in
      '[A') [ "$VY" != "1" ] && VX=0 && VY=-1 ;;
      '[B') [ "$VY" != "-1" ] && VX=0 && VY=1 ;;
      '[C') [ "$VX" != "-1" ] && VX=1 && VY=0 ;;
      '[D') [ "$VX" != "1" ] && VX=-1 && VY=0 ;; esac ;;
  esac
  step || break
  draw
done
[ $SCORE -gt $BEST ] && echo $SCORE > ~/.hydra_snake_best && BEST=$SCORE
printf "\033[?25h\033[0m\n"
echo "🐉 final score: $SCORE  |  best: $BEST"
echo "your agents kept hunting while you played."
