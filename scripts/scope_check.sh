#!/usr/bin/env bash
# scope_check.sh — HYDRA policy gate: PASS/DENY before any packet is sent
#
# Agents MUST call this before touching a target. Exit 0 = allowed, 1 = DENIED.
# Allowlist: ~/.config/opencode/SCOPE_ALLOWLIST.txt   (one domain/wildcard per line)
#   example.com
#   *.example.dev
#   localhost
#
# usage: scope_check.sh <domain-or-url>
set -uo pipefail
RAW="${1:?usage: $0 <domain-or-url>}"
D="${RAW##*://}"; D="${D%%/*}"; D="${D%%\?*}"; D="${D%%\#*}"; D="${D%%:*}"; D="${D,,}"; D="${D%.}"
if [[ "$D" == *@* || -z "$D" ]]; then
  echo "DENY: malformed target hostname"
  exit 1
fi
AL="$HOME/.config/opencode/SCOPE_ALLOWLIST.txt"

if [ ! -s "$AL" ]; then
  echo "DENY: allowlist empty/missing → $AL"
  echo "Add your authorized program domains there, one per line."
  exit 1
fi

match_labels(){
  local host="$1" rule="$2" i
  local -a host_parts rule_parts
  IFS='.' read -r -a host_parts <<< "$host"
  IFS='.' read -r -a rule_parts <<< "$rule"
  [ "${#host_parts[@]}" -eq "${#rule_parts[@]}" ] || return 1
  for ((i=0; i<${#host_parts[@]}; i++)); do
    case "${host_parts[$i]}" in
      ${rule_parts[$i]}) ;;
      *) return 1 ;;
    esac
  done
  return 0
}
while IFS= read -r line; do
  line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
  [ -z "$line" ] && continue
  line="${line,,}"
  # A leading *. matches one or more complete labels; embedded * matches
  # within exactly one label (e.g. onboarding-*.cloud.com).
  if [[ "$line" == \*.* ]]; then
    pat="${line#\*.}"
    [[ "$pat" == *.* && "$pat" != *\** ]] || continue
    case "$D" in *."$pat") echo "PASS: '$D' matches wildcard '$line'"; exit 0;; esac
  elif [[ "$line" == *\** ]]; then
    if match_labels "$D" "$line"; then
      echo "PASS: '$D' matches label pattern '$line'"; exit 0
    fi
  elif [ "$D" = "$line" ] || [[ "$D" == *."$line" ]]; then
    echo "PASS: '$D' is covered by '$line'"; exit 0
  fi
done < "$AL"

echo "DENY: '$D' is NOT on your authorized allowlist ($AL)"
echo "If this target IS in an active program's scope, add its domain to the allowlist first."
exit 1
