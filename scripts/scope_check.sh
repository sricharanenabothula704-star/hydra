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
D="${RAW##*://}"; D="${D%%/*}"; D="${D%%:*}"; D="${D,,}"
AL="$HOME/.config/opencode/SCOPE_ALLOWLIST.txt"

if [ ! -s "$AL" ]; then
  echo "DENY: allowlist empty/missing → $AL"
  echo "Add your authorized program domains there, one per line."
  exit 1
fi

match(){ case "$D" in $1) return 0;; *) return 1;; esac; }
while IFS= read -r line; do
  line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
  [ -z "$line" ] && continue
  line="${line,,}"
  # strip leading *. for glob matching (*.dev.example matches foo.dev.example)
  if [[ "$line" == \** ]]; then pat="${line#\*.}"; case "$D" in *"$pat") echo "PASS: '$D' matches wildcard '$line'"; exit 0;; esac
  fi
  if match "$line" || match "*.$line" && [ "${D%."$line"}" != "$D" ]; then
    echo "PASS: '$D' is covered by '$line'"; exit 0
  fi
done < "$AL"

echo "DENY: '$D' is NOT on your authorized allowlist ($AL)"
echo "If this target IS in an active program's scope, add its domain to the allowlist first."
exit 1
