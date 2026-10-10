#!/usr/bin/env bash
# cors_probe.sh — origin-reflection / null-origin / credentialed CORS audit
# usage: ./cors_probe.sh https://target.com/api [more.urls...]
for U in "$@"; do
  echo "=== $U ==="
  for O in "https://evil.example" "null"; do
    H=$(curl -skI --max-time 10 -H "Origin: $O" "$U")
    AO=$(echo "$H"|grep -i "^access-control-allow-origin"); AC=$(echo "$H"|grep -i "^access-control-allow-credentials")
    if [ -n "$AO" ]; then echo "  [$O] REFLECTED: $AO ${AC:+| $AC}"; fi
  done
  # subdomain wildcard bypass attempt
  H=$(curl -skI --max-time 10 -H "Origin: https://target.com.evil.example" "$U")
  echo "$H"|grep -qi access-control-allow-origin && echo "  [suffix] possible suffix bypass!"
done
echo "(no output above a target = no CORS issue found)"
