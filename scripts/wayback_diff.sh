#!/usr/bin/env bash
# wayback_diff.sh — surface NEW endpoints since last snapshot (surface-diff)
# usage: ./wayback_diff.sh target.com   (stores baseline next to script)
T="${1:?usage: $0 domain.com}"; SNAP="$HOME/.wayback_snapshots"; mkdir -p "$SNAP"
F="$SNAP/${T//./_}.txt"
command -v waybackurls >/dev/null || { echo "waybackurls required"; exit 1; }
echo "[*] fetching historical URLs for $T…"
NEW=$(mktemp)
waybackurls "$T" 2>/dev/null | grep -E "\?[^=]+=" | sort -u > "$NEW"
wc -l < "$NEW" | xargs echo "  total parameterized URLs:"
if [ -f "$F" ]; then
  echo "[*] URLs NEW since last run:"
  comm -13 "$F" "$NEW" | tee "${T}.new_urls.txt"
  echo "  lost since last run: $(comm -23 "$F" "$NEW" | wc -l)"
else
  echo "[*] first run — baseline stored. Run again later to see fresh surface."
fi
cp "$NEW" "$F"
[ -f "${T}.new_urls.txt" ] && wc -l < "${T}.new_urls.txt" | xargs echo "  new:"
