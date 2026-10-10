#!/usr/bin/env bash
# js_secret_hunt.sh — pull every JS file for a domain, grep secret patterns
# usage: ./js_secret_hunt.sh urls.txt   (or: ./js_secret_hunt.sh https://target.com)
set -uo pipefail
IN="${1:?usage: $0 <urls.txt | https://domain>}"
TMP=$(mktemp -d)
if [[ "$IN" == http* ]]; then
  echo "crawling $IN for JS…"
  { command -v gospider >/dev/null && gospider -s "$IN" --js -d 2 -c 5 -t 3 --quiet || true; } | grep -oE 'https?://[^"<> ]+\.js[^"<> ]*' | sort -u > "$TMP/js.txt"
else
  grep -oE 'https?://[^"<> ]+\.js[^"<> ]*' "$IN" | sort -u > "$TMP/js.txt"
fi
wc -l < "$TMP/js.txt" | xargs echo "JS files:"
mkdir -p "$TMP/dl"
while read -r u; do
  curl -skL --max-time 15 "$u" -o "$TMP/dl/$(echo "$u" | md5sum | cut -d' ' -f1).js" &
done < "$TMP/js.txt"
wait
PATS='AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk_live_[0-9a-zA-Z]+|pk_live_[0-9a-zA-Z]+|eyJ[A-Za-z0-9_-]{10,}\.eyJ|xox[baprs]-[A-Za-z0-9-]{10}|-----BEGIN [A-Z ]*PRIVATE KEY|firebaseio\.com|access_key|api[_-]?key\s*[:=]\s*["'"'"'][A-Za-z0-9_\-]{16,}'
grep -rnoE "$PATS" "$TMP/dl" 2>/dev/null | sort -u | tee js_secrets_found.txt | sed 's/^/[HIT] /'
echo "results → js_secrets_found.txt ($(wc -l < js_secrets_found.txt) hits)"
rm -rf "$TMP"
