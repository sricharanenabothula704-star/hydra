#!/usr/bin/env bash
# recon_pipeline.sh — full passive→active recon in one shot
# usage: ./recon_pipeline.sh target.com
set -uo pipefail
T="${1:?usage: $0 target.com}"; OUT="recon_${T}_$(date +%m%d)"; mkdir -p "$OUT"
have(){ command -v "$1" >/dev/null; }

echo "[1/5] subdomain enumeration"
{ have subfinder && subfinder -d "$T" -silent; have assetfinder && assetfinder --subs-only "$T"; \
  curl -s "https://crt.sh/?q=%25.${T}&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//'; } | sort -u > "$OUT/subs.txt"
wc -l < "$OUT/subs.txt" | xargs echo "  subdomains:"

echo "[2/5] liveness + CDN tagging"
httpx -l "$OUT/subs.txt" -silent -title -tech-detect -ip 2>/dev/null > "$OUT/live.txt" || true
grep -icE "cloudflare|akamai|fastly|cloudfront" "$OUT/live.txt" | xargs echo "  cdn-shielded:"
grep -ivE "cloudflare|akamai|fastly|cloudfront" "$OUT/live.txt" | awk '{print $1}' > "$OUT/origins.txt"

echo "[3/5] port scan (origin only)"
have naabu && naabu -l "$OUT/origins.txt" -top-ports 100 -rate 1500 -verify -silent -o "$OUT/ports.txt" || true

echo "[4/5] nuclei CVE pass"
have nuclei && (cat "$OUT/origins.txt"; cat "$OUT/ports.txt") 2>/dev/null | sort -u | nuclei -tags cve -bs 200 -silent >> "$OUT/nuclei.log" || true

echo "[5/5] URL harvest"
have gau && gau --subs "$T" 2>/dev/null | uro 2>/dev/null > "$OUT/urls.txt" || true
echo "DONE → $OUT/"
