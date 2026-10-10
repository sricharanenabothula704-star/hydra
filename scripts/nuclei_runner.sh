#!/usr/bin/env bash
# nuclei_runner.sh — tagged nuclei pass w/ rate control + triaged output
# usage: ./nuclei_runner.sh targets.txt [tags=cve,exposure] [severity=critical,high]
T="${1:?usage: $0 targets.txt [tags] [severity]}"
TAGS="${2:-cve,exposure,misconfig,tech}"; SEV="${3:-critical,high,medium}"
have nuclei || { echo "nuclei required"; exit 1; }
OUT="nuclei_$(date +%m%d_%H%M)"; mkdir -p "$OUT"
nuclei -l "$T" -tags "$TAGS" -severity "$SEV" -bs 150 -rl 120 -silent -o "$OUT/findings.txt" || true
echo "=== TRIAGE ==="
[ -f "$OUT/findings.txt" ] && awk -F'] ' '{print $1"]"}' "$OUT/findings.txt" | sort | uniq -c | sort -rn | head -15
wc -l < "$OUT/findings.txt" 2>/dev/null | xargs echo "total findings:"
echo "output → $OUT/findings.txt"
