#!/usr/bin/env bash
# takeover_probe.sh — dangling CNAME + known takeover fingerprints
# usage: ./takeover_probe.sh subs.txt
while read -r D; do
  CN=$(dig +short CNAME "$D" 2>/dev/null | head -1)
  [ -z "$CN" ] && continue
  BODY=$(curl -sk --max-time 8 "https://$D" 2>/dev/null | head -c 4000)
  MSG=""; echo "$BODY" | grep -qiE "NoSuchBucket|bucket not found" && MSG="S3"
  echo "$BODY" | grep -qiE "There isn't a GitHub Pages site here" && MSG="GitHub Pages"
  echo "$BODY" | grep -qiE "app not found|heroku.*no such app" && MSG="Heroku"
  echo "$BODY" | grep -qiE "the specified blob does not exist" && MSG="Azure"
  echo "$BODY" | grep -qiE "domain is not configured|unusual activity" && MSG="Webflow/other"
  [ -n "$MSG" ] && echo "[!!] $D → CNAME=$CN → $MSG takeover candidate"
done < "${1:?usage: $0 subdomains.txt}"
echo "(scan complete)"
