#!/usr/bin/env bash
# backup_brute.sh — backup/config extension fuzzing via ffuf on live hosts
# usage: ./backup_brute.sh live.txt [wordlist.txt]
LIVE="${1:?usage: $0 live.txt [wordlist]}"; W="${2:-backups.txt}"
EXT="bak,bak2,old,orig,save,swp,~,copy,tmp,conf,config,ini,json,xml,yml,yaml,sql,zip,tar.gz,tgz,rar,7z,git,env"
have(){ command -v "$1" >/dev/null; }
have ffuf || { echo "ffuf required"; exit 1; }
[ -f "$W" ] || printf 'index\ndatabase\ndump\nbackup\nsite\ndb\nusers\nwp-config\nconfiguration\nsettings\nsecret\ncredentials\n.env\napp\nprod\n' > "$W"
mkdir -p backup_hits
while read -r H; do
  H="${H%% *}"
  ffuf -u "$H/FUZZ.FUZZ2" -w "$W":FUZZ -w <(echo "$EXT"|tr ',' '\n'):FUZZ2 \
    -mc 200,301,403 -t 20 -rate 60 -s -o "backup_hits/$(echo "$H"|md5sum|cut -d' ' -f1).json" 2>/dev/null || true
done < "$LIVE"
grep -ho '"url":"[^"]*"' backup_hits/*.json 2>/dev/null | sort -u | tee backup_findings.txt
echo "findings → backup_findings.txt ($(wc -l < backup_findings.txt))"
