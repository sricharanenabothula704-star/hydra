---
name: detecting-linux-world-writable-file-permission-privesc
description: >-
  World-writable files and directories, writable PATH components, or unprotected script/config files let any local user inject code that a privileged process later executes.
---

# SKILL: World-writable files and directories, writable PATH components, or unprotected script/config files let any local user inject code that a privileged process later executes.

> **AI LOAD INSTRUCTION**: Load when auditing Linux filesystem permissions, cron jobs, init scripts, or PATH integrity for local privilege escalation paths in an authorized assessment.

## 0. RELATED ROUTING
- [detecting-linux-sudo-misconfiguration-privesc](#) for policy-level escalation to root
- [detecting-linux-exposed-service-binary-path-hijack](#) for the service-account variant
- [detecting-linux-core-dump-credential-exposure](#) for post-compromise credential harvest

## 1. THE CORE MECHANISM

Escalation via permissions works whenever a privileged process — root, a systemd unit, a
cron job, an init script, a setuid binary — reads or executes a file an unprivileged user can
modify. The attack is write-then-wait: drop a payload into the trusted path, then trigger
whatever runs it. Variants worth checking:

- **World-writable config or script** (`chmod 666 /etc/app.conf`, `chmod 777 /opt/tool/run.sh`)
- **World-writable directory** in a privileged process's PATH or a cron working directory
- **Relative PATH entries** (`.` or a home directory) letting a user shadow a command
- **Unset umask** in a script that writes into a shared or privileged directory
- **World-writable scripts** referenced by `/etc/rc.local`, init scripts, cron, or `ExecStart=`

## 2. READ-ONLY DETECTION

```bash
# world-writable files/dirs, excluding pseudo filesystems
find / -xdev -perm -0002 -type f -o -xdev -perm -0002 -type d 2>/dev/null | grep -vE '^/(proc|sys|dev|run)'
# root-owned but group-writable files (writable by a non-root group)
find / -xdev -type f -user root -perm -0020 2>/dev/null | grep -vE '^/(proc|sys|dev|run|var/lib)'

# world-writable files that are referenced by privileged automation
grep -rE '/etc/rc\.local|/etc/init\.d|cron' /etc/cron* /var/spool/cron 2>/dev/null
ls -la /etc/rc.local /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null

# systemd services whose ExecStart points at something writable
for u in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
  path=$(systemctl show "$u" -p ExecStart --value 2>/dev/null | grep -oE '/[^ ;]+' | head -1)
  [ -n "$path" ] && [ -w "$path" ] && echo "WRITABLE ExecStart: $u -> $path"
done

# cron jobs and their target scripts
cat /etc/crontab /etc/cron.d/* 2>/dev/null
for f in $(awk '!/^#/ && NF{{print $NF}}' /etc/crontab 2>/dev/null); do
  [ -e "$f" ] && [ -w "$f" ] && echo "cron script writable: $f"
done
ls -la /var/spool/cron/crontabs/ /etc/cron.d/ /etc/rc.local 2>/dev/null
```

## 3. PATH INTEGRITY

A PATH is unsafe if any component before a trusted directory is writable by the user. An empty
entry is the current directory, so `sh` with `PATH=:/bin/sh` runs `./ls` before `/bin/ls`:

```bash
echo "$PATH" | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE PATH DIR: $d"; done
echo "$PATH" | tr ':' '\n' | grep -xE '\.|(~|\$)'   # relative entries shadow system binaries
```

## 4. TESTING SAFELY

Only assess hosts you own or are explicitly authorized to test, and prefer the read-only
checks above — `find`, `grep`, and `stat` change nothing. Do not modify permissions on
production files to demonstrate the finding; a `chmod` during an assessment can break a
running job and masks the condition being reported. Escalation proof must be a benign marker
file in a temp directory you own, never a setuid shell, an `authorized_keys` entry, or a
modified cron entry, and never a write to `/etc` or any service-referenced path.

## 5. BENIGN PROOF

Never leave a payload in place. Use a **harmless marker** in a temp directory you own, then
remove it:

```bash
test -w /opt/tool/run.sh && echo "WRITABLE: /opt/tool/run.sh"
printf '#!/bin/sh\ntouch /tmp/privesc-proof-$(id -u)-$(date +%%s)\n' > /tmp/writable-proof.sh
chmod +x /tmp/writable-proof.sh && /tmp/writable-proof.sh && ls -l /tmp/privesc-proof-*
rm -f /tmp/writable-proof.sh /tmp/privesc-proof-*
```

Prefer proving writability of a cron-referenced target over scheduling an actual job; if the
assessment requires triggering, use a script whose only effect is writing a marker file.

## 6. REMEDIATION

```bash
chmod 644 /etc/app.conf /opt/tool/run.sh     # remove world-write; 750 if owner-exec only
chown root:root /etc/app.conf /opt/tool/run.sh
chmod 755 /opt/tool                           # directory not world-writable
# add `umask 027` to any script writing shared files; set PATH in /etc/environment
find / -xdev -perm -0002 -type f 2>/dev/null   # re-run to verify zero findings
```

Add an integrity check to configuration management (Ansible check mode, `aide`/`tripwire` FIM)
so world-write regressions are caught in CI, not at exploit time.

## 7. DETECTION SIGNALS

- `auditd`/`inotify` writes to `/etc/cron*`, `/etc/rc.local`, or a systemd `ExecStart` path by a non-root uid
- New files in a world-writable directory that a root cron references
- `find / -perm -4000` executed by a non-admin account
- Group-writable root-owned files in `/opt`, `/usr/local`, or `/etc`

## Sources
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
- CWE-276: https://cwe.mitre.org/data/definitions/276.html
- GNU coreutils chmod: https://www.gnu.org/software/coreutils/manual/html_node/Invocation.html
