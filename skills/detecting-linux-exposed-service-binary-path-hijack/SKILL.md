---
name: detecting-linux-exposed-service-binary-path-hijack
description: >-
  Services that run with an unqualified binary name, a user-writable working directory, or a hijackable library/environment variable let a local user execute code as the service account.
---

# SKILL: Services that run with an unqualified binary name, a user-writable working directory, or a hijackable library/environment variable let a local user execute code as the service account.

> **AI LOAD INSTRUCTION**: Load when auditing systemd units, init scripts, cron jobs, or container entrypoints for unsafe ExecStart/PATH/environment settings during an authorized assessment.

## 0. RELATED ROUTING
- [detecting-linux-world-writable-file-permission-privesc](#) for the writable-file variant
- [detecting-linux-sudo-misconfiguration-privesc](#) for policy-based escalation
- [detecting-linux-core-dump-credential-exposure](#) for credential retention in services

## 1. WHERE THE HIJACK HAPPENS

A process resolves an unqualified `ExecStart=backup` by searching `PATH`; if `PATH` contains a
directory the service user can write, the attacker supplies the binary. The same applies to
interpreter one-liners, relative script invocations, and libraries loaded via `LD_PRELOAD`,
`LD_LIBRARY_PATH`, or `PYTHONPATH`. The classic sub-case is a service whose working directory
is writable or controlled (`/tmp`, `/var/tmp`, a home directory) plus a script that sources a
relative file (`. ./conf`). Running as root this is instant root; as a dedicated account it is
still a service-account compromise and often a lateral pivot.

## 2. READ-ONLY DETECTION

```bash
# units with an unqualified ExecStart (no '/' in the binary name => PATH lookup)
systemctl list-units --type=service --state=running --no-legend | awk '{print $1}' |
while read u; do
  bin=$(systemctl show "$u" -p ExecStart --value 2>/dev/null |
        grep -oE '\{[^}]*\}[^ ;]*|[^ ;]+' | head -1 | tr -d '{}')
  case "$bin" in */*) ;; *) echo "UNQUALIFIED: $u -> $bin";; esac   # absolute path is safe
done

# per-unit hardening state and the process's real environment
systemctl show nginx -p User -p NoNewPrivileges -p ProtectSystem -p ProtectHome \
  -p PrivateTmp -p Environment --no-pager
tr '\0' '\n' < /proc/$(pgrep -o nginx)/environ | grep -E '^(PATH|LD_|PYTHON)'

# writable directories that appear in any root process's PATH
for pid in $(pgrep -u root); do
  p=$(tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | sed -n 's/^PATH=//p'); [ -n "$p" ] || continue
  echo "$p" | tr ':' '\n' | while read d; do
    [ -w "$d" ] && echo "root pid $pid has WRITABLE PATH DIR: $d"
  done
done

# cron/init scripts sourcing relatively from a writable cwd
grep -rnE '^\s*\.\s+\./|WorkingDirectory=/tmp|cd /tmp' /etc/cron* /etc/init.d /etc/systemd/system 2>/dev/null
```

## 3. BENIGN PROOF

Never drop a shell into a production unit. Prove it with an **inert marker** on a throwaway host:

```bash
# On an isolated lab host that reproduces the unit:
mkdir -p /tmp/hijacktest && printf '#!/bin/sh\ntouch /tmp/hijack-proof\n' > /tmp/hijacktest/myapp
chmod +x /tmp/hijacktest/myapp
PATH=/tmp/hijacktest:$PATH myapp && cat /tmp/hijack-proof   # proves PATH precedence
rm -rf /tmp/hijacktest /tmp/hijack-proof
```

In a live production assessment, do not execute the hijack. Report the condition with the
unit's `ExecStart`, `User=`, `WorkingDirectory=`, and the PATH evidence from section 2.

## 4. REMEDIATION

```ini
# systemd: absolute paths, dedicated account, sandboxing directives
[Service]
User=appsvc
Group=appsvc
ExecStart=/usr/local/bin/myapp --config /etc/myapp/myapp.conf
WorkingDirectory=/var/lib/myapp
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
RestrictSUIDSGID=true
SystemCallFilter=@system-service
CapabilityBoundingSet=
```

Unset any `LD_PRELOAD`/`LD_LIBRARY_PATH` inherited from the manager, score sandboxing with
`systemd-analyze security <unit>`, and keep writable directories out of every unit's PATH.
For cron, always use absolute paths and `cd` to a root-owned directory.

## 5. TESTING SAFELY

Only test on infrastructure you own or hold written authorization for. Section 2 is entirely
read-only: `systemctl show`, `/proc/<pid>/environ`, and `grep` change nothing. Do **not** restart
a production service to prove a hijack — a failed `ExecStart` can extend an outage, and a
successful hijack runs as the service account. Reproduce the configuration on a lab host or in
a container instead, using a marker file rather than any interactive shell. Never hijack a
service outside the declared scope, and do not modify unit files during an assessment; report
the exact directive change needed.

## 6. DETECTION SIGNALS

- `execve` audit events where argv[0] differs from the unit's `ExecStart` value
- `PATH` entries containing `/tmp`, `/var/tmp`, a home directory, or an empty element
- `LD_PRELOAD`/`LD_LIBRARY_PATH` present in a root process environment
- Units with `User=root` and no `NoNewPrivileges`, per `systemd-analyze security`

## Sources
- CWE-426: https://cwe.mitre.org/data/definitions/426.html
- CWE-427: https://cwe.mitre.org/data/definitions/427.html
- systemd.exec(5) man page: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
