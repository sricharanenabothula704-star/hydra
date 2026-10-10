---
name: detecting-linux-sudo-misconfiguration-privesc
description: >-
  Overly broad sudoers rules (NOPASSWD: ALL, wildcard command arguments, writable sudoers.d files) let any unprivileged account become root without a password.
---

# SKILL: Overly broad sudoers rules (NOPASSWD: ALL, wildcard command arguments, writable sudoers.d files) let any unprivileged account become root without a password.

> **AI LOAD INSTRUCTION**: Load when reviewing sudoers configuration, sudoers.d includes, or Linux host privilege boundaries during an authorized internal assessment.

## 0. RELATED ROUTING
- [detecting-linux-world-writable-file-permission-privesc](#) for the writable-file class of escalation
- [detecting-linux-exposed-service-binary-path-hijack](#) for service-level path hijacking
- [detecting-linux-core-dump-credential-exposure](#) for post-compromise credential harvest

## 1. SUDO'S TRUST MODEL

sudo trusts three things: the sudoers policy file, the integrity of the binaries it
references, and the sudoers.d include directory. Every sudo escalation attacks one of those.
The dangerous policy patterns are:
- `user ALL=(ALL) NOPASSWD: ALL` — passwordless root for everything
- `user ALL=(root) NOPASSWD: /bin/bash` or any interactive shell
- `NOPASSWD:` on editors/pagers/interpreters — `vi`, `nano`, `less`, `awk`, `find`, `perl`,
  `python` all spawn interactive shells from inside sudo
- Wildcards in the *argument* field (`cp /home/attacker/* /etc/*`, `tar *`) — argument
  injection turns a "safe" binary into an arbitrary root file write
- `Defaults env_keep += "LD_PRELOAD"` or `LD_LIBRARY_PATH` — environment injection

## 2. READ-ONLY ENUMERATION

```bash
sudo -ll -U "$USER"          # effective privileges, resolved by sudo itself
sudo -l                      # all policy (may prompt for a password)
ls -la /etc/sudoers /etc/sudoers.d/
grep -rnEv '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# flag the classic dangerous patterns (needs sudo to read the protected files)
sudo grep -rniE '(NOPASSWD|!authenticate|env_keep|LD_PRELOAD|LD_LIBRARY_PATH|PATH\s*=)' \
  /etc/sudoers /etc/sudoers.d/

# unprivileged view: include dir writable by anyone? bad file perms?
stat -c '%A %U:%G %n' /etc/sudoers /etc/sudoers.d /etc/sudoers.d/*
find /etc/sudoers.d -type f ! -perm 0440 2>/dev/null
```

Because `sudo -l` prompts, build the case from the writable path instead: `test -w
/etc/sudoers.d` (critical), `find / -xdev -name 'sudoers*' -writable`, and group membership
via `getent group sudo`, `getent group wheel`, plus `id; groups` for the current principal.

## 3. TESTING SAFELY AND PROVING ESCALATION

Only test on hosts you own or hold written authorization for, and prefer the read-only checks
above — `sudo -l`, the `grep` sweep, and the permission `stat` calls change nothing. When
escalation is confirmed and proof is required, use a **benign marker**, never a destructive
payload: write only inside `/tmp`, and never install a shell, a setuid binary, or an
authorized_keys entry as evidence. Never modify `/etc/sudoers.d` to escalate for real, and
never use a discovered rule against systems outside the declared scope:

```bash
# from a NOPASSWD ALL rule
sudo -n id
sudo -n /usr/bin/id

# from an editor rule: prove shell spawn without touching system files
sudo -n /usr/bin/vi /tmp/proof.txt +':!/usr/bin/id > /tmp/sudo-escalation-proof.txt' +q

# from a cp/wildcard rule: write only inside a temp dir you own
sudo -n /bin/cp /tmp/attacker.txt /tmp/sudo-proof-target.txt && echo "writable by root"

# from a tar/awk/find rule: write only to /tmp
sudo -n /usr/bin/find / -maxdepth 1 -name passwd -exec /usr/bin/id \; 2>/dev/null
```

Cleanup: `rm -f /tmp/sudo-escalation-proof.txt /tmp/sudo-proof-target.txt /tmp/attacker.txt`.

## 4. REMEDIATION

```bash
# 1. Replace NOPASSWD:ALL with scoped rules
#    GOOD: allow only a specific script owned by root, not a shell or editor
echo 'deploy ALL=(root) NOPASSWD: /usr/local/bin/deploy-approved.sh' >> /etc/sudoers.d/deploy

# 2. Remove dangerous NOPASSWD entries (vi, nano, less, more, awk, find, tar, cp, perl, python)
# 3. Correct the include directory and file ownership
chown root:root /etc/sudoers /etc/sudoers.d
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d          # directory not group/world writable
chmod 440 /etc/sudoers.d/*

# 4. Never put user-writable directories on the sudo secure_path
grep secure_path /etc/sudoers     # ensure /tmp and ~ are absent
visudo -c                          # syntax-check before the file is in effect
```

Always validate with `visudo -c` before writing; an invalid sudoers file can lock you out
of sudo. Prefer `visudo` over direct `echo >>` for edits.

## 5. DETECTION SIGNALS

- `sudo` log entries showing NOPASSWD programs run in tight loops by a non-admin account
- Repeated `id`, `whoami`, `find / -perm -4000`, or `/tmp` writes immediately after sudo
- New files appearing in `/etc/sudoers.d` without a change ticket
- `auditd` execve of a shell whose parent is a sudo'd editor (vi/nano/less/awk)

## Sources
- CWE-250: https://cwe.mitre.org/data/definitions/250.html
- CWE-269: https://cwe.mitre.org/data/definitions/269.html
- sudoers manual (visudo, Defaults, secure_path): https://www.sudo.ws/docs/manuals/sudoers/
