---
name: detecting-linux-core-dump-credential-exposure
description: >-
  Core dumps, `su`/`sudo` failure logs, and crash artefacts often contain cleartext process memory — hashed passwords, session keys, and private keys — readable without any further exploitation.
---

# SKILL: Core dumps, `su`/`sudo` failure logs, and crash artefacts often contain cleartext process memory — hashed passwords, session keys, and private keys — readable without any further exploitation.

> **AI LOAD INSTRUCTION**: Load when reviewing `coredumpctl`, `/var/lib/systemd/coredump`, or `/var/crash` on Linux hosts for credential exposure during an authorized assessment.

## 0. RELATED ROUTING
- [detecting-linux-sudo-misconfiguration-privesc](#) for the policy-level escalation path
- [detecting-linux-world-writable-file-permission-privesc](#) for the writable-file escalation path
- [detecting-linux-exposed-service-binary-path-hijack](#) for service-level code injection

## 1. WHY CORE DUMPS LEAK CREDENTIALS

When a process dies on a fatal signal, the kernel writes a core dump: a snapshot of the
process address space, including stack, heap, and mapped memory. Applications routinely keep
passwords, tokens, and key material in memory long after use — SSH sessions, `su`/`sudo`
transitions, IMAP/SMTP sessions, LDAP simple binds, database drivers, JVMs with live
sessions, anything holding a private key. One dump from a failed `su`, a crashed `sshd`
child, or an OOM-killed agent can hand over cleartext or trivially-reversible credentials.

The exposure is a permissions problem, not an exploit: if a dump lands in
`/var/lib/systemd/coredump`, `/var/crash`, or the process working directory and is readable
by a low-privilege user, those credentials are already lost. Many defaults ship dumps as
`0644` root-owned, meaning every local user can read them.

## 2. READ-ONLY DETECTION

```bash
coredumpctl list --no-pager | tail -20          # systemd-coredump view
systemctl status systemd-coredump@<unit> --no-pager

# on-disk locations and their permissions
ls -la /var/lib/systemd/coredump/ /var/crash/ 2>/dev/null
find /var/lib/systemd/coredump /var/crash -type f -readable -print 2>/dev/null  # any local read?
find / -xdev \( -name 'core*' -o -name '*.core' -o -name '*.dump' \) 2>/dev/null | head -40

# metadata only, never the memory itself
coredumpctl info "$(coredumpctl list --no-legend | tail -1 | awk '{print $NF}')" --no-pager
```

```bash
auditctl -w /var/lib/systemd/coredump -p wa -k coredump_writes
cat /proc/sys/kernel/core_pattern
ulimit -c                       # per-shell; 0 disables dumps, unlimited permits them
```

## 3. PROVING EXPOSURE WITHOUT DUMPING SECRETS

Do **not** paste live credential strings into a ticket. Prove exposure structurally:

```bash
# show that memory regions of interest are present, without printing them
strings -n 8 /var/lib/systemd/coredump/core.1234 2>/dev/null |
  grep -cE 'BEGIN (RSA|OPENSSH|PRIVATE) KEY'          # count, not content
strings -n 8 /var/lib/systemd/coredump/core.1234 2>/dev/null |
  grep -E '^(sshd|su|login|dbus|java)' | sort | uniq -c | head   # which processes dumped
# salted-hash fingerprinting proves a specific secret is present without revealing it
strings /var/lib/systemd/coredump/core.1234 | sha256sum | cut -c1-16   # report-only fingerprint
```

A count of matching private-key headers, or a hash fingerprint matching a known credential
of yours, is sufficient evidence. Never extract or use the recovered credential.

## 4. REMEDIATION

```bash
# 1. Restrict storage: dumps owned by root, readable only by root
chmod 700 /var/lib/systemd/coredump /var/crash
chmod 600 /var/lib/systemd/coredump/* 2>/dev/null

# 2. Disable coredumps on sensitive hosts (kernel-wide or per-unit ProcessSizeMax=0)
echo 'kernel.core_pattern=|/bin/false' > /etc/sysctl.d/99-no-coredump.conf && sysctl --system

# 3. Purge existing dumps — these are already burned credentials, so rotate them too
find /var/lib/systemd/coredump /var/crash -type f -delete
#    rotate: SSH keys, service passwords, database creds, session tokens
```

Key point: deleting dumps does not un-expose the secrets. Any credential that lived in a
readable core dump must be rotated as part of remediation.

## 5. TESTING SAFELY

Only assess hosts you own or are explicitly authorized to test. Start read-only
(`coredumpctl list`, `ls -la`, `strings | wc -l`) — none of those modify or copy memory. Do
not run `gcore`/`gdb` against production services to force a dump; that pauses the process
and can cause an outage. Do not extract, decrypt, or authenticate with any credential found
in a dump; report its presence and location and hand rotation to the system owner. Avoid
copying dumps to your own workstation; if one must be preserved as evidence, encrypt it and
delete it at engagement close.

## 6. DETECTION SIGNALS

- `coredumpctl list` showing repeated dumps of `sshd`, `su`, `login`, or a database agent
- New files in `/var/lib/systemd/coredump` or `/var/crash` with mode `0644`
- `kernel.core_pattern` set to a shared or world-readable path
- SSH key authentication attempts succeeding immediately after a known credential change
  (suggesting the credential was harvested before rotation)

## Sources
- CWE-312: https://cwe.mitre.org/data/definitions/312.html
- CWE-532: https://cwe.mitre.org/data/definitions/532.html
- systemd-coredump(8) man page: https://www.freedesktop.org/software/systemd/man/systemd-coredump.html
