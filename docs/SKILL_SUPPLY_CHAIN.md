# Skill supply-chain vetting

A large curated skill library is an attack surface, not only an asset. Analysis
of 31,132 public agent skills found **26.1% contained vulnerabilities and 5.2%
showed likely malicious intent**, because skills execute with implicit trust and
minimal vetting.

HYDRA ships 1,179 modules. This page describes how it vets them.

```bash
python scripts/skill_supply_chain_scan.py                    # full report
python scripts/skill_supply_chain_scan.py --fail-on critical # CI gate
python scripts/skill_supply_chain_scan.py --json             # machine readable
```

Runs in CI on every push and blocks new `critical` findings.

## Current result

```
files scanned     : 4241
  executable      : 1089
  documentation   : 3152

findings by severity: high=166, medium=14, informational=143
actionable        : 180
```

## How severity is decided

Severity is tiered by **whether the text is executable**, because the same
string carries different blast radius in each place:

* `.py`, `.sh`, `.ps1` → `critical` / `high` / `medium`. Live code.
* `.md`, `.txt`, `.json` → `informational`. A technique shown in a playbook
  is not a technique being run.

Rules that only make sense for shipped code (pipe-to-shell, destructive
commands, credential reads) never fire on documentation at all.

## The problem this scanner hit, and the honest fix

Running it against HYDRA's own corpus produced **twenty `critical` findings**.
Almost every one was a false positive, and all for the same reason:

* `detecting-supply-chain-attacks-in-ci-cd:152`
  → `if "curl" in stripped and "| sh" in stripped:`
  That *is* the detection logic. The dangerous string is the signature.
* `performing-credential-access-with-lazagne`
  → browser profile and SSH key paths
  That tool's purpose is credential recovery. Those paths are its targets.
* `performing-container-image-hardening:119`
  → `if upper.startswith("RUN") and "curl" in stripped and "| sh" in stripped:`
  Detecting `curl | sh` in a Dockerfile.

**A pattern scanner cannot distinguish a tool that hunts a dangerous construct
from a tool that is one.** This is the mechanism behind the 26.1% figure, and
it is why shipping a scanner without a suppression mechanism is just noise with
confidence.

One rule was deleted for the same reason: an endpoint rule that flagged every
hardcoded third-party host produced 1,243 matches, almost all legitimate
public read-only APIs (NVD, CISA, abuse.ch, crt.sh). A rule that cannot
discriminate is worse than no rule, so it was removed rather than tuned into
usefulness.

## Suppressions

Reviewed suppressions live in
[`.skill-scan-suppressions.json`](../.skill-scan-suppressions.json). Each is
scoped to **one file plus one rule id** and carries a written reason that is
reviewed when the file changes.

* Never wildcarded. A blanket suppression would hide the next real finding in
  the same file.
* Line numbers are deliberately not pinned, so the entry survives edits.
* Suppressed findings are still **reported** in the scan output and in
  `--json`. Nothing is silently discarded.

Two tests keep this honest:

* a suppression pointing at a file that no longer exists fails the build;
* a suppression that matches nothing fails the build, so the config cannot rot.

## Rules

| Rule | Severity | Mechanism |
|---|---|---|
| `EXEC-BASE64-PIPE` | critical | Encoded payload piped to a shell — obfuscated RCE |
| `EXEC-CURL-PIPE-SHELL` | critical | Unreviewed remote code executed directly |
| `CRED-SSH-KEY-READ` | critical | Access to key stores turns a test tool into an exfiltration path |
| `SEC-HARDCODED-SECRET` | critical | Committed credentials |
| `NET-TLS-VERIFY-DISABLED` | high | `verify=False` / `-k` removes the trust anchor |
| `NET-HARDENED-BYPASS` | high | Disabling a defensive control |
| `EXEC-DESTRUCTIVE-UNGUARDED` | high | Irreversible deletion or wipe |
| `EXEC-EVAL-UNTRUSTED` | high | `eval`/`exec`/`pickle` on influenced input |
| `EXEC-SHELL-TRUE` | medium | Shell string interpolation, the standard injection surface |
| `NET-SCOPE-UNBOUNDED` | medium | Enumeration with no explicit bound |

## The largest real finding

After triage, the dominant genuine issue is **`verify=False` in shipped
executable modules** — 166 high-severity matches across the corpus. For
authorized testing against self-signed lab targets this is sometimes
deliberate, but as an unaudited default it is wrong: it removes the trust
anchor for every request the module makes, including against hosts the operator
never intended to reach.

That is a genuine remediation backlog, tracked here rather than hidden behind a
suppression.

## What this is not

This is a deterministic pattern scanner, not a malware classifier. It cannot
decide intent, it has no semantic understanding, and a clean run is not a
proof of safety. Its value is that it is reproducible: the same corpus produces
the same report on any machine, so a maintainer reviews every hit instead of
trusting a verdict.

Skills remain markdown guidance executed by an agent under the gates in
[`ENFORCEMENT.md`](ENFORCEMENT.md). Those gates — not this scanner — are what
constrain what a skill can do.
