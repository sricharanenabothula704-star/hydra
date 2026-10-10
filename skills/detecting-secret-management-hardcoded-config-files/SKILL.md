---
name: detecting-secret-management-hardcoded-config-files
description: >-
  Locate credentials embedded in source, config, build artifacts, and history, and assess whether rotation and detection controls exist for what is found.
---

# SKILL: Locate credentials embedded in source, config, build artifacts, and history, and assess whether rotation and detection controls exist for what is found.

> **AI LOAD INSTRUCTION**: Load when auditing a repository, reviewing a release pipeline, or responding to a suspected credential exposure.

## 0. RELATED ROUTING
- [detecting-blob-storage-public-read-misconfiguration](#) for secrets exposed via public objects
- [implementing-secrets-scanning-in-ci-cd](#) for pipeline prevention
- [detecting-aws-credential-exposure-with-trufflehog](#) for provider-specific scanning

## 1. WHY COMMITTED SECRETS PERSIST

A secret in git is not deleted by removing it from the working tree. It remains in
history, in every clone, in CI caches, in release tarballs, and in the forks of
anyone who cloned the repository. The response to a confirmed live credential is
rotation first and history cleanup second, in that order.

## 2. HIGH-VALUE LOCATIONS

| Location | Why |
|---|---|
| `.env`, `.env.*`, `env.php`, `settings.py` | Development credentials committed by habit |
| Terraform / CloudFormation | Provider blocks with hardcoded keys or secrets |
| CI config | Deploy keys and registry passwords in YAML |
| Dockerfiles, `docker-compose.yml` | `ENV`, `ARG`, and build-time secrets |
| Kubernetes manifests | Secret objects with base64, which is not encryption |
| Test fixtures and `conftest.py` | Real service keys copied from a console |
| Frontend bundles | Keys shipped to the browser are public by definition |
| Git history and tags | Secrets in a deleted file, or in a reverted commit |

## 3. SCANNING APPROACH

Run history-aware tools with high-confidence rules, then review matches manually.
Never paste a discovered secret into a ticket, chat, or report.

```bash
# History-aware secret scanning
trufflehog git file://. --only-verified --no-update
gitleaks detect --source . --redact -v

# High-signal patterns worth grepping for directly
grep -rnE 'AKIA[0-9A-Z]{16}' . --exclude-dir=.git
grep -rnE 'gh[pousr]_[A-Za-z0-9]{36,}' . --exclude-dir=.git
grep -rnE 'xox[baprs]-[A-Za-z0-9-]{10,}' . --exclude-dir=.git
grep -rnE '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . --exclude-dir=.git
grep -rnE 'AIza[0-9A-Za-z_-]{35}' . --exclude-dir=.git
grep -rnE '(password|passwd|secret|api_?key|token)\s*[:=]\s*["\x27][^"\x27]{8,}' \
  --include='*.py' --include='*.js' --include='*.yaml' --include='*.yml' . --exclude-dir=.git
```

Then check the places scanners routinely miss:

```bash
# .env files that exist but were not tracked
find . -name '*.env*' -not -path './.git/*'
# Base64 "secrets" in manifests, which decode to plaintext
grep -rn 'data:' --include='*.yaml' k8s/ | head
# Secrets that leaked into the client bundle
grep -rniE 'secret|apikey|api_key' dist/ build/ assets/ 2>/dev/null | head
# Check whether it was ever committed, even if later removed
git log --all --full-history -- '**/.env*' --oneline
```

## 4. VERIFYING WITHOUT ABUSING

Do not authenticate to a third-party service with a found credential. Prefer
structural evidence: does the value match the expected format, is it in the working
tree or only in history, and does the owner report recent use? Report format,
location, and commit with the value redacted.

## 5. FALSE POSITIVE DISCIPLINE

Tighten the pattern rather than ignoring the class. Exclude examples, testdata, and
documentation placeholders explicitly, and require a length and charset match to
reduce hits from variable names and comments. Track suppressions with a reason and
an expiry; an unreviewed suppression list becomes a permanent blind spot.

## 6. PREVENTION AND REMEDIATION SEQUENCE

Keep secrets out of the repository entirely and load them from a managed secret
store at runtime. Fail the build on verified findings, run history-aware scanning
on a schedule as well as per commit, enforce pre-commit hooks locally, and replace
long-lived CI keys with short-lived, least-privilege per-job tokens.

When a live credential is found: revoke or rotate it immediately and assume it is
compromised; audit provider logs for use from unexpected sources; remove the value
from the working tree, then purge it from history if project policy requires;
invalidate caches and artifacts that embedded it; and document the incident.

## 7. RESPONSIBLE TESTING

Scan only repositories, accounts, and storage you own or are explicitly authorized
to review, with written authorization for shared systems. Never validate a
discovered credential by logging in to a service, never use a found key to access
data, and never include secret values in findings; redact them and report the
location and format. Prefer read-only scans and never modify repository history
without explicit owner approval.

## Sources
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-259: https://cwe.mitre.org/data/definitions/259.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
