---
name: detecting-exposed-git-repository-source-disclosure
description: >-
  An internet-reachable .git directory exposes full source history, deleted secrets, and commit metadata without any authentication.
---

# SKILL: An internet-reachable .git directory exposes full source history, deleted secrets, and commit metadata without any authentication.

> **AI LOAD INSTRUCTION**: Load when auditing web roots for leftover .git paths, running an authorized external exposure review, or triaging a leaked repository.

## 0. RELATED ROUTING
- [detecting-exposed-environment-file-secret-leak](#) for the sibling config-file exposure class
- [detecting-exposed-backup-archive-file-download](#) for adjacent backup artifacts next to the repo
- [detecting-api-secret-embedded-in-frontend-bundle](#) for secrets recovered after source recovery

## 1. WHY .git MATTERS MORE THAN THE SOURCE

A public `.git/` directory usually survives because a deploy copied the whole build
context, or a `.gitignore` rewrite dropped the exclusion. The web server serves
dotfiles by default on nginx/Apache unless explicitly denied. Because `.git` is a
directory, the bare path `/` returns 403 while individual *files inside it* return
200. That asymmetry is the detection primitive.

Recovered content includes every historical commit, deleted files that never left
history, `.git/config` with upstream remote URLs, developer names and emails in
author fields, and — critically — any `.env`, `*.pem`, or `id_rsa` blob that was
committed once and later "removed".

## 2. PASSIVE / LOW-IMPACT CHECKS FIRST

Check the canonical objects without downloading a pack. `HEAD`, `config`, and
`description` are a few hundred bytes total:

```
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  https://target.example/.git/HEAD
curl -s https://target.example/.git/HEAD
curl -s -o /dev/null -w '%{http_code}\n' https://target.example/.git/config
curl -s https://target.example/.git/config | head -20
```

Interpretation: `200` with `ref: refs/heads/main` confirms the object store is live.
`403` on `/` but `200` on `/HEAD` is the dangerous silent case — listing off, files readable.
Check for sibling artifacts that leak the same way: `/package.json`,
`/composer.lock`, `/Gemfile.lock`, `/webpack.config.js`, `/.env`, `/backup.zip`,
`/.svn/entries`, `/.hg/requires`.

## 3. CONFIRMING REACHABILITY OF HISTORY

`.git/index` proves tracked files exist; `refs/heads/` and `packed-refs` expose
branch names. Enumerate without pulling a pack:

```
curl -s https://target.example/.git/packed-refs
curl -s https://target.example/.git/info/refs?service=git-upload-pack
curl -s https://target.example/.git/logs/HEAD | head
```

`info/refs?service=git-upload-pack` is the strongest single signal: the smart-HTTP
advertisement returns the full object list when the repo is readable.

## 4. LOW-IMPACT CONFIRMATION WITH GITHUB TOOLING

`git ls-remote` performs a *read-only* advertisement — it does not clone or write,
making it the standard first move against systems you are authorized to test:

```
git ls-remote https://target.example/.git/
```

Enumerate index filenames without a full clone (read-only, still needs authorization).
Keep the clone shallow:

```
git clone --depth 1 --no-checkout https://target.example/.git/ /tmp/opencode/leak
git -C /tmp/opencode/leak ls-files | head -50
```

Historical secret recovery needs an explicit unshallow (still read-only):

```
git -C /tmp/opencode/leak fetch --unshallow
git -C /tmp/opencode/leak log --all --diff-filter=D --name-only | sort -u | head -50
git -C /tmp/opencode/leak log -p --all -G '(api[_-]?key|secret|password|PRIVATE KEY)' | head -100
```

Treat any recovered key as compromised. Report the *existence and class* of the
secret; do not transmit the value.

## 6. REMEDIATION VERIFICATION

Fix the origin, then confirm the sink is closed:

- Delete the `.git` directory from the deployed artifact; `.gitignore` does nothing at runtime.
- Add explicit deny rules: `location ~ /\.git { deny all; return 404; }` (nginx)
  or `RedirectMatch 404 /\.git` (Apache). Deny `.env`, `*.bak`, `*.sql`, `*~`, `*.old` alongside.
- Rotate every credential appearing anywhere in history, even deleted ones — assume it was harvested.
- Rebuild from a clean CI artifact rather than a developer's working tree.

## 7. RESPONSIBLE TESTING

Only scan systems you own or are explicitly authorized to test. Start with
single-file HEAD probes rather than mirroring the repository — a full clone can pull
gigabytes and load the origin. Do not use recovered credentials, tokens, or keys; do
not push to the remote, create branches, or leave the clone on shared
infrastructure. Never propagate recovered source into third-party ticketing or chat
systems — reference file paths instead.

## Sources
- CWE-527: https://cwe.mitre.org/data/definitions/527.html
- CWE-538: https://cwe.mitre.org/data/definitions/538.html
- OWASP WSTIG-CONF: https://owasp.org/www-project-web-security-testing-guide/
