---
name: detecting-exposed-environment-file-secret-leak
description: >-
  A dotenv or env file served as static content hands attackers database credentials, API keys, and signing secrets with no authentication.
---

# SKILL: A dotenv or env file served as static content hands attackers database credentials, API keys, and signing secrets with no authentication.

> **AI LOAD INSTRUCTION**: Load when auditing web roots for .env exposure, reviewing frontend deploys, or scoping a suspected secret leak before rotation.

## 0. RELATED ROUTING
- [detecting-exposed-git-repository-source-disclosure](#) for the sibling source-disclosure class
- [detecting-exposed-backup-archive-file-download](#) for archives that bundle the same env file
- [detecting-default-credentials-on-exposed-services](#) for what leaked values enable next

## 1. WHY DOTENV FILES ESCAPE

Twelve-factor apps read configuration from `.env` at boot, and the file lives in the
repo root. A frontend build server rooted at the project directory — the default for
many static hosts and misconfigured SPA containers — then serves `.env` as a static
file because no rewrite rule exists for it. The tell is a 200 response with the raw
`KEY=value` body rather than the SPA `index.html` fallback.

The blast radius is total: database URIs, `DATABASE_URL`, `SESSION_SECRET`,
`STRIPE_SECRET_KEY`, JWT signing keys, SMTP passwords, and cloud provider keys.
`SESSION_SECRET` or `JWT_SECRET` recovery alone permits forging valid sessions for
any user without touching the application.

## 2. PASSIVE PROBES FIRST

Single-file GETs with no parameters, no auth, no side effects. Check the canonical
name plus the platform variants that tooling generates:

```
for f in .env .env.local .env.production .env.development .env.staging .env.backup \
         env.js config.js env.json .env.example environment.js; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target.example/$f")
  echo "$code $f"
done
```

The most reliable signal is *differential*: if the SPA returns `index.html` for every
unknown path, a `.env` request returning something materially different — key/value
lines, a `404` from the upstream rather than the rewrite, or a noticeably different
content-type — is a real hit.

```
curl -sI https://target.example/.env | grep -iE 'content-type|content-length|server'
curl -s https://target.example/.env | head -30
```

## 3. DISTINGUISHING REAL EXPOSURE FROM ECHO

A framework that rewrites all paths to `index.html` will return 200 for `.env` too.
Confirm by content, not status:

- Real exposure: body contains `=`-delimited keys, `PGPASSWORD=`, `sk_live_`,
  `AKIA`, `ghp_`, `-----BEGIN`, or long base64 blobs.
- Echo: body is HTML, identical byte-length to `https://target.example/nonexistent`,
  and the `ETag` matches the SPA shell.

## 4. WHERE ELSE THE VALUES LEAK

Once you know the key *names*, look for the values in adjacent surfaces — this is
read-only and much cheaper than chasing each source:

```
curl -s https://target.example/js/main.js | grep -oE '[A-Z_]{4,}(KEY|SECRET|TOKEN|PASSWORD)' | sort -u
curl -s https://target.example/assets/config.js | head -40
curl -s 'https://target.example/.well-known/' | head
```

Client-side bundles, source maps, and framework error overlays frequently echo the
same values. Presence of `sourcesContent` in a `.map` file means the full original
source, including a `.env` inlined at build time, is downloadable.

## 5. CONFIRMING SEVERITY WITHOUT USING CREDENTIALS

Do not authenticate with recovered material. Establish impact from configuration
shape alone: the *presence* of `DATABASE_URL`, `REDIS_URL`, `SESSION_SECRET`, or a
cloud `*_ACCESS_KEY` pair is sufficient evidence of critical severity. Record which
key names were present and which were populated — never copy the values into the
report or any external system.

## 6. REMEDIATION VERIFICATION

- Remove `.env` from the deployed artifact and from the served static root.
- Deny it at the web server regardless of app-layer attempts:
  `location ~ /\.env { deny all; return 404; }` (nginx) or
  `RedirectMatch 404 /\.env` (Apache).
- Never bake secrets into a frontend bundle; proxy secrets server-side.
- Rotate **every** populated value. Assume full compromise — they were fetchable
  by anyone, including search-engine crawlers and archive.org.
- Add `*.env` to `.gitignore` and to a pre-commit secret scanner.

## 7. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Begin with HEAD
requests and then at most a few hundred bytes of body — never download a discovered
credential file wholesale into shared tooling. Do not use any recovered value to
authenticate, and do not validate keys against third-party APIs, since that confirms
liveness to the provider's logs. Report key *names* and file paths, never values.
Stop and notify the owner immediately rather than continuing to enumerate once a
live credential is confirmed.

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-522: https://cwe.mitre.org/data/definitions/522.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
