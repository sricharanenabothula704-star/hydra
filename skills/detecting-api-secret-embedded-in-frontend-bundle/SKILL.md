---
name: detecting-api-secret-embedded-in-frontend-bundle
description: >-
  Find API keys, tokens, and service credentials shipped inside frontend JS bundles and mobile web assets.
---

# SKILL: Find API keys, tokens, and service credentials shipped inside frontend JS bundles and mobile web assets.

> **AI LOAD INSTRUCTION**: Load when auditing a web or mobile client build for secrets that should never reach the browser.

## 0. RELATED ROUTING
- [performing-web-application-logging-with-modsecurity](#) for WAF-side detection context
- [detecting-aws-credential-exposure-with-trufflehog](#) for key-pattern scanning engines
- [implementing-api-key-security-controls](#) for correct key issuance and scoping design

## 1. WHY ANYTHING IN THE BUNDLE IS PUBLIC

Anything shipped to a browser is retrievable by the user, including source maps, cached service
worker bundles, and webpack chunk manifests. Distinct secret classes found in practice:

- Cloud provider keys (AWS `AKIA`/`ASIA`, GCP `AIza`, Azure connection strings)
- Long-lived third-party tokens (Stripe, Twilio, SendGrid, Firebase admin, GitHub PAT)
- Private API base URLs paired with an unauthenticated internal endpoint
- JWT signing secrets or HS256 shared secrets
- Database URLs, `.pgpass`, kubeconfig, SSH keys pasted into source

## 2. ACQUIRE THE BUNDLE THE WAY A REAL ATTACKER WOULD

```
# 1. Crawl entry points
curl -s https://app.example.com/ -o /tmp/opencode/index.html

# 2. Extract script sources
grep -oE 'src="[^"]+\.js"' /tmp/opencode/index.html | cut -d'"' -f2

# 3. Fetch each bundle and any source map it references
curl -s https://app.example.com/static/js/main.abc123.js -o /tmp/opencode/main.js
grep -oE '//# sourceMappingURL=.*' /tmp/opencode/main.js
curl -s https://app.example.com/static/js/main.abc123.js.map -o /tmp/opencode/main.js.map
```

Also check `/assets/`, `/static/`, `/build/`, `/dist/`, chunk files discovered from the
runtime manifest, and any `.env`, `.git/config`, `Dockerfile`, or `config.json` still served.

## 3. PATTERN SCAN

```
cd /tmp/opencode
tr -d '\000-\011\013-\037' < main.js | grep -oE '[A-Za-z0-9_/+=-]{40,}' | sort -u > strings.txt

grep -nEi '(AKIA|ASIA)[0-9A-Z]{16}' main.js
grep -nEi 'AIza[0-9A-Za-z_\-]{35}' main.js
grep -nEi 'gh[pousr]_[0-9A-Za-z]{36}' main.js
grep -nEi 'sk_(live|test)_[0-9a-z]{20,}' main.js
grep -nEi 'SG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}' main.js
grep -nEi '(postgres|mysql|mongodb|redis)://[^"'"'"']{6,}@' main.js
grep -nEi 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' main.js
```

Automated assist (choose one, run against only your own or authorized assets):

```
trufflehog filesystem /tmp/opencode --only-verified
gitleaks detect --source /tmp/opencode --report-format sarif
```

## 4. CONTEXT REVIEW (PATTERN MATCH IS NOT A FINDING)

A match is only exploitable if the value authenticates to something real. For each candidate:

1. Confirm the value is actually sent as an auth credential, not an example or a public ID.
2. Check reachability of the corresponding service using a **benign, non-destructive** call,
   such as a metadata endpoint or a read-only self-lookup on an account you own.
3. Distinguish public client IDs (safe, designed for the browser) from secret keys (never safe).
4. Record whether the value is scoped, rate-limited, or environment-restricted.

## 5. OBFUSCATION AND HIDDEN SPOTS

- Base64 / hex blobs decoded at runtime: search for `atob(`, `Buffer.from(`, `decodeURIComponent`.
- Split strings reassembled at runtime (`"AK" + "IA"`), so also scan de-obfuscated output.
- React Native / Flutter: `index.android.bundle`, `main.jsbundle`, `flutter_assets/`.
- Environment injection: `window.__ENV__ = {...}` often ships every config value.
- Service worker `precache` manifests exposing assets that the HTML does not link.

## 6. REMEDIATION

1. Rotate every exposed credential immediately; treat it as compromised.
2. Move privileged calls server-side and expose only a thin authenticated proxy.
3. Ship only short-lived, audience-restricted, user-delegated tokens to clients.
4. Enforce CSP, disable `unsafe-inline`/`unsafe-eval`, and drop public `.map` files.
5. Add a pre-deploy secret scan and pre-commit hook so regressions fail the build.

## 7. RESPONSIBLE TESTING

Only fetch bundles and test credentials belonging to assets you own or have explicit written
permission to assess. Validate a suspected key only against your own account or a test fixture;
never call third-party services, never enumerate or access data belonging to another customer,
and do not republish discovered secrets outside the authorized engagement report.

## Sources
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-312: https://cwe.mitre.org/data/definitions/312.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- GitHub secret scanning docs: https://docs.github.com/code-security/secret-scanning
