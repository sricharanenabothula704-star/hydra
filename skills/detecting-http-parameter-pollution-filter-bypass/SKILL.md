---
name: detecting-http-parameter-pollution-filter-bypass
description: >-
  Detect HTTP Parameter Pollution where duplicated parameters are parsed differently by the WAF/proxy and the backend, letting an attacker smuggle payloads past input filters.
---

# SKILL: Detect HTTP Parameter Pollution where duplicated parameters are parsed differently by the WAF/proxy and the backend, letting an attacker smuggle payloads past input filters.

> **AI LOAD INSTRUCTION**: Load when a target sits behind a reverse proxy, CDN, WAF, or API gateway that inspects request parameters before the application parses them.

## 0. RELATED ROUTING
- [detecting-http-security-header-misconfiguration](#) for other proxy-to-origin boundary gaps
- [detecting-json-mass-assignment-overposting](#) for duplicate-key handling in JSON bodies
- [detecting-sqli-sql-injection](#) for the most common high-impact consequence of HPP bypass

## 1. THE PARSING DISAGREEMENT

HTTP Parameter Pollution (HPP) is not one bug but a boundary condition: every layer that
reads the request may pick a different value for the same repeated key. The classic split is
first-value-wins versus last-value-wins:

- `Sec`/some WAF cores and PHP-style stacks: first value
- ASP.NET, Express with `qs`, many Java/JAX-RS stacks: last value (collections)
- Apache + `mod_rewrite`/some gateways: last value, joined

The exploit is not "send two parameters" — it is "make the inspecting layer sanitize value A
while the application executes value B."

## 2. BASELINE AND DETECTION

First, learn how the target already behaves with duplicates. Use an endpoint that echoes or
reflects the parameter into a response you can observe (search, filter, or debug page):

```bash
# Baseline: single value
curl -s "https://target/search?q=alpha" -o /dev/null -w '%{http_code}\n'

# Duplicate: same key twice
curl -s "https://target/search?q=alpha&q=beta" -o /dev/null -w '%{http_code}\n'
```

Compare the response body/headers. If the two requests produce visibly different selection
(first, last, both, array, or an error), the layers disagree — that is the finding. Even a
`400` from the app on duplicates is useful: it means the backend saw an unexpected shape.

## 3. FILTER BYPASS CONFIRMATION

Assume an input filter blocks a known marker (script tag, SQL metacharacter, path traversal).
Try to smuggle it past the filter by placing the malicious value where the backend will
prefer it:

```bash
# If WAF inspects the first value and the app uses the last:
curl -s "https://target/search?q=SAFE&q=%27%20OR%20%271%27%3D%271"
curl -s "https://target/search?q=%27%20OR%20%271%27%3D%271&q=SAFE"
```

Interpretation:

- Payload executed while `SAFE` is what the filter saw → classic HPP filter bypass.
- Both values reach the parser as an array and the app joins/errors → HPP exists but the
  downstream use is not directly exploitable; still a robustness finding.

The same technique applies to JSON bodies with duplicate keys, array-style params
(`q[]=`), and encoded separators (`q=a&q=b` vs `q=a%26q%3Db`).

## 4. IMPACT SURFACE

Where duplicate-parameter confusion turns into real impact:

- **Filter bypass** of WAF rules for SQLi, XSS, or path traversal on a downstream sink.
- **Authorization ambiguity** — a filter layer authorizes `role=user`, backend reads
  `role=admin` (pairs with the mass-assignment skill).
- **SSRF/host confusion** when a duplicated `url`/`host` parameter is validated by one layer
  and consumed by another.
- **Cache poisoning** where the CDN caches the first-value interpretation while the origin
  used the last, serving inconsistent content.

## 5. DETECTION & HARDENING

- Normalize parameters at the edge: reject requests with duplicate scalar keys, or collapse
  them to a single canonical value before any security check and before the backend sees them.
- Ensure the WAF and the application share one parsing implementation and one precedence rule.
- For JSON, enforce that the body parser rejects duplicate object keys.
- Log requests containing repeated parameter names; alert on `=` appearing inside a value
  (encoded nested-parameter injection).
- Test key precedence explicitly in CI against your specific stack after any proxy change.

## 6. RESPONSIBLE TESTING NOTE

Stay on a benign, self-controlled endpoint (search, filter, or echo) and use harmless marker
values to prove precedence — do not weaponize the bypass into a live SQL injection or stored
XSS on production data. Send a small number of requests (a few dozen), avoid the
parameter-heavy admin or auth endpoints unless they are explicitly in scope, and never use
HPP to overwrite a value that causes a destructive action. Duplicate-parameter tests are
non-destructive by nature but can trip rate limiters or cache layers; coordinate with the
owner before running many variations, and report precedence findings even when downstream
impact is not exploitable — they are latent risk that grows as the stack changes.

## Sources
- CWE-235: https://cwe.mitre.org/data/definitions/235.html
- PortSwigger HTTP Parameter Pollution: https://portswigger.net/web-security/http-parameter-pollution
- OWASP WSTG (Input Validation): https://owasp.org/www-project-web-security-testing-guide/
- RFC 9110 (HTTP Semantics): https://www.rfc-editor.org/rfc/rfc9110
