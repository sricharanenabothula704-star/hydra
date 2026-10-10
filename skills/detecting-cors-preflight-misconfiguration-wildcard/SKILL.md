---
name: detecting-cors-preflight-misconfiguration-wildcard
description: >-
  Detect CORS misconfigurations — wildcard origins, origin reflection with credentials, and broken preflight handling — that let arbitrary sites read authenticated API responses.
---

# SKILL: Detect CORS misconfigurations — wildcard origins, origin reflection with credentials, and broken preflight handling — that let arbitrary sites read authenticated API responses.

> **AI LOAD INSTRUCTION**: Load when auditing any browser-facing API's Access-Control-* headers, especially endpoints authenticated by cookies or tokens stored in JS-readable storage.

## 0. RELATED ROUTING
- [exploiting-cors-origin-reflection-with-credentials](#) for the exploitation mechanics of origin reflection
- [testing-cors-misconfiguration](#) for the general CORS testing matrix
- [detecting-http-security-header-misconfiguration](#) for the wider header hygiene review

## 1. THE TWO-PART QUESTION

CORS is only as strong as the browser boundary it enforces, and only applies to browser-made
requests. Two independent questions must both be answered: **which origins are allowed?**
(allowlist, reflection of any `Origin`, or `*`) and **are credentials allowed?**
(`Access-Control-Allow-Credentials: true` with a non-`*` origin is the dangerous pair — since
browsers reject `*` + credentials, naive configs reflect the origin instead, defeating the
safety net).

Also audit preflight: an `OPTIONS` handler answering `200` with permissive headers for
endpoints the real handler would reject, or a CDN/proxy injecting CORS headers the origin
never intended.

## 2. PROBE SIMPLE REQUESTS

Send an `Origin` header from a domain you control and inspect what comes back:

```bash
curl -i -sS -H "Origin: https://attacker.example" \
  "https://target/api/v1/me" -H "Cookie: session=TESTONLY"
```

| Response header | Meaning |
| --- | --- |
| your exact origin | reflection — dangerous with credentials |
| `*` | wildcard — safe only without credentials |
| nothing | CORS not enabled here |
| unrelated fixed origin | allowlist, correctly restrictive |

The critical combination is `ACAO: <your origin>` **and** `ACAC: true` on a cookie-authed
endpoint returning private data — confirmed finding.

## 3. PREFLIGHT (OPTIONS) TESTING

For non-simple requests (custom headers, `Content-Type: application/json`, PUT/DELETE) the
browser sends a preflight. Test it directly:

```bash
curl -i -sS -X OPTIONS "https://target/api/v1/me" \
  -H "Origin: https://attacker.example" \
  -H "Access-Control-Request-Method: PATCH" \
  -H "Access-Control-Request-Headers: authorization, x-custom"
```

Look for permissive `ACAO`, `ACAC: true`, `Allow-Methods: *` (or echoing any method), and
`Allow-Headers` reflecting arbitrary headers (allowing `Authorization` from any site). A
permissive OPTIONS that the real endpoint honors turns a same-origin assumption into
cross-origin write access.

## 4. NULL / SUFFIX / SUBSET BYPASSES

Test the classic bypasses for allowlists that check `endswith("example.com")` or similar:

| Origin | Why it may pass a weak check |
| --- | --- |
| `https://attacker.example.com` | suffix match without dot boundary |
| `https://example.com.attacker.test` | naive `contains("example.com")` |
| `null` | sandboxed iframe / `data:` context |
| `https://EXAMPLE.com` | case-sensitive comparison bug |
| `http://example.com` (http) | scheme not validated |

Each of these returning `ACAO` with credentials bypasses an otherwise-correct allowlist.

## 5. WHAT TO TEST SAFELY

Confirm exploitability by reading **your own** data with **your own** session, from a page on a
domain you control. Reflection + `ACAC: true` returning your own private data to your origin
proves the finding without touching anyone else's account.

## 6. DETECTION & REMEDIATION

- Use a strict origin allowlist compared after normalizing (scheme, case, port); never reflect
  arbitrary origins and never `contains()`-match.
- Send `Vary: Origin` whenever responses vary by origin, so CDNs don't serve the wrong
  `ACAO` from cache (a cache-poisoning variant).
- Prefer short-lived bearer tokens over `cookie` auth for APIs; keep cookies `HttpOnly` +
  `SameSite=Strict/Lax` so cross-site reads fail regardless of CORS.
- Restrict `Access-Control-Allow-Methods`/`Allow-Headers` to what you actually use; never `*`.
- Add an automated test asserting a disallowed origin receives no `ACAO` and no `ACAC`.

## 7. RESPONSIBLE TESTING NOTE

Only ever read your own data from origins you control — never attempt cross-origin reads of
another user's account, and never build a credential-harvesting page pointed at the live
production app or a third party. CORS testing is read-only and non-destructive, so keep it
that way: use a test session cookie you created, avoid enumerating endpoints at scale, and
remember that a permissive header does not by itself mean "this is exploitable" — confirm the
credentialed cross-origin read with your own account before reporting it as High/Critical.
Reporting requires written authorization for the target origin; coordinate with the owner so
your controlled probe domain is allowlisted or temporarily expected in logs.

## Sources
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- PortSwigger CORS misconfiguration: https://portswigger.net/web-security/cors
- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- OWASP WSTG (CORS): https://owasp.org/www-project-web-security-testing-guide/
