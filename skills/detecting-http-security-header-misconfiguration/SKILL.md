---
name: detecting-http-security-header-misconfiguration
description: >-
  Audit missing, weak, or malformed HTTP security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and cookie flags across an application's responses.
---

# SKILL: Audit missing, weak, or malformed HTTP security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and cookie flags across an application's responses.

> **AI LOAD INSTRUCTION**: Load when performing baseline hardening review of any web application's response headers and cookies.

## 0. RELATED ROUTING
- [detecting-clickjacking-missing-frame-options](#) for the framing-directive portion of this audit
- [detecting-cors-preflight-misconfiguration-wildcard](#) for CORS header correctness
- [performing-security-headers-audit](#) for the broader infrastructure-level header sweep

## 1. SCOPE THE AUDIT

Headers are set at different layers — application, framework, reverse proxy, CDN — and each
layer can add, override, or drop them. The audit must reflect what the **end user actually
receives**, so always test through the real public hostname, not against localhost. Sample
each distinct response class: authenticated HTML page, API JSON response, error page, static
asset, redirect, and the login/logout flows (cookies).

## 2. THE BASELINE SWEEP

```bash
for u in https://target/ https://target/login https://target/api/v1/me https://target/404; do
  echo "== $u"; curl -sI "$u" | grep -iE 'strict-transport|content-security-policy|x-content-type|x-frame|referrer-policy|permissions-policy|cache-control'
done
```

Baseline (non-sensitive) responses matter too — a login page without `Cache-Control:
no-store` can have credentials written to disk caches.

## 3. HEADER-BY-HEADER CRITERIA

| Header | Expected | Common failure |
| --- | --- | --- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (optionally `preload`) | absent; too-short `max-age`; no `includeSubDomains` |
| `Content-Security-Policy` | restrictive `default-src`, no `unsafe-inline`/`*` | absent; `unsafe-eval`; wildcard sources |
| `X-Content-Type-Options` | `nosniff` | absent (MIME-sniffing) |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN` (or CSP `frame-ancestors`) | absent (see clickjacking skill) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | absent; leaks full URL/tokens |
| `Permissions-Policy` | disable unused powerful features (`camera=()`, `geolocation=()`, `payment=()`) | absent; browser features over-permissive |
| `Cache-Control` (auth) | `no-store` on sensitive pages | absent; cached secrets |

## 4. CSP ASSESSMENT

A CSP is only useful if it actually restricts and has no trivially-bypassable allowlist.
Fetch the delivered header and evaluate the directives:

- `default-src` present and restrictive? A missing `default-src` with only `script-src` lets
  everything else load from anywhere.
- `unsafe-inline` / `unsafe-eval` in `script-src` largely defeats script-based XSS mitigation —
  `'unsafe-inline'` is ignored when a nonce/hash is present, so its presence alongside a nonce
  is not itself a bypass (mention this nuance in the finding).
- Wildcard hosts (`*`, `data:`, `https:`) or over-broad CDNs.
- `report-uri`/`report-to` for monitoring (absence is a detection gap, not a vuln).

Confirm the policy is actually delivered on **every** HTML response, not just the homepage —
per-page gaps are the usual finding.

## 5. COOKIE ATTRIBUTES

```bash
curl -sI https://target/login | grep -i '^set-cookie'
```

For each session/auth cookie require:

- `Secure` — no transmission over plain HTTP.
- `HttpOnly` — not readable by JS (mitigates token theft via XSS).
- `SameSite=Lax|Strict` — mitigates CSRF; `None` without `Secure` is a defect.
- Non-expiring or long-lived session tokens with no rotation — flag for review.
- Sensitive values not placed in a cookie readable by scripts or in URLs.

## 6. MISPLACEMENT & REDUNDANCY

Flag headers set only on some responses, headers injected by a CDN then overwritten by the
origin (or vice versa), duplicate/conflicting directives (two `Set-Cookie` handling paths,
two CSPs — browsers enforce the intersection, often more restrictive but confusing), and
prototype-pollution-style control characters/newlines in header values (header injection).

## 7. REMEDIATION

Set all headers **once, globally, at the edge** (reverse proxy/CDN) so every response inherits
them; per-route overrides only to tighten. Start HSTS in report-only or short `max-age`,
ramping to `includeSubDomains` + preload once all subdomains are HTTPS. Deploy CSP in
report-only first, fix violations, then enforce. Add a CI/CD check asserting required headers
on HTML, API, and error responses.

## 8. RESPONSIBLE TESTING NOTE

This audit is read-only and non-destructive — inspecting response headers and `Set-Cookie` on
a handful of page types carries no risk and requires no special authorization beyond the
engagement scope. Keep it bounded: sample representative URLs rather than crawling the entire
site, do not fetch or store cookies/session tokens you did not need to examine (view their
attributes, not their values), and avoid triggering edge cases that generate large responses.
Do not "fix" or inject headers against a production host — report findings with the exact
response and recommended header value instead. If you find a header issue on a third-party
component (CDN, embedded widget) you cannot fix, note it as third-party risk rather than
attempting to bypass it.

## Sources
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP headers reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- RFC 6797 (HSTS): https://www.rfc-editor.org/rfc/rfc6797
