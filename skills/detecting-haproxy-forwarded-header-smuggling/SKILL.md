---
name: detecting-haproxy-forwarded-header-smuggling
description: >-
  Detect header-based request smuggling and cache poisoning through HAProxy's X-Forwarded-* handling.
---

# SKILL: Detect header-based request smuggling and cache poisoning through HAProxy's X-Forwarded-* handling.

> **AI LOAD INSTRUCTION**: Load when assessing HAProxy-tiered architectures, auditing header trust, or triagging cache poisoning.

## 0. RELATED ROUTING
- [exploiting-http-request-smuggling](#) for CL/TE and TE/CL desync mechanics
- [web-cache-deception](#) for cache-key mismatches caused by untrusted headers
- [http-host-header-attacks](#) for Host-derived absolute URL poisoning
- [detecting-apache-mod-proxy-path-normalization-bypass](#) for the adjacent normalization split

## 1. WHY HAProxy IS THE INTERESTING TIER

HAProxy sits between the internet and the origin and *rewrites* headers. Two properties create the
smuggling surface: which hop's value HAProxy trusts, and whether it normalizes header names and values
before forwarding. Configuration variables to audit:

```bash
grep -rnE 'X-Forwarded-For|X-Forwarded-Host|X-Forwarded-Proto|forwardfor|option forwardfor|http-request (set-header|del-header)' /etc/haproxy/*.cfg
grep -rnE 'http-request set-header (X-Forwarded|X-Real-IP)' /etc/haproxy/haproxy.cfg
```

Two dangerous shapes:

| Config | Problem |
|---|---|
| `http-request set-header X-Forwarded-Host %[req.hdr(Host)]` over a client-supplied header | Origin trusts attacker value if not overwritten first |
| No `http-request del-header X-Forwarded-*` before setting | Client-supplied duplicates survive downstream |
| `option forwardfor` without `hdr` control on a chained proxy | Spoofable source IP for authz and rate limiting |

## 2. PASSIVE FINGERPRINT AND CONFIG OBSERVATION

```bash
curl -s -D- -o /dev/null https://target.tld/ | grep -iE '^server:|^via:|x-forwarded|x-cache|age:'
curl -s -D- -o /dev/null -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Forwarded-Host: attacker.example' \
  https://target.tld/ | grep -iE 'x-forwarded|x-varnish|cache|age'
```

A reflected `X-Forwarded-Host: attacker.example` in the response, or a cache `Age`/`X-Cache: HIT`
generated for a response to a request carrying an attacker-controlled forwarding header, is a direct
confirmation. Reflection alone is low severity; reflection plus caching is critical.

## 3. HEADER TRUST TESTS (READ-ONLY)

```bash
# Does the origin believe an arbitrary client IP?
curl -s https://target.tld/health/ip | grep -E '203.0.113.9|127.0.0.1'

# Duplicate header confusion: two values, origin may pick the first
curl -s -D- -o /dev/null -H 'X-Forwarded-Host: legit.tld' -H 'X-Forwarded-Host: attacker.example' \
  https://target.tld/

# Case and whitespace variance that normalizers may treat differently
curl -s -o /dev/null -w '%{http_code}\n' -H 'x-forwarded-for: 198.51.100.1' https://target.tld/ip
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For : 198.51.100.1' https://target.tld/ip
```

An IP-echo endpoint that reports `198.51.100.1` for a request arriving from an unrelated address means
the edge is blindly trusting a spoofable header for the security decision.

## 4. REQUEST-LINE AND PERSISTENT-CONNECTION DESYNC

When HAProxy and the origin disagree on where a request ends, a single connection carries two
requests. Test only against systems you are authorized to test, and prefer the observable, read-only
side: watch whether a benign probe sent on the same keep-alive connection appears twice in the origin
log.

```bash
# Non-destructive desync signal: send a normal request and a marked one on one connection
printf 'GET /healthz HTTP/1.1\r\nHost: target.tld\r\nConnection: keep-alive\r\n\r\n' | nc target.tld 443
```

Cross-check the origin access log for duplicated request lines with a single connection ID. Desync
testing never uses a second smuggled request that performs state-changing work.

## 5. CACHE POISONING CONFIRMATION

Poisoning is proven when a response you influenced is served to a *different* client. Do this safely:

1. Send a request with a unique OOB marker host in `X-Forwarded-Host` (a hostname you control).
2. Poll the same URL from a clean session with no special headers.
3. A cache `HIT` whose body references your marker confirms the poisoning.

Use a benign marker (a hostname string echoed into a page title or an error message), never injected
script or content that reaches real users. If the origin reflects the header into HTML, that reflection
is itself an XSS finding and must be reported even when the cache is not vulnerable.

## 6. RESPONSIBLE TESTING BOUNDARY

Fingerprint and read headers first. Desync and poisoning are state-affecting: a poisoned cache entry
serves attacker content to real users, and a desync can corrupt unrelated in-flight requests. Run both
only on systems with explicit written authorization, prefer a maintenance window, and flush the cache
(`POST / PURGE` on Varnish, HAProxy `socat` runtime command) and verify restoration in the report.

## 7. HARDENING

Delete untrusted `X-Forwarded-*` headers at the edge before setting your own. Normalize and reject
duplicate forwarding headers at the edge rather than passing them through. Use a strict, trusted-proxies
allowlist for `src` and `dst` ACLs and deny by default. Prefer PROXY protocol for internal hops instead
of spoofable headers. Set `http-server-close` or `http-request set-option http-reuse safe` to limit
request reuse ambiguity. Disable caching on any endpoint whose response varies by forwarded header, or
include a normalized host in the cache key. Strip `X-Forwarded-*` at the CDN tier too so they cannot be
injected upstream of HAProxy.

## Sources
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- CWE-444 Request Smuggling overview: https://owasp.org/www-community/attacks/Request_Smuggling
- OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- PortSwigger Web Cache Poisoning: https://portswigger.net/web-security/cache-poisoning
