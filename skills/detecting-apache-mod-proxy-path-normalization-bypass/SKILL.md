---
name: detecting-apache-mod-proxy-path-normalization-bypass
description: >-
  Detect Apache mod_proxy path handling where normalization differs between frontend and backend.
---

# SKILL: Detect Apache mod_proxy path handling where normalization differs between frontend and backend.

> **AI LOAD INSTRUCTION**: Load when assessing Apache reverse proxies, reviewing ProxyPass/ProxyPassMatch rules, or triaging access-control bypass.

## 0. RELATED ROUTING
- [detecting-nginx-off-by-slash-alias-misconfiguration](#) for the nginx-side parallel bug
- [exploiting-http-request-smuggling](#) for parser-level request desync
- [detecting-tomcat-ghostcat-ajp-file-inclusion](#) for the AJP path-handling analogue
- [http-host-header-attacks](#) for Host-driven routing and access-control confusion

## 1. WHERE THE SPLIT HAPPENS

Apache's `mod_proxy`, `mod_rewrite`, and the backend each normalize paths independently and at different
times. `AllowEncodedSlashes`, `MergeSlashes`, `Options +MultiViews`, and `ProxyPass` trailing-slash
behavior are the four dials that decide whether `/admin` and `/admin/` and `/%61dmin` reach the same
backend resource.

```bash
grep -rnE 'ProxyPass|ProxyPassMatch|AllowEncodedSlashes|MergeSlashes|MultiViews|AcceptPathInfo' /etc/apache2/ /usr/local/apache2/conf/ 2>/dev/null | head -50
apachectl -S 2>/dev/null | head -20
httpd -t -D DUMP_VHOSTS 2>/dev/null | head -20
```

## 2. CONFIG SHAPES THAT MATTER

```apache
# Normalization split: Apache does not merge slashes, backend does
ProxyPass "/app/" "http://backend:8080/api/"
ProxyPassReverse "/app/" "http://backend:8080/api/"

# Encoded slashes reaching the backend differently than Apache expects
AllowEncodedSlashes NoDecode        # or On / Off — each changes downstream interpretation

# Access control applied on a path that mod_rewrite normalizes afterwards
RewriteRule "^/admin/(.*)" - [F]
ProxyPass       "/admin/"  "http://backend:8080/private/"
```

That last shape is the canonical bypass: `mod_rewrite` denies `/admin/x`, but a request that normalizes
*after* the rewrite (encoded slash, doubled slash, `//admin/x`, backslash, or a `.` segment) still
matches `ProxyPass` and reaches the backend as `/private/x`.

## 3. NON-MUTATING PATH-EQUIVALENCE PROBES

Probe equivalence on an endpoint whose response you already know. Compare status code and body hash:

```bash
base='https://target.tld/admin/index.html'
for p in '/admin/index.html' '/admin//index.html' '//admin/index.html' \
         '/admin/./index.html' '/admin/%2e/index.html' '/%61dmin/index.html' \
         '/admin%2findex.html' '/admin/../admin/index.html' '/ADMIN/index.html'; do
  printf '%-30s %s\n' "$p" \
    "$(curl -sk -o /tmp/b -w '%{http_code}' "https://target.tld$p"; sha256sum /tmp/b | cut -c1-12 | tr -d '\n')"
done
```

A restricted path returning the same `(200, hash)` as an unrestricted equivalent — or returning `200`
where the canonical form returns `403` — is a confirmed authorization bypass. Different `Content-Length`
with matching status is also a signal (soft-404 vs real content).

Cross-check against the backend's own view:

```bash
curl -sk 'https://target.tld/admin/index.html' -H 'X-Forwarded-Prefix: /x' | md5sum
curl -sk 'https://backend-host:8080/private/index.html' 2>/dev/null | md5sum   # authorized only
```

## 4. MOD_REWRITE ORDER AUDIT

The rewrite phase always precedes the proxy phase, so a rule placed after `ProxyPass` never fires for
proxied requests — and a `[F]` rule matching a normalized form while `ProxyPass` matches the raw form is
the bypass in one line of config. Read the effective config, not the source, because `Include` chains
and `.conf` load order routinely hide the offending block:

```bash
httpd -t -D DUMP_RUN_CFG 2>/dev/null | grep -n 'RewriteRule\|ProxyPass\|Directory'
```

Look specifically for:
- `[F]` / `Require all denied` rules placed **after** the `ProxyPass` they intend to guard
- `SetEnvIf Request_URI` conditions using raw, unnormalized values
- `ProxyPassMatch` regexes with `^/api(/|$)` written as `^/api` (prefix over-match)
- `DocumentRoot` protection absent on a `ProxyPass`-ed prefix

## 5. RESPONSIBLE TESTING BOUNDARY

Everything in section 3 is read-only and safe against production. Do **not** extend path-equivalence
probing to admin-protected resources with a valid authenticated session unless you are explicitly
authorized to test authorization boundaries — an authenticated bypass proof can disclose data. Prefer
probing a resource you own or one you know is a decoy. If a backend comparison is required, request
read-only access to the backend from a host already inside its trust boundary rather than tunneling
through the frontend.

## 6. HARDENING

Normalize exactly once, at the edge, and reject rather than pass through: enable `MergeSlashes On`,
set `AllowEncodedSlashes Off`, disable `Options +MultiViews`, and add an explicit deny for `//`, `/./`,
and `%2f` in paths at the WAF. Replace prefix `ProxyPass` with a `ProxyPassMatch` regex anchored with
`(/|$)`. Ensure every access-control rule uses the same normalized form the proxy uses, and place
deny rules before any `ProxyPass` for that prefix. Prefer explicit `Require`/`ProxyPass` pairs over
`mod_rewrite [F]`. Test normalization changes in CI against a matrix of encoded path variants so a
future httpd upgrade cannot silently reintroduce the split.

## Sources
- CWE-41: https://cwe.mitre.org/data/definitions/41.html
- CWE-441: https://cwe.mitre.org/data/definitions/441.html
- Apache mod_proxy documentation: https://httpd.apache.org/docs/current/mod/mod_proxy.html
- OWASP WSTG - Path Traversal: https://owasp.org/www-project-web-security-testing-guide/
