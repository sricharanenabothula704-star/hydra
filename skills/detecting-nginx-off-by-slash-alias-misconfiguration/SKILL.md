---
name: detecting-nginx-off-by-slash-alias-misconfiguration
description: >-
  Detect nginx `location`/`alias` off-by-slash misconfigurations that expose parent-directory contents.
---

# SKILL: Detect nginx `location`/`alias` off-by-slash misconfigurations that expose parent-directory contents.

> **AI LOAD INSTRUCTION**: Load when reviewing nginx configs, assessing static file serving, or triaging a suspected path traversal.

## 0. RELATED ROUTING
- [path-traversal-lfi](#) for the traversal mechanics once the misconfig is confirmed
- [detecting-apache-mod-proxy-path-normalization-bypass](#) for the Apache-side equivalent
- [detecting-tomcat-ghostcat-ajp-file-inclusion](#) for the AJP-side equivalent
- [hardening-web-server-configuration](#) for the nginx baseline

## 1. THE TWO BROKEN CONFIG SHAPES

`alias` with a missing trailing slash on the `location`, or with an unmatched prefix, maps the prefix
onto the directory in a way that lets `../` escape. Both of these are exploitable:

```nginx
# BROKEN: location lacks trailing slash, alias has one
location /static { alias /var/www/static/; }

# BROKEN: location is a prefix of a security-critical path
location /api { alias /srv/internal-api/; }
```

The first lets `/static../etc/passwd` resolve to `/var/www/static/../etc/passwd`. The second lets
`/apinternal/...` reach anything under `/srv/internal-api`.

## 2. LOCATE SUSPECT DIRECTIVES

```bash
grep -rnE '^\s*(location|alias|root)\b' /etc/nginx/ 2>/dev/null | head -60
grep -rn -A3 'location' /etc/nginx/sites-enabled/ | grep -E 'alias|root' | head -40
nginx -T 2>/dev/null | grep -nE 'location|alias' | head -60
```

`nginx -T` dumps the fully-included config including `include`-ed fragments. Use it when file inspection
misses something.

Classification heuristics:

| Finding | Severity |
|---|---|
| `alias` + missing trailing slash + no `rewrite ... break` | Critical |
| `alias` inside a `location` matched by a regex | Critical |
| `location /x` + `alias` where `x` prefixes a real route (`/x-admin`) | High |
| `root` (not `alias`) anywhere | Safe — no traversal |

Only `alias` inside a prefix-matching `location` has this bug class.

## 3. PASSIVE, NON-DESTRUCTIVE PROBES

These read only. They never write, and target paths whose existence you already know.

```bash
# Off-by-slash probe: request the parent directory listing / known index
curl -s -o /dev/null -w 'parent:%{http_code}\n' 'https://target.tld/static../'
curl -s 'https://target.tld/static../' | head -5

# URL-encoded traversal through the same path
curl -s -o /dev/null -w 'enc:%{http_code}\n' 'https://target.tld/static%2e%2e/'
curl -s -o /dev/null -w 'enc2:%{http_code}\n' 'https://target.tld/static%252e%252e/'

# Prefix-confusion: does /api also answer to /apinternal?
curl -s -o /dev/null -w 'prefix:%{http_code}\n' 'https://target.tld/apinternal/'
```

Interpretation: `200` with a listing or index = confirmed traversal. `301` to `/static../` means the
location matched and resolved to a directory — still a finding. `403` means the location matched but
filesystem access was denied — misconfigured, report at Medium. `404` means no match.

## 4. CONFIRMING SENSITIVITY WITHOUT OVER-REACH

Show impact without dumping secrets: pick a file that exists and is non-sensitive — a `.gitignore`, a
static `version.json`, or a marker you planted.

```bash
echo marker > /var/www/marker-probe.txt   # test/staging only
curl -s 'https://target.tld/static../marker-probe.txt'
```

If traversal reaches system files on an authorized system, do **not** exfiltrate `/etc/shadow` or
private keys. Retrieve at most one line of a low-sensitivity file, record the byte count, and describe
the impact — that is sufficient evidence of arbitrary file read.

## 5. DIFFERENTIAL PROBING ACROSS LOCATIONS

Run the same probe against every `alias` location to rank exposure:

```bash
for l in /static /assets /media /uploads /files; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://target.tld${l}../")
  [ "$code" != "404" ] && printf '%-10s %s\n' "$l" "$code"
done
```

Any non-404 result is a candidate location to fix first.

## 6. HARDENING
Use `root` instead of `alias` when the location maps one-to-one to a directory. If `alias` is required,
ensure both `location` and `alias` end with `/`, or add `rewrite ^/static/(.*)$ /static/$1 break;` before
the alias. Deny dotfiles with `location ~ /\.(?!well-known) { deny all; }`. Disable `autoindex`. Run
workers as an unprivileged user. Add a CI lint that fails when an `alias` path does not share the
location prefix. Validate with `nginx -t` before reload.

## Sources
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CWE-548: https://cwe.mitre.org/data/definitions/548.html
- nginx `alias` directive reference: https://nginx.org/en/docs/http/ngx_http_core_module.html#alias
- OWASP Path Traversal Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html
