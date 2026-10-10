---
name: detecting-wordpress-rest-api-authorization-bypass
description: >-
  Detect WordPress REST API authorization bypass flaws that expose or mutate content without authentication.
---

# SKILL: Detect WordPress REST API authorization bypass flaws that expose or mutate content without authentication.

> **AI LOAD INSTRUCTION**: Load when auditing a WordPress site, reviewing custom REST route code, or assessing wp-json exposure and privilege boundaries.

## 0. RELATED ROUTING
- [api-authorization-and-bola](#) for the generic object-level auth pattern WordPress routes violate
- [detecting-broken-function-level-authorization](#) for admin-only route guards implemented in callbacks
- [mass-assignment-in-rest-apis](#) for writable-field over-posting into post meta
- [detecting-graphql-schema-introspection-disabled-bypass](#) for the alternate query surface on modern WP builds

## 1. SURFACE FINGERPRINTING (PASSIVE FIRST)

Confirm the REST root and enumerate what is exposed without any credentials:

```bash
curl -s https://target.tld/wp-json/ | jq '.namespaces, .routes | keys' | head -50
curl -s -o /dev/null -w '%{http_code}\n' https://target.tld/?rest_route=/wp/v2/users
curl -s 'https://target.tld/?rest_route=/wp/v2/posts&per_page=1' -D- | head -20
```

`Link` and `X-WP-Total` headers confirm enumeration primitives are present. Record the WordPress
core version from `/wp-includes/version.php` output, generator meta, or `/wp-json/` `name` field.

## 2. UNAUTHENTICATED READ CHECKS

```bash
# Draft/private/draft-status posts leaking
curl -s 'https://target.tld/?rest_route=/wp/v2/posts&status=draft,private,pending&per_page=100' | jq '.[].status' | sort -u

# Full user enumeration (object ids -> login harvesting)
curl -s 'https://target.tld/?rest_route=/wp/v2/users&per_page=100&context=edit' | jq '.[].slug'

# Media library browsing
curl -s 'https://target.tld/?rest_route=/wp/v2/media&per_page=100' | jq '.[].source_url' | head
```

Note: `context=edit` and non-public `status` should return 401/403 for anonymous callers.

## 3. CUSTOM ROUTE AUTHZ ANALYSIS

Grep the codebase for custom registrations — this is where the real bugs live:

```bash
grep -rn "register_rest_route" --include=*.php . | head -40
grep -rn "permission_callback" --include=*.php . | grep -c "'__return_true'"
grep -rn "permission_callback" --include=*.php . | grep -c "current_user_can"
```

Triage rules of thumb:

| Pattern | Risk |
|---|---|
| Missing `permission_callback` entirely | WP < 5.5 default `__return_true` — public |
| `'__return_true'` on write routes | Critical, unauthenticated mutation |
| Callback checks only `is_user_logged_in()` | Any subscriber can escalate |
| Callback checks nonce but not capability | CSRF-token presence confused for authz |
| Route reachable via `?rest_route=` bypasses plugin guards | High, permalink rewrite dependent |

WordPress authz is capability-based. A correct check looks like
`current_user_can( 'edit_post', $id )` — never a bare role string comparison.

## 4. METHOD AND PARAMETER TAMPERING

```bash
# GET route accepting POST -> state change without CSRF token
curl -s -X POST 'https://target.tld/?rest_route=/wp/v2/custom/vote' -d 'post_id=1&choice=up'

# Read route leaking admin-only fields by context trick
curl -s -H 'X-WP-Nonce: bogus' 'https://target.tld/?rest_route=/wp/v2/users&context=embed'
```

Also test the `X-HTTP-Method-Override` and `_method` override paths, and `?_jsonp=` JSONP reflection.

## 5. AUTH BYPASS CONFIRMATION

For candidate bypasses, prefer read-only proof. Use a cross-origin probe to test whether anonymous
responses are readable by arbitrary origins:

```bash
curl -s -H 'Origin: https://attacker.example' -D- 'https://target.tld/?rest_route=/wp/v2/users&per_page=1' | grep -i 'access-control-allow'
```

For write-capability bypasses, do **not** send mutation payloads against systems you are not
explicitly authorized to change. Instead: prove reachability with `OPTIONS`, confirm route existence
from the index, and diff behavior between anonymous and `author`-level staging accounts if a test
instance is provided. Out-of-band callbacks (Burp Collaborator, `oastify.me`) are the preferred
confirmation channel when a callback-style leak is suspected, since they leave no state change on the
target.

## 6. DETECTION SIGNALS

- Unauthenticated `200` on `/wp/v2/users?per_page=100`
- Any `200` on `status=draft|private|pending` from an anonymous session
- `wp-json/` routes list containing plugin namespaces with no `permission_callback`
- `?_jsonp=` accepted on privileged endpoints with `Access-Control-Allow-Origin: *`
- Login attempts against usernames harvested from `/wp/v2/users`

## 7. REMEDIATION NOTES

Upgrade to supported WordPress core, register `permission_callback` on every route, use object-scoped
capability checks, strip `context=edit` responses for unauthenticated callers, disable author archives,
and set an explicit CORS allowlist. Log anonymous access to admin-semantics routes.

## Sources
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- WordPress REST API Handbook: https://developer.wordpress.org/rest-api/
