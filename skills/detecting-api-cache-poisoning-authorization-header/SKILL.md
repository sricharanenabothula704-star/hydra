---
name: detecting-api-cache-poisoning-authorization-header
description: >-
  Detect web cache poisoning where Authorization or identity headers are ignored in the cache key.
---

# SKILL: Detect web cache poisoning where Authorization or identity headers are ignored in the cache key.

> **AI LOAD INSTRUCTION**: Load when assessing whether CDN and application caches vary responses correctly on identity headers.

## 0. RELATED ROUTING
- [performing-web-cache-poisoning-attack](#) for unkeyed header and parameter poisoning
- [performing-web-cache-deception-attack](#) for path-based cache confusion
- [detecting-api-authorization-bypass-tenant-boundary](#) for tenant scoping in cached responses

## 1. WHY IDENTITY HEADERS GET CACHED

A cache stores a response and replays it to later requests. If the cache key omits the
credential, an authenticated response can be served to the next anonymous request, or worse,
one user's response served to another. Failure modes:

- `Authorization` not in `Vary`, so a private response is cached publicly
- Cache key derived only from method + host + path, ignoring query and headers
- CDN configured to ignore `Authorization` on a cookie-authenticated API
- `Cache-Control: public` set by the app on a user-specific endpoint
- Soft-purge ("purge by URL") invalidation when a single record changes
- Cache poisoning via unkeyed inputs: `X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Proto`

## 2. MAP THE CACHE LAYERS

```
curl -si https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN_A" \
  | grep -iE '^(cache-control|vary|x-cache|age|via|cf-cache-status|cdn-cache|x-served-by|etag):'
```

Record `Age`, `X-Cache`, `Vary`, and `Cache-Control`. Repeat anonymously and compare.

## 3. CROSS-USER RESPONSE LEAK (OWN ACCOUNTS)

Create two accounts you own, `A` and `B`, each with distinct data.

```
# request A's private resource (prime the cache)
curl -si https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN_A" | head -40

# request the same path anonymously, with a cache-busting host header where needed
curl -si https://api.example.com/v1/me -H 'Cookie:' | head -40

# and as user B
curl -si https://api.example.com/v1/me -H "Authorization: Bearer $TOKEN_B" | head -40
```

A `200` with user A's body on the anonymous or user-B request is a confirmed cache leak.

## 4. CACHE-KEY PARAMETER POISONING

```
curl -si 'https://api.example.com/v1/products?list=1' -H "Authorization: Bearer $TOKEN_A"
curl -si 'https://api.example.com/v1/products?list=1&list=0' -H "Authorization: Bearer $TOKEN_B"
curl -si 'https://api.example.com/v1/products?list=0' -H 'Cookie:'
```

If the first response reappears for the third request, the backend picks one duplicate parameter
while the cache keys on all of them, or vice versa. This is the classic desync variant.

## 5. UNKEYED HEADER INJECTION

```
curl -si https://api.example.com/ -H "X-Forwarded-Host: attacker.example" | grep -iE 'location|x-forwarded-host|x-cache'
curl -si https://api.example.com/ -H 'X-Original-URL: /v1/me'
curl -si https://api.example.com/ -H 'X-Forwarded-Proto: http'
```

Check whether the response body or `Location` reflects the injected value and whether a
subsequent normal request is served the poisoned response.

## 6. CACHE DECEPTION PATH PROBING

```
for p in /v1/me.json /v1/me/ /v1/me/anything.css /v1/me%23.png /v1/me?x=.css; do
  curl -s -o /dev/null -w "$p code=%{http_code} type=%{content_type} size=%{size_download}\n" \
    "https://api.example.com$p" -H 'Cookie:'
done
```

A `200` at a path with an unrecognized extension usually means the cache is matching on a
broad prefix and storing a private response under a static-looking key.

## 7. FIX RECOMMENDATIONS

1. Never cache responses that vary by identity: `Cache-Control: private, no-store` for
   authenticated/user-specific data.
2. If an authenticated response must be cached, set `Vary: Authorization, Cookie` and ensure the
   CDN honors `Vary`; many do not - verify explicitly.
3. Include the full normalized URL (all query params) plus the relevant headers in the cache key.
4. Reject or ignore untrusted `X-Forwarded-*`, `X-Original-URL`, and `X-Rewrite-URL` at the edge.
5. Normalize duplicate query parameters server-side instead of picking first/last.
6. Purge by surrogate key (user or object), not just by URL.

## 8. RESPONSIBLE TESTING

Perform cache testing only against systems you own or are authorized to test, using two accounts
you created yourself, and read back only your own synthetic data. Do not attempt to poison shared
caches for other users, do not target third-party CDNs, and stop once the cache behavior is
confirmed; restore any primed cache entries you created.

## Sources
- CWE-525: https://cwe.mitre.org/data/definitions/525.html
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- PortSwigger Web Cache Poisoning: https://portswigger.net/web-security/host-header/exploiting
- OWASP HTTP Headers (Cache-Control): https://owasp.org/www-project-secure-headers/
