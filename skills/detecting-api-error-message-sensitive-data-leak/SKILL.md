---
name: detecting-api-error-message-sensitive-data-leak
description: >-
  Detect sensitive data disclosure through verbose API errors, stack traces, debug modes, and framework pages.
---

# SKILL: Detect sensitive data disclosure through verbose API errors, stack traces, debug modes, and framework pages.

> **AI LOAD INSTRUCTION**: Load when assessing API error responses for leaked internals, identifiers, or personal data.

## 0. RELATED ROUTING
- [performing-web-application-logging-with-modsecurity](#) for log-side leakage review
- [testing-for-sensitive-data-exposure](#) for broader exposure validation
- [detecting-api-authorization-bypass-tenant-boundary](#) for authorization-aware error behavior

## 1. WHAT LEAKS IN ERRORS

Error handling is the most commonly misconfigured output path. Data that shows up:

- Stack traces with absolute paths, source snippets, and internal hostnames
- ORM errors echoing full SQL with table and column names
- Framework debug pages: Django `DEBUG=True`, Rails `show_exceptions`, Spring Boot, Flask
- Validation errors returning the whole submitted object, including rejected secrets
- `401` bodies differing between "no such user" and "wrong password" (enumeration oracle)
- `403` bodies naming the internal role or policy that denied access
- Serialization exceptions leaking the full serialized graph or a token in a header dump

## 2. TRIGGER A 500

On systems you own, provoke errors with malformed but harmless input.

```
curl -si -X POST https://api.example.com/v1/orders \
  -H "Authorization: Bearer $MY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"items":"not-an-array"}'

curl -si "https://api.example.com/v1/orders/../../etc/passwd" -H "Authorization: Bearer $T"
curl -si -X POST https://api.example.com/v1/orders -H 'Content-Type: application/json' -d 'not json at all'
curl -si "https://api.example.com/v1/orders?limit=abc" -H "Authorization: Bearer $MY_TOKEN"
```

Inspect status, `Content-Type`, and body. A `500` with `text/html` and a traceback is the classic
finding. Confirm the environment header: `X-Powered-By`, `Server`, `X-AspNet-Version`.

## 3. TYPE CONFUSION FOR ORM LEAKAGE

```
curl -si "https://api.example.com/v1/orders?limit[]=1&limit[]=2" -H "Authorization: Bearer $T"
curl -si "https://api.example.com/v1/orders?order[status]=nonexistent_col" -H "Authorization: Bearer $T"
curl -si "https://api.example.com/v1/orders/1;SELECT%201" -H "Authorization: Bearer $T"
```

ORMs surface table names, column names, and driver versions in these errors. Capture the exact
strings; they map directly to a follow-up injection or information-gathering test.

## 4. ENUMERATION ORACLES IN 4xx BODIES

Compare responses for a user you do not own (use a synthetic email, not a real person's).

```
curl -si -X POST https://api.example.com/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.invalid","password":"Wrong!123"}'

curl -si -X POST https://api.example.com/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.test","password":"Wrong!123"}'
```

Differences in message, status, body length, or timing reveal account existence.

## 5. DEV vs PROD PARITY

Check for `RAILS_ENV`/`NODE_ENV`/`APP_DEBUG` in headers, dev-only exception middleware,
and exposed `/__debug__/`, `/actuator/env`, `/phpinfo.php`, `/server-status`, `/_profiler/`.

```
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.com/__debug__/
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.com/actuator/env
```

## 6. VALIDATION ECHO

Schema validators often echo the rejected input. Confirm that a masked field stays masked.

```
curl -s -X POST https://api.example.com/v1/payment-methods \
  -H "Authorization: Bearer $MY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"cardNumber":"4242424242424242","expiry":"xx"}'
```

A response echoing `4242...4242` in full indicates missing field-level masking (PCI relevance).

## 7. FIX RECOMMENDATIONS

1. Return a generic error code and message to clients; log the detail server-side only.
2. Disable debug mode and debug toolbars in every environment reachable by users.
3. Normalize 400/401/403/404 bodies to prevent enumeration; add uniform response timing.
4. Validate input with an allowlist and return field names without values.
5. Mask sensitive fields before serialization and never serialize request objects wholesale.
6. Add `X-Content-Type-Options: nosniff` and strip version-revealing headers at the edge.

## 8. RESPONSIBLE TESTING

Only trigger errors against systems you own or are authorized to test, using inputs that affect
only your own account and data. Use synthetic email addresses and placeholder credentials; never
probe for the existence of real user accounts, and never include live secrets in test payloads.

## Sources
- CWE-209: https://cwe.mitre.org/data/definitions/209.html
- CWE-497: https://cwe.mitre.org/data/definitions/497.html
- OWASP Error Handling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
