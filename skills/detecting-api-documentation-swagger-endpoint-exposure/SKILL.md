---
name: detecting-api-documentation-swagger-endpoint-exposure
description: >-
  Public OpenAPI/Swagger documents hand attackers the full endpoint map, parameter names, auth scheme, and internal hostnames in one request.
---

# SKILL: Public OpenAPI/Swagger documents hand attackers the full endpoint map, parameter names, auth scheme, and internal hostnames in one request.

> **AI LOAD INSTRUCTION**: Load when assessing REST APIs for exposed specification files during an authorized external review or pre-production audit.

## 0. RELATED ROUTING
- [detecting-graphql-endpoint-schema-enumeration-recon](#) for the introspection equivalent on GraphQL
- [detecting-exposed-environment-file-secret-leak](#) for keys that appear inside specs
- [detecting-directory-listing-exposure-sensitive-files](#) for finding spec files by index browsing

## 1. WHY THE SPEC IS A FINDING BY ITSELF

An OpenAPI document is an attack map. It names every route including undocumented
ones, every parameter, the declared authentication scheme, example values, server
URLs that reveal internal hostnames and non-production environments, and often
`x-internal` extensions, tag descriptions, and deprecation notes that confirm which
endpoints exist but are unadvertised. It converts hours of endpoint discovery into
one GET, and it lets an attacker test every route with correctly formed requests,
which matters because many authorization checks only fire on unexpected input.

## 2. PASSIVE DISCOVERY OF THE SPEC FILE

Check the standard locations plus the vendor UI, which serves the same document:

```
for p in /swagger.json /openapi.json /swagger.yaml /openapi.yaml \
         /api-docs /api-docs.json /v2/api-docs /v3/api-docs \
         /swagger/v1/swagger.json /docs/openapi.json /api/openapi.json \
         /swagger-ui/ /swagger-ui.html /redoc /docs /api-docs/; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "https://target.example$p"
done
```

Content is the oracle, not the status code — SPAs return 200 for everything and some
gateways return 200 with a login page. Confirm on content:

```
curl -s https://target.example/openapi.json | head -c 200
curl -s https://target.example/openapi.json | grep -oE '"(openapi|swagger)":"[0-9.]+"'
```

A body starting `{"openapi":"3.0` or `{"swagger":"2.0"` is definitive.

## 3. READING THE DOC WITHOUT DUMPING IT

A spec can be megabytes. Query it in place so nothing large lands on disk and no
sensitive example values enter a report:

```
curl -s https://target.example/openapi.json \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('servers:', [s.get('url') for s in d.get('servers',[])])
print('schemes:', d.get('securityDefinitions') or list(d.get('components',{}).get('securitySchemes',{})))
print('paths:', len(d.get('paths',{})))
for p,ops in d['paths'].items():
    print(p, ','.join(o.upper() for o in ops if o in ('get','post','put','patch','delete')))
"
```

The path/method listing alone is enough evidence. Grep for leaked internal detail
without printing values: `grep -oE '"(url|host|basePath)":[^,]*'` and a presence-only
check for keys, `grep -icE 'sk_live|BEGIN.*PRIVATE KEY|password'`.

## 4. ASSESSING WHAT THE SPEC REVEALS

- **Internal servers**: `https://10.0.3.7/api` or `staging.corp.example.com` in
  `servers[]` is an internal network map.
- **Admin routes**: paths containing `/admin`, `/internal`, `/debug`, `/actuator`,
  or `/metrics` in a public spec indicate exposed management surface.
- **Over-broad parameters**: mass-assignment risk from writable fields listed in
  schemas (`role`, `isAdmin`, `balance`, `price`).
- **Example secrets**: `example:` values in schemas frequently contain real tokens.
- **Deprecated routes**: entries marked `deprecated: true` are often unmaintained.

## 5. REMEDIATION VERIFICATION

- Serve the spec only in non-production, or behind the same auth as the API.
- If the API is public, publish a *curated* consumer-facing doc rather than the
  internal source of truth; generate it from an allowlist of paths.
- Strip `example` and `x-internal` fields at build time before publishing.
- Set `servers[]` to the public hostname only.
- Add a CI check that the built artifact contains no spec file.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Retrieve the spec
read-only and parse it in a pipeline — do not save multi-megabyte documents to shared
storage, and do not copy example payloads into tickets. Do not call any endpoint the
spec reveals, especially `PUT`, `DELETE`, or `/admin` routes; enumerating a route
map is the objective, invoking routes is out of scope. Do not run automated fuzzers
seeded from a discovered spec. Report route counts and paths by category rather
than pasting full parameter schemas that may contain internal hostnames.

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- OWASP API Security Top 10 (API9): https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
- OpenAPI Specification: https://spec.openapis.org/oas/latest.html
