---
name: detecting-api-authorization-bypass-tenant-boundary
description: >-
  Detect cross-tenant data access and privilege escalation across organization boundaries in multi-tenant APIs.
---

# SKILL: Detect cross-tenant data access and privilege escalation across organization boundaries in multi-tenant APIs.

> **AI LOAD INSTRUCTION**: Load when assessing whether API requests are scoped to the caller's tenant or organization context.

## 0. RELATED ROUTING
- [testing-for-broken-access-control](#) for general access-control verification
- [exploiting-idor-vulnerabilities](#) for object-reference manipulation
- [auditing-aws-s3-bucket-permissions](#) for storage-level tenant isolation patterns

## 1. WHY TENANT ISOLATION FAILS

Multi-tenant systems derive context from the wrong layer: from the request body instead of the
authenticated principal, from a header the client controls, or from a cache populated under one
tenant and served to another. Classic breakages:

- `tenantId` taken from a header, query parameter, or JWT claim the user can influence
- Queries filtered by `id` but not by `org_id` on the same row
- Background jobs, exports, or search indexes that drop the tenant predicate
- Object storage paths that encode tenant only in the URL, not in the IAM policy
- Caches (CDN, in-process) keyed without the tenant dimension

## 2. SET UP TWO TENANTS YOU CONTROL

Create tenant `A-user` and `B-user` in your own workspace and seed each with distinct,
synthetic records. Everything below stays inside your own data.

```
curl -s -X POST https://api.example.com/v1/orgs \
  -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
  -d '{"name":"Tenant A"}'
```

Record identifiers: `ORG_A`, `ORG_B`, `USER_A`, `USER_B`, and the record IDs seeded in each.

## 3. HEADER AND PARAMETER TAMPERING

```
curl -s https://api.example.com/v1/records -H "Authorization: Bearer $TOKEN_A"
curl -s https://api.example.com/v1/records -H "Authorization: Bearer $TOKEN_A" \
  -H "X-Tenant-Id: $ORG_B"
curl -s "https://api.example.com/v1/records?tenantId=$ORG_B" \
  -H "Authorization: Bearer $TOKEN_A"
curl -s "https://api.example.com/v1/records?org_id=$ORG_B&include_all=true" \
  -H "Authorization: Bearer $TOKEN_A"
```

Any record from Tenant B in the response is a confirmed tenant-boundary failure.

## 4. CROSS-TENANT OBJECT ACCESS

```
curl -s https://api.example.com/v1/records/$RECORD_B \
  -H "Authorization: Bearer $TOKEN_A"          # expect 403/404
curl -s -X PATCH https://api.example.com/v1/records/$RECORD_B \
  -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
  -d '{"status":"archived"}'                    # never modify foreign records
curl -s https://api.example.com/v1/records/$RECORD_B/audit \
  -H "Authorization: Bearer $TOKEN_A"          # audit/exports leak too
```

A `404` is the preferred correct answer; `403` is acceptable; `200` is the finding.

## 5. NESTED AND INDIRECT PATHS

- `/v1/orgs/{ORG_B}/users` and `/v1/records?owner={USER_B}`
- GraphQL: `node(id:"<base64 global id>")` where IDs encode a different tenant
- Reports, webhooks, exports, and search facets that run a separate query path
- Batch endpoints: one item referencing a foreign ID inside an array

## 6. CACHE AND HEADER LEAKAGE

```
curl -si https://api.example.com/v1/reports/summary -H "Authorization: Bearer $TOKEN_A" | grep -i cache
# repeat for B with a shared CDN in front; look for a cache hit (x-cache: HIT) serving A's data
```

Test whether `Cache-Control: private` / `Vary: Authorization` are set, and whether a shared
cache key omits tenant identity.

## 7. FIX RECOMMENDATIONS

1. Resolve tenant from the authenticated session only; never trust a client-supplied tenant field.
2. Enforce tenant scoping in the data-access layer so it cannot be forgotten per query.
3. Reject any explicit tenant filter that disagrees with the session tenant.
4. Add `Vary: Authorization, X-Tenant-Id` and `Cache-Control: private` on tenant-scoped routes.
5. Apply the tenant predicate to search, exports, jobs, and audit endpoints too.
6. Test the isolation path in CI with automated cross-tenant negative cases.

## 8. RESPONSIBLE TESTING

Perform all isolation testing between two tenants you created yourself in your own workspace.
Stop at proving isolation failure with a read of your own synthetic records; never create,
modify, or delete another customer's data, never access real customer records, and obtain
written authorization before testing a third-party multi-tenant system.

## Sources
- CWE-668: https://cwe.mitre.org/data/definitions/668.html
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP API1 (BOLA): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP multi-tenant guidance: https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html
