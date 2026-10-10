---
name: detecting-broken-object-level-authorization-bola
description: >-
  Detect Broken Object Level Authorization where an API authenticates the caller but fails to verify they own or may access the specific object ID requested (OWASP API1).
---

# SKILL: Detect Broken Object Level Authorization where an API authenticates the caller but fails to verify they own or may access the specific object ID requested (OWASP API1).

> **AI LOAD INSTRUCTION**: Load when assessing REST/GraphQL endpoints that take an object identifier in the path, query, or body and return per-user data or state.

## 0. RELATED ROUTING
- [detecting-idor-sequential-identifier-enumeration](#) for the predictable-ID framing of the same flaw
- [detecting-json-mass-assignment-overposting](#) for over-writable ownership fields that chain into BOLA
- [detecting-insecure-direct-object-reference-graphql](#) for the GraphQL resolver-level variant

## 1. WHAT BOLA ACTUALLY MEASURES

BOLA (OWASP API1, the #1 API risk) is a horizontal/vertical authorization failure at the
object layer. The app checks *who you are* (authentication) and sometimes *what role you
hold* (function-level authorization), but never checks *whether this specific record belongs to
you or your tenant*. Correct authn + missing object authz = BOLA.

Three axes break in different ways:

- **Horizontal**: user A reads/writes user B's object.
- **Vertical**: a normal user performs an admin action on an object.
- **Tenant**: user in org 1 reaches org 2's object.

## 2. BUILD A TWO-IDENTITY TEST MATRIX

Create two accounts you control (A and B) plus, if in scope, a third in another tenant.
Collect a token for each and a list of object IDs each owns. You will cross every object with
every identity:

```bash
TOK_A="<A>"; TOK_B="<B>"
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOK_A" \
  "https://target/api/v1/invoices/B_INVOICE_ID"
```

Methodically test A-token against B-object and B-token against A-object for every endpoint and
method. A `200` where you expect `403`/`404` is a confirmed BOLA.

## 3. SYSTEMATIC ENDPOINT COVERAGE

For each candidate endpoint, walk this ladder:

1. **Unauthenticated** — no token at all. Should be `401`. `200` = unauthenticated data leak.
2. **Wrong object** — valid token, other user's object. Should be `403`/`404`.
3. **Nested object** — parent owned by A, child of B (`/invoices/A_INV/items/B_ITEM`). Child
   IDs are frequently unvalidated because developers check the parent and forget the child.
4. **Method sweep** — GET, PUT, PATCH, DELETE, and bulk/export endpoints.
5. **Alternate identifier types** — internal numeric ID vs public UUID vs slug. An endpoint
   that accepts the internal ID often skips the ownership check the slug endpoint has.

Nested-object step 3 is the highest-yield common bug: verifying the parent but not the child.

## 4. FIELD-LEVEL LEAK CHECK

A `200` with the right object but extra fields is overexposure that still matters. Compare the
response body for A's own object against B's object — any field populated from another tenant
(tier, email, balance, internal notes) is a data leak even if IDs match:

```bash
curl -s -H "Authorization: Bearer $TOK_B" \
  "https://target/api/v1/invoices/A_INVOICE_ID" | jq 'keys'
```

## 5. GRAPHQL AND BATCH ANGLE

GraphQL collapses many endpoints into one, so BOLA often hides in resolver arguments. Also
test REST batching (`[{"id":1},{"id":2}]`) and bulk endpoints, where per-item authorization
is frequently skipped in favor of a single top-level check.

## 6. DETECTION & REMEDIATION

- Enforce object authorization centrally: derive `owner_id`/`tenant_id` from the token, never
  from the request, and scope every query/lookup by it (ORM-level scoping, not per-handler).
- Centralize in a policy/data-access layer so every endpoint inherits it; new endpoints should
  be secure-by-default.
- Default-deny: an endpoint with no explicit object policy returns `403`.
- Return `404` over `403` for foreign objects to avoid existence leaks.
- Add automated cross-tenant regression tests to CI for every object endpoint.
- Log and alert on cross-tenant access denials; spikes may indicate enumeration.

## 7. RESPONSIBLE TESTING NOTE

Only use identities and objects you created or were explicitly provisioned for this test. Do
not enumerate or probe real customer records, other tenants, or admin accounts you were not
given — reading another user's real invoice is a data breach regardless of authorization. Test
read-only first and stop at the first confirmed `200`; do not perform write, delete, or state
changes on foreign objects. Keep request volume minimal, coordinate with the owner on
production, and note in your report exactly which identities you used as evidence so the
finding can be responsibly reproduced.

## Sources
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP API1 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PortSwigger IDOR: https://portswigger.net/web-security/idor
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
