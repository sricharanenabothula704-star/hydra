---
name: detecting-json-mass-assignment-overposting
description: >-
  Detect mass assignment/overposting where a JSON API binds extra client-supplied fields (role, isAdmin, price, balance) to the data model, enabling privilege or price tampering.
---

# SKILL: Detect mass assignment/overposting where a JSON API binds extra client-supplied fields (role, isAdmin, price, balance) to the data model, enabling privilege or price tampering.

> **AI LOAD INSTRUCTION**: Load when testing REST/JSON create or update endpoints that accept an object body and persist more fields than the UI exposes.

## 0. RELATED ROUTING
- [detecting-broken-object-level-authorization-bola](#) for the authorization gap that usually accompanies mass assignment
- [detecting-http-parameter-pollution-filter-bypass](#) for duplicate-key and multi-field parsing tricks
- [exploiting-mass-assignment-in-rest-apis](#) for exploitation-side tooling and payloads

## 1. HOW MASS ASSIGNMENT WORKS

An endpoint receives JSON, an ORM/model binds every supplied key to a settable attribute, and
fields the client never should control (`role`, `is_admin`, `price_cents`, `balance`,
`email_verified`, `owner_id`) get written straight to the database. UI hiding is not
enforcement: an attacker posts the same JSON the browser would, plus extra keys.

The vulnerability is architectural — an allowlist is absent at the binding boundary — so it
tends to appear on every endpoint that shares the same serializer/serializer_factory.

## 2. MAP THE WRITABLE SURFACE

Enumerate create/update endpoints and, for each, note the response body: it usually lists the
model's real fields, which is your candidate set of over-writable attributes.

```bash
# Baseline create (use your own low-privilege test account)
curl -s -X POST https://target/api/v1/users \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","email":"t@example.com"}' | jq .
```

From the returned object, build a candidate list: any field the client should never set
(roles, flags, ownership, pricing, audit/stamp fields, counters).

## 3. BENIGN CONFIRMATION

Add one sensitive field at a time to a benign create, using your own test account and your own
data. Do not test on real users or production records.

```bash
curl -s -X POST https://target/api/v1/users \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser2","email":"t2@example.com","is_admin":false}' | jq .is_admin
```

Patterns worth probing (one field per request, on data you own):

| Field class | Examples | Signal if persisted |
| --- | --- | --- |
| Privilege | `role`, `is_admin`, `permissions[]`, `scope` | response/GET shows elevated value |
| Ownership | `user_id`, `owner_id`, `tenant_id`, `account_id` | record linked to another principal |
| Integrity | `email_verified`, `kyc_status`, `approved` | flag true without doing the flow |
| Financial | `price`, `amount`, `credit`, `discount_pct`, `balance` | value differs from what was charged |

Nested objects and arrays (`{"profile":{"is_admin":true}}`) often bypass a shallow field
allowlist — test the shape the ORM actually binds, not just the top level.

## 4. UPDATE/PATCH OVERPOSTING

Creation is not the only surface. Partial updates with PUT/PATCH frequently bind the whole
model:

```bash
curl -s -X PATCH https://target/api/v1/users/ME_ID \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' | jq .role
```

If `role` changes, mass assignment is confirmed on update. Follow with a GET to confirm the
change persisted, not just appeared in the response.

## 5. IMPACT ASSESSMENT

- **Privilege escalation**: setting `role`/`is_admin`/`permissions` to gain capabilities.
- **Financial tampering**: altering `price`, `balance`, `credit`, or refund amounts.
- **Ownership takeover**: rebinding `owner_id`/`tenant_id` to access another principal's data.
- **Compliance flags**: setting `kyc_status`/`email_verified` to bypass onboarding.

Chain with the BOLA skill: mass assignment sets a foreign key, BOLA reads/writes through it.
Privilege escalation on an admin field is Critical even without further exploitation.

## 6. DETECTION & REMEDIATION

- Enforce an explicit per-endpoint field allowlist at the serializer (deny-by-default), not a
  denylist of dangerous keys — denylists miss vendor-specific and future fields.
- Bind a request DTO/schema, then map field-by-field to the model.
- Ignore client-supplied values for ownership, pricing, and status fields; derive server-side.
- Add negative tests asserting `role`/`price` in a request body are ignored or rejected (400).
- Add a CI check: any new serializer/model must declare its writable field list.

## 7. RESPONSIBLE TESTING NOTE

Only ever modify records you created under your own test account — never escalate a real
user, never touch production pricing or balances, and never set flags on records you don't
own. Attempting `role:"admin"` is a controlled, non-destructive probe; actually using the
resulting privilege would not be. If a field is accepted, stop at demonstrating persistence
via a GET and report — do not exercise the elevated capability. Keep request counts minimal,
use dedicated test data, and have destructive/privileged actions (actually granting roles,
altering live financial data) pre-authorized in writing by the system owner.

## Sources
- CWE-915: https://cwe.mitre.org/data/definitions/915.html
- PortSwigger Mass Assignment: https://portswigger.net/web-security/mass-assignment
- OWASP API5 / API Mass Assignment: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
