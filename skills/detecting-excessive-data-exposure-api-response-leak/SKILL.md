---
name: detecting-excessive-data-exposure-api-response-leak
description: >-
  Detecting over-fetching APIs that return more fields than the UI needs (OWASP API3). Covers PII/secret leakage in JSON responses and testing by diffing API output vs rendered UI.
---

# SKILL: Detecting over-fetching APIs that return more fields than the UI needs (OWASP API3). Covers PII/secret leakage in JSON responses and testing by diffing API output vs rendered UI.

> **AI LOAD INSTRUCTION**: Load when assessing whether REST/GraphQL APIs over-return sensitive fields (emails, phone, internal IDs, hashed passwords, tokens) beyond what the interface displays. Covers diffing API vs UI exposure and severity framing.

## 0. RELATED ROUTING
- [detecting-api-error-message-sensitive-data-leak](#) for error-path leakage
- [detecting-api-secret-embedded-in-frontend-bundle](#) for client-side exposure
- [exploiting-cwe-200-server-side-information-exposure](#) for the general exposure class

## 1. THE PATTERN

The frontend requests a subset but the API returns the whole record. Classic extras: `password_hash`, internal `user_id`, `role`, `email` (when not shown), `internal_notes`, `billing_details`, `debug_flags`, session or reset tokens.

## 2. TESTING METHOD

1. Capture the API response (browser devtools / proxy) for a read endpoint.
2. Compare fields returned vs fields rendered in the UI.
3. Any field the UI doesn't need but the API returns is a candidate.

Also probe alternate fields/params requesting more (`?fields=all`, `?include=`, over-posting a nested include).

## 3. SEVERITY FRAMING

High if the leaked field is a secret (hash, token, key) or sensitive PII and the endpoint is reachable pre-auth or for other users' records. Medium for internal IDs/roles that aid other attacks.

## 4. CONFIRM SAFELY

Use your own account/fixture and read your own record's response. Do not enumerate other users' data to prove reachability without authorization — demonstrate on your own data and show the field is present but unused by the UI.

## 5. REMEDIATION

Allowlist response fields (DTO/serializer patterns), not `SELECT *`. Version your API responses. Strip sensitive fields server-side; never rely on the client to ignore a field.

## Sources
- CWE-213: https://cwe.mitre.org/data/definitions/213.html
- OWASP API3 Excessive Data Exposure: https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/

## 6. WHERE IT HIDES

Common over-fetch surfaces that tutorials miss:

- List/bulk endpoints returning full objects when the grid shows only a name
- GraphQL without field-level authorization (request `password`/`email` explicitly)
- "Me"/profile endpoints returning internal account flags
- Export/report endpoints returning raw rows instead of aggregates
- Nested includes (`?include=orders,address`) pulling entire child objects

## 7. ENUMERATION TECHNIQUE

GraphQL makes over-fetch trivial to test — request the sensitive field explicitly:

```graphql
{ user(id: "me") { id email password role internalNotes } }
```

If `password` or `internalNotes` returns data, that's schema-level over-exposure. Confirm on your own account.

## 8. REMEDIATION DETAIL

- Response DTOs/serializers with explicit field lists (never pass the ORM object through)
- GraphQL: field-level resolvers with authorization, not a blanket resolver
- Remove fields entirely rather than nulling them (null still confirms existence)
- Audit historical API versions for the same over-fetch
