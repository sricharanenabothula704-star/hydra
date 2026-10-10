---
name: detecting-idor-sequential-identifier-enumeration
description: >-
  Detect Insecure Direct Object Reference via predictable sequential identifiers that let an attacker enumerate and access other users' resources without authorization.
---

# SKILL: Detect Insecure Direct Object Reference via predictable sequential identifiers that let an attacker enumerate and access other users' resources without authorization.

> **AI LOAD INSTRUCTION**: Load when API or web endpoints expose object IDs (numeric, short, or guessable) and you are assessing horizontal privilege boundaries between accounts.

## 0. RELATED ROUTING
- [detecting-broken-object-level-authorization-bola](#) for the general object-authorization class
- [detecting-insecure-direct-object-reference-graphql](#) for the GraphQL variant
- [detecting-jwt-key-confusion-rs256-hs256](#) for when weak IDs compound with token flaws

## 1. WHAT MAKES AN IDOR WITH SEQUENTIAL IDS

A sequential identifier (`/users/1001`) makes objects trivially enumerable. Three things must
coincide: **predictable IDs**, **no ownership check** (the app asks "is the caller logged in?"
but never "does the caller own this object?"), and **data returned** for foreign objects.

Only the missing ownership check is the defect; predictable IDs just lower the cost of
exploiting it. Fix the authorization check first, then add opaque IDs as defense-in-depth.

## 2. ESTABLISH BASELINE ACCOUNTS

Create two low-privilege accounts under your control: **Account A** (owns objects) and
**Account B** (owns nothing relevant). Record their IDs. This gives you a clean authorized /
unauthorized pair to test against.

```bash
TOKEN_A="<token for account A>"; TOKEN_B="<token for account B>"
```

Confirm A can read its own object — this is your positive control:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" https://target/api/v1/orders/A_ORDER_ID
```

## 3. CROSS-ACCOUNT ACCESS TEST

Request an object owned by A using B's token. A `200` with A's data is confirmed horizontal
privilege escalation:

```bash
# Account B requests Account A's object
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_B" https://target/api/v1/orders/A_ORDER_ID
```

| Response | Meaning |
| --- | --- |
| `200` + A's data | IDOR confirmed (object authorization missing) |
| `200` + summary only | Partial leak — fields overexposed |
| `403` | Ownership check exists; verify it holds across all methods |
| `404` | Good — existence not leaked either |

Test every method on the same object: GET, PUT, PATCH, DELETE, and any download/export
variant. Write methods matter most — a DELETE IDOR is high impact.

## 4. SEQUENTIAL ENUMERATION

Confirm the IDs are actually sequential by sampling a small range around a known object, using
only B's token and only a handful of requests:

```bash
for id in $(seq 1000 1010); do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN_B" "https://target/api/v1/orders/$id")
  echo "$id -> $code"
done
```

A run of `200`s across consecutive IDs shows enumeration yields broad access. Keep the range
tiny — proving predictability, not harvesting data. Also test offset encodings
(`?offset=1001`), since IDs are often hidden behind opaque-looking parameters.

## 5. IMPACT ASSESSMENT

Scale by exposure and method:

- **Read** another user's PII, invoices, messages → High/Critical by sensitivity.
- **Write/PATCH** → High (integrity, possible stored XSS). **DELETE** → High (destructive).
- **Financial objects** (invoices, balances, payouts) → Critical.

Also cover file IDs, address IDs, tokens, and nested resources reachable by parent ID
(`/orders/A_ORDER/items/…`).

## 6. DETECTION & HARDENING

- Enforce object-level authorization on **every** request: derive owner from the
  authenticated principal, never from a request parameter, and compare before returning data.
- Prefer opaque, non-sequential IDs (UUIDv4 / ULID) as defense-in-depth, not as the fix.
- Centralize the check in a data-access layer or ORM scope so it applies uniformly across
  every endpoint and method.
- Return `404` (not `403`) for unauthorized objects to avoid leaking existence.
- Add a regression test: for each object endpoint, assert a second account gets `404`.
- Monitor for enumeration patterns (many near-miss IDs from one principal) and alert.

## 7. RESPONSIBLE TESTING NOTE

Use only accounts and data you created; never enumerate into other people's real records or
third-party tenants. Keep ranges minimal — you need the pattern, not the data, since dumping
sequential objects is itself a breach. Never issue write or delete against objects you don't
own; a read-only `200` on one foreign ID already confirms the finding. Obtain written scope
for cross-account testing and stop on confirmation rather than mapping the full data set.

## Sources
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- PortSwigger IDOR: https://portswigger.net/web-security/idor
- OWASP API1 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
