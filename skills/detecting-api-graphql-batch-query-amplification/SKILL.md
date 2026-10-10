---
name: detecting-api-graphql-batch-query-amplification
description: >-
  Detect GraphQL query-cost, depth, and alias-based amplification attacks against an API.
---

# SKILL: Detect GraphQL query-cost, depth, and alias-based amplification attacks against an API.

> **AI LOAD INSTRUCTION**: Load when assessing whether a GraphQL endpoint limits query complexity, depth, and batched document count.

## 0. RELATED ROUTING
- [performing-graphql-introspection-attack](#) for schema enumeration context
- [performing-graphql-depth-limit-attack](#) for nested-recursion DoS
- [performing-api-rate-limiting-bypass](#) for transport-level throttling bypass

## 1. THE AMPLIFICATION PROBLEM

GraphQL removes response-shape constraints: one HTTP request can request many fields. Attack
classes that multiply server cost from a single request:

- **Aliasing** - 50 aliases of the same field in one selection set
- **Batching** - an array of operations in one POST body
- **Depth** - nested resolvers each hitting the database
- **Fragments** - recursive spreads expanding combinatorially
- **Directive abuse** - `@skip`/`@include` masking true cost
- **Introspection** - `__schema` on a large schema is itself expensive

Amplification = work performed / work requested. Anything above 5-10x deserves a report.

## 2. BASELINE A BENIGN QUERY

```
curl -s -X POST https://api.example.com/graphql \
  -H "Authorization: Bearer $MY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"{ me { id email } }"}' -w '\nTTFB:%{time_total}s SIZE:%{size_download}\n'
```

Record wall time, response bytes, and DB query count from server logs if available.

## 3. ALIAS AMPLIFICATION

```
curl -s -X POST https://api.example.com/graphql -H "Authorization: Bearer $MY_TOKEN" \
 -H 'Content-Type: application/json' -d @- <<'JSON'
{"query":"{ a1: user(id:1){id} a2: user(id:2){id} a3: user(id:3){id} a4: user(id:4){id}
 a5: user(id:5){id} a6: user(id:6){id} a7: user(id:7){id} a8: user(id:8){id} }"}
JSON
```

Scale gradually toward 100-500 aliases; watch for timeout, 500, or memory growth. A
per-record field like `user(id)` is also a BOLA candidate (see BOLA routing).

## 4. REQUEST BATCHING

```
curl -s -X POST https://api.example.com/graphql -H "Authorization: Bearer $MY_TOKEN" \
 -H 'Content-Type: application/json' -d '[
  {"query":"{ me { id } }"},{"query":"{ me { id } }"},{"query":"{ me { id } }"}]'
```

If the gateway throttles per HTTP request but the app executes an array, one "request" becomes
N operations. Check for an operations-per-request cap.

## 5. DEPTH AND RECURSIVE FRAGMENTS

```
{"query":"{ a { b { c { d { e { f { g { h { i { j { id } } } } } } } } } } }"}
```

```graphql
fragment F0 on Node { id ...F1 }
fragment F1 on Node { id ...F2 }
fragment F2 on Node { id ...F3 }
query { search { ...F0 } }
```

A server that expands fragments without a depth cap can exhaust the stack or build a huge
intermediate selection tree. Look for `MaxDepthError` / `MaxTokensError`-style rejections.

## 6. VALIDATION TO CHECK FOR

The endpoint should clearly reject each of these:

```
{"query":"{ a1: node ... a50: node }","variables":{}}
{"query":"query Q($n:Int){ first:$n }","variables":{"n":100000}}
{"query":"{ users(first: 999999) { id } }"}
```

Missing controls usually show as no error and a slow or huge response. Also verify whether
`__schema { types { fields { ... } } }` is gated in production.

## 7. FIX RECOMMENDATIONS

1. Enforce max depth, max aliases per document, and a computed query-cost metric server-side.
2. Hard-cap every pagination argument (`first`, `last`, `limit`).
3. Limit batched operation count and aggregate cost per HTTP request.
4. Disable introspection in production; expose a curated schema document instead.
5. Time-bound resolvers and enforce per-principal cost budgets over a rolling window.

## 8. RESPONSIBLE TESTING

Run these against your own account or a local fixture with seeded data. Keep alias counts and
batch sizes modest (tens, not thousands) so you never actually load the service. Never target a
third-party GraphQL endpoint without written authorization, and never try to exhaust shared
production capacity.

## Sources
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
- PortSwigger GraphQL: https://portswigger.net/web-security/graphql
- OWASP API4: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
