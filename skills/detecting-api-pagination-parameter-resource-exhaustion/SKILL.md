---
name: detecting-api-pagination-parameter-resource-exhaustion
description: >-
  Detect unbounded limit, offset, page, and cursor parameters that exhaust backend resources.
---

# SKILL: Detect unbounded limit, offset, page, and cursor parameters that exhaust backend resources.

> **AI LOAD INSTRUCTION**: Load when assessing whether list endpoints cap page size, bound deep offsets, and time out safely.

## 0. RELATED ROUTING
- [performing-api-rate-limiting-bypass](#) for request-volume based exhaustion
- [detecting-api-graphql-batch-query-amplification](#) for query-shape amplification
- [detecting-anomalous-authentication-patterns](#) for correlating abusive callers

## 1. THE EXHAUSTION PATTERN

Pagination is the least-validated input on most APIs. Dangerous parameter shapes:

- `limit`, `page_size`, `per_page`, `count`, `size` with no hard maximum
- `offset`, `skip`, `start_index` forcing deep scans (OFFSET 1000000 in PostgreSQL)
- Negative or overflowing values (`limit=-1`, `limit=0`, `limit=1e9`)
- Type confusion (`limit[]=1&limit[]=2`, `limit={"a":1}`)
- Multiple/conflicting params (`limit=10&per_page=1000`) where the looser wins
- `fields`/`include` expansion multiplying result size without a cap
- Cursor params accepted as unbounded opaque blobs

## 2. ESTABLISH A BASELINE

```
curl -s -o /dev/null -w 'code=%{http_code} time=%{time_total}s bytes=%{size_download}\n' \
  'https://api.example.com/v1/items?limit=20' -H "Authorization: Bearer $MY_TOKEN"
```

Measure with your own data volume first. If your dataset is small, prefer a staging
environment or a seeded fixture so the effect is observable without stressing production.

## 3. TEST UNBOUNDED LIMITS

```
for v in 1000 100000 1000000 -1 0 2147483647; do
  curl -s -o /dev/null -w "limit=$v code=%{http_code} time=%{time_total}s size=%{size_download}\n" \
    "https://api.example.com/v1/items?limit=$v" -H "Authorization: Bearer $MY_TOKEN"
done
```

A correct server clamps to a maximum (often 100) or returns 400. Watch for 200 responses whose
size and latency grow linearly with the parameter.

## 4. TEST DEEP OFFSETS

```
for o in 1000 10000 100000; do
  curl -s -o /dev/null -w "offset=$o code=%{http_code} time=%{time_total}s\n" \
    "https://api.example.com/v1/items?limit=50&offset=$o" -H "Authorization: Bearer $MY_TOKEN"
done
```

If latency grows roughly linearly with offset, the query is doing a full scan and discard.
Properly designed APIs use keyset/cursor pagination where cost stays flat.

## 5. TYPE CONFUSION AND CONFLICT

```
curl -s 'https://api.example.com/v1/items?limit[]=100000&limit[]=1' -H "Authorization: Bearer $T"
curl -s 'https://api.example.com/v1/items?limit=10&per_page=1000000'      -H "Authorization: Bearer $T"
curl -s 'https://api.example.com/v1/items?limit=100000&page_size=1'      -H "Authorization: Bearer $T"
curl -s 'https://api.example.com/v1/items?limit=NaN'                    -H "Authorization: Bearer $T"
curl -s 'https://api.example.com/v1/items?limit=100000&fields=a,b,c,d'  -H "Authorization: Bearer $T"
```

Ambiguous parameter names are a design smell: the server should reject unknown duplicates.

## 6. SERVER-SIDE SIGNALS

Look for correlated resource use: database CPU, connection pool saturation (`too many clients`),
GC pressure, or upstream timeouts. Common fingerprints of exhaustion in logs:

```
grep -E 'FATAL: sorry, too many clients|connection pool exhausted|upstream timed out' app.log
```

Verify that queries are indexed and that `COUNT(*)` for a total is not run per request on huge
tables. Confirm response compression is on; an uncompressed 500 MB JSON page is a DoS by itself.

## 7. FIX RECOMMENDATIONS

1. Enforce a hard server-side maximum (e.g. 100) and reject out-of-range values with 400.
2. Validate type and reject arrays, objects, NaN, and negative numbers at the parser.
3. Prefer keyset/cursor pagination; cap `offset` at a low threshold.
4. Reject unknown or conflicting pagination parameter names instead of picking one.
5. Cap field-expansion counts; disable total counts on large result sets.
6. Enforce statement timeouts, connection pool limits, and per-principal cost budgets.

## 8. RESPONSIBLE TESTING

Test only systems you own or are authorized to test, against your own account and your own data
or a seeded fixture. Use a small set of escalating values and stop at the first sign of
degradation; do not attempt to actually exhaust or take down production capacity, and never run
these against a third-party service.

## Sources
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- OWASP API4: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
