---
name: detecting-time-based-blind-sql-injection-waf-bypass
description: >-
  Detecting and confirming time-based blind SQLi, including WAF-evading variants and avoiding noisy load on the target. Covers SLEEP/WAITFOR/pg_sleep/benchmark and timing hygiene.
---

# SKILL: Detecting and confirming time-based blind SQLi, including WAF-evading variants and avoiding noisy load on the target. Covers SLEEP/WAITFOR/pg_sleep/benchmark and timing hygiene.

> **AI LOAD INSTRUCTION**: Load when boolean-based SQLi appears blocked or normalized, and you need to confirm injection via response timing. Covers DB-specific time functions, WAF-evading variations, and how to measure timing without overloading the target.

## 0. RELATED ROUTING
- [exploiting-cwe-89-sql-injection-in-orm-raw-queries](#) for the injection class
- [offensive-sqli](#) for full SQLi methodology
- [detecting-sql-injection-via-waf-logs](#) for WAF-side detection

## 1. TIME FUNCTIONS BY ENGINE

- MySQL/MariaDB: `SLEEP(5)`, `BENCHMARK(10000000,SHA1('test'))`
- PostgreSQL: `pg_sleep(5)`, `SELECT pg_sleep(5)`
- MSSQL: `WAITFOR DELAY '0:0:5'`, `WAITFOR TIME '0:00:05'`
- Oracle: `DBMS_LOCK.SLEEP(5)`
- SQLite: heavy recursive query or `LIKE` with large blob (no SLEEP)

## 2. WAF-EVASING VARIANTS

- Comment/case splitting: `SL/**/EEP(5)`, `SlEeP(5)`
- Conditional wrap: `IF(1=1,SLEEP(5),0)`
- Arithmetic time: `SLEEP(5-4)` so the literal "5" doesn't appear
- Double-URL-encoding the keyword
- Splitting via parameter concatenation where app reassembles

## 3. TIMING HYGIENE (IMPORTANT)

- Establish a baseline with N requests first (network jitter is real).
- Use a low delay (2-3s), not 30s — you only need a detectable delta.
- Never run many concurrent time-based payloads; they add real load to the DB.
- Measure client-side elapsed time yourself; compare distributions, not single samples.

## 4. CONFIRM

Send the same payload 3-5 times and a benign baseline 3-5 times. A consistent multi-second delta only with the injected condition = confirmed time-based blind SQLi. Report the timing evidence.

## 5. REMEDIATION

Parameterize queries (bound parameters). Never string-concatenate SQL. Least-privilege DB accounts. WAF is defense-in-depth, not the fix.

## Sources
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- PortSwigger time-based blind SQLi: https://portswigger.net/web-security/sql-injection/blind#time-based-blind-sql-injection-examples
