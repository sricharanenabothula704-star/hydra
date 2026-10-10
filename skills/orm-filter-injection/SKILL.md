---
name: orm-filter-injection
description: >-
  ORM leak / relational filter injection playbook. Use when apps spread client input into ORM query filters or expose generic filtering/search DSLs — hidden-field lookups, password-column oracles, mass data extraction without raw SQLi.
---

# SKILL: ORM Leak & Relational Filter Injection

> **AI LOAD INSTRUCTION**: Filter-injection class from 2025 research ("Leaking More Than You Bargained For", Top-10 2025 nominee pool). No raw SQL needed: when user input becomes ORM filter keys/values, attackers query columns they should never touch (password hashes, reset tokens, is_admin). Scanner-invisible — pure logic.

## 1. CORE CONCEPT

Frameworks build queries like `Model.filter(**request.args)` or accept JSON filter DSLs. If the FILTER FIELD NAME is attacker-controlled, you choose which column to match on:

```
GET /api/users?username=alice          # intended
GET /api/users?password[$ne]=x         # injected: matches EVERY user
GET /api/users?reset_token=abc         # oracle: does this token exist?
```

No quotes broken, no SQL error — yet full-table reads and blind oracles are yours.

## 2. VULNERABLE PATTERNS BY STACK

### Django (Python)
```python
User.objects.filter(**request.GET.dict())   # spreads any column name
# Inject: ?is_superuser=1  ?password__startswith=a  (char-by-char extraction)
```

### Prisma (Node)
```json
POST /api/search {"filter": {"role": "admin"}}
{"filter": {"password": {"startsWith": "a"}}}   // nested operators
```

### Ransack (Rails) / GraphQL where-inputs / Mongoose `$where`
Same shape: attacker picks field + operator. Mongoose variant lives in `nosql-injection/SKILL.md`.

## 3. DETECTION (differential, no extraction)

For each candidate param, send lookup twins:
1. **Empty-prefix probe**: `field[$starts_with]=""` style → matches ALL rows (response count jumps)
2. **Impossible-prefix probe**: same field with value `"zzz-impossible-zzz"` → matches NONE
3. **Reproducible flip** between twins = the field is being applied as a filter → LEAD confirmed

Also probe hidden fields directly: `password`, `token`, `secret`, `is_admin`, `email_verified`, `reset_token`.

## 4. EXPLOITATION LADDER

1. Existence oracle: does `reset_token=X` exist? (account-takeover recon)
2. Boolean extraction: `password[starts_with]=a` → binary-search every char of every hash
3. Mass read: operator flips (`$ne`, `$gt`) returning whole tables
4. Privilege probing: `is_admin=true` filters reveal admin accounts
Stop at proof-of-concept scale — extraction beyond 1–2 records is weaponization.

## 5. METHODOLOGY

1. Inventory list/filter/search/export endpoints + their param shapes
2. Fuzz filter KEYS (not values): common column names × operator suffixes (`__gt`, `_gte`, `$ne`, `startsWith`)
3. Run twin-differential per hit; log reproducible flips
4. Map reachable sensitive columns; report with one clean differential PoC

## 6. FALSE POSITIVE TRAPS

- Response-count changes from pagination/caching — use identical requests differing ONLY in the probe value
- Strictly-typed schemas reject unknown keys (400) = not injectable via that param (note it, try nested/base objects)
- Public search fields matching by design ≠ leak — prove a SENSITIVE column responds

## 7. DEFENSES (for reports)

Allowlist filterable fields explicitly; never spread raw dicts into ORM calls; strip operator suffixes; type-coerce filter values; denylist sensitive columns at the repository layer.

## REFERENCES
- "Leaking More Than You Bargained For" (2025, Top-10 nominee pool)
- Related: `nosql-injection/SKILL.md` (operator injection for document stores)
