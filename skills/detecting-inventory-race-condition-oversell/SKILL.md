---
name: detecting-inventory-race-condition-oversell
description: >-
  Find and confirm non-atomic stock reservation paths where concurrent checkouts can decrement inventory below zero or fulfill orders that exceed supply.
---

# SKILL: Find and confirm non-atomic stock reservation paths where concurrent checkouts can decrement inventory below zero or fulfill orders that exceed supply.

> **AI LOAD INSTRUCTION**: Load when reviewing order placement, reservation, or warehouse allocation code, or when reconciling stock counts against orders.

## 0. RELATED ROUTING
- [detecting-coupon-discount-stackable-business-logic-abuse](#) for concurrent coupon consumption
- [race-condition](#) for the general concurrency playbook
- [business-logic-vuln](#) for the broader logic-abuse family

## 1. WHY OVERSELL HAPPENS

The classic defect is a read-then-write gap: the handler reads available stock,
checks it against the requested quantity, then later decrements. Between those two
statements another request can pass the same check. The check is a snapshot, not
an invariant; correct implementations make the reservation atomic at the storage
layer.

## 2. LOCATE THE INVENTORY CODE PATH

```bash
grep -rn --include='*.py' -E 'stock|inventory|quantity|on_hand|available' app/ | head -40
grep -rn --include='*.sql' -E 'UPDATE .*(stock|quantity)|SELECT .*(stock|quantity)' . | head
grep -rn -E 'decrement|reserve|allocate' --include='*.py' --include='*.js' app/ src/
```

Classify each path:

- **Check-then-act**: `SELECT stock; if stock >= qty: UPDATE stock = stock - qty`.
- **Guarded update**: `UPDATE stock SET qty = qty - :n WHERE id = :id AND qty >= :n`,
  then check the affected row count. This is correct only if the application
  verifies `rowcount == 1` and fails the order otherwise.
- **Serialized transaction**: correct if the transaction isolation actually
  prevents the anomaly, which requires knowing the isolation level and whether the
  read takes a lock.
- **Cache-backed availability**: a Redis or in-process counter that is decremented
  but reconciled asynchronously. Inherently oversells unless a hard bound exists
  at the database.

## 3. CONFIRMING THE DEFECT

Test only against inventory you control, using a dedicated test product you
created and a test account you own. Set stock to a small number (for example 1),
then fire concurrent purchase attempts and count successes:

```bash
# Only against your own test SKU in a staging or test environment
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://app.example.com/api/orders \
    -H 'Authorization: Bearer <your-own-session>' -H 'Content-Type: application/json' \
    -d '{"items":[{"sku":"SELFTEST-1","qty":1}]}' &
done; wait

# Reconcile: confirmations must not exceed stocked quantity
curl -s https://app.example.com/api/inventory/SELFTEST-1 \
  -H 'Authorization: Bearer <your-own-session>' | jq .
```

More than one confirmed order for a quantity of 1 is a confirmed oversell defect.
Stop immediately after demonstrating it; do not attempt to complete purchases or
to exploit the resulting negative stock for value.

## 4. TIMING WINDOWS AND AMPLIFICATION

Oversell probability rises with contention. Align requests to the same instant
with a small thread pool rather than a large load. Two extra classes to check
statically, since they are hard to trigger safely:

- **Multi-region**: two databases or caches with independent stock counters and
  no shared authority.
- **Async processing**: order confirmed immediately, but the decrement runs in a
  background job, so no user-visible failure occurs when stock runs out.

## 5. CONFIRMATION VS RESERVATION SEMANTICS

A robust design distinguishes `available`, `reserved`, and `sold`, with a
reservation expiry. Check whether cancellation and payment timeout release a
reservation, and whether that release is idempotent. Decrementing on confirm
without a prior reservation leaves a window that only luck closes.

## 6. OBSERVABILITY

Inventory reconciliation should alert on negative or implausible stock, and
oversell alerts should exist at order confirmation. Absence of these signals is
its own finding: oversells can persist undetected for months.

## 7. REMEDIATION

Use a single atomic statement per reservation, or a serializable transaction with
an explicit lock:

```sql
UPDATE inventory SET available = available - :qty
WHERE sku = :sku AND available >= :qty;
-- application must check that exactly one row was updated
```

Use a test SKU, test orders, and accounts you created. Never place real orders
against a merchant, never consume real stock, and never complete a financial
transaction to demonstrate the defect. Prefer a staging environment or a
local fixture. Stop at the first confirmed oversell and report the count
discrepancy. Written authorization is required before concurrency testing any
shared or third-party inventory system.

## Sources
- CWE-362: https://cwe.mitre.org/data/definitions/362.html
- CWE-840: https://cwe.mitre.org/data/definitions/840.html
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
