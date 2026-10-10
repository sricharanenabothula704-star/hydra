---
name: detecting-coupon-discount-stackable-business-logic-abuse
description: >-
  Test discount engine invariants for stacking, exclusivity, expiry, and reuse defects that let clients exceed intended pricing rules.
---

# SKILL: Test discount engine invariants for stacking, exclusivity, expiry, and reuse defects that let clients exceed intended pricing rules.

> **AI LOAD INSTRUCTION**: Load when reviewing a checkout, promotion engine, or pricing service, or when a pricing dispute suggests client-side enforcement.

## 0. RELATED ROUTING
- [detecting-inventory-race-condition-oversell](#) for concurrent order manipulation
- [offensive-business-logic](#) for the wider logic-abuse methodology
- [testing-for-business-logic-vulnerabilities](#) for manual interception workflow

## 1. THE INVARIANT THAT MATTERS

Discount logic is only as strong as its server-side enforcement. The defect class
is rarely a broken calculation but a missing invariant: every promotion rule
should be a predicate evaluated server-side at checkout time, independent of what
the client sends.

## 2. MAP THE RULES FIRST

From code and product docs, document intended semantics per promotion type:
single-use vs reusable, per-user vs per-cart, per-order vs per-item, exclusive vs
stackable, minimum spend thresholds, discount caps, and expiry boundaries.

```bash
grep -rn --include='*.py' -E 'discount|coupon|promo|voucher' app/ | head -40
grep -rn --include='*.js' -E 'discount|coupon|promoCode|applyCoupon' src/ | head -40
grep -rn -E 'request\.(json|form).*discount|total.*request\.' --include='*.py' app/
```

The single most important check: does the server recompute the final total from
catalog prices, or does it accept a `total` or `discount` field from the client?
Both are one-line indicators, and the second is almost always the bug.

## 3. HIGH-VALUE TEST CASES

Run these against your own cart, one row at a time.

| Case | What it tests |
|---|---|
| Percent coupon plus amount coupon together | Stacking policy |
| Same single-use coupon in two separate carts | Consumption timing |
| Coupon applied, then qualifying item removed | Threshold re-evaluation |
| Coupon applied after changing shipping country | Region eligibility |
| Lower-priced item moved to meet a basket threshold | Threshold gaming |
| Coupon applied, then quantity below the minimum | Post-apply revalidation |
| Time-zone boundary one second either side of expiry | Expiry enforcement |
| Coupon on an already-discounted sale item | Exclusion policy |
| Currency changed after applying | Currency-specific reuse |
| Duplicate coupon key in one JSON body | Parser ambiguity |

## 4. OBSERVING SERVER-SIDE BEHAVIOR

# Stacking policy, then whether the server honors a client-supplied total
curl -s -X POST https://app.example.com/api/checkout/preview \
  -H 'Authorization: Bearer <your-own-session>' -H 'Content-Type: application/json' \
  -d '{"items":[{"sku":"TEST-1","qty":2}],"coupons":["SAVE10","FLAT5"]}' | jq .
curl -s -X POST https://app.example.com/api/checkout/preview \
  -H 'Authorization: Bearer <your-own-session>' -H 'Content-Type: application/json' \
  -d '{"items":[{"sku":"TEST-1","qty":2}],"coupons":["SAVE10"],"total":0.01}' | jq .
```

If the response echoes a `total` you supplied, or a figure violating documented
policy, that is a confirmed logic defect. Report the policy violation and the
response, not an attempt to extract real value.

## 5. CONCURRENCY AND DOUBLE-SPEND

Coupon consumption must be atomic with order placement. Test only with your own
coupons, capped to a handful of parallel requests:

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    https://app.example.com/api/checkout/commit \
    -H 'Authorization: Bearer <your-own-session>' -H 'Content-Type: application/json' \
    -d "{\"coupon\":\"SELFTEST-$1\"}" &
done; wait
```

More than one success for a single-use coupon is a race defect.

## 6. COMMON DEFECTS AND REMEDIATION

Common defects: client-side total calculation the server trusts; coupon validated
at add-to-cart but not re-checked at commit; discount applied per item rather
than per order; mutually exclusive coupons each validated independently;
threshold checked against pre-discount subtotal; coupon state cached per session;
and duplicate JSON keys where parsers disagree on which value wins.

Evaluate all promotions server-side in one place at commit time, deriving the
total from catalog data. Model exclusions as a set evaluated after all coupons
apply, cap the aggregate discount, and consume redemption in the same transaction
as order creation. Add integration tests asserting the invariant for every pair
of mutually exclusive promotion types.

## 7. RESPONSIBLE TESTING

Use your own account, cart, and test SKUs or coupons created for this purpose.
Never complete a real financial transaction, redeem a customer-facing or
partner-issued code, or exploit a found condition to obtain unpaid goods. Confirm
with a benign preview or validation call and report it. Do not test a third-party
merchant or marketplace without written authorization.

## Sources
- CWE-840: https://cwe.mitre.org/data/definitions/840.html
- CWE-472: https://cwe.mitre.org/data/definitions/472.html
- OWASP Business Logic Abuse: https://owasp.org/www-project-web-security-testing-guide/
