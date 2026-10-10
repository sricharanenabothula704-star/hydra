---
name: detecting-race-condition-in-payment-checkout-flow
description: >-
  Detect TOCTOU race conditions in checkout, payment, coupon, and balance-spend flows where concurrent requests bypass a check-then-act sequence and cause double spending or discount abuse.
---

# SKILL: Detect TOCTOU race conditions in checkout, payment, coupon, and balance-spend flows where concurrent requests bypass a check-then-act sequence and cause double spending or discount abuse.

> **AI LOAD INSTRUCTION**: Load when testing order/booking/payment endpoints, coupon or promotion redemption, wallet/balance debits, and inventory holds.

## 0. RELATED ROUTING
- [offensive-toctou](#) for the general time-of-check/time-of-use exploitation methodology
- [exploiting-race-condition-vulnerabilities](#) for Turbo Intruder single-packet tooling
- [detecting-json-mass-assignment-overposting](#) for the adjacent client-side price/field tampering flaw

## 1. WHY RACE CONDITIONS LIVE HERE

Classic flow: read state → decide → write. In a payment path:

```
balance = get_balance(user)          # CHECK
if balance >= amount:               # DECIDE
    debit(balance, amount)          # ACT
```

Two concurrent requests both read the pre-debit balance, both pass, both debit. The defect is
not "no lock" but "check and act are not atomic", so the state the decision relied on is stale
by the time the write lands. Web servers process requests concurrently by design.

## 2. MAP THE CHECK-THEN-ACT SURFACE

Identify endpoints where a validation reads state that a write immediately changes:

- Coupon/promo redemption (`POST /coupons/redeem`) — one coupon, many redemptions.
- Balance/credit spend (`POST /wallet/spend`, gift-card redeem).
- Checkout discount application (`POST /checkout/apply-discount`).
- Inventory/seat holds — book N items, confirm, release.
- One-time actions: "claim", "redeem reward", "apply referral", "issue credit".

For each, note the precondition and the state it reads.

## 3. PARALLEL REPLAY (SAFE, CONTROLLED)

The benign way to test: fire many **identical** requests at your own test checkout or test
coupon, sent in true concurrency, then inspect whether the invariant broke (coupon used twice,
balance overdrawn, two bookings for one seat). Use a sandbox payment gateway and a coupon you
own.

```bash
# 10 identical redemptions, concurrent
for i in $(seq 10); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST https://target/api/coupons/redeem \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"code":"TESTONLY10","order_id":"'$ORDER_ID'"}' &
done; wait
```

Replace with a burst tool (Apache `ab -n 50 -c 20`, `wrk`, or Burp Turbo Intruder) when the
endpoint is slower. `ab` example:

```bash
ab -n 50 -c 25 -X POST https://target/api/coupons/redeem \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"TESTONLY10","order_id":"12345"}'
```

## 4. INTERPRETING THE RESULT

Break = the invariant did not hold. Evidence looks like:

- Coupon/discount applied **more than once** to the same order or account.
- Balance/spend recorded twice, or driven negative.
- Two confirmed orders for one seat/slot, or inventory count below zero.
- A one-time action (referral credit, reward) credited multiple times.

A single-threaded retry does **not** disprove the bug — races need concurrency. If 50
concurrent requests never broke it, that suggests the flow serializes (lock, DB constraint, or
idempotency key); confirm the mechanism in code before concluding.

## 5. ORDERING-BASED VARIANTS

Races are not always "same request × N". Also probe **split across endpoints** (apply discount
and submit order sent concurrently, so the discount lands after the price was computed),
**duplicate submit** (two tabs → two charges for one order ID), and **bracketed reads** (two
balance reads around a single write).

## 6. DETECTION & REMEDIATION

- Make check-and-act atomic: perform the read, decision, and write inside a single DB
  transaction with row locking (`SELECT ... FOR UPDATE`) or an atomic conditional update
  (`UPDATE ... WHERE balance >= amount`).
- Enforce invariants at the data layer with unique constraints (one redemption per coupon per
  account) and non-negative check constraints (balance >= 0, inventory >= 0).
- Use idempotency keys on payment/charge endpoints and reject replays of the same key.
- Serialize per-resource with a distributed lock where cross-service races are possible.
- Alert on near-simultaneous redemptions of the same code and on any negative-balance write.

## 7. RESPONSIBLE TESTING NOTE

Race testing is inherently high-volume and financially risky — only ever run it against a
sandbox/staging payment gateway and coupons, balances, and inventory you created. Never
concurrency-test a production payment endpoint or use real funds: even if the race "succeeds"
you have just created a real double-charge against a real customer. Keep the burst small (10–50
requests), target a single test order/coupon you own, and abort immediately once you observe
the invariant breaking — you do not need to prove it repeatedly. Never race a refund, payout,
or transfer endpoint, and never point the test at another user's order. Any testing that
transfers value, even test value, needs explicit written authorization and a named sandbox
owner on the call.

## Sources
- CWE-362: https://cwe.mitre.org/data/definitions/362.html
- CWE-367: https://cwe.mitre.org/data/definitions/367.html
- PortSwigger Race Conditions: https://portswigger.net/web-security/race-conditions
- OWASP Testing Guide (Business Logic): https://owasp.org/www-project-web-security-testing-guide/
