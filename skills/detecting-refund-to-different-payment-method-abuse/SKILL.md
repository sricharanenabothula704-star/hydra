---
name: detecting-refund-to-different-payment-method-abuse
description: >-
  Test refund flows for destination substitution, amount inflation, and replay, where a refund is redirected to an instrument other than the charge or exceeds the captured amount.
---

# SKILL: Test refund flows for destination substitution, amount inflation, and replay, where a refund is redirected to an instrument other than the charge or exceeds the captured amount.

> **AI LOAD INSTRUCTION**: Load when reviewing refunds, chargebacks, credits, or wallet payouts in a payment integration.

## 0. RELATED ROUTING
- [detecting-coupon-discount-stackable-business-logic-abuse](#) for sibling commerce logic flaws
- [testing-for-business-logic-vulnerabilities](#) for the interception workflow
- [detecting-inventory-race-condition-oversell](#) for concurrent mutation patterns

## 1. WHY REFUNDS ARE A DISTINCT ATTACK SURFACE

Refunds invert the trust direction: instead of proving you hold funds, the caller
must prove entitlement to funds that do not yet exist. Every refund path must bind
three things together, the original charge, the requested amount, and the
destination instrument. When any is decoupled, an attacker chooses where money
appears.

## 2. THE FOUR DECOUPLINGS

| Decoupling | Abuse |
|---|---|
| Arbitrary destination | Cash out stolen card data to an attacker instrument |
| Uncapped amount | Refund the full order repeatedly against a partial capture |
| Unsettled charge | Refund an authorization never captured, or a refunded charge |
| Request replay | Re-submit the same request to multiply payouts |

## 3. TRACE THE CODE PATH

```bash
grep -rn --include='*.py' -E 'refund|chargeback|credit|void|reversal' app/ | head -40
grep -rn --include='*.js' -E 'refund|chargeback|void' src/ | head -40
# Where does the destination instrument come from?
grep -rn -E 'request\.(json|form|args).*(account|destination|payout|iban|card)' --include='*.py' app/
```

Read the handler and ask whether the payout account is derived from the original
charge record or supplied by the caller. A `destination_account_id` accepted from
the request body is a high-confidence finding.

## 4. WHAT CORRECT IMPLEMENTATION REQUIRES

Store the charge's instrument identifier server-side at capture time and never
accept it on the refund request. Validate the amount against the settled amount
minus prior refunds, in integer minor units, never floating point. Require a
settled, non-disputed charge owned by the authenticated principal. Enforce
idempotency with a key scoped to the charge, and record an immutable audit trail
of actor, charge, amount, instrument, and reason.

## 5. SAFE VALIDATION WITH OWN FIXTURES

Use your own merchant test account in a sandbox or with test-mode credentials.
Never use a live card or a real customer account. Each call targets a distinct
behavior, on charges you created:

```bash
AUTH='Authorization: Bearer <your-own-sandbox-key>'
CT='Content-Type: application/json'
B='https://api.example.com/v1/refunds'
# 1. Baseline single refund
curl -s -X POST $B -H "$AUTH" -H "$CT" -d '{"charge_id":"ch_selftest_1","amount":1000}' | jq .
# 2. Amount above the captured amount
curl -s -X POST $B -H "$AUTH" -H "$CT" -d '{"charge_id":"ch_selftest_1","amount":999999}' | jq .
# 3. Replay of the identical request
curl -s -X POST $B -H "$AUTH" -H "$CT" -d '{"charge_id":"ch_selftest_1","amount":1000}' | jq .
# 4. Caller-supplied destination instrument
curl -s -X POST $B -H "$AUTH" -H "$CT" \
  -d '{"charge_id":"ch_selftest_1","amount":100,"destination_account":"acct_OTHER"}' | jq .
```

Read the outcome as authorization behavior, not as a transfer. A `200` on the
over-amount request, a second `200` on replay with a distinct refund id, or a `200`
honoring `destination_account` are confirmed defects. Then stop.

## 6. CONCURRENCY

Parallel refunds against one charge are the highest-value variant, because
sequential validation passes. Launch six identical refund calls to a charge you
created with `for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" -X
POST $B -H "$AUTH" -H "$CT" -d '{"charge_id":"ch_selftest_2","amount":1000}' & done;
wait`. More successful refunds than the remaining refundable balance is a
confirmed race.

## 7. RELATED CHECKS, REMEDIATION, AND MONITORING

Check for free-form reason codes used as attacker-controlled storage, admin tooling
that refunds any user's charge without second approval or customer notification,
wallet payouts with no reconciliation against settled amounts, partial-capture
flows refunding against the authorized rather than captured amount, and currency
mismatch on multi-currency charges.

Derive every refund attribute from the server-side charge record, wrap the balance
check and refund write in one transaction with a row lock, and require an
idempotency key. Alert on refund volume spikes, refunds issued seconds after
capture, and destination differing from the capture instrument.

## 8. RESPONSIBLE TESTING

Use only sandbox credentials, test-mode gateways, test cards, charges, and accounts
you created. Never perform a real refund, move real funds, test a third-party
payment provider or a merchant's live keys, or attempt a refund against another
user's charge. Confirm behavior from the API's authorization responses and
document the finding. Written authorization is required before any payment-flow
testing beyond your own sandbox.

## Sources
- CWE-841: https://cwe.mitre.org/data/definitions/841.html
- CWE-472: https://cwe.mitre.org/data/definitions/472.html
- OWASP Business Logic Abuse: https://owasp.org/www-project-web-security-testing-guide/
