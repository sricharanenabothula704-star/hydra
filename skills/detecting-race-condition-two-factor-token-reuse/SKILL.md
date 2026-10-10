---
name: detecting-race-condition-two-factor-token-reuse
description: >-
  Detecting OTP/TOTP replay and race conditions. Covers one-time-token reuse windows, concurrent verification bypasses, and time-window edge cases.
---

# SKILL: Detecting OTP/TOTP replay and race conditions. Covers one-time-token reuse windows, concurrent verification bypasses, and time-window edge cases.

> **AI LOAD INSTRUCTION**: Load when assessing OTP/MFA token verification for replay or race conditions. Covers whether a used OTP can be reused, whether concurrent requests bypass one-time enforcement, and safe testing with your own tokens.

## 0. RELATED ROUTING
- [detecting-mfa-fatigue-push-bombing-session-hijack](#) for MFA-side attacks
- [detecting-race-condition-in-payment-checkout-flow](#) for the general TOCTOU pattern
- [exploiting-cwe-362-race-condition-bypass-limits](#) for the CWE class

## 1. THE FLAWS

- **Replay window:** the token remains valid after use (server doesn't mark it consumed) → the same 6-digit code works twice within its time window.
- **Race on verification:** the "is this OTP already used?" check and the "mark used" write aren't atomic. Fire two concurrent verifications with the same valid OTP; both may succeed.
- **Window edge cases:** a TOTP accepted one code too early/late (skew) or at boundary times.
- **Bind failures:** the OTP isn't bound to the specific user/session/action, so it can be reused elsewhere.

## 2. SAFE TESTING

Only with your OWN account and your OWN OTP.

1. Request an OTP for your account.
2. Verify it once (succeeds).
3. Immediately verify the **same** OTP again — if it succeeds, replay confirmed.
4. For the race: with a fresh valid OTP, fire 2-5 concurrent verification requests. If more than one succeeds, it's a race.

Never attempt this against another user's account or OTP.

## 3. ROOT CAUSES & FIX

- Store a used-token marker atomically with the verification (single DB transaction / compare-and-set on nonce or counter).
- Bind OTP to (user, purpose, session) and single-use.
- Enforce a small clock-skew tolerance and invalidate on use.
- Rate-limit verification attempts and lock the flow after N failures.

## 4. FRAMING

A replayable OTP undermines MFA (it's now a reusable second factor) — medium/high. A concurrent-verification race that yields multiple authenticated sessions is high. Show your own-account reproduction.

## Sources
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CWE-367: https://cwe.mitre.org/data/definitions/367.html
- OWASP MFA guidance: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
