---
name: detecting-mfa-fatigue-push-bombing-session-hijack
description: >-
  Assess MFA challenge flows for push-bombing resistance, number matching, replay, and session binding, so an attacker holding a password cannot ride a legitimate user's approval.
---

# SKILL: Assess MFA challenge flows for push-bombing resistance, number matching, replay, and session binding, so an attacker holding a password cannot ride a legitimate user's approval.

> **AI LOAD INSTRUCTION**: Load when reviewing MFA enrollment, challenge issuance, approval handling, or step-up authentication.

## 0. RELATED ROUTING
- [detecting-session-token-predictability-brute-force](#) for post-approval session handling
- [detecting-password-reset-account-enumeration-timing](#) for the credential-recovery path
- [authbypass-authentication-flaws](#) for adjacent authentication defects

## 1. THE ATTACK MODEL

Push bombing assumes the attacker already has the password, typically from a
credential fill. The victim is on a real device receiving authentic-looking
prompts; a train of them induces a reflexive tap, and one approval completes the
attacker's pending request. The defect is not that the user approved, it is that
the flow trained the user to approve under pressure without showing which request
they were approving.

## 2. NUMBER MATCHING AND APPROVAL BINDING

The core control is letting the user correlate the prompt with a login they
initiated.

```bash
grep -rn --include='*.py' -E 'mfa|2fa|totp|push|otp|challenge' app/ | head -40
grep -rn --include='*.js' -E 'mfa|totp|push|otpChallenge' src/ | head
grep -rn -E 'number.?match|user.?present' --include='*.py' --include='*.js' app/ src/
```

Verify that the prompt shows a **number match** (two-digit code) or at minimum the
service, location, and device; that a visible `deny` control ends the challenge;
that the pending request carries a session identifier bound to the authenticating
device and network context, so approval elsewhere cannot complete it; and that
approval is consumed exactly once, with rejected or timed-out challenges
unreplayable.

## 3. RATE LIMITING AND FLOODING BEHAVIOR

```bash
M='https://app.example.com/api'
# Trigger several challenges against your OWN account only
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST $M/mfa/push \
    -H "Authorization: Bearer <your-own-session>" -H 'Content-Type: application/json' \
    -d '{"factor_id":"f_self_test"}'
done
```

Expect increasing delays, a per-factor cap, and eventually a hard stop with an alert.
Absence of any throttle means an attacker holding a password can generate an
indefinite prompt train and, on some devices, mask the legitimate prompt. Also
check the denial-of-service variant: a per-account throttle protects the account
but lets an attacker lock the legitimate user out. Both controls are needed and
neither should be permanent.

## 4. NUMBER-MATCHING AND REPLAY DEFECTS

- Prompt text omits the number, or shows a fixed or sequential value.
- The number is not regenerated per challenge and can be predicted from a
  previous one.
- Approval endpoint accepts a challenge id with no nonce, so a value observed
  once can be resubmitted.
- "Approve" and "Deny" share the same handler with an inverted boolean that a
  crafted request can force.
- Session established on approval is not invalidated when the underlying password
  login is superseded or the device changes.

```bash
# Replay the same challenge id against your own account
curl -s -X POST $M/mfa/verify -H "Authorization: Bearer <your-own-session>" \
  -H 'Content-Type: application/json' \
  -d '{"challenge_id":"SELFTEST_CHALLENGE","decision":"approve"}'
```

A second success for the same challenge id confirms a replay defect.

## 5. SESSION HIJACK AND RECOVERY INTERACTION

An attacker who wins approval gains a full session. Two controls limit blast
radius: pre-MFA sessions that are capability-free and short-lived, and high-risk
actions requiring fresh, recent authentication. Review the recovery path too: an
alternate SMS factor to a compromised phone converts push bombing into account
takeover with far less effort.

## 6. OBSERVABILITY

Detect flooding by logging challenge issuance per account and source, alerting on
bursts, and recording the approving device against the requesting device.

## 7. REMEDIATION

Require number matching, bind challenges to session and device context with a
single-use nonce, enforce exponential backoff and a hard cap, provide a reliable
deny path, keep pre-MFA sessions capability-free, and require recent
authentication for sensitive actions. Prefer WebAuthn or FIDO2 keys over push and SMS.

## 8. RESPONSIBLE TESTING

Test only your own accounts and factors, and only with written authorization. Never
enroll a factor on another user's device, trigger pushes to a real user's phone, or
approve a challenge on their behalf. Cap testing at a handful of requests, prefer a
staging tenant with test factors, and stop if any prompt reaches a device you do
not control. Never use these techniques against a third-party service.

## Sources
- CWE-308: https://cwe.mitre.org/data/definitions/308.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
