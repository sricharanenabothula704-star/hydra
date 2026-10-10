---
name: detecting-user-registration-email-verification-bypass
description: >-
  Find registration flows that grant authenticated or privileged access before email ownership is proven, or where the verification step can be skipped, replayed, or swapped.
---

# SKILL: Find registration flows that grant authenticated or privileged access before email ownership is proven, or where the verification step can be skipped, replayed, or swapped.

> **AI LOAD INSTRUCTION**: Load when auditing signup, invite acceptance, or account activation code paths.

## 0. RELATED ROUTING
- [detecting-password-reset-account-enumeration-timing](#) for the sibling email flow
- [detecting-mfa-fatigue-push-bombing-session-hijack](#) for step-up verification patterns
- [api-authorization-and-bola](#) for object-level checks on activation records

## 1. WHAT VERIFICATION IS SUPPOSED TO PREVENT

Unverified signup means anyone can claim an identity. Impact depends on what an
account can do before verification: a placeholder login may be acceptable, but any
ability to post, message other users, spend credit, or reach an administrative
surface turns spam into impersonation.

## 2. MAP THE STATE MACHINE

Registration is a state machine, and the vulnerability is a reachable unverified
state with too much privilege: `anonymous -> submitted -> token_issued ->
verified -> active`.

```bash
grep -rn --include='*.py' -E 'verified|is_verified|email_confirmed' app/ | head -40
grep -rn --include='*.js' -E 'verified|emailConfirmed|activate' src/ | head
grep -rn -E 'verify|confirm|activate' --include='*.sql' . | head -20
```

The decisive question: does any authorization check test `verified`? If `is_verified`
appears only in the UI layer and never in a permission decorator or middleware, the
gate is client-side.

## 3. CONFIRMING A BYPASS

Use addresses at a domain you control so you can observe the full lifecycle. Register
with a throwaway alias and check access at each step:

```bash
R='https://app.example.com/api'
# Sign up; capture the session cookie
curl -s -c c.txt -X POST $R/register -H 'Content-Type: application/json' \
  -d '{"email":"selftest+1@yourdomain.example","password":"TestOnly-9f2a!"}'
# Privileged action before clicking any link
curl -s -b c.txt -X POST $R/projects -H 'Content-Type: application/json' \
  -d '{"name":"selftest"}' | jq .
# Administrative surface
curl -s -b c.txt $R/admin/users | jq 'length'
```

A successful privileged action, an authenticated dashboard render, or a non-zero
admin response before verification is a confirmed bypass. Also check moderation,
search indexing, and outbound messaging, the common abuse channels.

## 4. TOKEN-LEVEL DEFECTS

With an account you registered yourself, examine the activation token:

Look for a predictable or sequential token, an expiry never enforced server-side, a
token reusable after verification, a token unbound to its account, and an
email-matching mismatch between registration and verification that permits a
domain-variant claim of a target address.

```bash
# Token from your own registration, replayed twice after successful use
curl -s -X POST https://app.example.com/api/verify -d 'token=SELFTESTTOKEN1'
curl -s -X POST https://app.example.com/api/verify -d 'token=SELFTESTTOKEN1'
```

A `200` on the second call is a single-use defect.

## 5. INVITE AND ACCOUNT-LINKING PATHS

Check adjacent flows reusing the same machinery: invitation acceptance that binds
the invite to the creating session; social login that marks an unverified account
verified without proving email ownership at that provider; change-email flows that
never invalidate prior sessions; and a `/verify` endpoint reachable by support
tooling without an audit trail.

## 6. OBSERVABILITY AND ABUSE CONTROL

Even a correct gate needs defense in depth: rate-limit sends per address and source,
cap resends, expire unverified accounts, prevent user-controlled content in the
verification email body, and alert on bursts of unverified accounts followed by
activity.

## 7. REMEDIATION

Enforce verification server-side in one authorization layer consulted by every
authenticated route, not per handler. Issue a high-entropy single-use token bound
to the account id with a short expiry, store only its digest, consume it in a
transaction that also revokes other outstanding tokens for that address, and keep
unverified sessions in a restricted scope with an explicit capability list.

## 8. RESPONSIBLE TESTING

Use only addresses at a domain you control and throwaway accounts you created.
Never register using another person's email address, never click or trigger
verification for accounts you do not own, and never attempt to verify or hijack a
third party's account. Limit registration attempts to a handful so that
verification email volume and abuse detection are not disrupted.

## Sources
- CWE-620: https://cwe.mitre.org/data/definitions/620.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
