---
name: detecting-session-token-predictability-brute-force
description: >-
  Evaluate session identifier entropy, lifetime, rotation, invalidation, and fixation resistance, and quantify offline versus online guessing feasibility.
---

# SKILL: Evaluate session identifier entropy, lifetime, rotation, invalidation, and fixation resistance, and quantify offline versus online guessing feasibility.

> **AI LOAD INSTRUCTION**: Load when reviewing authentication sessions, hardening a login flow, or assessing breach-related token revocation.

## 0. RELATED ROUTING
- [detecting-weak-random-value-generation-tokens](#) for the generator-side analysis
- [authbypass-authentication-flaws](#) for adjacent auth logic
- [detecting-mfa-fatigue-push-bombing-session-hijack](#) for post-login token theft paths

## 1. SESSION LIFECYCLE REQUIREMENTS

A secure session identifier must be unguessable, bound to the client, rotated on
privilege change, and revocable server-side. Most defects are lifecycle omissions
rather than entropy failures.

- Generate >= 128 bits of entropy via a CSPRNG.
- Regenerate the identifier on login, on logout, and on any privilege change
  (anonymous to user, step-up MFA, role elevation).
- Bind to context: user agent, and ideally client IP or a network fingerprint,
  but avoid aggressive IP binding that breaks mobile users.
- Enforce absolute and idle timeouts; invalidate server-side.
- Support total revocation, not just client-side cookie deletion.

## 2. STATIC REVIEW CHECKLIST

```bash
grep -rn --include='*.py' -E "session\[|session_id\s*=" app/
grep -rn -E "cookies?\.set\(|Set-Cookie" --include='*.py' --include='*.js' src/
grep -rn --include='*.js' -E 'cookie.*(secure|httponly|samesite)' src/ -i
```

Confirm in code and config:

- Cookie flags: `Secure`, `HttpOnly`, `SameSite=Lax|Strict`, `Path=/`, no
  `Domain` widening beyond the host.
- Sessions stored server-side with an index keyed by a digest of the token, not
  the raw token, so a store dump does not yield live sessions.
- Idle timeout enforced on read, not only on write.
- Logout destroys the server-side record and issues a fresh anonymous session.

## 3. FIXATION

The classic defect is failing to reissue the identifier after authentication:

```python
# Vulnerable
if authenticate(user, password):
    session['user_id'] = user.id      # pre-login identifier survives

# Correct
if authenticate(user, password):
    session.cycle_key()               # new id, same session data
    session['user_id'] = user.id
```

Pre-authentication state can leak privilege (cart contents, impersonated role
flags) and is the mechanism behind session fixation.

## 4. PREDICTABILITY ASSESSMENT

Sample identifiers from your own accounts across a controlled number of requests:

- Token length in bytes after decoding; confirm >= 16 bytes.
- Position-wise character distribution; skew indicates a counter/time component.
- Serial relationship between successive tokens (monotonic delta, shared prefix).
- Duplicate tokens across separate sessions.

Absence of collisions in a small sample does not establish security. Derive
conclusions from the generation code; use sampling only to confirm deployed code
matches reviewed code.

## 5. BRUTE-FORCE AND RATE-LIMIT VALIDATION

```bash
# Confirm lockout/throttle exists, using your own throwaway account only
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    -X POST https://app.example.com/login \
    -d "username=testuser+self@example.com&password=wrong-$i"
done
```

Verify per-account and per-source-IP throttling, exponential backoff, and a monitored
alert on repeated failures. A `429` or generic `401` with constant response time is acceptable.

## 6. CONCURRENT SESSION HANDLING AND REVOCATION

Document the intended policy: single-session enforcement, a bounded session count,
or unlimited with a "view active sessions" control. Unlimited sessions with no
revocation UI means a stolen token persists indefinitely. Confirm a password
change or reset invalidates existing sessions server-side.

## 7. RESPONSIBLE TESTING

Use only accounts you created yourself, with data you own. Do not enumerate other
users' sessions, do not attempt to guess or hijack a third party's session, and
do not replay captured tokens against a production service. Cap your own
guessing attempts and keep them rate-limited. Report findings as structural
defects with the code path, not as demonstrated account compromises.

## Sources
- CWE-384: https://cwe.mitre.org/data/definitions/384.html
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
