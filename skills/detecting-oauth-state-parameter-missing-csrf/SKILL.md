---
name: detecting-oauth-state-parameter-missing-csrf
description: >-
  Detect OAuth/OIDC login flows that omit or fail to validate the `state` parameter (or `nonce`/PKCE), enabling login CSRF where an attacker forces a victim to authenticate into the attacker's account.
---

# SKILL: Detect OAuth/OIDC login flows that omit or fail to validate the `state` parameter (or `nonce`/PKCE), enabling login CSRF where an attacker forces a victim to authenticate into the attacker's account.

> **AI LOAD INSTRUCTION**: Load when assessing any OAuth/OIDC authorization-code, implicit, or "Sign in with X" integration and its callback endpoint.

## 0. RELATED ROUTING
- [detecting-open-redirect-in-authentication-flows](#) for the redirect-handling half of auth flow testing
- [oauth-oidc-misconfiguration](#) for state/nonce/PKCE and redirect-URI misconfiguration
- [detecting-jwt-key-confusion-rs256-hs256](#) for token-layer flaws in the same flow

## 1. THE THREAT: LOGIN CSRF, NOT ACCOUNT TAKEOVER

The classic confusion is that login CSRF is not "hijack an account." The attacker starts an
OAuth flow on the IdP with **their** credentials, captures the callback `code`+`state` before
the browser uses it, then lures the victim into hitting the callback URL. The app binds the
victim's browser session to the **attacker's** IdP identity. The victim then uses the app
normally — entering their own sensitive data — believing they logged into their own account,
while actually operating inside the attacker's.

Impact is data exfiltration and action attribution: the attacker later sees everything the
victim uploaded or did. The `state` parameter exists to bind the authorization request to the
user-agent session that started it, so a missing or unvalidated `state` is the core bug.

## 2. OBSERVE THE AUTHORIZATION REQUEST

Start the flow yourself and capture the redirect to the IdP:

```bash
curl -i -sS "https://target/auth/login?provider=google" -o - | grep -i '^location'
```

Record whether `state` (and for OIDC, `nonce`) are present, and whether they appear as
opaque random values. Weak/absent/constant state is the first signal.

## 3. THE MISSING-STATE PROOF (BENIGN, LOCAL)

Test entirely against your own accounts — this requires no victim:

1. Start the flow on your browser/profile A. Note the absence of `state` (or reuse the same
   `state` across two logins — a constant is as bad as absent).
2. Complete login on profile B using the **same** authorization request / callback URL.
3. If the app accepts the callback and establishes a session for B **without B having started
   a flow**, the flow has no anti-CSRF binding — state is missing or unvalidated.

A robust check is to compare two independent login attempts: with proper `state`, the second
attempt's callback must be rejected (`state` mismatch / expired). Both succeeding on replay
indicates the state is not being checked.

## 4. STATE VARIANTS THAT MATTER

- **Absent** — no parameter at all.
- **Constant/static** — same value every login (predictable, no freshness).
- **Not bound to session** — issued but never compared against the stored value on callback.
- **No expiry/one-time use** — replayable after login completes.
- **Missing `nonce` (OIDC)** — enables replay of the ID token into a different session.
- **Missing PKCE (public/SPA clients)** — the authorization code is a bearer credential; without
  `code_verifier` binding, a leaked/injected code is redeemable.

## 5. THE INJECTION VARIANT (ADVANCED, AUTHORIZED)

The full login-CSRF demo has the attacker complete the flow on their own account and deliver
the callback URL to a victim. This requires two test accounts you own (attacker + victim), a
hostile origin you control, and explicit written authorization — it involves luring a real
session. Treat it as a separate, approved phase after the read-only analysis above has already
established the missing/unvalidated `state`.

## 6. DETECTION & REMEDIATION

- Generate a cryptographically random `state` (≥128 bits), store it server-side bound to the
  initiating session, verify it on callback, and single-use it with a short TTL.
- For OIDC, send and validate `nonce`; for public clients (SPA/mobile), use PKCE
  (RFC 7636) with `S256`.
- Bind the state to the session/user-agent and never to a value supplied by the request.
- Use short-lived, single-use authorization codes; prefer the code flow with PKCE over implicit.
- Alert on callbacks whose state is missing, mismatched, or replayed.

## 7. RESPONSIBLE TESTING NOTE

Do the analysis against your own accounts and a browser profile you control. The read-only
stages (inspecting the authorization request, replaying your own callback against your own
session, comparing two of your own logins) are non-destructive and safe. The luring/injection
phase is different: it requires a "victim" session, so use a **second test account you own**
in a separate profile and a hostile origin you control — never a real employee or customer, and
never their live session. Do not build a working phishing page against the production
authorization endpoint; demonstrate on a staging tenant where possible. Any phase that
tricks a human into a login requires explicit written authorization and coordination with the
app owner beforehand.

## Sources
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- CWE-384: https://cwe.mitre.org/data/definitions/384.html
- RFC 6749 (OAuth 2.0): https://www.rfc-editor.org/rfc/rfc6749
- OAuth Security BCP (RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
