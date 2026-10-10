---
name: detecting-oauth2-authorization-code-pkce-downgrade
description: >-
  Detect OAuth 2.0 authorization servers and clients that skip, weaken, or bypass PKCE during code exchange.
---

# SKILL: Detect OAuth 2.0 authorization servers and clients that skip, weaken, or bypass PKCE during code exchange.

> **AI LOAD INSTRUCTION**: Load when reviewing an OAuth/OIDC integration for PKCE enforcement, downgrade paths, and code interception risk.

## 0. RELATED ROUTING
- [offensive-oauth-misconfiguration](#) for redirect URI and token leakage testing
- [testing-oauth2-implementation-flaws](#) for interactive authorization-code testing
- [exploiting-jwt-algorithm-confusion-attack](#) for post-exchange token validation

## 1. WHY PKCE MATTERS

RFC 7636 binds an authorization code to the client instance that requested it via a
`code_verifier` and `code_challenge`. Without it, anyone who intercepts the code (open
redirect, browser history, malicious app on the device, log leakage) can redeem it.
Downgrade paths to detect:

- Client sends no `code_challenge` and the AS still issues a code.
- AS ignores `code_challenge_method=plain` when the client registered S256.
- AS does not enforce that `code_verifier` matches, or accepts an empty verifier.
- Confidential clients exchange codes with no client authentication at all.
- PKCE applied only on the browser client, absent on the native/mobile client.
- AS validates `redirect_uri` only after code issuance.

## 2. MAP THE FLOW

```
curl -s https://idp.example.com/.well-known/openid-configuration | python3 -m json.tool \
  | grep -iE 'code_challenge|pkce|issuer'
```

Log in with an account you own and capture the real redirect through a local listener, noting
`client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, and any challenge params.

## 3. TEST 1 - MISSING CHALLENGE

```
curl -si "https://idp.example.com/oauth/authorize\
?response_type=code&client_id=$MY_CLIENT&scope=openid%20profile\
&redirect_uri=https%3A%2F%2F127.0.0.1%3A8765%2Fcb&state=xyz" | head -20
```

A 302 with `Location: .../cb?code=...` means no PKCE was required.

## 4. TEST 2 - CHALLENGE DOWNGRADE TO plain

```
curl -si "https://idp.example.com/oauth/authorize\
?response_type=code&client_id=$MY_CLIENT&scope=openid\
&redirect_uri=https%3A%2F%2F127.0.0.1%3A8765%2Fcb&state=xyz\
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
&code_challenge_method=plain"
```

The AS must reject `plain` when the client is registered for S256 (RFC 7636 §4.2).

## 5. TEST 3 - VERIFIER MISMATCH AND EMPTY VERIFIER

```
# wrong verifier -> expect invalid_grant
curl -s -X POST https://idp.example.com/oauth/token \
  -d "grant_type=authorization_code&code=$CODE&client_id=$MY_CLIENT\
&redirect_uri=https://127.0.0.1:8765/cb&code_verifier=$WRONG_VERIFIER"

# omitted verifier -> expect the same rejection
curl -s -X POST https://idp.example.com/oauth/token \
  -d "grant_type=authorization_code&code=$CODE&client_id=$MY_CLIENT\
&redirect_uri=https://127.0.0.1:8765/cb"
```

Any 200 with tokens means PKCE is decorative.

## 6. TEST 4 - CONFIDENTIAL CLIENT DOWNGRADE

```
curl -s -X POST https://idp.example.com/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://127.0.0.1:8765/cb"
```

If the AS accepts a client-secret-only exchange for a code issued without PKCE, policy is not
enforced per client. Also check whether the native client registers
`token_endpoint_auth_method=none` and is genuinely public.

## 7. INTERCEPTED-CODE PROOF OF CONCEPT

Demonstrate impact with a code you yourself triggered and captured: request one code with
PKCE, then a second without a challenge, then redeem the second from a different client
context with no verifier. A successful exchange proves the code is not bound to the requester.

## 8. FIX RECOMMENDATIONS

1. Require PKCE for all clients, confidential included (OAuth 2.1 baseline).
2. Enforce `S256` only; reject `plain`, missing, and empty challenges.
3. Bind the code to the exact `redirect_uri` and the authenticated client identity.
4. Use one-time, short-lived codes (RFC 6749 §4.1.2), invalidated on first use attempt.
5. Enforce `state` for CSRF and exact-match redirect URIs.

## 9. RESPONSIBLE TESTING

Only use your own registered client and account against your own or explicitly authorized
identity provider, with loopback redirect URIs you control and codes you generated yourself. Do
not attempt code interception against third-party clients or real users, and never use a captured
code to reach anyone else's data.

## Sources
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- RFC 6749 §4.1.2: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- PortSwigger OAuth: https://portswigger.net/web-security/oauth
