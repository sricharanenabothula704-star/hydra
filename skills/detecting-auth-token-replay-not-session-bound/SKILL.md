---
name: detecting-auth-token-replay-not-session-bound
description: >-
  Detect bearer token theft and replay where tokens are not bound to client, session, or device context.
---

# SKILL: Detect bearer token theft and replay where tokens are not bound to client, session, or device context.

> **AI LOAD INSTRUCTION**: Load when assessing whether a stolen access token can be replayed from an unauthorized client or context.

## 0. RELATED ROUTING
- [offensive-jwt](#) for JWT-specific claim manipulation
- [extracting-credentials-from-memory-dump](#) for post-compromise token recovery
- [performing-adversary-in-the-middle-phishing-detection](#) for AiTM token interception

## 1. THE THREAT MODEL

A bearer token, by definition, is sufficient proof. If the server accepts it from anywhere, any
interception yields full account access. Replay risk is highest for:

- Long-lived access tokens (`exp` measured in hours or days)
- Tokens with no `aud` (audience) or `iss` restriction
- Tokens not bound to a channel (browser vs mobile vs server)
- Refresh tokens usable from a different client
- ID tokens accepted directly as access tokens

## 2. INVENTORY THE TOKEN

From a legitimate login you control, record: token format, claim set, `exp - iat` lifetime,
refresh window, rotation/reuse-detection behavior, storage mechanism (cookie flags vs JS
reachability), and which resource server validates it.

```
python3 - <<'PY'
import os, base64, json
h, p, s = os.environ['TOKEN'].split('.')
pad = lambda x: x + '=' * (-len(x) % 4)
print("HEADER", json.loads(base64.urlsafe_b64decode(pad(h))))
print("PAYLOAD", json.loads(base64.urlsafe_b64decode(pad(p))))
PY
```

## 3. REPLAY FROM A FOREIGN CLIENT

Send the same token with no cookies and no browser state, from two throwaway accounts you own.

```
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/me

curl -H "Authorization: Bearer $TOKEN_A" -H "User-Agent: python-requests/2.x" \
     https://api.example.com/v1/me

curl -H "Authorization: Bearer $TOKEN_A" -H "Origin: https://evil.example" \
     https://api.example.com/v1/me

curl -H "Authorization: Bearer $TOKEN_A" -H "X-Forwarded-For: 203.0.113.9" \
     https://api.example.com/v1/me
```

If all return 200 with the same identity data, the token is unbound. A hardened server should
reject at least the foreign-channel case via DPoP or mTLS binding.

## 4. CROSS-CLIENT AND CROSS-POPULATION REPLAY

1. Obtain token M through the mobile client, present it to the web/API surface as a plain header.
2. Reverse the direction with a web-issued token W against the mobile API.
3. Replay a token issued to user A against user B's session context if the API supports
   session carrying (cookie-based APIs are especially prone to this).

Audience and client-id claims should make at least one of these fail. Record which.

## 5. TOKEN THEFT PATHS

- `localStorage` is readable by any XSS payload; HttpOnly cookies are not, but auto-send.
- Refresh tokens in `localStorage` survive logout if not revoked server-side.
- Tokens in URL query or fragment leak through `Referer`, history, and access logs.
- Unencrypted caches, shared browser profiles, and device backups expose tokens at rest.

Verify revocation: log out, then replay the previously captured token. A 200 means no revocation.

## 6. REFRESH TOKEN REUSE DETECTION

RFC 6819 recommends detecting reuse of a rotated refresh token and revoking the whole family.

```
curl -s -X POST https://api.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=refresh_token&refresh_token=$OLD_REFRESH&client_id=$MY_CLIENT"
```

A compliant server returns `invalid_grant` and kills the family. A server that still mints
access is not enforcing rotation.

## 7. FIX RECOMMENDATIONS

1. Shorten access-token lifetime to minutes; rotate refresh tokens with reuse detection.
2. Bind tokens to audience, issuer, client ID, and channel; reject mismatches.
3. Require proof-of-possession: DPoP (RFC 9449) or mTLS-bound tokens (RFC 8705).
4. Store refresh tokens in HttpOnly, Secure, SameSite cookies or native secure storage.
5. Revoke server-side on logout, password change, and detected replay.

## 8. RESPONSIBLE TESTING

Replay only tokens you issued to yourself, in accounts you own, against your own or explicitly
authorized systems. Do not replay, capture, or probe tokens belonging to other users or any
third-party service. Use benign read-only endpoints and stop once you have confirmed the binding
behavior you were testing for.

## Sources
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- RFC 9449 (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- RFC 8705 (mTLS-bound tokens): https://www.rfc-editor.org/rfc/rfc8705
