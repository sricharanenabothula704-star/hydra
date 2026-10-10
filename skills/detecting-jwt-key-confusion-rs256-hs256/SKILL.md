---
name: detecting-jwt-key-confusion-rs256-hs256
description: >-
  Detect JWT algorithm-confusion / key-type confusion where an RS256 token is replayed as HS256 signed with the public key, plus alg:none and unverified-claims flaws.
---

# SKILL: Detect JWT algorithm-confusion / key-type confusion where an RS256 token is replayed as HS256 signed with the public key, plus alg:none and unverified-claims flaws.

> **AI LOAD INSTRUCTION**: Load when assessing any API that validates JWTs — especially when you hold, or can fetch, the server's RSA public key from JWKS, OIDC discovery, or the token header.

## 0. RELATED ROUTING
- [offensive-jwt](#) for the full JWT attack methodology including jwk/jku injection
- [detecting-oauth-state-parameter-missing-csrf](#) for adjacent token-lifecycle weaknesses
- [detecting-http-security-header-misconfiguration](#) for the endpoint-discovery step (leaked JWKS)

## 1. WHY ALGORITHM CONFUSION WORKS

A JWT header declares its own algorithm, and many libraries honor it. If the verifier accepts
both RS256 (asymmetric, verified with the public key) and HS256 (symmetric, verified with a
secret), an attacker can take a legitimate RS256 token, change the header to `HS256`, and
re-sign it using the **public** key as the HMAC secret. Since the public key is public, the
attacker can forge tokens the server accepts — full authentication bypass.

The root causes are: (a) the verifier trusts the token's `alg` field, (b) it accepts a
key-type it was never meant to use, and (c) the key is a single shared config that both roles
could use.

## 2. CONFIRM THE VERIFIER'S ALGORITHM HANDLING

First, learn what the server issues and whether it advertises its keys:

```bash
# Obtain a normal token, then inspect its header
echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# Fetch the JWKS (public key material is what makes confusion possible)
curl -s https://target/.well-known/jwks.json | jq .
curl -s https://target/.well-known/openid-configuration | jq '.jwks_uri'
```

If the verifier accepts HS256 tokens signed by the same key material it uses for RS256
verification, the confusion vulnerability is present.

## 3. THE RS256→HS256 REPLAY (BENIGN, LOCAL)

The proof is entirely local — you re-sign a token you already have; you never need to hit the
server with a forged privilege token against real accounts. Take your own token, flip `alg` to
HS256, and HMAC it with the public key. If the server accepts the tampered token *as valid for
your own account*, key confusion is confirmed.

Python (using the RSA public key PEM/JWK you already fetched):

```python
import json, hmac, hashlib, base64
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
header  = {"alg":"HS256","typ":"JWT"}
payload = json.loads(base64.urlsafe_b64decode(TOKEN.split('.')[1] + '=='))
signing = b64(json.dumps(header).encode()) + b'.' + b64(json.dumps(payload).encode())
# secret = the RSA PUBLIC key in PEM form exactly as the server presents it
sig = b64(hmac.new(PUBLIC_KEY_PEM, signing, hashlib.sha256).digest())
print((signing + b'.' + sig).decode())
```

Send the result to a benign endpoint that echoes your own identity. Acceptance (200 with your
claims) = confirmed algorithm confusion; a `401`/`500` = the verifier is pinning `alg`.

Key detail: the HMAC secret must be the public key bytes *exactly* as the library loads them
(PEM including headers and trailing newline, or the raw modulus — mismatches are the most
common reason a true vulnerability looks unconfirmed). Try both the PEM and the JWK `n` form.

## 4. RELATED FLAWS TO CHECK WHILE HERE

- **`alg: none`** — strip the signature, set `"alg":"none"`, send empty sig. Accept = trivial bypass.
- **Unverified `kid`** — `kid` pointing at a file path or URL the server loads as a key.
- **`jku`/`x5u`** — token-supplied key URL; if the server fetches it, you control the key.
- **Claim trust** — a valid signature over a token whose `role`/`sub` you control for a *different*
  subject, or unsigned internal headers, still means privilege issues.

## 5. IMPACT

Algorithm confusion that yields arbitrary claim control is authentication bypass — forge a token
for any user/role → Critical. Even if only `sub` is controllable, impersonating an admin is
Critical. Key-injection via `jku`/`kid` is similarly Critical (attacker-supplied signing key).

## 6. DETECTION & REMEDIATION

- Pin the expected algorithm server-side (e.g. only `RS256`) and reject any `alg` that doesn't
  match — never trust the token header's `alg`.
- Never use the same key material as both a public verification key and an HMAC secret.
- Validate `kid` against an in-memory allowlist; do not fetch `jku`/`x5u` from tokens.
- Require and check `exp`, `nbf`, `iss`, `aud`, and `alg` on every verification path.
- Use a well-maintained library that enforces these, keep it patched, and add a regression test
  asserting `alg:none` and HS256-vs-RS256 rejection.

## 7. RESPONSIBLE TESTING NOTE

The RS256→HS256 proof is safe and non-destructive: you re-sign a token you already own and
confirm acceptance against your own benign endpoint. Do **not** forge tokens impersonating real
users or elevated roles to "prove" impact — acceptance of an HS256 token for your own account
is sufficient evidence and avoids creating a live account-takeover artifact. Never point `jku`
or `kid` at third-party or infrastructure URLs; if you test key injection, use your own
collaborator host and confirm written authorization first. Keep tokens in scope only to your
own issued credentials, and confirm with the owner whether production signing keys are rotated
before they test any key-material handling paths.

## Sources
- CWE-347: https://cwe.mitre.org/data/definitions/347.html
- PortSwigger JWT attacks: https://portswigger.net/web-security/jwt
- RFC 7519 (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
