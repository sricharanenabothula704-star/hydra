---
name: detecting-open-redirect-in-authentication-flows
description: >-
  Open redirect detection in login/SSO/logout flows. Covers parameter discovery, allowlist bypass, and the phishing+AATO escalation (redirecting OAuth tokens).
---

# SKILL: Open redirect detection in login/SSO/logout flows. Covers parameter discovery, allowlist bypass, and the phishing+AATO escalation (redirecting OAuth tokens).

> **AI LOAD INSTRUCTION**: Load when a target has login, logout, SSO, or post-action redirects and you want to confirm whether a redirect parameter is validated. Covers finding the param, proving an external redirect safely, allowlist bypass, and the high-impact OAuth/SSO token-leak chain.

## 0. RELATED ROUTING
- [testing-for-open-redirect-vulnerabilities](#) for the core class
- [saml-sso-assertion-attacks](#) for SSO-specific angles
- [configuring-oauth2-authorization-flow](#) for OAuth redirect validation
- [phishing-resistant-security-controls](#) for why this matters (ATO via redirect)

## 1. FIND THE REDIRECT PARAMETER

Common names: `redirect`, `redirect_uri`, `return`, `returnUrl`, `next`, `url`, `continue`, `dest`, `destination`, `goto`, `target`, `redir`, `checkout_url`, `callback`.

```bash
gf redirect urls.txt | uro | httpx -silent -fr -mr "your-domain"
```

Watch login (`?next=`), logout, and any "you were here" post-action redirect.

## 2. PROVE IT SAFELY

Use a domain **you control** as the redirect target and confirm the response issues a `Location:` (or meta/JS redirect) to it.

```bash
curl -skI "https://target/logout?next=https://YOUR-CANARY.example/" | grep -i '^location'
```

Never use a real phishing kit. A canary domain proving the redirect is sufficient.

## 3. ALLOWLIST BYPASS TECHNIQUES

If the app validates with `startsWith(allowed.com)` or a bad regex:

- `https://allowed.com.evil.com/` — prefix but not the domain
- `https://evil.com/?x=allowed.com` — allowed string in query
- `https://allowed.com\@evil.com` / `allowed.com%2eevil.com` — userinfo / encoding tricks
- `//evil.com` — protocol-relative
- `https:/\evil.com` — backslash normalized to slash by some browsers
- Double encoding, open redirect via your own open redirect (chained)
- `https://evil.com#.allowed.com` — fragment confusion

## 4. THE HIGH-IMPACT CHAINS

**OAuth/OIDC token theft** — if the app passes the token or code in the redirect (`?code=...&state=...` → `Location`), an attacker-controlled `redirect_uri` steals the auth code/token → account takeover. This is the severe version.

**Referer leak** — a redirect to your site sends the original URL (with any token in it) in the `Referer`.

**Tabnabbing/phishing** — redirect after login to a fake "session expired, re-enter password" page.

## 5. SEVERITY

- Standalone open redirect: usually **low/medium** — many programs won't pay.
- Redirect that leaks a token/secret, or bypasses a security boundary (e.g. trusted-domain check for an admin action): **medium/high**. Frame it around the *leak or bypass*, not "redirect."

## 6. CONFIRM & REPORT

Show: the parameter, the request, the `Location:` header pointing to your canary, and clearly explain the real-world impact (phishing or token leak). Suggest the fix: exact-match allowlist of full paths (relative), never full URLs from user input.

## 7. FIX

- Redirect to a **relative path** only, validated against a known set, or use opaque one-time tokens mapped server-side to a destination.
- Never build the redirect from raw user input; canonicalize and match against an allowlist of exact paths.
- For OAuth, enforce exact-match `redirect_uri` (no wildcards, no fragments).

## Sources
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
- PortSwigger open redirect: https://portswigger.net/web-security/host-header/exploiting#open-redirect
- OAuth redirect_uri best practice: https://oauth.net/2/practices/
