---
name: detecting-openidconnect-redirect-validation-bypass
description: >-
  Detecting OAuth/OIDC `redirect_uri` validation bypass. Covers exact-match requirements, wildcards, fragment-injection, subdomain matching, and the account-takeover impact when auth codes leak.
---

# SKILL: Detecting OAuth/OIDC `redirect_uri` validation bypass. Covers exact-match requirements, wildcards, fragment-injection, subdomain matching, and the account-takeover impact when auth codes leak.

> **AI LOAD INSTRUCTION**: Load when assessing an OAuth/OIDC provider or relying party's redirect_uri handling. Covers why validation must be exact-match, common bypass patterns (wildcard, prefix, subdomain, encoding), and how a bypass becomes auth-code theft → account takeover.

## 0. RELATED ROUTING
- [detecting-oauth-state-parameter-missing-csrf](#) for the state/CSRF side
- [detecting-oauth2-authorization-code-pkce-downgrade](#) for PKCE
- [exploiting-host-header-injection-password-reset-poisoning](#) for host-trust issues
- [configuring-oauth2-authorization-flow](#) for correct config

## 1. THE RULE

RFC 6749 §3.1.2.3: `redirect_uri` MUST be compared using **simple string comparison** against the registered value. No wildcards, no prefix matching, no "starts with".

A bypass means the authorization code / token is delivered to the attacker → account takeover of the victim who completes the flow.

## 2. COMMON BYPASS PATTERNS (what to test)

- Wildcard registration (`https://app.com/*`) — should not be allowed
- Prefix match: registering `https://app.com` and using `https://app.com.evil.com`
- Path traversal in the redirect: `https://app.com/callback/../../evil`
- Subdomain matching: registering `app.com`, using `evil.app.com`
- URL encoding / double-encoding differences between validation and actual use
- Fragment injection: `https://app.com#@evil.com` or fragment abuse in implicit flow
- Open-redirect chaining: an app open-redirect becomes a redirect_uri bypass

## 3. SAFE TESTING

Test the provider's validation with your **own** client and redirect URIs. Use a domain you control as the malicious target. Do not complete flows against real victims' accounts.

## 4. DETECTION

- Enumerate registered redirect URIs for your client (if the provider allows) and check for wildcards.
- Attempt the bypass patterns above with your own client; observe whether the authorization server issues a code to your domain.

## 5. REMEDIATION

- Exact string match, nothing else. No wildcards, no prefixes, no normalization that reintroduces ambiguity.
- Require HTTPS for all redirect URIs (except loopback for native apps).
- Reject URIs with fragments in the authorization request.
- Use PKCE (S256) so a stolen code is useless without the verifier.

## Sources
- RFC 6749 §3.1.2.3: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
- OAuth Security BCP: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
