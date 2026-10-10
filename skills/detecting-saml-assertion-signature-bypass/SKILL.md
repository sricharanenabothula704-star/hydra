---
name: detecting-saml-assertion-signature-bypass
description: >-
  Detect SAML weaknesses where assertions are accepted without signature validation, signatures cover only the response (not the assertion), or an attacker-signed assertion is trusted due to embedded-certificate trust.
---

# SKILL: Detect SAML weaknesses where assertions are accepted without signature validation, signatures cover only the response (not the assertion), or an attacker-signed assertion is trusted due to embedded-certificate trust.

> **AI LOAD INSTRUCTION**: Load when assessing SAML SSO service-provider integrations (SP) that consume assertions from an identity provider (IdP).

## 0. RELATED ROUTING
- [saml-sso-assertion-attacks](#) for assertion wrapping and full SAML attack taxonomy
- [oauth-oidc-misconfiguration](#) for the OIDC counterpart of trust-boundary failures
- [detecting-jwt-key-confusion-rs256-hs256](#) for the analogous algorithm-confusion flaw in tokens

## 1. THE TRUST BOUNDARY IN SAML

SAML assertions are **XML documents signed with XML-DSig**. The service provider (SP) must
verify three things: (1) the signature is valid, (2) the signature actually covers the
**assertion** it is consuming (not merely the enclosing `<Response>` wrapper), and (3) the
signing key/certificate is **trusted** (from IdP metadata), not just well-formed.

Classic bypasses fail one of these:

- **Unsigned acceptance** — the SP skips signature validation entirely.
- **Response-only signature** — the `<Response>` is signed but the `<Assertion>` inside is not,
  so an attacker can wrap/modify the assertion. (Assertion wrapping / XML Signature Wrapping.)
- **Embedded-cert trust** — the SP trusts any certificate carried *inside* the assertion's
  `<KeyInfo>` instead of the pre-configured IdP cert, so an attacker self-signs.
- **Signature stripped** — attacker removes the `<Signature>` element and the SP accepts anyway.

## 2. CAPTURE A LEGITIMATE ASSERTION

You need a real, benign assertion from your own test IdP account to work with. Log in via the
SP with your own credentials, then capture the SAMLResponse POSTed to the ACS endpoint:

```bash
curl -i -sS -X POST https://target/saml/acs \
  --data-urlencode "SAMLResponse=<BASE64_ASSERTION_FROM_YOUR_TEST_LOGIN>" \
  --data-urlencode "RelayState=x" -o /dev/null -w '%{http_code}\n'
```

Decode it locally to inspect structure:

```bash
echo "$SAMLResponse" | base64 -d | xmllint --format - 2>/dev/null | head -60
```

You are looking for: is there a `<Signature>` inside the `<Assertion>` or only in `<Response>`?
Which certificate signs it, and does it match the IdP cert in the SP's metadata?

## 3. THE THREE PROBES (ALL ON YOUR OWN ASSERTION)

Using only an assertion you legitimately obtained from your own account:

- **Strip the signature** — remove the `<Signature>` from the assertion, resubmit. If the SP
  still returns success and a session, it accepts unsigned assertions.
- **Swap the embedded certificate** — replace `<KeyInfo><X509Certificate>` with a cert you
  generated, keeping the assertion content. If accepted, the SP trusts the embedded cert.
- **Signature-position test** — if only the `<Response>` is signed, note that the assertion
  content is unprotected; the SP should reject an assertion lacking its own valid signature.

Any acceptance of a modified/untrusted assertion = confirmed authentication bypass (Critical),
because it lets an attacker assert any identity.

## 4. STAYING SAFE

All tampering is done locally on an assertion you already own, then submitted once to the ACS
endpoint as a benign confirmation. You are not forging assertions for other users or attempting
to authenticate as a real person — you are testing whether the SP's validator accepts a
non-conforming document at all. Expect the SP to reject tampered assertions; acceptance is the
finding.

## 5. RELATED SAML WEAKNESSES

- **Unsigned assertions allowed** (`WantAssertionsSigned="false"`) — the core defect above.
- **Missing audience/recipient validation** — an assertion from another SP/tenant is accepted.
- **Assertion replay** — no `NotOnOrAfter`/`InResponseTo` checks; a captured assertion replays
  until expiry.
- **Weak NameID binding** — account is matched on mutable attributes rather than a stable ID.
- **IdP-initiated SSO without access control** — any IdP user can log in to the SP.

## 6. DETECTION & REMEDIATION

- Require `WantAssertionsSigned` and `WantAuthnRequestsSigned`; validate the **assertion**
  signature explicitly and reject if the only signature is on the response.
- Validate against the pinned IdP certificate from trusted metadata; **never** trust a
  certificate embedded in the message.
- Enforce `NotBefore`/`NotOnOrAfter`, `InResponseTo`, `Destination`, and `Audience`/Recipient.
- Use a maintained SAML library with signature-wrapping protection; XML signature wrapping is
  the default failure mode of naive implementations.
- Disable IdP-initiated SSO unless explicitly required and access-controlled.
- Log SAML validation failures (bad sig, untrusted cert, expired) as security events.

## 7. RESPONSIBLE TESTING NOTE

Only submit tampered copies of assertions you obtained through your **own** test login — never
fabricate assertions naming real users, and never use a bypass to authenticate as someone else;
proving the SP accepts an unsigned/untrusted document is sufficient and does not require
impersonating an account. Work on a staging tenant where possible, since signature validation
bugs can be sensitive to SP config. Do not stress-test the IdP with repeated submissions, and
never submit an assertion to a third party's SP. Capture of your own SAML traffic is fine;
sharing captured assertions containing real user data is not. Document each tampered
submission so the owner can reproduce it.

## Sources
- CWE-347: https://cwe.mitre.org/data/definitions/347.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- PortSwigger SAML attacks: https://portswigger.net/web-security/saml-attacks
- OASIS SAML 2.0 Core: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
