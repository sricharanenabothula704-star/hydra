---
name: detecting-smtp-header-injection-email-spoofing
description: >-
  Detect email header (CRLF) injection that lets user input add Bcc/Cc/Subject or extra recipients, enabling spam relay and spoofed-mail abuse.
---

# SKILL: Detect email header (CRLF) injection that lets user input add Bcc/Cc/Subject or extra recipients, enabling spam relay and spoofed-mail abuse.

> **AI LOAD INSTRUCTION**: Load when testing contact forms, password-reset mailers, invite flows, ticket systems, or any feature that builds an SMTP message from user-controlled fields.

## 0. RELATED ROUTING
- [email-header-injection](#) for SMTP-layer injection primitives
- [detecting-cors-preflight-misconfiguration-wildcard](#) for header-handling inconsistency across layers
- [detecting-http-parameter-pollution-filter-bypass](#) for multi-layer parsing disagreements that enable injection

## 1. BASELINE THE MAIL PATH

Identify every endpoint that triggers an outbound message and which fields reach the
message builder: contact forms, password reset, email verification, ticket comments,
invitations, and webhook-to-email bridges.

Capture a benign baseline:

```bash
curl -s -D- -o /dev/null -X POST https://target/contact \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","message":"hello"}'
```

Confirm whether the app sends immediately, via a queue, or after moderation.

## 2. CONFIRM CRLF INJECTION BENIGNLY

Use a collaborator address you own. Do not mail third parties; do not send live spam.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://target/contact \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"me@example.com%0d%0aBcc:%20sink+PROBEID1@collaborator.example","message":"hi"}'
```

Variants worth trying one at a time: `%0d` (CR), `%0a` (LF), `%0d%0a` (CRLF),
`%250d%250a` (double-encoded, survives one decode pass), `%0d%0a%20` (space-padded
terminator).

Only a delivered message proves injection. A `200` alone proves nothing — check your sink.

## 3. INJECTION PAYLOAD SHAPE

The canonical proof is an additional header plus a body terminator:

```
attacker@example.com\r\nBcc: probe@collaborator.example\r\nSubject: x\r\n\r\nInjected body text
```

Confirmation criteria, ascending in strength: body terminator honored (arbitrary body
text delivered); extra recipient delivered (`Bcc`/`Cc` at your sink); subject overwritten.
A relay claim needs item 2 plus proof the endpoint is unauthenticated and rate-unlimited.

## 4. IMPACT ASSESSMENT

- **Relay abuse**: message accepted from unauthenticated input, delivered to third parties.
- **Header spoofing**: `From`/`Reply-To` rewritten to redirect replies to the attacker.
- **Phishing pivot**: attacker body and link delivered from your trusted domain.
- **Queue amplification**: each request enqueues a message; check rate limiting.

Severity keys on relay + no-auth + no-rate-limit. One authenticated user bcc'ing arbitrary
addresses is Medium; unauthenticated unlimited relay is High/Critical.

## 5. SERVER-SIDE CONFIRMATION

On a test instance, inspect the assembled message before it leaves the app: log raw
RFC 5322 bytes at the SMTP library boundary and look for extra `\r\n` outside intended
values. Node (`nodemailer`), Python (`smtplib`), PHP (`mail()`), and Java
(`InternetAddress`) differ — some re-quote, some pass raw bytes through. The bug lives
wherever the library is permissive.

## 6. DETECTIVE CONTROLS

- Alert when an unauthenticated caller produces mail with more than one recipient.
- Reject `\r`/`\n` at the header-assignment boundary, not just at the HTTP layer.
- Prefer structured APIs (`setAddress`) over raw header string concatenation.
- Rate-limit outbound mail and cap recipients per session.
- Enforce SPF/DKIM/DMARC so forged `From` fails at the receiver.

## 7. RESPONSIBLE TESTING NOTE

Use only addresses you control under a dedicated probe domain, one payload variant at a
time, and delete messages from the sink afterward. Never target third-party addresses,
distribution lists, or a real customer base. Stop and report to the owner as soon as relay
is confirmed — do not push toward high-volume or spam-filter-evasion testing; one extra
recipient in a sandboxed inbox is sufficient evidence. All mail-triggering actions require
written authorization in scope.

## 8. REMEDIATION CHECKLIST

- Reject `\r`/`\n` in header-bound values; build messages via typed address objects.
- Authenticate and rate-limit every mail-triggering endpoint.
- Alert on abnormal outbound volume per source; monitor DMARC alignment failures.

## Sources
- CWE-93: https://cwe.mitre.org/data/definitions/93.html
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- PortSwigger SMTP Injection: https://portswigger.net/web-security/smtp-injection
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
