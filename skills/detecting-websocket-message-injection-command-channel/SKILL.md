---
name: detecting-websocket-message-injection-command-channel
description: >-
  Detecting injection and authorization gaps in WebSocket message handling. Covers missing auth on upgrade, JSON message injection, command dispatch abuse, and cross-frame hijacking defense-in-depth.
---

# SKILL: Detecting injection and authorization gaps in WebSocket message handling. Covers missing auth on upgrade, JSON message injection, command dispatch abuse, and cross-frame hijacking defense-in-depth.

> **AI LOAD INSTRUCTION**: Load when auditing a WebSocket endpoint's message handling. Covers auth at handshake vs per-message, JSON field trust leading to command injection, and how to test message authorization safely with your own session.

## 0. RELATED ROUTING
- [exploiting-websocket-cross-site-hijacking-weak-origin](#) for the CSWSH angle
- [detecting-api-authorization-bypass-tenant-boundary](#) for authz patterns
- [testing-websocket-api-security](#) for the full test workflow

## 1. TWO AUTH LAYERS

Many WebSocket servers authenticate **only at the HTTP upgrade** (cookie present) but never re-check on each message. When a long-lived socket is shared, revoked/expired auth or cross-tenant access can persist. Also: some frameworks accept the upgrade then never validate the session at all.

## 2. MESSAGE INJECTION

If the server parses each message as JSON and dispatches to a handler keyed on a client-supplied field (action/type/id), then:

- **Command injection:** a message like `{"action":"exec","cmd":"..."}` reaching a dangerous handler.
- **IDOR via message:** `{"action":"getData","id":<other user id>}` — no per-object auth on the socket.

## 3. SAFE TESTING

Connect with your **own** session and send benign messages. Probe:

- An `action`/`type` value that doesn't exist — observe the error (proves dispatch on client input).
- Your own resource ID — confirms the handler works.
- Only then, with authorization, test whether a foreign ID is rejected.

Do not access other users' data during testing.

## 4. DETECTION

Review the server's `onmessage` handler for: schema validation, per-message authorization, and rate limiting. Flag any handler that dispatches on a client string to a sensitive operation.

## 5. REMEDIATION

- Re-validate session/permissions per message (or on a short interval), not just at upgrade.
- Validate/sanitize every message against a strict schema; reject unknown fields.
- Enforce object-level authorization inside each message handler.
- Rate-limit and size-cap messages; reject oversized payloads.

## Sources
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- OWASP WebSocket Security: https://owasp.org/www-project-websocket-security/
