---
name: detecting-ssrf-in-websocket-upgrade-handshake
description: >-
  Detect server-side request forgery where attacker-controlled data in a WebSocket Upgrade request makes the server open a connection to an internal or arbitrary host.
---

# SKILL: Detect server-side request forgery where attacker-controlled data in a WebSocket Upgrade request makes the server open a connection to an internal or arbitrary host.

> **AI LOAD INSTRUCTION**: Load when a WebSocket endpoint accepts a URL, host, or path-derived target in the handshake, or when a reverse proxy proxies WebSocket to a backend selected by request data.

## 0. RELATED ROUTING
- [exploiting-cwe-1902-dns-rebinding-ssrf-bypass](#) for resolving-time SSRF filter bypass
- [detecting-ssrf-in-websocket-upgrade-handshake](#) for the WebSocket-specific variant of this class
- [exploiting-aws-imdsv1-ssrf-credential-exposure](#) for credential impact once metadata is reachable

## 1. WHY THE HANDSHAKE IS A DISTINCT SURFACE

A WebSocket upgrade is an ordinary HTTP request with `Upgrade: websocket`, but many
implementations proxy the connection: the server, not the browser, establishes the upstream
TCP connection. Any value the server uses to build the upstream host and port becomes an SSRF
sink, and it is evaluated server-side — the browser's own security restrictions do not apply.

Sink locations to audit:

- A `wss://host:port` or endpoint URL supplied by the client in body/params.
- A subdomain, tenant, or environment identifier used to select the upstream host.
- A path forwarded to an internal gateway, broker, or registry (e.g. `nats://`).
- Proxy config deriving the upstream from a header or query parameter.

## 2. BENIGN BASELINE

Establish a working normal upgrade first so you can distinguish protocol failure from
vulnerability:

```bash
curl -i -N -sS \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target/ws/chat"
```

Expect `101 Switching Protocols`. Record the baseline headers, session token, and whether the
endpoint requires authentication.

## 3. CONTROLLED CONFIRMATION

Use an external collaborator host you control (a listener on your own VPS) to confirm the
server connects out. Point the SSRF parameter at it — never at internal services first.

```bash
# Confirm outbound connection to a collaborator-controlled listener
curl -i -N -sS \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target/ws?upstream=ws://YOUR_COLLAB_HOST:9000/probe"
```

On your listener, a connection attempt from the target's egress IP confirms SSRF. Capture
the source IP and the request line. This is the clean, non-destructive proof.

Internal targets (`169.254.169.254`, `127.0.0.1`, `10.x`, cluster service names) are more
impactful but riskier; test them only in an authorized staging environment.

## 4. BYPASS OF NAIVE FILTERING

Many filters block `localhost`/`127.0.0.1`/`169.254.169.254` by substring but resolve DNS
or parse URLs inconsistently. In staging, evaluate: loopback aliases (`0.0.0.0`, `127.1`,
`[::1]`, `0x7f000001`); redirect-based (point at your host, it 302s internal); DNS rebinding
to `127.0.0.1`; scheme confusion (`file://`, `gopher://`); parse quirks (trailing dot
`127.0.0.1.`, userinfo `http://allowed@127.0.0.1`).

Confirm against your collaborator listener rather than internal metadata services whenever
possible.

## 5. IMPACT ASSESSMENT

- **Credential theft**: reaching `169.254.169.254`/IMDSv1 for instance roles or a
  Kubernetes API/token service.
- **Internal service abuse**: reaching unauthenticated internal APIs or admin panels.
- **Protocol confusion**: a client library following redirects into other schemes.
- **Port scanning**: timing oracles reveal internal open ports.

Severity keys on reach (loopback only vs. cloud metadata) and whether responses return to
the attacker or merely cause an outbound connection.

## 6. RESPONSIBLE TESTING NOTE

Start and end with a collaborator listener you own — it proves the vulnerability without
touching internal infrastructure. Send a handful of requests, not a scan. Never point the
parameter at production metadata services, cloud admin endpoints, or internal production
APIs; reaching them can leak live credentials and is destructive to real systems. Port-scan
oracles must be limited, low-volume, and confirmed in scope in writing — treat any action
that reaches an internal production system as requiring explicit authorization from the
system owner, not just the web owner. Stop once SSRF is confirmed and hand back evidence.

## 7. REMEDIATION

- Allowlist upstream WebSocket destinations; never derive host from client input alone.
- Resolve and validate the IP (reject loopback/link-local/private ranges) before connecting,
  and pin the resolved IP to defeat DNS rebinding.
- Do not follow redirects when connecting upstream, or re-validate each hop.
- Restrict egress from the application tier with network policy / firewall rules.
- Disable IMDSv1 and require session auth on internal endpoints.

## Sources
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- RFC 6455 (WebSocket): https://www.rfc-editor.org/rfc/rfc6455
