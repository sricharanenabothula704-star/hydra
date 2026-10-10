---
name: detecting-crlf-injection-in-log-entries
description: >-
  Find response-splitting and header/log-forging vectors where CR and LF reach HTTP response construction or log sinks, and validate the sanitization that blocks them.
---

# SKILL: Find response-splitting and header/log-forging vectors where CR and LF reach HTTP response construction or log sinks, and validate the sanitization that blocks them.

> **AI LOAD INSTRUCTION**: Load when testing any endpoint that reflects user input into a response header, redirect, filename, or log line.

## 0. RELATED ROUTING
- [detecting-log-injection-log-forging-prevention-bypass](#) for the log-sink variant
- [crlf-injection](#) for the general response-splitting playbook
- [email-header-injection](#) for SMTP header contexts

## 1. VECTOR AND IMPACT

CRLF injection lets an attacker embed additional protocol structure inside a
value. In an HTTP response it splits headers or the body boundary; in a log it
starts a new record; in an email header it adds recipients or headers. Impact
ranges from cache poisoning and reflected-content XSS to credential capture via
injected headers.

## 2. SOURCE IDENTIFICATION

```bash
# Reflected values commonly routed to headers or logs
grep -rn --include='*.py' -E "Location|redirect\(|send_header|headers\[" src/ | head -40
grep -rn --include='*.js' -E "res\.(set|setHeader|redirect|write)\(" src/ | head -40
grep -rn --include='*.py' -E "request\.(args|values|form|json|cookies|headers)" src/
```

Trace which request fields reach a response header (`Location`, `Refresh`,
`Content-Disposition`, custom `X-`), a redirect target such as `next` or
`redirect_uri`, a body built by string concatenation rather than an auto-escaping
template engine, or a download filename derived from a request parameter.

## 3. ENCODING VARIANTS

Testers and attackers bypass naive filters, so cover:

| Encoding | Raw form |
|---|---|
| Percent / mixed case | `%0d%0a`, `%0D%0a`, `%0d%0A` |
| Double percent | `%250d%250a` |
| Raw bytes | literal `\r\n` in body |
| UTF overlong (legacy) | `%c0%8d%c0%8a` |
| Bare CR or bare LF | `%0d` or `%0a` alone |
| Unicode separators | `U+2028`, `U+2029` |
| Tab/space padding | `\t\r\n` or space-before-CRLF |

A filter that decodes only once is bypassed by double encoding, since the
framework decodes again before the header is written.

## 4. OBSERVATION WITHOUT HARM

Never aim payloads at a shared monitoring endpoint or third-party service. Use a
local instance, staging deployment, or a listener you control:

```bash
# Local sink to observe raw header bytes
python3 -c 'import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(repr(self.raw_requestline), repr(self.headers))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()' &
sleep 1
curl -i 'http://127.0.0.1:8099/?next=http%3A%2F%2Fexample.com%0d%0aX-Test%3A+injected'
kill %1
```

Success criteria: the application rejects the input, encodes CR/LF inertly, or
confines it to a position where it cannot alter structure. A visible extra header
line confirms the finding.

## 5. APPLICATION-LEVEL PROBES

Test only endpoints tied to accounts you own:

```bash
# Redirect parameter
curl -sI 'https://app.example.com/login?next=%0d%0aSet-Cookie:%20a%3Db' | cat -A | head -20

# Reflected value in a header
curl -sI -H 'X-Trace: test' 'https://app.example.com/echo?name=a%0d%0aX-Injected:%201'
```

Then confirm the response contains no header you did not send.

## 6. CODE-LEVEL CONTROLS AND HARDENING

Verify the application uses APIs that reject CR/LF rather than manual filtering.
Python `http.client` and Werkzeug header setters raise on embedded newlines;
confirm the codebase does not bypass them with raw writes. Node `res.setHeader`
throws on invalid characters while `res.writeHead` with a hand-built object may
not. Validate redirect URLs with an allowlist of schemes and hosts, never derive
`Content-Disposition` filenames from unsanitized input, and escape control
characters at log sinks. Add a CI regression test asserting that a request
carrying `%0d%0a` never produces an extra header.

## 7. RESPONSIBLE TESTING

Send payloads only to a local instance, a staging environment, or endpoints
backed by accounts and data you own. Never target a third-party domain with
injected headers or shared monitoring infrastructure, and never use this
technique to influence caches or proxies you do not administer. Written
authorization is required before testing any shared system.

## Sources
- CWE-93: https://cwe.mitre.org/data/definitions/93.html
- CWE-113: https://cwe.mitre.org/data/definitions/113.html
- OWASP WSTG Response Splitting: https://owasp.org/www-project-web-security-testing-guide/
