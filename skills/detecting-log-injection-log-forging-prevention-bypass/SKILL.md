---
name: detecting-log-injection-log-forging-prevention-bypass
description: >-
  Assess whether untrusted input reaching log sinks can forge, truncate, or hide records, and verify the controls that neutralize control characters and delimiters.
---

# SKILL: Assess whether untrusted input reaching log sinks can forge, truncate, or hide records, and verify the controls that neutralize control characters and delimiters.

> **AI LOAD INSTRUCTION**: Load when reviewing logging in an application that handles user-supplied identifiers, filenames, headers, or query parameters.

## 0. RELATED ROUTING
- [detecting-crlf-injection-in-log-entries](#) for the response-header variant
- [analyzing-web-server-logs-for-intrusion](#) for downstream detection impact
- [analyzing-linux-audit-logs-for-intrusion](#) for log pipeline trust boundaries

## 1. WHY INJECTION INTO LOGS MATTERS

Log injection is an evasion primitive, not merely a formatting bug. An attacker
who can embed a newline plus a fabricated record can forge an audit trail, split
one event into two, truncate a log by emitting a partial line, or hide an entry
inside the text of a later one. The impact depends entirely on whether anything
downstream parses those logs as structured data.

Injection becomes materially severe when a SIEM, alerting pipeline, or log shipper
treats attacker-controlled lines as independent events.

## 2. SINKS AND SOURCES

Map every path from request data to a log call. Common vectors include HTTP
headers (`User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie`), path and query
parameters including 404 paths reflected verbatim, usernames and free-text form
fields, multipart upload filenames, and webhook payloads logged wholesale.

```bash
grep -rn --include='*.py' -E '(log|logger)\.(info|debug|warn|error|print)\(' src/ | head -50
grep -rn --include='*.js' -E 'console\.(log|error|warn)\(|logger\.' src/ | head -50
grep -rn -E "getheader|request\.headers|request\.args" --include='*.py' src/
```

Confirm whether any call uses string formatting/concatenation with a raw request
value rather than structured logging parameters.

## 3. NEUTRALIZATION CONTROLS

The fix is to encode or escape at the boundary, not to blacklist. Blacklists of
`\n` and `\r` alone are insufficient because control characters span
U+0000-U+001F and U+007F. Use structured logging with field separation so a
newline inside a value cannot start a new record, plus explicit
control-character escaping at the sink and length capping per field.

```python
import json, logging, re
_CTRL = re.compile(r'[\x00-\x1f\x7f]')

def safe(v, maxlen=256):
    v = _CTRL.sub(lambda m: '\\x%02x' % ord(m.group()), str(v))
    return v[:maxlen]

logger.info(json.dumps({"user": safe(username), "path": safe(request.path)}))
```

## 4. VALIDATION TEST (SAFE, OWN DATA ONLY)

Submit values through your own test account or a local instance only. Use a
clearly-attributable marker string rather than content resembling a real
security event:

| Input | Purpose |
|---|---|
| `testuser%0aINFO%20forged%20entry` | newline record forgery |
| `testuser%0d%0aSet-Cookie:%20x=1` | CRLF into structured logs |
| `testuser%00truncated` | NUL truncation in C-based pipelines |
| `a`*5000 | length-cap / log-flooding check |

Inspect the resulting log with `cat -A` to reveal non-printing characters, then
confirm each submission produced exactly one record:

```bash
grep -c 'testuser' app.log        # expect exactly the number you sent
grep -n 'forged' app.log          # expect no match
```

A forged line appearing in the log confirms the finding at the record-parsing
level, which is the meaningful bar. Keep markers obviously synthetic so no
alerting or on-call process acts on them.

## 5. BYPASS SURFACE REVIEW

Check for Unicode line separators `U+2028`, `U+2029`, `U+0085`, which some
parsers treat as line breaks; delimiter injection where logs are CSV or
pipe-separated, shifting columns in downstream tooling; injection via stored
application data such as a username containing delimiters; and missing escaping
when the value is re-serialized for a second destination.

## 6. REMEDIATION CHECKLIST

1. Migrate affected sinks to structured JSON logging with escaping.
2. Add centralized input sanitization used by every log call site, enforced by
   a lint rule or wrapper logger so new code cannot bypass it.
3. Cap field lengths and set per-request log-volume limits.
4. Restrict log file permissions so a compromised web process cannot rewrite
   history, and forward to an append-only store.

## 7. RESPONSIBLE TESTING

Use accounts and data you own, and prefer a staging or local environment. Never
inject content into a shared production SIEM that resembles a genuine security
alert, and never use another user's identifiers. Keep test markers unmistakable
and clean up any records your test creates in shared log destinations.

## Sources
- CWE-117: https://cwe.mitre.org/data/definitions/117.html
- CWE-93: https://cwe.mitre.org/data/definitions/93.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
