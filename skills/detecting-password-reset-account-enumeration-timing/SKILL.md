---
name: detecting-password-reset-account-enumeration-timing
description: >-
  Detect user enumeration in password reset and recovery flows through response differences, status codes, body content, redirects, and timing side channels.
---

# SKILL: Detect user enumeration in password reset and recovery flows through response differences, status codes, body content, redirects, and timing side channels.

> **AI LOAD INSTRUCTION**: Load when auditing account recovery, testing login and registration forms, or reviewing any endpoint that accepts an email or username.

## 0. RELATED ROUTING
- [detecting-user-registration-email-verification-bypass](#) for the sibling verification path
- [detecting-session-token-predictability-brute-force](#) for post-recovery token handling
- [authbypass-authentication-flaws](#) for the wider authentication family

## 1. THE FOUR LEAKS

Enumeration rarely comes from one obvious signal but from four weak signals that
combine: message text ("No account with that email" versus "Reset link sent"),
HTTP status (`404` versus `200`), response body length (a template rendering an
extra element for unknown accounts), and timing (a nonexistent user skips the
hash lookup and mail send). Each alone is defensible; together they are decisive.

## 2. IDENTIFY ENUMERABLE INPUTS

```bash
grep -rn --include='*.py' -E 'does not exist|no account|unknown user' app/
grep -rn --include='*.js' -E 'no account|user not found|invalid email' src/
grep -rn -E 'forgot|reset|recover' --include='*.py' --include='*.js' app/ src/
```

Cover every recovery variant: reset by email, username, or phone, security-question
fallback, and "resend" endpoints.

## 3. RESPONSE COMPARISON (OWN ACCOUNTS ONLY)

Compare your own registered address against an address at your own domain that
you know is unregistered. Never test another person's real address.

```bash
KNOWN='selftest-owned@example.com'      # an account you created
UNKNOWN='selftest-absent@example.com'    # unregistered, at a domain you control
R='https://app.example.com/api/password/reset'

curl -s -o /dev/null -w 'known   %{http_code} %{size_download} %{time_total}\n' \
  -X POST $R -d "email=$KNOWN"
curl -s -o /dev/null -w 'unknown %{http_code} %{size_download} %{time_total}\n' \
  -X POST $R -d "email=$UNKNOWN"

# Field-level diff of the full responses
curl -s -X POST $R -d "email=$KNOWN"  > r1
curl -s -X POST $R -d "email=$UNKNOWN" > r2
diff <(jq -S . r1) <(jq -S . r2)   # any structural delta is a finding
```

Run each variant several times, since some differences appear only on repeat.

## 4. TIMING ANALYSIS

Timing differences are only meaningful statistically. Collect enough samples to
separate signal from jitter:

```bash
for email in "$KNOWN" "$UNKNOWN"; do
  for i in $(seq 1 30); do
    curl -s -o /dev/null -w '%{time_total}\n' -X POST $R -d "email=$email"
  done
done | paste - - | awk '{s+=$2-$1; n++} END {print "delta_ms:", s/n*1000}'
```

A consistent delta above roughly 50-100 ms, reproducible across runs, indicates a
branch on account existence; single outliers are noise. Confirm by reading the
handler, since an unknown address that skips a hash computation or a mail call
produces exactly this signal.

## 5. HEADER AND REDIRECT LEAKS

Also compare response headers. Differences in `Location`, `Set-Cookie`, a
tracking header, or redirect destination reveal existence even when the body is
identical:

```bash
curl -sI -X POST $R -d "email=$KNOWN"  > h1
curl -sI -X POST $R -d "email=$UNKNOWN" > h2
diff <(sort h1) <(sort h2)
```

Some frameworks issue a `303` to a page that reveals the outcome, so verify the
destination page too.

## 6. CORRECT IMPLEMENTATION

- Return one identical response for every input: same status, body, headers, and
  comparable execution path.
- Perform a dummy password hash verification and a no-op mail queue publish for
  unknown accounts so the timing profile matches.
- Queue mail asynchronously and always report success.
- Rate limit per source, per identifier, and per IP regardless of message
  uniformity.
- Never alert with the plaintext identifier for unknown-account cases, since that
  turns enumeration into an incident-response tool.

## 7. RESPONSIBLE TESTING

Use only addresses you own or control: your own account plus an unregistered
address at a domain where you may receive mail. Never probe third-party addresses,
enumerate a customer list, or trigger reset emails for accounts you do not own.
Keep volume low enough that no real user is affected, and prefer staging for
timing measurement.

## Sources
- CWE-203: https://cwe.mitre.org/data/definitions/203.html
- CWE-209: https://cwe.mitre.org/data/definitions/209.html
- OWASP Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
