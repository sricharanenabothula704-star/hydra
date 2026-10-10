---
name: detecting-weak-random-value-generation-tokens
description: >-
  Audit token, nonce, and identifier generation for predictable or low-entropy randomness that enables session hijacking, password reset abuse, or ID enumeration.
---

# SKILL: Audit token, nonce, and identifier generation for predictable or low-entropy randomness that enables session hijacking, password reset abuse, or ID enumeration.

> **AI LOAD INSTRUCTION**: Load when reviewing authentication code paths that mint security-sensitive values or when entropy findings block sign-off.

## 0. RELATED ROUTING
- [detecting-session-token-predictability-brute-force](#) for post-generation entropy validation
- [detecting-password-reset-account-enumeration-timing](#) for token surface analysis
- [detecting-mfa-fatigue-push-bombing-session-hijack](#) for downstream token abuse paths

## 1. WHY PREDICTABLE RANDOMNESS IS CRITICAL

A predictable secret is not a secret. If an attacker can narrow a token space to a
small set, offline or online guessing becomes feasible regardless of TLS. Every
value derived from `Math.random()`, `rand()`, `time()`, PID, MAC address, or a
seeded PRNG inherits the generator's entropy, not the token's apparent length.

## 2. INSECURE SOURCE PATTERNS

| Language | Insecure | Secure |
|---|---|---|
| Python | `random`, `random.randint`, `random.choice` | `secrets.token_bytes`, `secrets.token_urlsafe` |
| JS/Node | `Math.random()`, `crypto.randomBytes` misuse | `crypto.randomUUID()`, `crypto.randomBytes` |
| PHP | `rand()`, `mt_rand()`, `uniqid()` | `random_bytes()`, `bin2hex(random_bytes(32))` |
| Java | `new Random()`, `ThreadLocalRandom` for secrets | `SecureRandom` |
| C# | `new Random()`, `Guid.NewGuid()` for tokens | `RandomNumberGenerator` |
| Go | `math/rand` | `crypto/rand` |
| Ruby | `rand` | `SecureRandom.hex(32)` |

Audit with targeted searches rather than reading every file:

```bash
grep -rn --include='*.js' --include='*.ts' -E 'Math\.random\(\)' src/
grep -rn --include='*.py' -E '\brandom\.(random|randint|choice|randrange)\b' app/
grep -rn --include='*.java' -E 'new Random\(\)' src/main/
grep -rn --include='*.cs' -E 'new Random\(\)|Guid\.NewGuid\(\)' src/
grep -rn -E '\buniqid\(|\bmt_rand\(|\brand\(\)' --include='*.php' .
```

Also flag timestamp-derivation: `token = base64(issued_at + user_id)`,
`hash(user_id + created_at)`, or any token whose only variation across users is a
counter.

## 3. VERIFYING ENTROPY EMPIRICALLY

Collect a large sample and test for structure rather than trusting inspection.

```bash
# 2000 tokens, look for repeats, per-position uniformity, and length variance
for i in $(seq 1 2000); do
  curl -s -X POST https://app.example.com/api/reset \
    -d "email=user$i@example.com" -o /dev/null -w '%{header_json}\n'
done | jq -r '.location // empty' > tokens.txt

sort tokens.txt | uniq -d                      # any duplicate = deterministic
awk '{print length($0)}' tokens.txt | sort -u  # length must be constant
tr -d '\n' < tokens.txt | fold -w1 | sort | uniq -c | sort -rn | head
```

Strong signals of a seeded generator: sorted order correlates with request
order, per-character distributions skew, or a fixed prefix appears across
samples. Absence of duplicates alone is NOT proof — a 32-bit PRNG with 2000
samples would likely collide, but a 64-bit LCG may not.

## 4. CONTENT-LENGTH TARGETS

- Session IDs, password-reset tokens, API keys: >= 128 bits of entropy.
- CSRF tokens: >= 128 bits.
- Object IDs, email-verification codes: >= 64 bits, or a 6+ digit code with
  rate limiting and short expiry.
- Anything below 64 bits must carry compensating controls and documented risk
  acceptance.

## 5. SERVER-SIDE CONFIRMATION (SAFE)

Use your own test accounts only. Create two throwaway users, request reset tokens
for each, and compare structure without attempting to guess or use any real
credential. Confirm tokens are compared in constant time and are single-use.

## 6. REMEDIATION PATTERNS

```python
# Python
import secrets, hashlib, hmac
raw = secrets.token_urlsafe(32)                      # 256-bit CSPRNG output
digest = hashlib.sha256(raw.encode()).hexdigest()     # store digest only
ok = hmac.compare_digest(digest, presented_digest)   # constant-time compare
```

```js
// Node
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('base64url');
const stored = crypto.createHash('sha256').update(token).digest('hex');
```

Ensure the OS CSPRNG is seeded (`/dev/urandom`, `getrandom(2)`) and never
reseed a library PRNG from `Date.now()` in application code.

## Sources
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- CWE-338: https://cwe.mitre.org/data/definitions/338.html
- CWE-1241: https://cwe.mitre.org/data/definitions/1241.html
- OWASP Testing Guide 4.6.3: https://owasp.org/www-project-web-security-testing-guide/
