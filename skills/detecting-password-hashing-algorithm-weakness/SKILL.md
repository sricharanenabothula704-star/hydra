---
name: detecting-password-hashing-algorithm-weakness
description: >-
  Identify insecure password storage by locating hashing primitives, cost parameters, salt handling, and upgrade paths in authentication code and existing credential stores.
---

# SKILL: Identify insecure password storage by locating hashing primitives, cost parameters, salt handling, and upgrade paths in authentication code and existing credential stores.

> **AI LOAD INSTRUCTION**: Load when auditing credential storage, migrating a password database, or reviewing a breach remediation plan.

## 0. RELATED ROUTING
- [detecting-session-token-predictability-brute-force](#) for offline cracking context
- [detecting-password-reset-account-enumeration-timing](#) for adjacent auth logic
- [detecting-secret-management-hardcoded-config-files](#) for static secret discovery

## 1. HASH FUNCTIONS ARE NOT PASSWORD HASHING

Fast general-purpose hashes are designed for throughput, which is exactly what
makes offline cracking cheap. A GPU rig exhausts unsalted MD5 or SHA-1
passwords at billions of attempts per second; a memory-hard KDF at cost 12 takes
orders of magnitude longer per guess.

| Algorithm | Verdict | Reason |
|---|---|---|
| MD5, SHA-1, SHA-256 | Reject | Fast, no memory cost, no tunable work factor |
| unsalted fast hash | Critical | Identical passwords produce identical digests; rainbow tables apply directly |
| PBKDF2-HMAC-SHA256 | Acceptable | Acceptable when iterations >= 600,000 (OWASP 2023) |
| scrypt | Preferred | Memory-hard, in stdlib-ish ecosystems, tunable N/r/p |
| bcrypt (cost >= 10) | Preferred | Battle-tested, embedded salt, native cost |
| Argon2id | Best | Memory-hard, winner of Password Hashing Competition |

## 2. STATIC DISCOVERY

```bash
# Language-specific primitive search
grep -rn --include='*.py' -E 'hashlib\.(md5|sha1|sha256)|\.hexdigest\(\)' app/
grep -rn --include='*.js' --include='*.ts' -E "createHash\('(md5|sha1|sha256)'" src/
grep -rn --include='*.php' -E '\b(md5|sha1|crypt)\s*\(' app/
grep -rn --include='*.java' -E 'MessageDigest\.getInstance\(' src/
grep -rn --include='*.go' -E '(md5|sha1)\.Sum\(' internal/

# Search for absence of a KDF - this grep returning nothing is itself a finding
grep -rn --include='*.py' -E 'bcrypt|argon2|scrypt|pbkdf2_hmac' app/
grep -rn --include='*.java' -E 'BCrypt|Argon2|SCrypt|PBKDF2' src/

# Hardcoded / duplicated salts are a serious defect
grep -rn --include='*.py' -E 'salt\s*=\s*["\x27]' app/
grep -rn -E 'SALT\s*=\s*["\x27][^"\x27]+["\x27]' --include='*.py' --include='*.js' .
```

## 3. INSPECTING AN EXISTING STORE (SAFE)

Do not brute force or attack a production database. Instead:

1. Review the hashing helper module and any migration scripts.
2. Ask for a redacted sample of the credential table format (e.g. two or three
   fake rows you generate yourself in a scratch environment).
3. Confirm the stored value encodes its parameters so the algorithm can be
   upgraded transparently:
   - bcrypt: `$2b$12$<22-char-salt><31-char-hash>`
   - argon2: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
   - scrypt: `$s2$<N>$<r>$<p>$<salt>$<hash>`
4. Verify comparison uses `password_verify` / `argon2.verify` / a constant-time
   compare rather than `==`, which leaks via timing.

## 4. COST PARAMETER REVIEW

- bcrypt: cost 10 minimum, 12 or above for interactive logins. Cost is log2
  iterations.
- scrypt: N >= 2^17, r = 8, p = 1 as a floor; measure against your server's
  latency budget.
- Argon2id: m = 64 MiB, t = 3, p = 4 as a floor; tune m upward on memory-rich
  hosts.
- Reject any configuration where hashing exceeds ~250 ms, which pushes users
  toward weaker passwords.

## 5. MIGRATION WITHOUT LOCKOUT

```python
# verify-and-rehash on successful login
def verify_and_upgrade(stored_hash, password):
    if bcrypt.checkpw(password.encode(), stored_hash):
        if bcrypt.gensalt(rounds=12)[:7] != stored_hash[:7]:   # cost drift
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        return stored_hash
    return None
```

Rehash on login only, never force a reset that asks users to reuse the same
password. Run an opportunistic background job for accounts that have not logged
in recently, and monitor the upgrade-rate metric for anomalies.

## 6. RELATED DEFECTS TO FLAG IN THE SAME PASS

Passwords truncated to 72 bytes (legacy bcrypt behavior), enabling
hash-collision-based second-preimage attacks. No maximum length, enabling
megabyte-length DoS against the KDF. Recovery or backup flows that decrypt
passwords rather than resetting them. APM traces capturing plaintext or full hashes.

## 7. RESPONSIBLE TESTING

Review configuration, code, and redacted samples you generate yourself. Do not
crack, brute-force, or attack real password hashes, even with store access. Never
request real user credentials, export a production credential table, or use
recovered passwords to access any account. Confirm with a throwaway credential in a
scratch environment, and report the algorithm and cost parameter rather than any
derived value. Written authorization is required before inspecting a live
credential store for anyone else's system.

## Sources
- CWE-916: https://cwe.mitre.org/data/definitions/916.html
- CWE-327: https://cwe.mitre.org/data/definitions/327.html
- CWE-759: https://cwe.mitre.org/data/definitions/759.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
