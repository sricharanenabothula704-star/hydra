# : Punycode IDN Homograph — 0-Click Account Takeover
- Source: (Jun 13, 2025) — infosecwriteups.com
- Critical technique using lookalike Unicode characters for ATO without user interaction

## What is an IDN Homograph Attack?
Internationalized Domain Name (IDN) Homograph Attacks use characters from different languages that look identical but are technically different Unicode code points. Example: Latin "a" (U+0061) vs Cyrillic "а" (U+0430).

Visually: `admin@company.com` vs `admin@соmpаnу.com` (all Cyrillic letters)
Server-side: Completely different domain → bypasses email validation.

## Attack Vectors

### 1. Email Registration with Punycode
```bash
# Step 1: Generate punycode email
# Original: victim@target.com
# Punycode: vіctіm@tаrgеt.com (using Cyrillic lookalikes)

# Step 2: Intercept in Burp (browsers auto-encode punycode)
# Replace email field with punycode version

# Step 3: Register account
# If server doesn't normalize, you get verified access as "victim@target.com"
```

### 2. Password Reset via Punycode Email
```bash
# Step 1: Request password reset for "victim@target.com"
# Step 2: Intercept and change email to punycode version
# Step 3: Reset link sent to punycode email (attacker controls)
# Step 4: Use reset link to change victim's password
# Step 5: Zero-click ATO — victim never notified
```

### 3. Punycode in Username Field
Input punycode characters in the username field, then use original username to log in after password reset bypass.

## Tools
```bash
# Burp Suite — intercept and modify email parameters
# Burp Collaborator — SMTP/email callback server
# Punycoder — generate punycode characters
# Python idna library
```

## Where to Test
- Magic link login systems
- Invite-by-email flows
- OAuth login whitelisting
- Forgot password / email change flows
- SSO / SAML trust domains
- Email-based 2FA bypass

## Testing Payloads
```bash
# Cyrillic lookalikes (visually identical to Latin)
а → Cyrillic а (U+0430)
е → Cyrillic е (U+0435)
о → Cyrillic о (U+043E)
р → Cyrillic р (U+0440)
с → Cyrillic с (U+0441)
х → Cyrillic х (U+0445)
у → Cyrillic у (U+0443)

# Example: replace all Latin chars in "target.com" with Cyrillic
# tаrgеt.соm (every letter is Cyrillic — visually identical)
```

## Prevention
- Normalize email domains before comparison: use IDNA library
- Never use `.endswith()` for security decisions
- Always verify user emails through confirmation links
- Whitelist verified domains, not user inputs
- Reject emails containing punycode-encoded domains unless required

## Impact
- No user interaction required (0-click)
- Bypasses firewalls and filters silently
- Most developers don't test for IDN spoofing
- Works at the logic level — hardest to detect
