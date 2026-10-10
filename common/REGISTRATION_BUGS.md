# : Hunting Bugs in User Registration Features
- Source: (Nov 23, 2025) — infosecwriteups.com
- Complete checklist of 22 registration vulnerabilities

## Full Vulnerability Checklist

### 1. Duplicate Registration and Account Overwrite
Test: Register with existing email — does it overwrite or error? When overwrite occurs, it can lock the original user out.

### 2. Case Sensitivity and Shadow Account Bypass
Test: `admin@example.com` vs `Admin@example.com` — two different accounts? Can be used for impersonation.

### 3. Denial of Service Through Large Input Fields
Test: Submit extremely long strings in name/email fields. If server processes without limits, it can crash or exhaust resources.

### 4. Missing Rate Limiting During Signup
Test: Send 1000+ registration requests in rapid succession from single IP. If all succeed, account creation can be automated at scale.

### 5. Stored XSS in Registration Fields
Test: Inject `<script>alert(1)</script>` in name, bio, or other profile fields. If rendered unsanitized on admin panel or profile pages, stored XSS.

### 6. Insufficient Email Verification
Test: Register with non-owned email or disposable email. Can the account access protected features without clicking verification link?

### 7. Unsafe Registration Practices (HTTP, Temp Emails)
Test: Registration over HTTP instead of HTTPS? Does it accept `@tempmail.com` addresses?

### 8. Weak Password Policies
Test: Can you set "123" or "password" as password? No complexity requirements?

### 9. Path Overwrite and Route Collision
Test: `/api/register/admin` — does it overwrite the registration route or access admin registration?

### 10. Server-Side Validation Bypass
Test: Disable JavaScript, modify minlength/maxlength HTML attributes, submit directly. Does server re-validate?

### 11. Hidden or Legacy Registration Endpoints
Test: Scan for old API versions: `/api/v1/register`, `/api/old/signup`, `/signup-legacy`. May lack current security controls.

### 12. HTTP Parameter Pollution in Signup
Test: `?email=attacker@evil.com&email=victim@target.com` — which one does server use?

### 13. Weak or Predictable Verification Links
Test: Analyze verification URL pattern — is it sequential/guessable? Can you verify anyone's account?

### 14. Punycode and IDN Homograph Signup Bypass
Test: Register with punycode domains: `xn--e1aybc@example.com` (looks different, same visual). Bypass blocklists.

### 15. OTP Verification Brute-Force During Signup
Test: Is OTP length sufficient (6+ digits)? Is rate limiting applied? Can you brute-force 4-digit OTP?

### 16. Weak or Reusable Session Tokens During Signup
Test: After registration, is session token predictable? Can same token be reused?

### 17. Null Byte Injection in Signup Inputs
Test: `admin%00@evil.com` — does null byte truncate during validation?

### 18. Missing Email Confirmation Enforcement
Test: Can you access paid/protected features without confirming email?

### 19. Session Fixation During Signup and Verification
Test: Set session ID before registration, check if same ID is used after successful registration.

### 20. Cache Control Issues in Signup and Verification
Test: After signup/logout, press browser back button. Are sensitive pages cached?

### 21. Cross-Account IDOR Testing After Signup
Test: After registration, modify user_id parameter in API calls. Can you access other users' data?

### 22. Mass-Assignment in JSON-Based Registration Flows
Test: See MASS_ASSIGNMENT.md for full JSON payload variants.

## Testing Methodology
1. Map all registration endpoints (signup, verify email, complete profile)
2. Proxy all traffic through Burp Suite
3. Test each checklist item systematically
4. Check both web form and API registration flows
5. Test for race conditions in verification bypass
6. Always test both happy path and edge cases

## Key Principle
The signup flow is the "front door" where user input first hits the database and auth layer — makes it a goldmine for bugs. A solid registration system sets the tone for the app's entire security posture.
