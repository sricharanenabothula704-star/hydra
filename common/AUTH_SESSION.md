# : Authentication and Session Management Vulnerabilities
- Source: (Dec 1, 2025) — infosecwriteups.com
- Complete checklist for finding session/auth flaws

## Complete Vulnerability Checklist

### 1. Old Session Does Not Expire After Password Change
- Test: Change password, check if old session still works
- Impact: Stolen session survives password reset

### 2. Failure to Invalidate Session on Logout
- Test: Logout, then reuse old session token
- Impact: Persistent session = permanent access

### 3. Browser Cache Weakness (Back Button Vulnerability)
- Test: After logout, click browser back button
- Impact: Cached pages expose sensitive data

### 4. Email Verification Bypass (Logic Flaw)
- Test: Register without verifying email, access protected features
- Impact: Unverified accounts with full access

### 5. Password Reset Token Persistence
- Test: Request new token, check if old token still valid
- Impact: Multiple valid reset tokens = multiple access paths

### 6. Password Reset Token Reuse
- Test: Use same token multiple times
- Impact: Replay attack on password reset

### 7. Lack of Session Validation on Sensitive Endpoints
- Test: Access admin/settings endpoints without valid session
- Impact: Direct object access without auth check

### 8. Session Fixation
- Test: Set a session ID before login, check if same ID after login
- Impact: Attacker-controlled session ID becomes authenticated

### 9. Concurrent Session Limit Bypass
- Test: Log in from multiple devices/IPs simultaneously
- Impact: No session limit = account sharing/abuse

### 10. Missing Session Rotation After Privilege Change
- Test: After role upgrade, check if old session has new privileges
- Impact: Session carries elevated privileges without rotation

### 11. Unrestricted Session Duration (Infinite Sessions)
- Test: Keep same session for days/weeks without expiry
- Impact: Stolen tokens never expire

### 12. Weak "Remember Me" Token Implementation
- Test: Analyze remember-me cookie for predictability
- Impact: Persistent token brute-force

### 13. JWT Misconfigurations (Stateless Session Issues)
```bash
# Test JWT weaknesses
# 1. None algorithm attack: change alg to "none"
# 2. Weak HMAC secret: crack weak signing key
# 3. Expiration bypass: modify exp claim
# 4. Kid injection: path traversal on key ID
# 5. JWK header injection: embed own public key
```

## Testing Methodology
1. Map all authentication endpoints (login, register, logout, reset, change)
2. Capture all tokens/cookies/session IDs
3. Test each checklist item systematically
4. Try race conditions on token validation
5. Check for cache headers on auth-related pages

## Key Principle
Strong session handling is crucial. Even simple mistakes (no rotation after password change, no logout invalidation) can lead to account takeover. Run this checklist regularly on every target.
