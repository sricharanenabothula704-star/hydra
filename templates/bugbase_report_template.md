# BugBase Report Submission Template

## Select Your Scope
[Choose the scope under which the bug was identified]

## Vulnerable Endpoint / Affected URL
[Specific endpoint or URL]

## Select Your Vulnerability Type
[Choose from: Authentication Bypass, XSS, IDOR, SQLi, SSRF, etc.]

## Select Severity
Severity: [Critical/High/Medium/Low/Informational]
CVSS: [CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N]

---

## Report Title
[VulnType] — [Specific Endpoint/Asset] [What it exposes/does]

## Report Summary
[2-3 sentence high-level overview of the vulnerability]

## Proof of Concept

### Description
[High-level summary about this vulnerability and the security implications of exploiting it]

### Security Impact
[To the best of your understanding, describe what the actual security impact is]

- [Impact 1]
- [Impact 2]
- [Impact 3]

### Steps To Reproduce
1. No prerequisites — [explain what's needed/not needed]
2. [Exact curl command]
   ```
   curl -sk [url]
   ```
   Response: [expected output]
3. [Next command]
   ```
   curl -sk [url]
   ```
   Response: [expected output]

### Specifics
- Testing Account: [email used]
- Affected Domain(s): [domain]
- Specific Versions/Vendors: [versions if applicable]

### Recommendations
**Immediate:**
- [Fix 1]
- [Fix 2]

**Long-term:**
- [Fix 3]
- [Fix 4]

---

## Vulnerability Impact
- IP Address: [your IP]
- Testing Email: [your email]

## Review And Submit Your Report
[Final notes or summary before submitting]
