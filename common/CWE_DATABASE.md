# CWE Database — Bug Bounty Reference

## Injection Vulnerabilities
| CWE | Name | BugBase Type | Severity |
|-----|------|-------------|----------|
| CWE-77 | Command Injection | Command Injection | Critical |
| CWE-78 | OS Command Injection | Command Injection | Critical |
| CWE-79 | Cross-Site Scripting (XSS) | XSS | High |
| CWE-89 | SQL Injection | SQL Injection | Critical |
| CWE-90 | LDAP Injection | LDAP Injection | High |
| CWE-93 | CRLF Injection | CRLF Injection | Medium |
| CWE-94 | Code Injection | RCE | Critical |
| CWE-96 | Template Injection | SSTI | Critical |
| CWE-98 | PHP Include | LFI/RFI | Critical |
| CWE-113 | HTTP Response Splitting | CRLF | Medium |
| CWE-134 | Format String | Format String | High |
| CWE-601 | Open Redirect | Open Redirect | Medium |
| CWE-611 | XXE | XXE | Critical |
| CWE-918 | SSRF | SSRF | High |
| CWE-917 | Expression Language Injection | SSTI | Critical |
| CWE-943 | NoSQL Injection | NoSQL Injection | High |
| CWE-1336 | Template Injection in SST | SSTI | Critical |

## Auth & Session
| CWE | Name | BugBase Type | Severity |
|-----|------|-------------|----------|
| CWE-269 | Privilege Escalation | Privilege Escalation | High |
| CWE-284 | Improper Access Control | IDOR/BAC | High |
| CWE-287 | Authentication Bypass | Auth Bypass | Critical |
| CWE-306 | Missing Auth | Auth Bypass | Critical |
| CWE-307 | Brute Force | Rate Limiting | Medium |
| CWE-345 | Insufficient Verification | Auth Bypass | High |
| CWE-346 | Origin Validation Error | CORS | Medium |
| CWE-347 | JWT Verification | JWT Issues | High |
| CWE-352 | CSRF | CSRF | Medium |
| CWE-384 | Session Fixation | Session Issues | Medium |
| CWE-613 | Session Expiration | Session Issues | Low |
| CWE-639 | IDOR | IDOR | High |
| CWE-640 | Password Reset Bypass | Auth Bypass | High |
| CWE-798 | Hardcoded Credentials | Secret Exposure | Critical |
| CWE-862 | Missing Authorization | IDOR/BAC | High |
| CWE-863 | Incorrect Authorization | IDOR/BAC | High |

## Info Disclosure
| CWE | Name | BugBase Type | Severity |
|-----|------|-------------|----------|
| CWE-200 | Information Exposure | Info Disclosure | Medium |
| CWE-209 | Error Message Info Leak | Info Disclosure | Medium |
| CWE-215 | Debug Information Leak | Info Disclosure | Medium |
| CWE-312 | Cleartext Sensitive Data | Info Disclosure | High |
| CWE-359 | PII Exposure | PII Leak | Critical |
| CWE-532 | Log Exposure | Info Disclosure | High |
| CWE-540 | Source Code Leak | Info Disclosure | High |
| CWE-548 | Directory Listing | Info Disclosure | Medium |

## CVSS 3.1 Quick Reference
| Vector | Score | Severity |
|--------|-------|----------|
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 | Critical |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | High |
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | High |
| AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | 6.1 | Medium |
| AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | 5.3 | Medium |
| AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.9 | Low |

## BugBase Severity Mapping
- **Critical (9.0-10.0)**: RCE, SQLi extraction, auth bypass admin, SSTI, LFI sensitive files
- **High (7.0-8.9)**: SSRF, CORS+credentials, IDOR PII, actuator /env, stored XSS
- **Medium (4.0-6.9)**: CORS wildcard, open redirect, actuator info, reflected XSS
- **Low (1.0-3.9)**: Stack traces, missing headers, non-sensitive info disclosure
- **Informational (0.0)**: Subdomains, open ports, non-sensitive endpoints

## WAF Detection Commands
```bash
# Detect WAF vendor
wafw00f https://target.com
whatwaf -u https://target.com

# Test WAF rules
curl -s -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://target.com/cgi-bin/
curl -s "https://target.com/?id=1'UNION SELECT 1,2,3--" | head -20
```

## WAF Bypass Techniques Summary
| Technique | Applicable To | Example |
|-----------|--------------|---------|
| Case randomization | SQLi, XSS | `uNiOn SeLeCt` |
| Comment injection | SQLi, XSS | `UN/**/ION SE/**/LECT` |
| URL encoding | All | `%55NION %53ELECT` |
| Double encoding | All | `%2555NION` |
| HTML entity encoding | XSS | `&#60;script&#62;` |
| Unicode normalization | XSS, SQLi | `%C0%AE%C0%AE/` |
| Null byte injection | LFI, SQLi | `%00` |
| HTTP Parameter Pollution | SQLi, Auth | `id=1&id=2` |
| Chunked encoding | All | Transfer-Encoding: chunked |
| Whitespace alternatives | SQLi | `UNION%0ASELECT` |
| Newline injection | SQLi, XSS | `%0A` |
| Mixed encoding | All | Multiple encoding layers |
| HTTP/2 downgrade | Protocol | Force HTTP/1.0 |
| Content-Type confusion | All | Switch JSON/XML/form |
| Body padding | All | Add junk to exceed WAF size limit |
