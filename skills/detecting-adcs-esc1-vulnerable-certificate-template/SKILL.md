---
name: detecting-adcs-esc1-vulnerable-certificate-template
description: >-
  ESC1 occurs when an AD CS certificate template lets a low-privileged enrollee specify an arbitrary subject and any SAN, yielding a certificate that authenticates as a domain controller.
---

# SKILL: ESC1 occurs when an AD CS certificate template lets a low-privileged enrollee specify an arbitrary subject and any SAN, yielding a certificate that authenticates as a domain controller.

> **AI LOAD INSTRUCTION**: Load when auditing AD CS enrollment templates for ESC1/ESC3 conditions or reviewing certificate-based privilege escalation in an authorized AD assessment.

## 0. RELATED ROUTING
- [detecting-adcs-esc8-ntlm-relay-web-enrollment](#) for the sibling escalation against the same CA
- [detecting-kerberos-preauthentication-disabled-asrep-roast](#) for the offline-crack route to the same accounts
- [detecting-expired-or-self-signed-certificate-misconfiguration](#) for general PKI hygiene on the CA host

## 1. THE ESC1 CONDITIONS

ESC1 requires all four of the following on a single enrollment template:
1. The enrollee's security principal has **Enroll** rights on the template.
2. **Client Authentication** is in the template's EKU list (or no EKU is constrained).
3. **SUPPLY_INFORMATION** is not in the template's schema permissions, letting the
   requester place their own subject.
4. Template is not flagged **ENROLLEE_SUPPLIES_SUBJECT** (critical extension absent or set false).
5. `msPKI-Certificate-Name-Flag` supports `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (bit 0 = 1).

The attack itself is one `Certipy req`/`certipy-ad` call producing a certificate whose
subject is `CN=Administrator` — but escalation is only meaningful with **PKINIT** (SCHANNEL)
enabled, which allows that certificate to request a TGT. Also verify `msPKI-Enrollment-Flag`
has `CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS` / template is not `CT_FLAG_NO_SECURITY_EXTENSION`
in a way that breaks PKINIT.

## 2. READ-ONLY DISCOVERY

```powershell
# enumerate the CA and its templates with the built-in PKI module (Windows Server only)
$ca = Get-ADObject -SearchBase (Get-ADObject -SearchBase "CN=Configuration,DC=example,DC=com" \
  -LDAPFilter '(objectClass=pKICertificateTemplate)' -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" |
  Where-Object {$_.displayName -eq 'CA01'} ).whenCreated
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" `
  -Filter {msPKI-Certificate-Name-Flag -eq 1} -Properties * | Select displayName, msPKI-Certificate-Name-Flag, pKIExtendedKeyUsage
```

Practical, portable check with Certipy (read-only enumeration, no enrollment):

```bash
certipy-ad req -u auditor@example.com -p 'REDACTED' -dc dc01.example.com -enumerate
certipy-ad req -u auditor@example.com -p 'REDACTED' -dc dc01.example.com -target 'CA01.example.com\\EXAMPLE-CA01' -template 'UserAuth' -no-passreq -outfile /dev/null
```

`CERTIFICATE_REQUIRED_ENROLLMENT_*` errors are fine; what matters is whether the
template is listed as enrollable *and* has the name flag.

## 3. ANALYSING A TEMPLATE MANUALLY

```powershell
$t = Get-ADObject -LDAPFilter '(displayName=UserAuth)' `
  -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Configuration,DC=example,DC=com" -Properties *

@{
  EnrolleeSuppliesSubject = ($t.'msPKI-Certificate-Name-Flag' -band 1) -eq 1
  SupplyInformation       = -not ($t.'msPKI-Enrollment-Flag' -band 0)   # informational note only
  ClientAuth              = ($t.pKIExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2') -or ($null -eq $t.pKIExtendedKeyUsage)
  AutoEnroll              = $t.'msPKI-Enrollment-Flag' -band 0x20
  StrongKeyEnforced       = $t.'msPKI-Enrollment-Flag' -band 0x8
}
```

`EnrolleeSuppliesSubject = True` combined with `ClientAuth = True` is the finding.

## 4. REMEDIATION

```powershell
# remove the enrollee-supplies-subject permission from the template's security descriptor
$dn = "CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
$acl = Get-Acl "LDAP://$dn"
$acl.SetAccessRuleProtection($true, $false)                     # remove inherited WRITE_DAC/WRITE_OWNER
Set-Acl "LDAP://$dn" $acl
# or, more commonly, remove the Authenticated Users / Domain Users write
$acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'WriteProperty' } |
  ForEach-Object { [void]$acl.RemoveAccessRule($_) }
```

Then enforce: Client Authentication only on templates that need it, require the
`msPKI-Enrollment-Flag` `CT_FLAG_PUBLISH_TO_DS`, set `msPKI-Certificate-Application-Policy`
to 1.3.6.1.4.1.311.21.8 for smartcard logon, and audit enrollment (Event 4886/4897).

## 5. TESTING SAFELY

Only test on infrastructure you own or hold written authorization for. Enumeration is
read-only and should be your default proof. If you must prove ESC1 impactfully, enroll
from a **dedicated test account you created**, never from a real privileged principal, and
validate with `certipy-ad req ... -no-passreq -oneline` and `certipy-ad auth` — a successful
PKINIT proves the escalation without ever touching Domain Admin's credentials. Do not
request certificates with the subject of a real administrator in a live environment: that
persists a credential you may not be able to revoke cleanly. Verify revocation with
`certutil -view -restrict "Disposition=20"` after revoking the test cert.

## 6. DETECTION SIGNALS

- Event 4886 (certificate issued) with SAN containing `administrator@`, `krbtgt@`, or `Domain Controller`
- Event 4898/4899 with a subject that does not match the requester's own CN
- Enrollment from a non-CA host by a standard user with no smartcard hardware
- Spike in enrollment at one template outside a reissue window

## Sources
- CWE-298: https://cwe.mitre.org/data/definitions/298.html
- CWE-288: https://cwe.mitre.org/data/definitions/288.html
- MS-ADTS Certificate Services overview: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
