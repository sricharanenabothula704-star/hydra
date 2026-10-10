---
name: detecting-kerberos-preauthentication-disabled-asrep-roast
description: >-
  Accounts with Kerberos preauthentication disabled can be cracked offline from any captured AS-REP request without ever contacting a domain controller with a credential.
---

# SKILL: Accounts with Kerberos preauthentication disabled can be cracked offline from any captured AS-REP request without ever contacting a domain controller with a credential.

> **AI LOAD INSTRUCTION**: Load when auditing Kerberos account flags for AS-REP roasting exposure or enumerating accounts in an authorized Active Directory assessment.

## 0. RELATED ROUTING
- [detecting-ldap-anonymous-bind-directory-enumeration](#) for finding the account list without credentials
- [detecting-adcs-esc1-vulnerable-certificate-template](#) for the other offline-crack path to privilege
- [detecting-weak-tls-cipher-suites-tls-downgrade](#) for the transport-side weakness class

## 1. THE MECHANISM

Normally a client sends a TGS-REQ preceded by a pre-authentication exchange in which the
KDC verifies possession of the password before issuing anything useful. If
`DONT_REQ_PREAUTH` (0x40000000) is set, the KDC issues the AS-REP *immediately*, and the
response contains the encrypted portion of the user's key material — the same material
protected by the password. Anyone who can capture that blob (network capture, or simply
the response to their own request) cracks it offline with hashcat/john and no further
KDC contact. No failed logon events are generated, so this attack is effectively silent
to the domain controller.

## 2. READ-ONLY ENUMERATION

Prefer passive detection — ask the directory, don't send AS-REQ requests.

```powershell
# authoritative check via the directory, no Kerberos traffic generated
Get-ADUser -Filter {msDS-SupportedEncryptionTypes -ne 0} -Properties msDS-User-PrincipalName |
  Where-Object { $_.PasswordNeverExpires -eq $false } | Out-Null

# the actual flag: UAC_DONT_REQ_PREAUTH bit 0x40000000
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
  -Properties msDS-SupportedEncryptionTypes | Select SamAccountName, userAccountControl
```

```bash
# ldapsearch equivalent against 389/636 from the assessment host
ldapsearch -x -H ldap://dc01.example.com -D "EXAMPLE\auditor" -W -b "DC=example,DC=com" \
  -s sub "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName userAccountControl
```

```powershell
# bulk, safe export for offline triage
Get-ADUser -Filter * -Properties userAccountControl,msDS-SupportedEncryptionTypes |
  Where-Object { [int]$_.userAccountControl -band 0x40000000 } |
  Select SamAccountName, DistinguishedName | Export-Csv .\asrep-roastable.csv
```

## 3. CONFIRMING ENCRYPTION TYPE

Account type matters as much as the flag. A user with `msDS-SupportedEncryptionTypes`
containing DES-CBC-CRC (value 1) allows RC4-HMAC tickets, which crack orders of magnitude
faster than AES. Check both:

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
  -Properties msDS-SupportedEncryptionTypes |
  Select SamAccountName,
    @{n='Types';e={ $_.msDS-SupportedEncryptionTypes }},
    @{n='Weak';e={ [bool]($_.msDS-SupportedEncryptionTypes -band 1) }}
```

DES-CBC-CRC (bit 0) or RC4-HMAC (bit 4) alongside no-preauth is the highest-priority
finding in the whole Kerberos audit.

## 4. REMEDIATION

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' |
  Set-ADUser -AccountNotDelegated $false -CannotChangePassword $false
# clear the bit directly via the computed property
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' | ForEach-Object {
  Set-ADObject $_.DistinguishedName -Replace @{ userAccountControl = [int]$_.userAccountControl -band (-bnot 0x40000000) }
}
# enforce AES on the domain functional level
Set-ADObject -Identity (Get-ADDomain).DistinguishedName -Replace @{ msDS-SupportedEncryptionTypes = 24 }
```

Windows 10+, Server 2019+ accounts can use AES256 (value 0x20) which is not crackable
by any public tool today — still enable preauth, it is the actual control.

## 5. TESTING SAFELY

Only test on infrastructure you own or are authorized in writing to assess. The
enumeration in section 2 uses your own read-only auditor credentials and generates no
attack traffic. Do **not** run Impacket's `GetUserSPNs.py -request` or any AS-REQ spray
against a production domain without explicit written authorization and a plan for the
resulting Kerberos traffic volume; request-mode tooling sends one AS-REQ per account,
which is exactly the traffic signature you are trying to detect. If crack
demonstration is required, restrict it to one dedicated test account that you created
solely for this purpose, and delete it after the engagement.

## 6. DETECTION SIGNALS

- Event 4769 with pre-auth type `0` for the requesting account
- AS-REQ/TGT volume from one host across many distinct sAMAccountNames
- No corresponding 4625 failures — successful KDC responses with no logon
- Long-running hashcat/john processes on a segment endpoint

## Sources
- CWE-521: https://cwe.mitre.org/data/definitions/521.html
- CWE-916: https://cwe.mitre.org/data/definitions/916.html
- MS-KERB Encryption types: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kerb/
