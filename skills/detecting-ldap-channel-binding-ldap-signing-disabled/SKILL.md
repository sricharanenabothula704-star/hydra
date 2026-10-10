---
name: detecting-ldap-channel-binding-ldap-signing-disabled
description: >-
  Without LDAP signing and channel binding, an intercepted LDAP session is replayable and a captured NTLM token can be relayed to authenticate as the victim elsewhere.
---

# SKILL: Without LDAP signing and channel binding, an intercepted LDAP session is replayable and a captured NTLM token can be relayed to authenticate as the victim elsewhere.

> **AI LOAD INSTRUCTION**: Load when auditing domain controllers and application servers for LDAP signing, channel binding, and NTLM relay exposure in an authorized assessment.

## 0. RELATED ROUTING
- [detecting-smb-signing-disabled-relay-exposure](#) for the identical weakness on SMB
- [detecting-ldap-anonymous-bind-directory-enumeration](#) for access control on the same ports
- [detecting-adcs-esc8-ntlm-relay-web-enrollment](#) for the highest-impact relay destination

## 1. THE TWO CONTROLS

**LDAP signing** (RFC 4511 / MS-ADTS) requires the LDAP message to be signed with the
session key, proving both parties' identity and preventing tampering.

**Channel binding** (MS-SSAS / MS-ADTS Extended Protection) binds NTLM authentication to
the underlying TLS channel via an `tls-server-end-point` hash. A captured NTLM blob cannot
be reused on a different TLS session, because the hash differs.

Together they defeat a two-step attack: capture the LDAP bind (plain 389 or a mis-trusted
TLS), then relay that NTLM token to HTTP, SMB, or LDAP elsewhere. With LDAPS but no channel
binding, relay still succeeds because the attacker presents the token on *their own* TLS
session with a server certificate the client trusts.

## 2. READ-ONLY AUDIT

Server-side configuration on the DC:

```powershell
foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\System')) {
  Get-ItemProperty $k | Select PSPath, LDAPServerIntegrity, ObjectLevel
}
# client-side defaults, i.e. what will sign when it connects out
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select LdapServerIntegrity, LdapClientSigning, LdapClientChannelBinding, NtmCompatibility
```

Hardened values: `LdapServerIntegrity = 2` (sign) or `1` (sign when the channel supports
it), `LdapClientChannelBinding = 1`. `0` means never sign.

```bash
# probe whether the server accepts an unsigned bind over plain LDAP
ldapsearch -x -H ldap://dc01.example.com -b "" -s base supportedCapabilities
crackmapexec ldap dc01.example.com -u svc_backup -p 'REDACTED' --ldap-signing
```

```python
import ldap3
srv = ldap3.Server('dc01.example.com', port=389, use_ssl=False, get_info=ldap3.ALL)
c = ldap3.Connection(srv, user='EXAMPLE\\svc_backup', password='REDACTED',
                     authentication=ldap3.NTLM, auto_bind=True)
print('bound:', c.result['description'], '| message:', c.result['message'])
```

A successful bind with `use_ssl=False`, or `NtmlmMinServerSec` below 128, is the finding.

```powershell
# channel binding / signing as observed on each LDAP connection
& 'C:\Windows\System32\netlogon.exe' /debug:ldapp /domain:example.com /lpt:34567
```

## 3. REMEDIATION

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LdapServerIntegrity 2
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LdapClientSigning 2
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LdapClientChannelBinding 1
```

For 2016-era and older, apply the Safer Domain Controller Settings hotfix (KB4490425 and
successors), which adds `LdapClientChannelBinding`, then confirm `NoChannelBinding = 1` for
the DC LDAP service. Enforce LDAPS (636) or STARTTLS in application configuration; forbid
`ldap://` URIs across any network boundary. Note that application servers (IIS, Exchange,
SQL) bind to the DC with a service account — those are the credentials worth stealing, so
force LDAPS there first.

## 4. ASSESSMENT OUTPUT

Per DC report `LdapServerIntegrity`, `LdapClientChannelBinding`, `LdapClientSigning`,
`NoChannelBinding`, and `NtmCompatibility`. Any zero for signing or channel binding,
combined with an NTLM rather than Kerberos bind method, is a relay finding. Prioritise DCs
reachable on port 389 from user subnets over hardened management networks.

## 5. TESTING SAFELY

Only test on infrastructure you own or are explicitly authorized to assess. Every command in
section 2 is a configuration read or an authenticated bind using your own auditor
credentials; none alter state. Do **not** perform a live relay or capture-and-replay of LDAP
NTLM tokens against production services — relaying real domain credentials can escalate
privilege and create persistence you cannot cleanly undo. Demonstrate impact by binding as a
dedicated read-only test account you created, or rely on the configuration audit alone,
since the registry value is sufficient evidence. Capture traffic only on a segment you own
and destroy any captured blobs securely.

## 6. DETECTION SIGNALS

- Plain LDAP (389) traffic toward DCs that support LDAPS (636) — downgrade indicator
- `netlogon /debug:ldapp` reporting `NoChannelBinding = 1` on DC service connections
- NTLM or Negotiate bind types toward LDAP where Kerberos was available
- One captured NTLM blob replayed to many distinct LDAP/HTTP targets from a single host

## Sources
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CWE-319: https://cwe.mitre.org/data/definitions/319.html
- MS-ADTS Channel Binding: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- RFC 4511 LDAP v3: https://datatracker.ietf.org/doc/html/rfc4511
