---
name: detecting-ldap-anonymous-bind-directory-enumeration
description: >-
  Anonymous binds against LDAP let unauthenticated clients read directory data and probe every account for existence; used for AD recon before credential attacks.
---

# SKILL: Anonymous binds against LDAP let unauthenticated clients read directory data and probe every account for existence; used for AD recon before credential attacks.

> **AI LOAD INSTRUCTION**: Load when assessing LDAP/AD ports (389, 636, 3268, 3269) for anonymous read access or enumerating domain objects in an authorized engagement.

## 0. RELATED ROUTING
- [detecting-ldap-channel-binding-ldap-signing-disabled](#) for the sibling LDAP misconfiguration class
- [detecting-active-directory-dns-zone-transfer-exposure](#) for passive directory enumeration via DNS
- [detecting-adcs-esc1-vulnerable-certificate-template](#) for escalation that follows anonymous recon

## 1. WHAT ANONYMOUS BIND ENABLES

Anonymous Simple Bind transmits no credentials, so it succeeds whenever the server
does not explicitly deny unauthenticated binds. Exposed reads typically include
`netlogon` naming contexts, `memberOf`, `userPrincipalName`, group memberships, and
password policy objects. Anonymous bind is also the cheap oracle for spraying: bind
as `cn=username,cn=users,dc=...` with a wrong password and compare the diagnostic to
a known-good account. Any difference in message, error code, or response length is an
account-enumeration oracle.

## 2. READ-ONLY VERIFICATION

Start passively and anonymously. No credentials, no writes. Hardened output is
`result: 1 Operations error` or `insufficient access`:

```
ldapsearch -x -H ldap://dc01.example.com -b "dc=example,dc=com" -s base namingContexts
```

```powershell
# Windows-side enumeration with the built-in .NET provider
$dc = [System.DirectoryServices.DirectoryEntry]"LDAP://dc01.example.com/DC=example,DC=com"
$dc.AuthenticationType = 'Anonymous'
$dc.Properties | ForEach-Object { $_.Name }
```

Account-existence probe — all three lines must read `denied` on a hardened DC:

```powershell
foreach ($u in 'admin','jdoe','zz_nonexistent_9931') {
  try {
    $e = New-Object System.DirectoryServices.DirectoryEntry(
      "LDAP://dc01.example.com/CN=$u,CN=Users,DC=example,DC=com")
    $e.AuthenticationType = 'Anonymous'
    $null = $e.GetType().InvokeMember('distinguishedName','GetProperty',$null,$e,$null)
    "$u : ENUMERATED"
  } catch { "$u : denied ($($_.Exception.InnerException.Message))" }
}
```

## 3. SCALED DISCOVERY

```bash
nmap -Pn -p 389,636,3268,3269 --script ldap-rootdse,ldap-search,ldap-novell-getpass \
  --script-args 'ldap.base="dc=example,dc=com"' dc01.example.com
```

```bash
# ldap3 in Python for a reproducible read-only check
python3 - <<'PY'
import ldap3
srv = ldap3.Server('dc01.example.com', port=389, get_info=ldap3.ALL)
conn = ldap3.Connection(srv, auto_bind=True)   # no credentials = anonymous
for nc in srv.info['naming_contexts']:
    conn.search(nc, '(objectClass=user)', search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName'], size_limit=5)
    print(nc, '->', conn.response)
PY
```

## 4. VERIFYING THE MITIGATION

```powershell
dsquery * -filter "objectClass=*" -limit 1 | Select-Object -First 3   # expect access denied
Get-ADObject -Filter {objectClass -eq 'user'} -Properties * -Server dc01 | Measure-Object
```

Remediation is centralized, not per-server:

```powershell
Set-ADObject -Identity "DC=example,DC=com" -Replace @{'msDS-ServerObjectFlags' = 782}
Set-ADAuthenticationPolicy -Identity 'Default Authentication Policy' -AllowAnonymousAuth $false
```

For NetIQ/AD LDS and non-AD directories the equivalent control is an anonymous ACL
removal or an Access Control Point scoped to `domainDnsZones` only. Firewalling 389
to untrusted zones is defence in depth, not a substitute.

## 5. TESTING SAFELY

Only probe infrastructure you own or are explicitly authorized to test. Begin with
anonymous read-only searches and LDAP_ROOTDSE reads; never create or modify directory
objects, and never password-guess against real accounts without written authorization
and an agreed lockout threshold. To demonstrate impact, report a count of returned
objects rather than their contents, so evidence proves exposure without exfiltrating
personal data.

## 6. DETECTION SIGNALS

- Repeated anonymous binds with no matching authentication event
- High-rate rootDSE requests from one source (payload discovery)
- Bundled hostname/SPN/domainSid enumeration in a single bind
- Successful directory reads carrying blank credentials

## Sources
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- CWE-521: https://cwe.mitre.org/data/definitions/521.html
- Microsoft LDAP bind policy: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/ldap-bind-policies
