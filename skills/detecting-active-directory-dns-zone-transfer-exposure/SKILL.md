---
name: detecting-active-directory-dns-zone-transfer-exposure
description: >-
  Unrestricted DNS zone transfers (AXFR) against AD-integrated zones hand a complete host, service, and SRV record inventory to an unauthenticated client with no credential use.
---

# SKILL: Unrestricted DNS zone transfers (AXFR) against AD-integrated zones hand a complete host, service, and SRV record inventory to an unauthenticated client with no credential use.

> **AI LOAD INSTRUCTION**: Load when assessing DNS servers for AXFR/ANY exposure or enumerating AD-integrated zones during authorized internal or external review.

## 0. RELATED ROUTING
- [detecting-ldap-anonymous-bind-directory-enumeration](#) for the sibling directory-recon path
- [detecting-adcs-esc1-vulnerable-certificate-template](#) for the escalation that typically follows
- [detecting-smb-signing-disabled-relay-exposure](#) for the next hop after host enumeration

## 1. WHY THIS LEAKS SO MUCH

AD-integrated zones store the domain's service inventory in plain text: DC hostnames
and global catalog SRVs, domain controllers, FSMO role holders, sites and subnets, mail
servers, and — critically for AD CS — the CA's CRL and AIA distribution points. Even
partially protected AD zones enumerate the internal namespace, which turns a black-box
external scan into a complete internal target list. Zone transfers are the highest-value
read-only primitive in AD enumeration: no credentials, no Kerberos tickets, no logs of
failed auth in most deployments.

## 2. READ-ONLY VERIFICATION

```bash
# the canonical probe: dig AXFR against each NS in the zone
for ns in $(dig +short NS example.com); do
  echo "== $ns"
  dig AXFR example.com @"$ns" +noall +answer | head -20
done
```

`Transfer failed` / `REFUSED` / `NOTAUTH` on every server is the hardened result.

```bash
# check ANY (QTYPE=255) and a TSIG-guarded zone
dig ANY example.com @ns1.example.com
dig AXFR example.com @ns1.example.com -y hmac-sha256:keyname:base64key
```

Windows-side, using the DNS module against each authoritative server:

```powershell
Get-DnsServerZone -Name 'example.com' | Select-Object -ExpandProperty ZoneType
Resolve-DnsName -Name example.com -Type AXFR -Server ns1.example.com -ErrorAction SilentlyContinue
Get-DnsServerZoneTransferPolicy -ZoneName example.com | Format-List *
```

`Secure` or `Dynamic` zone type means the zone is not AD-integrated and the same
command still verifies secondary-zone transfer policy.

## 3. READING THE RESULTS

```bash
# harvest just the interesting record types from a successful transfer
dig AXFR example.com @ns1.example.com | grep -E '_ldap\._tcp|_kerberos\._tcp|_msdcs|_crl|_cacert|_pki' \
  | awk '{print $4, $5}' | sort
```

What to flag in a report:
- Any `_msdcs` / `_ldap._tcp` / `_kerberos._tcp` SRV set (domain controller locations)
- `dc01.example.com.` A records on routable IPs (direct host targeting)
- A `_crl` or `_cacert` record naming an internal CA (feeds ESC/ESC8 discovery)
- SPF/MX records revealing mail infrastructure and third-party senders

## 4. REMEDIATION

Restrict transfers at the zone and server scope, not per source host:

```powershell
Set-DnsServerZoneTransferPolicy -Name 'example.com' -IsProtected $true `
  -SecureSecondaryServers (Get-DnsServerZoneTransferPolicy -Name 'example.com').SecureSecondaryServers
Set-DnsServerPrimaryZone -Name 'example.com' -Notify $false
```

For a secondary-only design, leave transfers enabled but restricted to the secondaries:

```powershell
Set-DnsServerZoneTransferPolicy -Name 'example.com' -IsProtected $true `
  -SecureSecondaryServers 'ns2.example.com' -Notify $true
```

Sign the zone with TSIG so even a mis-scoped ACL cannot be walked, and firewall UDP/TCP
53 AXFR from any source that is not a member server or the backup server list. Verify
from an unauthorized vantage point after the change; a fix that only works from the
DNS subnet has not fixed anything.

## 5. TESTING SAFELY

Only query DNS servers you own or are explicitly authorized to test. AXFR is a
read-only protocol operation, so a full transfer request from an in-scope resolver is
low risk, but it is still data exfiltration — prefer `dig` with a small record count and
report record *types and counts* rather than pasting full zone contents into tickets.
Never attempt transfers against third-party or government DNS root servers, never
attempt zone transfer with guessed TSIG keys, and do not use zone data to brute-force
hostnames against systems outside the declared engagement scope.

## 6. DETECTION SIGNALS

- AXFR queries from hosts that are not configured secondaries
- Repeated SOA-probe bursts preceding a full transfer attempt
- Non-standard resolvers (public DNS) appearing in resolver logs for internal zones
- Bulk responses: single-source answers exceeding a few hundred records

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-668: https://cwe.mitre.org/data/definitions/668.html
- MS-ADTS DNS SRV records: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
