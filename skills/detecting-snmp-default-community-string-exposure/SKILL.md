---
name: detecting-snmp-default-community-string-exposure
description: >-
  SNMP v1/v2c transmits the community string in cleartext, so a default value such as public or private grants unauthenticated read and often write access to an entire device.
---

# SKILL: SNMP v1/v2c transmits the community string in cleartext, so a default value such as public or private grants unauthenticated read and often write access to an entire device.

> **AI LOAD INSTRUCTION**: Load when assessing network infrastructure, printers, switches, or applications on UDP/TCP 161 for default SNMP community strings and version exposure.

## 0. RELATED ROUTING
- [detecting-ldap-anonymous-bind-directory-enumeration](#) for the directory-side equivalent
- [detecting-active-directory-dns-zone-transfer-exposure](#) for another unauthenticated read path
- [detecting-expired-or-self-signed-certificate-misconfiguration](#) for device PKI hygiene

## 1. WHY SNMP STILL MATTERS

SNMP v1/v2c carries the community string in cleartext in both directions, so one capture on
any traversed path exposes it. Default communities shipped by every vendor (`public`,
`private`, `cisco`, `monitor`) are a standing assumption. Read access alone yields the full
interface list, routing table, ARP cache, and on Cisco the running configuration containing
passwords. Write access is often also granted and permits interface shutdowns and OSPF
teardown. Neither version has message integrity, so responses can be modified in flight.

## 2. READ-ONLY VERIFICATION

Enumerate first, then attempt authentication with your own agreed test community:

```bash
# masscan-style sweep for the service, then targeted probes
nmap -sU -p 161 --open --min-rate 5000 10.0.0.0/24
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.1.0        # sysDescr: works with default community
snmpwalk -v1 -c private 10.0.0.1 2.5.4.6.0                # ifIndex table on private
snmpget  -v2c -c public 10.0.0.1 1.3.6.1.4.1.9.9.109.1.1.1.1.6  # ciscoConfig copy running-config
```

Bulk community check, then confirm the value came from the device not a middlebox:

```bash
onesixtyone -c ./default-snmp-community.txt 10.0.0.0/24
snmpbulkwalk -v2c -c public -Cr50 10.0.0.1 .1 2>&1 | head -40
snmpget -v2c -c public -Oqv 10.0.0.1 1.3.6.1.2.1.1.1.0
# expected: "Cisco IOS Software, C2960 Software, Version 12.2(58)SE2"
```

## 3. WHAT TO ENUMERATE WHEN ACCESS EXISTS

These OIDs prove impact without changing device state:

| OID | Meaning |
| --- | --- |
| `1.3.6.1.2.1.1.1.0` | sysDescr — device make/model/version |
| `1.3.6.1.2.1.1.6.0` | sysName — hostname |
| `1.3.6.1.2.1.2.2.1.2` | ifDescr — every interface present |
| `1.3.6.1.2.1.4.20.1.1` | ipRouteTable — full routing table |
| `1.3.6.1.4.1.9.9.109.1.1.1.1.6` | ciscoConfig copy running-config |
| `1.3.6.1.2.1.25.4.2.1.2` | hrStorageTable — printers, storage |
| `1.3.6.1.4.1.9.2.1.1` | cisco memory pool utilization |

If `ciscoConfig` returns base64, decode it and treat any contained password as a finding,
never as a working credential for testing.

## 4. REMEDIATION

```cisco
! Cisco IOS: SNMPv3 only, with authPriv, and no v1/v2c communities left at all
snmp-server group SNMPV3-GROUP v3 priv
snmp-server user audituser SNMPV3-GROUP auth sha <authpass> priv aes 128 <privpass>
snmp-server user audituser REMOTE-ACCESS SNMPv3
no snmp-server community public
no snmp-server community private
snmp-server host 10.0.10.5 traps version 3 priv audituser
snmp-server enable traps linkdown
```

Other vendors: disable the community strings, create an SNMPv3 `group`/`user` with SHA
authentication and AES-128 privacy, and ACL the SNMPv3 user to the NMS address. Printers
are the most exposed device class — replace SNMPv1 with SNMPv3 or restrict it to the print
server VLAN. Enable `logging snmp-host traps` so a successful community guess becomes an
event.

## 5. TESTING SAFELY

Only test on infrastructure you own or are explicitly authorized to test. Prefer the
`public`/`private` defaults — do not run large community dictionaries against a live
production network without agreement, since sprayed wrong communities can trip device
lockout or alarm floods. Start read-only: `snmpwalk`/`snmpget` change no state. Never issue
`snmp-set` against production devices; report write access as a finding rather than proving
it. Capture traffic only on infrastructure you control and destroy the capture afterward,
since it may contain credentials for other systems.

## 6. DETECTION SIGNALS

- UDP/161 from monitoring stations to device VLANs with no corresponding SNMPv3 engine
- `snmpget` against `ciscoConfig`, `hrStorage`, or `ifDescr` from a non-NMS address
- One host walking large OID subtrees across many devices (mass enumeration signature)
- SNMPv1/v2c packets appearing on networks where SNMPv3-only is claimed

## Sources
- CWE-1188: https://cwe.mitre.org/data/definitions/1188.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- RFC 3411 SNMPv3 architecture: https://datatracker.ietf.org/doc/html/rfc3411
- NVD SNMP weak community advisories: https://nvd.nist.gov/vuln/search
