---
name: detecting-adcs-esc8-ntlm-relay-web-enrollment
description: >-
  ESC8 is an NTLM relay into the AD CS web enrollment role, turning a coerced or relayed authentication into a domain controller certificate usable for full takeover.
---

# SKILL: ESC8 is an NTLM relay into the AD CS web enrollment role, turning a coerced or relayed authentication into a domain controller certificate usable for full takeover.

> **AI LOAD INSTRUCTION**: Load when reviewing AD CS web enrollment (HTTP) exposure, Extended Protection settings, or NTLM relay paths into a CA in an authorized assessment.

## 0. RELATED ROUTING
- [detecting-adcs-esc1-vulnerable-certificate-template](#) for the other CA-based escalation path
- [detecting-smb-signing-disabled-relay-exposure](#) for the signing prerequisite that enables relay
- [detecting-ldap-channel-binding-ldap-signing-disabled](#) for the same class on a different protocol

## 1. THE ESC8 CHAIN

1. **Coercion or relay source** — a low-privileged attacker induces a domain controller
   (or any machine with an outbound connection) to send NTLM to the attacker's listener:
   PetitPotam/Coercer (`MS-EFSR`, `MS-RPRN`, `MS-DFSNM`), PrinterBug (`MS-RPNP`),
   or `Potato` variants.
2. **NTLM relay** — the attacker relays that authentication to the CA's HTTP `/certsrv`
   endpoint, which performs unauthenticated integrated Windows auth.
3. **Web enrollment** — if the CA allows unauthenticated access to the Web Enrollment role
   **and** does not require Extended Protection for Authentication (EPA) or channel binding,
   the relayed auth becomes an enrollment identity.
4. **Certificate issuance** — the attacker enrolls with SAN `@example.com` /
   `administrator@EXAMPLE.COM` plus arbitrary SID authorization, obtaining a DC-valid cert.
5. **Escalation** — `certipy-ad auth -pfx cert.pfx` requests a TGT over PKINIT/SCHANNEL.

## 2. READ-ONLY VERIFICATION

```powershell
# inspect CA web enrollment role, its security, and HTTP config
Install-AdsrvWebEnrollmentRole
Get-WebServiceConfiguration -CAURL https://ca01.example.com/certsrv -UseDefaultPort |
  Select SSLCertificates, SecureProtocol, ClientAuthentication

# check the IIS authentication on the cgi-bin alias (unauthenticated must be denied)
Get-WebConfiguration -Path / -Recurse |
  Select-String '/certsrv/cgi-bin' -Context 2,2
```

```bash
# network-level: does the CA's HTTP endpoint even answer, and does it accept HTTP (not HTTPS)?
nmap -Pn -p 80,443,445,135 --script ssl-cert,http-auth,smb2-security-mode ca01.example.com
curl -skI https://ca01.example.com/certsrv/  # expect 401 Unauthorized, not 200
```

Confirm the relay prerequisite on the *coercible* hosts (DCs especially):

```powershell
Get-SmbServerConfiguration | Select EnableSMB2Protocol, EnableSecuritySignature,
  RequireSecuritySignature, EncryptData
# EPA is the specific control that defeats ESC8 relay:
Get-WebServiceConfiguration -CAURL https://ca01.example.com/certsrv |
  Select ExtendedProtectionLevel   # should be AllowWhenRequired or Higher on an internal CA
```

`ExtendedProtectionLevel = Disabled` (or the CA site binding has no client-certificate
requirement) is the finding.

## 3. THE DC-ONLY MITIGATION

If hardening the CA is not immediately possible, blocking outbound SMB from domain
controllers closes the coercion→relay path for the highest-value targets:

```powershell
# DC-only inbound SMB restriction (Windows Server 2025 / patched 2012 R2, 2016, 2019)
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled False -Profile Domain
```

Enable inbound SMB hardening (MSHT0020/0021) across DCs, and on servers generally:

```powershell
Set-SmbServerConfiguration -EncryptData $true -RequireEncryption $true
Set-SmbClientConfiguration -EnableSMBQUIC $true
```

## 4. WHAT GOOD LOOKS LIKE

- `ExtendedProtectionLevel = Higher` on the CA (EPA bound to HTTPS, channel binding enforced).
- IIS `/certsrv` requires either Windows authentication with EPA or explicit Deny for anonymous.
- No `MS-EFSR`/`MS-RPC` reachable inbound on DCs from user segments; RPC restricted per RPC Firewall/CAE.
- SMB signing **required** domain-wide (blocks relay to SMB, not to HTTP — EPA is what blocks HTTP).
- PKNTRAFFIC / audit enabled on the CA; Event 4886 anomalies monitored.

## 5. TESTING SAFELY

Only test on infrastructure you own or are explicitly authorized to assess. Prefer
read-only checks in section 2 — `Get-WebServiceConfiguration`, the `curl` HEAD, and SMB
signing audits generate no relay traffic. Do **not** run `ntlmrelayx.py` against a
production CA, and do not perform HTTP-to-HTTP or HTTP-to-SMB relay or coercion against
domain controllers unless you have written authorization naming the specific DC and an
agreed maintenance window; coercion generates MS-RPC traffic to domain controllers and
can destabilize them if unauthenticated RPC is not already restricted. To demonstrate
impact benignly, relay to a **lab CA** you control and use a dedicated test principal.
After any test, revoke the issued certificate and confirm the DC did not retain state.

## 6. DETECTION SIGNALS

- Event 4768/4769 with `Certificate` preauth and logon on a host where the user never used a smartcard
- Event 4886 with SAN `*@example.com` or `*administrator@EXAMPLE.COM`
- MS-RPC (TCP 135 / dynamic high ports) bursts from a workstation to a DC with no prior SMB session
- IIS 401-less `/certsrv/certreq` requests from hosts not running a CA agent

## Sources
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- MS-ADTS Web Enrollment: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/
- Microsoft SMB signing guide: https://learn.microsoft.com/en-us/windows-server/security/tasks/basics-of-smb-security
