---
name: detecting-smb-signing-disabled-relay-exposure
description: >-
  Hosts that neither require nor enable SMB signing accept relayed NTLM authentication, turning a coerced or captured request into an authenticated session on a second protocol.
---

# SKILL: Hosts that neither require nor enable SMB signing accept relayed NTLM authentication, turning a coerced or captured request into an authenticated session on a second protocol.

> **AI LOAD INSTRUCTION**: Load when auditing SMB signing, NTLM configuration, or network-level relay exposure across Windows servers and workstations in an authorized assessment.

## 0. RELATED ROUTING
- [detecting-adcs-esc8-ntlm-relay-web-enrollment](#) for relay into a CA web enrollment endpoint
- [detecting-ldap-channel-binding-ldap-signing-disabled](#) for the identical class on LDAP
- [detecting-weak-tls-cipher-suites-tls-downgrade](#) for the transport-hardening companion

## 1. WHY SIGNING MATTERS

SMB2 session setup carries the NTLM or Kerberos token. When the server does not verify a
signature over that token, a man-in-the-middle (or the target of a coerced connection) can
capture the authentication and replay it verbatim to a second service. Signing binds the
authentication to the connection by including the server's challenge in the signed blob, so
a captured token is useless elsewhere. Signing must be *required*; signing merely *enabled*
still allows an unsigned session, and therefore still permits relay.

Relay targets ranked by outcome: HTTP/S → OWA/Exchange (direct mailbox), LDAP (credential
write), AD CS web enrollment (domain takeover), SMB (lateral movement), WinRM.

## 2. READ-ONLY AUDIT

```powershell
# server side — RequireSecuritySignature $true is the passing state
Get-SmbServerConfiguration | Select EnableSMB2Protocol, RequireSecuritySignature,
  EnableSecuritySignature, EncryptData

# client side
Get-SmbClientConfiguration | Select EnableInsecureGuestLogons, EnableSecuritySignature,
  RequireSecuritySignature

# NTLM protocol settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select NlmCompatibility, lmCompatibilityLevel, RestrictAnonymous, RestrictAnonymousSAM
```

DCs need `LmCompatibilityLevel = 5` (NTLMv2 only) and `NtmlmMin*Sec = 128`:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select NtmlmMinClientSec, NtmlmMinServerSec, RestrictNtlmIncomingDomain,
  RestrictNtlmOutgoingDC, IncomingNtlmMin, OutgoingNtlmMin
```

Remote, read-only sweep across the estate, plus relay-target enumeration with no relay:

```bash
nmap -Pn -p 445 --script smb2-security-mode,smb-protocols -oN smb-audit.txt 10.0.0.0/24
grep -E 'signing|challenge_response' smb-audit.txt | head -50
python3 ntlmrelayx.py -enum-smb 10.0.0.0/24 -no-smb-server   # lists relayable HTTP/S, relays nothing
```

## 3. REMEDIATION

```powershell
# domain-wide, all domain-joined hosts via GPO "Network security: Lan Manager authentication level"
secedit /export /cfg secpol.cfg /quiet
# edit: Lan Manager Authentication Level = "Send NTLMv2 response only. Refuse LM & NTLM"
secedit /configure /db secedit.sdb /cfg secpol.cfg /quiet

# per-host immediate, then enforce through GPO
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true
Set-SmbClientConfiguration -RequireSecuritySignature $true
# Restrict NTLM to audit + strong crypto
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' NtmlmMinClientSec 128
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' NtmlmMinServerSec 128
```

On domain controllers specifically, enable inbound SMB hardening (MSHT0020/0021/0023)
and restrict RPC so coercion has no endpoint to target.

## 4. ASSESSING RESULT

Report per-host: SMB signing required (pass/enforced), signing enabled only (fail —
relay still possible), disabled (critical), plus NTLM minimum security level and whether
anonymous/NullSession shares are enabled. Rank fixes by reachability: internet-facing
relay targets first, then any DC with inbound SMB open from a user subnet.

## 5. TESTING SAFELY

Only test on infrastructure you own or hold written authorization for. Every command above
is a configuration read and is safe to run broadly. Do **not** run an actual NTLM relay
against production services merely to prove a finding — relay writes attacker-controlled
credentials into a target service and can lock out accounts. If proof is required, stand up
a relay listener on an isolated lab host and relay only to a service you control; otherwise
report "signing not required, so relay to <target> is possible" backed by the
`smb2-security-mode` output. Never send coercion attempts at a domain controller without
written authorization naming the DC and a maintenance window.

## 6. DETECTION SIGNALS

- Event 4624 LogonType 3 without a 3071 signature state transition on the source host
- NTLM authentication where a Kerberos ticket was available (protocol downgrade)
- Single host establishing many NTLM auths to distinct servers over one short window
- `Microsoft-Windows-Security-Auditing` 4776 with NTLM from hosts configured for Kerberos

## Sources
- CWE-294: https://cwe.mitre.org/data/definitions/294.html
- CWE-300: https://cwe.mitre.org/data/definitions/300.html
- MS-SMB2 signing: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
