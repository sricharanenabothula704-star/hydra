---
name: detecting-expired-or-self-signed-certificate-misconfiguration
description: >-
  Expired, self-signed, wrong-hostname, or weak-chain certificates break trust and push users toward browser warnings and TLS-stripping downgrade attacks.
---

# SKILL: Expired, self-signed, wrong-hostname, or weak-chain certificates break trust and push users toward browser warnings and TLS-stripping downgrade attacks.

> **AI LOAD INSTRUCTION**: Load when auditing web endpoints, load balancers, API gateways, or internal service certificates for validity dates, chain trust, and hostname match.

## 0. RELATED ROUTING
- [detecting-weak-tls-cipher-suites-tls-downgrade](#) for the transport-layer companion audit
- [detecting-snmp-default-community-string-exposure](#) for device PKI and credential hygiene
- [detecting-adcs-esc8-ntlm-relay-web-enrollment](#) for the CA-side that should have issued these

## 1. WHY IT IS A SECURITY FINDING, NOT JUST OPS

An expired or untrusted certificate is usually "fixed" by users clicking through a warning.
That habituation is the security problem: a user trained to ignore one warning will ignore a
fraudulent certificate too, enabling man-in-the-middle interception. Weak or short chains
break non-browser clients (Java keystores, pinned CA bundles, Go's strict defaults) in ways
usually invisible until integration time, and self-signed internal certs train users to
accept untrusted TLS everywhere, including externally.

## 2. READ-ONLY CHECKS

```bash
# expiry, chain, and hostname in one shot
echo | openssl s_client -connect app.example.com:443 -servername app.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256

# hostname verification (must print "verify OK")
echo | openssl s_client -connect app.example.com:443 -servername app.example.com \
  | openssl x509 -noout -checkhost app.example.com

# full chain verification against the system trust store
openssl s_client -connect app.example.com:443 -CApath /etc/ssl/certs -verify_return_error </dev/null 2>&1 \
  | grep -E 'Verify return code|verify (error|OK)'
```

```bash
# who signed it, and how weak is the signature algorithm
openssl s_client -connect app.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -E 'Signature Algorithm|Public-Key|Issuer:'

# scan a range for expiring or self-signed endpoints
nmap -p443 --script ssl-cert -iL hosts.txt -oN certs.txt
grep -E 'days=0|notAfter=|issuer=' certs.txt | head -40
```

Massive TLS sweep with JSON output for reporting:

```bash
tlsx -l hosts.txt -san -cn -so -silent -json -o certs.json
```

## 3. WINDOWS AND ACTIVE DIRECTORY PKI

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) } |
  Select Subject, NotAfter, Thumbprint
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject } |   # self-signed
  Select Subject, NotAfter, Thumbprint

# domain-issued certs that expired or are still pending renewal
Get-ADObject -Filter {objectClass -eq 'pKICertificate'} -Properties pKIExtendedKeyUsage |
  Where-Object { $_.NotAfter -lt (Get-Date).AddDays(45) } |
  Select SamAccountName, NotBefore, NotAfter
```

Publicly trusted certificates must come from an ACME/enterprise PKI path; a self-signed
leaf presented on a public hostname is a hard finding.

## 4. WHAT TO REPORT AND HOW TO FIX

For each endpoint record: FQDN, SAN list, issuer, `notBefore`/`notAfter`, days remaining,
key size and signature algorithm, chain depth, and whether hostname verification passes.

| Issue | Fix |
| --- | --- |
| Expired | Renew via ACME (`certbot`, cert-manager, win-acme) and automate renewal + alerting at 30/14/7 days |
| Self-signed on public name | Replace with an ACME-issued certificate; remove the root from client trust stores |
| Self-signed internally | Issue from the internal CA and distribute that CA to clients via Group Policy / base image |
| Hostname mismatch | Correct the SAN list, not the client-side warning bypass |
| SHA-1 or RSA < 2048 | Reissue with SHA-256 and 2048+ bits (ECDSA P-256 acceptable) |
| Missing intermediate | Serve the full chain, not just the leaf |

An expiry alert pipeline matters more than the renewal itself: a monitoring check that
fails the build or pages the owner before day 0 prevents recurrence.

## 5. TESTING SAFELY

Only test hosts you own or are explicitly authorized to assess. Every command here is a
read-only handshake — no requests reach application handlers and no trust store is modified.
Do not "fix" anything during the assessment: adding a certificate to a client's trust store
to silence a warning invalidates the finding and hides real risk. Do not forge or impersonate
a certificate for any host as proof; the existing misconfiguration is sufficient evidence,
and generating a fraudulent certificate for a third-party domain may be unlawful. If the
engagement covers an internal CA, validate with `certutil -verify` rather than installing
test roots on shared systems.

## 6. DETECTION SIGNALS

- Monitoring sweeps reporting `days=0` or negative on any public endpoint
- Internal endpoints whose issuer equals their own subject (self-signed)
- SAN mismatch between the requested hostname and the certificate's subjectAltName
- Client logs containing certificate verification failures during TLS handshakes

## Sources
- CWE-295: https://cwe.mitre.org/data/definitions/295.html
- CWE-298: https://cwe.mitre.org/data/definitions/298.html
- NIST SP 800-52 Rev. 2 TLS guidelines: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
