---
name: detecting-weak-tls-cipher-suites-tls-downgrade
description: >-
  Legacy cipher suites (RC4, DES, 3DES, EXPORT, MD5-based MACs, small RSA keys) and missing protocol pinning leave TLS traffic passively decryptable or actively downgradeable.
---

# SKILL: Legacy cipher suites (RC4, DES, 3DES, EXPORT, MD5-based MACs, small RSA keys) and missing protocol pinning leave TLS traffic passively decryptable or actively downgradeable.

> **AI LOAD INSTRUCTION**: Load when reviewing HTTPS endpoints, API gateways, load balancers, or internal service TLS configuration for weak ciphers and protocol downgrade risk.

## 0. RELATED ROUTING
- [detecting-expired-or-self-signed-certificate-misconfiguration](#) for the other half of TLS PKI hygiene
- [detecting-smb-signing-disabled-relay-exposure](#) for the same downgrade/relay class on SMB
- [detecting-ldap-channel-binding-ldap-signing-disabled](#) for the same weakness on LDAP

## 1. WHAT ACTUALLY BREAKS

- **RC4 and 3DES**: RC4 biases and Sweet32 make plaintext recovery feasible from captured
  traffic; RC4 is prohibited outright by RFC 7465. **EXPORT / NULL / anon** give none.
- **MD5-based MACs** are a forgery risk.
- **TLS 1.0/1.1** are deprecated (RFC 8996), BEAST affects TLS 1.0 CBC, PCI DSS 4.0 bars them.
- **TLS compression (CRIME)** plus attacker-controlled content leaks plaintext, and **no
  HSTS** makes a first visit trivially strippable to plain HTTP.

Together these let a network-position attacker downgrade or passively read traffic carrying
session cookies, bearer tokens, and API credentials.

## 2. SCANNING

```bash
# broad, readable summary
testssl.sh --quiet --warnings off https://app.example.com
testssl.sh --protocols --server-defaults --cipher-per-proto https://app.example.com

# which protocol versions does the endpoint accept?
for v in tls1 tls1_1 tls1_2 tls1_3; do
  openssl s_client -connect app.example.com:443 -$v </dev/null 2>&1 | grep -q "Protocol.*$v" \
    && echo "$v ACCEPTED" || echo "$v refused"
done
```

```bash
# mass TLS assessment across a range
masscan -p443 10.0.0.0/24 --rate 5000 --open | tee tls-hosts.txt
nmap -p443 --script ssl-enum-ciphers,ssl-protocols -iL tls-hosts.txt -oA tls-audit
```

`sslyze` gives machine-readable JSON for baseline diffing across environments:

```bash
sslyze --regular app.example.com --json_out=tls.json
sslyze --cipher_client_cert app.example.com:443
```

## 3. CHECKING THE COMPLIANT BASELINE

```bash
# Mozilla intermediate: TLS 1.2+ only, AEAD suites, forward secrecy, >=2048-bit keys
openssl s_client -connect app.example.com:443 -cipher 'ECDHE+AESGCM' </dev/null 2>&1 \
  | grep -E 'Server Temp Key|Protocol|Cipher *:'
```

Assert: no SSLv3/TLS 1.0/1.1; no NULL/EXPORT/RC4/DES/3DES/MD5 MACs; ECDHE or DHE present
for forward secrecy; `Server Temp Key: X25519`, `ECDH, P-256`, or `DHE, 2048 bit`; RSA
modulus >= 2048; compression off; HSTS with max-age >= 31536000 plus `includeSubDomains`.

## 4. REMEDIATION

```nginx
# nginx: TLS 1.2/1.3 only, modern suites, OCSP stapling, HSTS
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_stapling on;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

```apache
# Apache: TLS 1.2+ only and the same suite policy
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305
SSLHonorCipherOrder off
SSLSessionTickets off
```

For internal workloads, prefer mTLS (RFC 8705) so that the client also authenticates the
server, and mark internal services with `ssl_protocols TLSv1.3` where client support allows.
Note that disabling TLS 1.2 breaks older clients — audit the client population first.

## 5. TESTING SAFELY

Only test hosts you own or are explicitly authorized to assess, from the engagement's agreed
vantage points — inside and outside results can differ legitimately due to load balancer
geography. Handshake testing is read-only, but avoid high-rate cipher enumeration against
production load balancers; `testssl.sh --fast` or `sslyze --regular` is plenty. Do not run
downgrade exploitation or BEAST/CRIME proof-of-concept traffic against production sessions
without authorization, since it requires active MITM of live user traffic.

## 6. DETECTION SIGNALS

- Inbound handshakes offering TLS 1.0/1.1 in the aggregate TLS metrics
- Certificates with RSA < 2048 or SHA-1 signatures
- Absence of `Strict-Transport-Security` despite `https` deployment
- Plaintext HTTP 301/200 responses for authenticated paths

## Sources
- CWE-327: https://cwe.mitre.org/data/definitions/327.html
- CWE-326: https://cwe.mitre.org/data/definitions/326.html
- RFC 8996 deprecating TLS 1.0/1.1: https://datatracker.ietf.org/doc/html/rfc8996
- testssl.sh: https://testssl.sh/
