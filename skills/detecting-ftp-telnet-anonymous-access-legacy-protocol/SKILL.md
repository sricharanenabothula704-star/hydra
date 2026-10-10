---
name: detecting-ftp-telnet-anonymous-access-legacy-protocol
description: >-
  Anonymous FTP and exposed Telnet on port 23 grant cleartext unauthenticated access to file shares and interactive shells over an unencrypted channel.
---

# SKILL: Anonymous FTP and exposed Telnet on port 23 grant cleartext unauthenticated access to file shares and interactive shells over an unencrypted channel.

> **AI LOAD INSTRUCTION**: Load when assessing legacy FTP/Telnet services during an authorized external exposure review of an aging infrastructure estate.

## 0. RELATED ROUTING
- [detecting-default-credentials-on-exposed-services](#) for the credentialed variant on the same ports
- [detecting-cloud-storage-bucket-listing-anonymous-access](#) for the cloud-hosted replacement pattern
- [detecting-directory-listing-exposure-sensitive-files](#) for the directory structure FTP reveals

## 1. WHY THESE PROTOCOLS STILL RUN

Legacy ERP exports, mainframe file transfer, vendor SFTP appliances, and embedded
device firmware update servers keep FTP alive. FTP defaults to anonymous login with
the password `anonymous@`, frequently without even that. Telnet transmits credentials
and session data in cleartext, so anything on-path — including a shared switch port
or an ISP hop — captures them. Both are also commonly bound to management interfaces
that were never intended to be internet-facing.

## 2. PASSIVE PORT AND BANNER CHECKS

Banner grabbing requires only a TCP connect plus one read; no login is attempted:

```
nmap -sT -sV -p 21,23,990,2116 target.example.com
curl -s --max-time 5 telnet://target.example.com:23 | head -3
echo | timeout 5 nc -v target.example.com 21
```

For FTP the anonymous path is designed to succeed without secrets, so probe with a
deliberately empty password first and read the directory listing:

```
curl -s --max-time 10 -u 'anonymous:' ftp://target.example.com/ | head -30
curl -s --max-time 10 -u 'anonymous:anonymous@' ftp://target.example.com/ | head -30
```

A returned listing — `drwxr-xr-x ... pub`, `226 Transfer complete`, or any
filename — confirms anonymous access. Note that `curl -u anonymous:` sends an empty
password, which some servers accept and others reject; test both forms before
concluding.

## 3. PASV AND WRITE-SIDE INDICATORS — READ-ONLY CHECKS

Directory listing is the objective. Do not attempt upload, rename, or delete. These
banner strings reveal the server and whether writes are permitted at all:

```
echo -e "USER anonymous\r\nPASS test@test\r\nSYST\r\nQUIT\r" | nc -w5 target.example.com 21
echo -e "USER anonymous\r\nPASS x\r\nHELP\r\nQUIT\r" | nc -w5 target.example.com 21
```

A `230 Login successful`, `215 UNIX Type: L8`, or `257 "/" is the current directory`
in the response is the finding. `530 Login incorrect` means anonymous is refused.

## 4. TELNET-ONLY VERIFICATION

For Telnet, do not authenticate. Confirm the service offers a login prompt and
capture the banner, then stop:

```
printf '\xFF\xFD\x18\xFF\xFD\x20\xFF\xFD\x23\xFF\xFD\x27' \
  | timeout 5 nc -v target.example.com 23 | strings | head -5
```

The `IAC DO` negotiation bytes are how you tell a real telnetd from a closed port
that a scanner guesses. A login prompt with no TLS option confirms full cleartext
session exposure.

## 5. WHAT TO REPORT WITHOUT EXPLORING FURTHER

Report: host, port, service banner and version, whether anonymous FTP listing
succeeded, whether the telnet login prompt is reachable, and whether the FTP server
advertises write permission. Do not enumerate deeper, download files, or attempt
authentication. Content of an anonymous FTP area frequently includes payroll exports
and customer data — knowing the filenames appear in a listing is sufficient.

## 6. REMEDIATION VERIFICATION

- Disable anonymous FTP; require per-user credentials with a real account database.
- Migrate to SFTP (over SSH) and remove both FTP and Telnet listeners entirely.
- Where FTP must remain for a vendor, restrict it to a dedicated VLAN behind a
  firewall with an allowlist, and enable FTPS implicit TLS on port 990.
- Replace Telnet with SSH; never enable Telnet as a fallback on network devices.
- Rotate any credentials that were ever sent over Telnet — assume capture.
- Scan the estate so these ports cannot silently reappear with a new appliance.

## 7. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Anonymous FTP
"anonymous:" is not a credential guess and is the designed public entry point, but
still confirm authorization before probing. Send only `USER`/`PASS`/`SYST`/`HELP`/
`QUIT`; never upload, delete, rename, or overwrite, and never download listing
contents beyond the first few entries. Do not brute-force real accounts on these
ports. Because cleartext capture is the core risk, do not deliberately route traffic
through third-party proxies or analysis services. Report filenames as categories
rather than reproducing potentially sensitive listing data.

## Sources
- CWE-319: https://cwe.mitre.org/data/definitions/319.html
- CWE-256: https://cwe.mitre.org/data/definitions/256.html
- NIST SP 800-52 Rev. 2 (Telnet/FTP guidance): https://csrc.nist.gov/pubs/sp/800/52/r2/final
