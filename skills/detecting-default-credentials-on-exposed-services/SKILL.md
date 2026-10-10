---
name: detecting-default-credentials-on-exposed-services
description: >-
  Factory-shipped usernames and passwords on internet-reachable consoles grant immediate administrative access without any exploitation.
---

# SKILL: Factory-shipped usernames and passwords on internet-reachable consoles grant immediate administrative access without any exploitation.

> **AI LOAD INSTRUCTION**: Load when assessing exposed management services for vendor defaults during an authorized external review or post-deployment audit.

## 0. RELATED ROUTING
- [detecting-exposed-database-admin-panel-portal](#) for the console class most often left defaulted
- [detecting-exposed-devops-tooling-ci-cd-endpoint](#) for build servers with shipped admin accounts
- [detecting-ftp-telnet-anonymous-access-legacy-protocol](#) for the no-credential variant on legacy ports

## 1. WHY DEFAULTS SURVIVE

Appliances ship with an admin account whose password is in the vendor manual.
Installers rarely change it because the device is not yet reachable from the
internet, and the credential is never revisited after the NAT rule opens the port.
Defaults also live in unit firmware, in images published to registries, and in
first-boot setup scripts. The finding is not the password's secrecy — it is that the
service answers on a public interface with the shipped identity intact.

## 2. PASSIVE IDENTIFICATION BEFORE ANY AUTH ATTEMPT

Fingerprint the service first so credential testing is never speculative:

```
nmap -sT -sV -p 21,23,80,443,445,3389,5900,8080,8443,9090 target.example.com
curl -sI https://target.example:8443/ | grep -iE 'server|www-authenticate|location'
curl -s https://target.example:8443/ | grep -ioE 'sonicwall|fortigate|pfsense|openwrt|horde|grafana|portainer'
```

`WWW-Authenticate`, the `Server` header, and body strings such as appliance model
names identify the vendor. Port 5900 is VNC, 3389 RDP, 8080/8443/9090 are the usual
appliance admin ports, and 9090 is frequently a load balancer or a second service.

## 3. NON-INVASIVE DEFAULT DETECTION

Prioritize three techniques that do not require a password at all:

- **Vendor documentation and CVE advisories** — CVE writeups for a given firmware
  routinely state whether a default credential was present.
- **Firmware image inspection** — for appliances you operate, extract the image and
  review shipped configuration for unchanged passwords.
- **Manufacturer config-audit commands** — most appliances ship a read-only audit
  that reports "password is still the default" without changing anything.

```
# appliance-side audit examples
show system admin | include password      # vendor CLI audit
grep -i 'default' /etc/passwd /etc/shadow | head
```

## 4. CONFIRMING WITHOUT BRUTE FORCE

When explicit written authorization covers credential testing, scope it tightly: one
known default pair per identified appliance, one attempt per account, then stop. Stop
immediately at any change in response — a different message, a redirect to a
dashboard, a session cookie, or a lockout notice. Lockout-triggering attempts on
production devices are an availability incident.

```
curl -s -o /dev/null -w '%{http_code}\n' -u 'admin:admin' https://target.example:8443/
```

A `200` or a `302` into an authenticated shell is confirmation. Report it and rotate
the credential immediately.

## 5. WHERE DEFAULTS MOST OFTEN SURVIVE

Network appliances (firewalls, VPN concentrators, routers, switches), NAS and backup
appliances, hypervisors and out-of-band management (IPMI, iLO, iDRAC), version control
and CI servers, wiki and ticket systems, and IoT gateways. Out-of-band management is
routinely left on the public internet with `admin/admin` and a weak management
protocol — a single valid default there is full host control.

## 6. REMEDIATION VERIFICATION

- Change every shipped credential during installation; automate this as a
  post-deploy check that fails the build.
- Disable or rename default accounts (`root`, `admin`, `ubuntu`) where the platform
  supports it, and require named per-operator accounts with individual auditing.
- Enforce a password policy and MFA on all administrative access paths.
- Remove direct management interfaces from the public internet entirely; reach them
  through a VPN or a bastion, and ACL management ports to a management subnet.
- Audit the estate on a schedule so newly added appliances are caught.

## 7. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test, and confirm in
writing that credential testing is in scope before making a single attempt —
unauthorized login attempts are a criminal offense in many jurisdictions and will
trigger incident response at the owner. Prefer passive identification plus vendor
advisories. When authorized, keep it to a handful of documented defaults on
identified appliances, never on user accounts, never against lockout-enabled systems,
and never with spray tools. Do not persist after a successful login: no file
creation, no shell commands, no configuration changes. Close the session, report
the finding with the exact host and account, and hand rotation to the owner.

## Sources
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-1392: https://cwe.mitre.org/data/definitions/1392.html
- NIST SP 800-63B (authenticator requirements): https://pages.nist.gov/800-63-3/sp800-63b.html
