---
name: detecting-exposed-database-admin-panel-portal
description: >-
  Internet-reachable phpMyAdmin, pgAdmin, Adminer, and similar consoles expose full database control to anyone who finds them.
---

# SKILL: Internet-reachable phpMyAdmin, pgAdmin, Adminer, and similar consoles expose full database control to anyone who finds them.

> **AI LOAD INSTRUCTION**: Load when scanning for exposed DB management consoles during an authorized external exposure review or incident scoping.

## 0. RELATED ROUTING
- [detecting-default-credentials-on-exposed-services](#) for the login that follows console discovery
- [detecting-exposed-devops-tooling-ci-cd-endpoint](#) for the sibling admin-portal class
- [detecting-origin-server-bypass-cdn-security-misconfig](#) for reaching the origin host directly

## 1. WHY THESE CONSOLES REACH THE INTERNET

phpMyAdmin, Adminer, pgAdmin, DBeaver web, MongoDB Compass web, RedisInsight, and
DBeaver-based SQL consoles get deployed for convenience and end up reachable because
the reverse proxy forwards the whole vhost, the panel binds `0.0.0.0`, or an
internal hostname leaked into public DNS. The console itself is not the vulnerability —
the exposure is. A single blank install of Adminer or phpMyAdmin on an unpatched PHP
is a direct path to every table in the backing database.

## 2. PASSIVE DETECTION FIRST

Scan names and ports, not logins. Common paths and their fingerprints:

```
for p in /phpmyadmin/ /phpMyAdmin/ /pma/ /adminer.php /adminer/ /pgadmin/ \
         /sqladmin/ /mysql/ /dbadmin/ /redisinsight/ /mongo/ /mongogui/; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "https://target.example$p"
done
```

Fingerprint responses rather than status alone — SPAs return 200 for everything:

```
curl -s https://target.example/phpmyadmin/ | grep -ioE 'phpmyadmin|phpMyAdmin' | head -3
curl -s https://target.example/adminer.php | grep -ioE 'adminer|login' | head -3
curl -sI https://target.example/pgadmin/ | grep -iE 'server|set-cookie|location'
```

Definitive banners: phpMyAdmin's `pma_session` cookie or `<title>phpMyAdmin`;
Adminer's "Adminer" login form; pgAdmin's `pgadmin` root path with an HTML5 login.

For ports, a connect-only TCP check is enough and generates no application traffic:

```
nmap -sT -p 3306,5432,27017,6379,9200,5984,15672 target.example.com
```

`5984` (CouchDB) and `15672` (RabbitMQ management) are frequently exposed and often
unauthenticated; note them for the next step.

## 3. CONFIRMING UNAUTHENTICATED ACCESS

The highest-value finding is a console that requires no login at all. Test only the
**login page reachability**, never a credential attempt:

- Adminer without a configured password renders straight into a server picker with
  no login form — that is conclusive at first byte.
- CouchDB `/` returns a JSON server banner with `db_name: _users` when open.
- RedisInsight and pgAdmin always prompt; reachability alone is the finding there.

```
curl -s https://target.example:5984/ | head -20
curl -s -o /dev/null -w '%{http_code}\n' https://target.example:15672/api/overview
```

## 4. SEVERITY TRIAGE WITHOUT TOUCHING DATA

Do not enumerate tables or run queries. Severity follows from reachability plus
architecture: a console on the same host as the database means the panel is already
behind the network perimeter, so a single console compromise is a full data breach.
An exposed pgAdmin with saved connections is worse still, because stored credentials
grant database access without touching the console.

## 5. REMEDIATION VERIFICATION

- Bind consoles to `127.0.0.1` or a management VLAN, never `0.0.0.0`.
- Remove unused consoles from the image entirely; do not just disable them.
- Enforce network-layer ACLs so only the jump host can reach the console port.
- Remove `root`/`admin` database accounts from application hosts; use a
  least-privilege application user.
- Put the console behind SSO and add IP allowlisting at the proxy.
- Patch the console's underlying runtime — phpMyAdmin and Adminer have had
  authenticated and pre-auth RCE chains.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Verify console
*reachability* only: send GET/HEAD requests to the login page and nothing else. Do not
submit default credentials, do not attempt logins, do not enumerate databases or
tables, and do not execute SQL through any console — that constitutes unauthorized
data access. Do not run automated brute-force scanners against the login form; rate
and lock out production consoles. Report the URL, port, and banner evidence only.

## Sources
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- OWASP WSTIG-CONF: https://owasp.org/www-project-web-security-testing-guide/
