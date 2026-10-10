---
name: detecting-exposed-backup-archive-file-download
description: >-
  Dump files and archives left in the web root let anyone download entire databases, site trees, or source without credentials.
---

# SKILL: Dump files and archives left in the web root let anyone download entire databases, site trees, or source without credentials.

> **AI LOAD INSTRUCTION**: Load when auditing internet-facing hosts for .sql/.zip/.tar.gz leftovers, or scoping a backup exposure for incident response.

## 0. RELATED ROUTING
- [detecting-exposed-environment-file-secret-leak](#) for config secrets inside a downloadable archive
- [detecting-exposed-git-repository-source-disclosure](#) for the parallel source-history leak
- [detecting-directory-listing-exposure-sensitive-files](#) for the listing that reveals these names

## 1. THE EXPOSURE CLASS

Backups reach the web root through ad-hoc `mysqldump` redirections, CI artifacts
copied wholesale, rsync mistakes, and editors writing `file.php~` beside `file.php`.
The archive is static: no interpreter runs it, so application-level access control
is irrelevant. Content types also betray the origin — a `.tar.gz` served as
`application/octet-stream` from the site root is almost always a backup.

Common artifacts: `dump.sql`, `backup.sql`, `db.sql`, `site.tar.gz`, `www.zip`,
`public_html.zip`, `release.zip`, `app.zip`, `*.bak`, `*.old`, `*.save`, `*.swp`,
`*.orig`, `*.tlog`, `*.7z`, and dated variants like `backup-2024-03-11.zip`.

## 2. LOW-IMPACT DETECTION

Use HEAD/range requests so you never pull a multi-gigabyte archive. A distinct
`Content-Length` plus a non-HTML content type is the pass/fail signal:

```
for f in dump.sql backup.sql db.sql site.tar.gz www.zip backup.zip app.zip \
         web.zip release.zip public_html.zip site.tar; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $f\n" -r 0-0 \
    "https://target.example/$f"
done
```

`curl -sI` gives headers without any body transfer:

```
curl -sI https://target.example/backup.sql | grep -iE 'HTTP/|content-type|content-length|content-disposition'
```

A `Content-Disposition: attachment; filename="backup.sql"` header on a public
response is conclusive. A 200 with `content-length: 41233981` on `/backup.zip` is
conclusive. Compare against a random path to rule out SPA catch-all echoes.

## 3. VALIDATING WITHOUT DOWNLOADING

Use a single-byte range request to confirm reachability, then read only the first few
kilobytes. Archive magic bytes identify the type and sometimes the tool:

```
curl -s -r 0-64 https://target.example/backup.zip | xxd | head -4
curl -s -r 0-512 https://target.example/dump.sql | head -20
```

`50 4b 03 04` = ZIP, `1f 8b` = gzip, `42 5a 68` = bzip2, `37 7a 5a 50` = 7z. SQL
headers that start with `-- MySQL dump` or `CREATE TABLE` confirm a live data dump
rather than a log file.

## 4. LISTING THE ARCHIVE WITHOUT EXTRACTING IT

Central-directory reads let you enumerate contents from a small tail range. For ZIP
the end-of-central-directory record sits in the last ~64KB, so a ranged fetch
confirms structure without pulling the payload:

```
curl -s -r -65536 https://target.example/backup.zip > /tmp/opencode/tail.bin
curl -s -r 0-64 https://target.example/backup.zip | xxd | head -4
```

In practice the safer route is to download only when the size is modest and the host
is authorized, then list without extracting: `unzip -l archive.zip`,
`tar tzf site.tar.gz`, `7z l archive.7z`. Listing names establishes severity;
you never need file contents.

## 5. IMPACT DETERMINATION FROM NAMES ALONE

A filename listing is sufficient. `wp-config.php`, `config.php`, `database.yml`,
`id_rsa`, `.aws/credentials`, `*.sql`, and `.env` inside an archive confirm critical
exposure without opening anything. Report the manifest, not the data.

## 6. REMEDIATION VERIFICATION

- Delete backups from the web root; move archival copies to object storage with
  authenticated, expiring access only.
- Deny by extension at the edge: nginx
  `location ~* \.(sql|bak|old|zip|tar\.gz|7z)$ { deny all; }`; Apache
  `<FilesMatch "\.(sql|bak|old|zip|tar\.gz|7z)$">Require all denied</FilesMatch>`.
- Generate backups outside the document root with randomized filenames.
- Assume full compromise: rotate any credential present, and treat dumped user data
  as disclosed per applicable breach-notification obligations.
- Check web access logs for prior downloads before deleting evidence.

## 7. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Never download an
archive you have not confirmed you are authorized to copy — it may hold personal
data and you do not need it. Use HEAD or single-byte range requests; do not extract
archives, read record contents, or restore anything recovered. Do not forward dumps
to third-party scanning services, which is itself a disclosure. Report the archive
manifest rather than its data, and coordinate deletion with the owner so forensic
state is preserved.

## Sources
- CWE-530: https://cwe.mitre.org/data/definitions/530.html
- CWE-538: https://cwe.mitre.org/data/definitions/538.html
- OWASP WSTIG-CONF-04: https://owasp.org/www-project-web-security-testing-guide/
