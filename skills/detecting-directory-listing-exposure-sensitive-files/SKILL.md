---
name: detecting-directory-listing-exposure-sensitive-files
description: >-
  Autoindex-enabled web roots publish the full filename inventory of a directory, exposing internal naming, backup artifacts, and versioned source files.
---

# SKILL: Autoindex-enabled web roots publish the full filename inventory of a directory, exposing internal naming, backup artifacts, and versioned source files.

> **AI LOAD INSTRUCTION**: Load when auditing web server directory-index settings or reviewing discovered index pages during an authorized external assessment.

## 0. RELATED ROUTING
- [detecting-exposed-backup-archive-file-download](#) for the artifacts a listing reveals
- [detecting-exposed-environment-file-secret-leak](#) for config files surfaced by browsing
- [detecting-exposed-git-repository-source-disclosure](#) for source paths exposed via indexes

## 1. LISTING AS AN ATTACK SURFACE

A directory index turns a guessing game into a browser. When `autoindex` is on, the
server returns a sortable, searchable table of every entry in the directory with
sizes and modification dates — and nested directories are one click away. The value
is not the files you can read today but the *inventory*: internal project names,
customer and vendor codenames, dated backups, `old/` and `test/` and `tmp/`
directories, `.sql` dumps, `logs/`, `uploads/` with user filenames, and config
fragments. Even when every listed file returns 403 on GET, the filename set is a
disclosure and a roadmap for the rest of an assessment.

## 2. DETECTING AUTOINDEX

Compare a known-missing path against directory-looking paths. A real index returns
HTML with a file table and a parent-directory link; a rewrite rule returns the app's
`index.html`:

```
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target.example/uploads/
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target.example/zz-nonexistent-9482/
curl -s https://target.example/uploads/ | grep -ioE 'index of|parent directory|\.zip|\.sql' | head
```

Two `Directory listing for` titles or `<h1>Index of` on distinct paths confirm the
server's default index page is exposed.

## 3. PARSING WITHOUT HARVESTING

Read names only; do not download. Extract the anchor list and reduce it to categories
so no sensitive filenames land in a report:

```
curl -s https://target.example/uploads/ \
  | grep -oE 'href="[^"]+"' | sed 's/href="//;s/"//' \
  | grep -vE '^\?|^/|\.\./' | head -40
curl -s https://target.example/uploads/ | grep -ioE 'href="[^"]+\.(sql|bak|zip|env|pem|log|conf)"' | sort -u
```

Useful signals: dated or numbered filenames indicating a backup cadence;
`.git/`, `.env`, `wp-config.php`, `config.php`, `application.properties`,
`appsettings.json`, `*.key`, `*.pfx`; and `.DS_Store` or `Thumbs.db` confirming the
directory was authored from a workstation.

## 4. SERVER-SPECIFIC AUTOINDEX VECTORS

- **Apache**: `mod_autoindex` on with `Options +Indexes`. `Options -Indexes` is the fix;
  `Indexes` in a virtual host overrides a server default.
- **nginx**: `autoindex on;` — off by default, so this is usually an explicit
  misconfiguration in a hand-written block.
- **SFTP/cloud sync frontends**: many web file managers enable browsing implicitly.
- **Container images**: `python -m http.server` used as a placeholder serves indexes
  from the current working directory, frequently including application source.

## 5. SEVERITY AND REPORTING

Severity scales with what's in the listing, not with the fact of listing. A listing
containing only `index.html` and a favicon is low. A listing containing `.env`,
`.git/`, `*.sql`, `backup.zip`, or `logs/` with app-server logs is critical. Report the
directory path, the count of entries, and a categorized summary of sensitive
filenames — avoid pasting full name lists containing customer identifiers or user
uploaded filenames.

## 6. REMEDIATION VERIFICATION

- Disable autoindex at the server level (`Options -Indexes` on Apache,
  `autoindex off;` on nginx) and set a directory without index files as the default.
- Move uploads and logs outside the document root and serve them through a
  controlled handler.
- Remove `.git`, `.env`, backups, and config files from the deployed artifact.
- Add a deny rule for dotfiles and backup extensions in case a future block re-enables
  indexing.
- Add a CI check that the built artifact contains no indexable directories and no
  sensitive filenames.

## 7. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Confirm indexing on
one or two obvious paths, then read only the index HTML — never fetch the files it
lists, since a listing is not authorization to read. Do not recursively crawl
indexes on an unbounded tree; one or two levels is enough to establish the finding
and prevents generating megabytes of load on a large directory. Do not download
uploads or customer documents. Report categorized filename patterns rather than
verbatim names, and avoid copying listing output into third-party scanners.

## Sources
- CWE-548: https://cwe.mitre.org/data/definitions/548.html
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- Apache mod_autoindex: https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html
