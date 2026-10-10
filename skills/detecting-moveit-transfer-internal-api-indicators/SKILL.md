---
name: detecting-moveit-transfer-internal-api-indicators
description: >-
  Detection and hunting guidance for MOVEit Transfer deployments: internal API abuse, staging tables, webshell artifacts, anomalous admin activity, and exfiltration signals. Deliberately CVE-agnostic so it also covers post-patch and custom-variant abuse.
---

# SKILL: Detection and hunting guidance for MOVEit Transfer deployments: internal API abuse, staging tables, webshell artifacts, anomalous admin activity, and exfiltration signals. Deliberately CVE-agnostic so it also covers post-patch and custom-variant abuse.

> **AI LOAD INSTRUCTION**: Load when you need to hunt a MOVEit Transfer environment for compromise independent of a specific CVE — internal API enumeration, transfer job abuse, staging artifacts, webshell droppings, and exfiltration indicators.

## 0. RELATED ROUTING
- [validating-cve-2023-34362-moveit-transfer-sql](#) for the SQL injection / auth bypass CVE chain
- [webshell-and-persistence-detection-on-iis](#) for IIS-hosted webshell patterns
- [detecting-data-staging-before-exfiltration](#) for T1074 staging correlation
- [hunting-for-command-and-control-beaconing](#) for post-compromise C2 correlation

## 1. DEPLOYMENT BASELINE FIRST

Before hunting, establish what normal looks like. MOVEit Transfer self-hosted runs under IIS as a service account; it has:
- A web UI at `/` (redirects into the self-service MFT portal)
- An internal API surface with endpoints like `/human2.aspx`, `/api/`, `/restapi/`, `/MFT/...`
- Service logs under `C:\Program Files\MOVEit\MOVEit Transfer\` (Logs, and `WebApi` staging)
- A `MFT` instance database (SQL Server or MySQL)

Baseline the service account, the IIS app pool identity, expected admin sources, and normal transfer job volumes.

## 2. INTERNAL API ENUMERATION (PASSIVE)

```powershell
# Enumerate MOVEit endpoints without touching the DB
Invoke-WebRequest "https://moveit-host/" -UseBasicParsing | Select-Object -Expand Content |
  Select-String -Pattern 'human2\.aspx|/api/|/restapi|MFT/' -AllMatches
# Collect JS bundles; they enumerate the internal API surface
$js = (Invoke-WebRequest "https://moveit-host/" -UseBasicParsing).Links.href | ? { $_ -match '\.js' }
foreach ($j in $js) { (Invoke-WebRequest $j).Content | Select-String -Pattern '/api/[A-Za-z]+' -AllMatches }
```

The internal API is where abuse shows up: bulk file listing, transfer-job creation, and user-management endpoints that a stolen cookie or injected session can hit repeatedly.

## 3. TRANSFER-JOB ABUSE SIGNALS

Compromise of MOVEit typically manifests as mass download of files from many folders by a small number of identities. Hunt the app's own audit trail plus system-level:

```sql
-- MOVEit audit table (schema varies; commonly dbo.auditlog)
SELECT TOP 100 Timestamp, UserName, Action, Detail FROM auditlog
WHERE Timestamp > DATEADD(day,-30,GETDATE())
  AND Action IN ('Download','DownloadMultiple','Logon','UserCreated','SetPassword')
ORDER BY Timestamp DESC;
```

Flag high-volume `Download*` per user, downloads spread across many folders in a short window, user creation/admin-group grants at odd hours, and transfers from IPs outside your egress ranges.

## 4. STAGING & WEBSHELL ARTIFACTS

MOVEit exploitation often writes a webshell into the web root and drops random-named files. Hunt:

```powershell
# Random-named files under the MOVEit web/staging directories
Get-ChildItem 'C:\Program Files\MOVEit\MOVEit Transfer' -Recurse |
  ? { $_.Name -match '^[A-Za-z0-9]{8,16}\.(aspx|asp|config|txt|bak)$' } |
  Select FullName, LastWriteTime

# Non-IIS-approved content in the web app folder
Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -Include *.aspx,*.config |
  ? LastWriteTime -gt (Get-Date).AddDays(-30)
```

Also check the IIS `applicationHost.config` for newly created virtual directories, and look for `.bak`/`.zip`/`.7z` archives that suggest staged exfiltration material.

## 5. ANOMALOUS SERVICE-ACCOUNT ACTIVITY

MOVEit stores credentials for downstream systems (SFTP, S3, Azure, SMTP, database). Compromise of MOVEit often pivots via those stored creds:

```powershell
# Unexpected network egress from the MOVEit service account / host
Get-NetTCPConnection -State Established | ? RemotePort -in 21,22,443,445,990 |
  Group RemoteAddress | Sort Count -Descending
# Local archives staged for shipment
Get-ChildItem 'C:\Program Files\MOVEit\MOVEit Transfer' -Recurse -Include *.zip,*.7z,*.bak
```

Because MOVEit centrally stores secrets (SFTP/SSH keys, S3/Azure keys, SMTP and DB passwords), any host that ran MOVEit with stored credentials should have those rotated regardless of patch status.

## 7. DETECTION RULES (SIEM)

- New MOVEit user creation or admin-group change outside business hours → high.
- Spike in download actions by a single account (>baseline × 5) → exfil suspect.
- `human2.aspx` / internal API hit with anomalous query length or `xp_`/`CONCAT`/`OR 1=1` indicators → injection probing.
- MOVEit host initiating outbound to rare IPs/ports → staging/exfil.

## 8. RESPONSE

1. Isolate the MOVEit host; preserve `MFT\Logs`, the database, and the web root.
2. Patch to the fixed build and re-run vendor remediation.
3. Rotate **all** credentials MOVEit stored, plus the MOVEit service account.
4. Reset the application database admin password; check for rogue users/admins.
5. Remove webshells/staged files; rebuild the app folder from a clean copy if needed.
6. Reconcile which files were downloaded vs. what the user was entitled to — defines breach scope for legal.
7. Coordinate with Cl0p leak-site monitoring (this actor is the primary threat using MOVEit).

## Sources
- https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability
- https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.mandiant.com/resources/blog/clop-claims-moveit-transfer-exploitation