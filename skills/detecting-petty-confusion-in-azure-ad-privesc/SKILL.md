---
name: detecting-petty-confusion-in-azure-ad-privesc
description: >-
  Detecting Azure AD / Microsoft Graph application-role confusion privilege escalation. Covers confusing-deputy app registrations, Graph app-role over-permission, credential add/update on service principals, and the tenant-takeover chain (add credential to Azure AD PowerShell → global admin). Read-only Graph hunting.
---

# SKILL: Detecting Azure AD / Microsoft Graph application-role confusion privilege escalation. Covers confusing-deputy app registrations, Graph app-role over-permission, credential add/update on service principals, and the tenant-takeover chain (add credential to Azure AD PowerShell → global admin). Read-only Graph hunting.

> **AI LOAD INSTRUCTION**: Load when auditing an Entra ID tenant for application-registration privilege escalation: role confusion, over-broad Graph app roles, credential additions, and consent abuse that leads to tenant takeover.

## 0. RELATED ROUTING
- [auditing-azure-active-directory-configuration](#) for broader tenant hardening
- [exploiting-broken-function-level-authorization](#) for the app-side privilege mechanics
- [detecting-oauth-token-theft-and-replay](#) for post-token-compromise correlation
- [incident-response-for-identity-and-sso](#) for identity IR

## 1. WHAT "APP ROLE CONFUSION" IS

Legitimate app roles are scoped: an app granted `Directory.Read.All` should not also be able to grant itself more. The confusion/abuse pattern is a low-privilege application that either:
- Was consented to high-privilege Graph app roles it doesn't legitimately need, or
- Gains those roles after an attacker adds a credential to its service principal, letting it mint a token with elevated claims it wasn't designed for.

Chain to full takeover: obtain write access to a service principal → add a credential (`addPassword`/`addKey`) → mint a token claiming a privileged app role → use Graph to gain Role Management or global admin → backdoor the tenant. This is the "confused deputy" class.

## 2. PASSIVE INVENTORY (READ-ONLY GRAPH)

Enumerate every app registration and its granted app roles, then flag over-privileged grants:

```powershell
# Connect read-only (Graph, no write scopes)
Get-MgServicePrincipal -All -Property Id,AppId,DisplayName | Select Id, AppId, DisplayName
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Select AppRoleId, PrincipalId
```

Flag any SP holding `Directory.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`/`.All`, `Application.ReadWrite.All`, or `User.ReadWrite.All` when the app's business need doesn't require it. `pacu`, `Roadtools`, or `GraphAuthorization`/`Storm-055` enumerate the same passively.

## 3. CREDENTIAL-ADDITION DETECTION

The critical signal is **who added a credential and when**. Flag any credential add on a service principal by an identity with no app-ownership relationship:

```powershell
Get-MgAuditLogSignIn | Where-Object {
  $_.Operation -match 'Add (application|password|credential) - (password|key|certificate) '
} | Select TimeStamp, Operation, InitiatedBy, ResultDescription, ClientAppUsed
```

Correlate for callers who are not the app owner, from a new geography/IP, or outside change windows.

## 4. CONFUSION INDICATORS

- **Publisher/owner mismatch**: an app consented for high-priv Graph roles but whose verified publisher domain differs from the consenting org's tenant domain — the classic confused deputy.
- **Role inflation over time**: an SP whose app-role assignments were expanded via admin consent shortly before a credential was added.
- **Unusual token claims**: a token minted for a low-priv app that carries app roles the app's manifest never referenced (view the `roles` claim in sign-in logs).
- **Cross-tenant consent**: consent granted by an admin for an app from an external publisher requesting broad directory write.

```powershell
# Apps consented for directory-write roles — check each publisher against intended use
Get-MgServicePrincipal -All | ForEach-Object {
  $roles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $_.Id -EA SilentlyContinue
  if ($roles.AppRoleId -match 'ReadWrite|RoleManagement') {
    [pscustomobject]@{ App=$_.DisplayName; Publisher=$_.PublisherDomain; Roles=($roles.AppRoleId -join ',') }
  }
}
```

## 5. CONSENT ABUSE DETECTION

```powershell
# Newly consented permissions (the enabling step)
Get-MgAuditLogSignIn | Where-Object {
  $_.Operation -match 'Add delegated permission grant|Add app role assignment to (service|user)'
} | Select TimeStamp, Operation, InitiatedBy, TargetResources, ClientAppUsed
# Flag broad Graph consent granted outside change windows or by non-app-owners.
# Bulk consent by a single actor across many apps = consent phishing.
```

## 6. TOKEN & POST-COMPROMISE CORRELATION

- Tokens for high-priv roles issued to unexpected client IDs (sign-in logs).
- `Add member to role`, `Update application`, and `Add service principal credentials` following a consent event.
- New MFA methods registered to privileged users (persistence via authentication-method registration).
- Enumerate privileged role assignments (`Get-MgRoleAssignment`) and alert on new global/admin assignments.

## 7. SAFE VALIDATION (READ-ONLY)

Do **not** attempt the escalation chain (add credential → mint privileged token → take over). Validate passively:
1. Inventory app roles per SP (section 2) — read-only.
2. Review credential-add audit logs (section 3) — read-only.
3. Confirm over-privileged grants by inspecting the `roles` claim in an existing sign-in log entry (recorded in clear, no decryption needed).
4. To prove impact, use a purpose-built test tenant and a test admin only — never production.

## 8. REMEDIATION

- Remove unnecessary app-role assignments; re-consent with least privilege.
- Remove rogue credentials; rotate any secret that was added or could be read.
- Delete attacker-created app registrations and service principals.
- Restrict consent: disable user/admin consent for high-priv permissions, require an admin consent workflow, restrict to verified publishers.
- Replace stored secrets with App Management Policies / workload identity federation — this eliminates the credential-add primitive entirely.
- Adopt PIM for standing privileged assignments; monitor credential-add, consent, and privileged-role events as standing detections.
- For confirmed exploitation: reset privileged credentials, review all app registrations, re-verify publisher domains, consider a full tenant credential reset.

## Sources
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-consent-overview
- https://learn.microsoft.com/en-us/graph/api/serviceprincipal-listapproleassignments
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log
- https://www.specterops.io/resources/posts/