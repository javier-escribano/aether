# Security Review: Operator Risk

This document is a prioritized security review of **Azure Attack Range** from the point of view of the **person who deploys and operates it** in their own Microsoft Entra tenant and Azure subscription.

## Scope

**In scope:** configurations, defaults, scripts, and documentation that could harm the operator. That means deploying into the wrong tenant, leaving tenant-wide changes or billable resources behind after teardown, leaking credentials, exposing the operator's subscription to third-party abuse, or contaminating the operator's production tooling.

**Out of scope:** the intentional attack paths **AP01 to AP08**. These vulnerabilities are deliberate. They are the point of the lab and are not reported here. A finding about an attack path appears only when its *implementation* reaches beyond the lab's intended audience or outlives the lab. One example is a lab credential that anyone on the Internet can reach, not just the student.

> **The Terraform state is toxic by design.** `terraform/terraform.tfstate` (and its `.backup`) holds every lab credential in cleartext. When AP03 or AP04 is enabled, that includes a working path to **Global Administrator of the tenant you deployed into**. Treat the state file like a Global Admin password.

### What is already done well

The review also confirmed these good practices:

- Every credential-bearing output in `terraform/outputs.tf` and the module outputs is marked `sensitive = true`.
- No secrets are hardcoded in the repository.
- The git history contains no state files or real `tfvars`.
- With the default `admin_source_cidr = null`, the domain controller's NSG has no inbound allow rules.
- AP02, AP05, AP06, AP07, and AP08 are scoped to their resource groups. No subscription-level role assignments are created.

### Status legend

| Status | Meaning |
|---|---|
| **Fixed in this release** | Already addressed in the code shipped with this release. |
| **Recommended** | Not yet applied. The maintainer can apply it before publishing. Operators should read the impact and use the mitigations in [Operating this lab safely](#operating-this-lab-safely). |

---

## Summary

| # | Severity | Area | Finding | Status |
|---|---|---|---|---|
| C-1 | Critical | Tenant safety | Nothing hard-blocks deployment into the wrong (production) tenant or subscription | Recommended |
| H-1 | High | Tenant safety | `seed-ap01.ps1` and `verify.ps1` connect to Microsoft Graph without pinning the tenant | Recommended |
| H-2 | High | Teardown | `destroy` never reverts the tenant-wide user-consent policy set by AP01 | Recommended |
| H-3 | High | Teardown / tenant | Directory roles and credentials created at runtime (AP03/AP04) survive `reset` and `destroy` | Recommended |
| H-4 | High | Internet exposure / cost | AP07 publishes a long-lived, writable account SAS to the entire Internet | Recommended |
| H-5 | High | Secrets | Local, unencrypted Terraform state contains a path to Global Administrator | Recommended |
| H-6 | High | Network exposure | The `admin_source_cidr` guard only rejects the literal `0.0.0.0/0` | Recommended |
| H-7 | High | Cost / teardown | `reset`/`destroy` fail and leave billable resources when runtime-created resources exist in a lab resource group | Recommended |
| M-1 | Medium | Tenant policy | `seed-ap01.ps1 -Remediate` wipes all consent policies instead of restoring the original | Recommended |
| M-2 | Medium | Supply chain | Terraform provider lockfile was not committed | **Fixed in this release** |
| M-3 | Medium | Secrets | EA, SSO, and sync passwords are passed in cleartext via `az vm run-command` arguments | Recommended |
| M-4 | Medium | Telemetry | Docs invite sending lab telemetry to the operator's existing Sentinel / Log Analytics workspace | Recommended |
| M-5 | Medium | Cost | Log Analytics workspaces have no daily cap, and AP06 enables unfiltered 4662 auditing | Recommended |
| M-6 | Medium | Cost | Auto-shutdown only deallocates the VMs. There is no budget, alert, or expiry | Recommended |
| M-7 | Medium | Network exposure | The secure default leaves the DC unreachable (no Bastion, no boot diagnostics), and its public IP is always created | Recommended |
| M-8 | Medium | Tenant / reputation | The AP01 app is multi-tenant (`AzureADMultipleOrgs`) | Recommended |
| L-1 | Low | Secrets | `.gitignore` did not cover plan files, SSH keys, token caches, and similar files | **Fixed in this release** |
| L-2 | Low | Scripts | `seed-ap06.ps1` parse bug | **Fixed in this release** |
| L-3 | Low | Secrets | One DC password is reused for the VM local admin and Enterprise Admin, and is compiled into a plaintext DSC MOF | Recommended |
| L-4 | Low | Network exposure | WinRM 5985/5986 are opened needlessly, and `dc_admin_password` has no strength validation | Recommended |
| L-5 | Low | Network / cost | AP02 SSH is open to `*` with no option to restrict it, and its VM identity has Contributor on the RG | Recommended |
| L-6 | Low | Teardown | Lost local state orphans every billable resource, and there is no name-based purge | Recommended |
| L-7 | Low | Teardown | The AP02 Key Vault stays soft-deleted for 7 days with the service principal secret inside | Recommended |
| L-8 | Low | Cost | Auto-shutdown time and time zone cannot be configured from the root module | Recommended |
| L-9 | Low | Documentation | The AP05 compute cost estimate appears to use Linux pricing and omits the cost of a deallocated VM | Recommended |

---

## Critical

### C-1. Nothing hard-blocks deployment into the wrong tenant or subscription

**Status:** Recommended
**Files:** `azrange.ps1` (`Assert-Prereqs`), `terraform/providers.tf`, `terraform/variables.tf`

**What it is.** `Assert-Prereqs` in `azrange.ps1` only prints the active tenant and subscription with `Write-Warn` and then continues. It does not prompt, uses no allowlist, and does not compare anything against `var.tenant_domain`. If `az account show` fails or returns nothing (stderr is discarded), the warning silently disappears. In `terraform/providers.tf`, `provider "azuread" {}` and `provider "azurerm" { features {} }` declare no `tenant_id` or `subscription_id`. Terraform therefore uses whatever ambient context exists: the `az` session or `ARM_TENANT_ID` / `ARM_SUBSCRIPTION_ID` / `ARM_CLIENT_ID`, which may differ from what the warning showed. `tenant_domain` has no `validation` block and is used only to build UPNs. `-AutoApprove` also skips Terraform's own confirmation, so `deploy`, `reset`, and `destroy` can run with no human gate at all. A mismatched `tenant_domain` does not protect the operator either. Resources that do not depend on the lab users (the AP01 application, everything in AP02/AP07/AP08) are created in parallel before `azuread_user.lab` fails, which leaves a partial deployment in the wrong tenant.

**Operator impact.** Operators who work in Azure daily often have `az` or `ARM_*` pointing at their corporate tenant. In that case, `./azrange.ps1 deploy -AutoApprove` creates the following in production:

- apps with `Mail.Read` / `Files.Read.All` scopes
- a service principal with admin-consented `RoleManagement.ReadWrite.Directory` (AP04)
- a role-assignable group with Privileged Role Administrator whose owner is a user with a known password (AP03)
- a VM with SSH open to the Internet (AP02)
- anonymous storage (AP07)

Together these create privilege-escalation paths to Global Administrator in the operator's real tenant. Because `docs/00-setup.md` asks the deployer to be a Global Administrator, every one of these operations succeeds.

**Recommended fix.**
1. Add required variables `expected_tenant_id` and `expected_subscription_id`, and pin them in both providers (`provider "azuread" { tenant_id = var.expected_tenant_id }`, and `tenant_id` / `subscription_id` on `azurerm`). Terraform then fails if the context does not match.
2. In `Assert-Prereqs`, `throw` if `az account show` fails or if its `tenantId` / `id` differ from the tfvars values. Fetch the initial domain via `az rest --url https://graph.microsoft.com/v1.0/organization` and abort if it does not match `tenant_domain`. Optionally refuse to continue if the tenant has verified domains other than `*.onmicrosoft.com`.
3. Require the operator to type the tenant name (`Read-Host`) even with `-AutoApprove`, unless an explicit environment variable such as `AZRANGE_I_UNDERSTAND=<tenantId>` is set.
4. Add `validation { condition = endswith(var.tenant_domain, ".onmicrosoft.com") }` to `tenant_domain`.
5. If `ARM_TENANT_ID` / `ARM_SUBSCRIPTION_ID` are set, verify they match the displayed context.

---

## High

### H-1. Microsoft Graph connections are not pinned to the lab tenant

**Status:** Recommended
**Files:** `scripts/seed-ap01.ps1`, `scripts/verify.ps1`

**What it is.** `seed-ap01.ps1` calls `Connect-MgGraph -Scopes ... -NoWelcome` without `-TenantId`. The Microsoft Graph PowerShell context is independent of both the `az` CLI and Terraform. It reuses a cached token or account, or opens a browser account picker where the corporate account is usually the default. The script then runs `Update-MgPolicyAuthorizationPolicy` against whichever tenant it connected to, without printing or checking which one that is. `verify.ps1` reuses any existing `Get-MgContext`, so it can report policy state from a different tenant.

**Operator impact.** Even when `az` and Terraform correctly target the test tenant, the AP01 seed can enable permissive user consent in the operator's **production** tenant. With `-Remediate`, it can also empty that tenant's consent policies. This opens a real consent-phishing vector in the operator's organization with no warning.

**Recommended fix.** Have `azrange.ps1` pass the already validated tenant ID (`seed-ap01.ps1 -TenantId $tid`). Have the seed use `Connect-MgGraph -TenantId $TenantId -ContextScope Process`, then abort unless `(Get-MgContext).TenantId -eq $TenantId`. Print the tenant before modifying the authorization policy. Apply the same pattern to `verify.ps1`.

### H-2. `destroy` never reverts the tenant-wide user-consent policy set by AP01

**Status:** Recommended
**Files:** `azrange.ps1` (`destroy` and `reset` branches), `scripts/seed-ap01.ps1`, `README.md`, `CONTRIBUTING.md`

**What it is.** `seed-ap01.ps1` changes the authorization policy of the **entire tenant** (`PermissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')`). This change is not tracked in Terraform state. Only the `reset` branch of `azrange.ps1` calls `seed-ap01.ps1 -Remediate`. The `destroy` branch only runs `terraform destroy` and does not warn about the leftover change. `reset` itself depends on the `ap01_app_id` Terraform output, so after a `destroy` that output is null and `reset` does not remediate either. The README claims that `azrange.ps1 destroy` removes everything, and `CONTRIBUTING.md` states that nothing should survive `destroy`. Both claims are false for this change.

**Operator impact.** After a `destroy` the operator believes is complete, any user in the tenant can still consent to any third-party multi-tenant app with delegated scopes (`Mail.Read`, `Files.Read.All`, `offline_access`). That is exactly the AP01 illicit-consent condition, and it stays active indefinitely without the operator knowing. The risk is real if the tenant is shared with other workloads or has real users, or if the seed ran against the wrong tenant (see H-1).

**Recommended fix.** In the `destroy` branch, run `seed-ap01.ps1 -Remediate` **before** `terraform destroy`. Remediate whenever the legacy policy is present, without depending on the `ap01_app_id` output (for example, make `-AppId` optional in `-Remediate` mode). Combine this with the restore logic in M-1. Have `verify.ps1` report this "out-of-state residue" after `destroy` as well. Correct the README claim.

### H-3. Directory roles and credentials created at runtime survive `reset` and `destroy`

**Status:** Recommended
**Files:** `azrange.ps1`, `scripts/verify.ps1`, `terraform/modules/entra-identity/main.tf`, `terraform/modules/entra-identity/ap03-role-assignable-group.tf`, `terraform/modules/entra-identity/ap04-app-credential-abuse.tf`

**What it is.** The `reset` branch only sets `enable_ap01..08 = false`. The base users (`azuread_user.lab`) are not behind a flag and survive. AP03 and AP04 end with the attacker (`azrange-user1`) assigning themselves Global Administrator outside Terraform. If the role is assigned directly to the user, rather than through the AP03 group or the AP04 service principal, the assignment survives the deletion of those objects. The same applies to any app, service principal, or secret the student creates as Global Admin. Those objects carry no `lab_prefix` and are not in state. A Global Admin can also call `elevateAccess`, which grants User Access Administrator at the root (`/`) of the management-group hierarchy and therefore control of **every** subscription in the tenant. The module headers acknowledge that such objects must be cleaned up by hand. However, neither `reset`, `destroy`, nor `verify.ps1` checks for leftover privileged assignments. The "RG-scoped" guarantee for AP08 in `docs/00-setup.md` no longer holds once Global Admin has been reached via AP03/AP04.

**Operator impact.** After a `reset` that `azrange.ps1` reports as a "clean base", an active Global Administrator can remain. That account has `force_password_change = false` and a password stored in state, and may come with service principal backdoors created by the student. The holder of those credentials can keep Global Admin, or Owner at the root, and use it against the operator's paid subscription (crypto-mining, expensive resources) after a teardown the operator considers clean. If the test tenant is linked to billing, or has B2B or cross-tenant trust, this is a persistent full takeover.

**Recommended fix.** Add an `audit-residue` step to `azrange.ps1` and call it at the end of `reset` and `destroy`. The step lists:

- directory `roleAssignments` whose principal is a lab user or service principal (by `lab_prefix`), or was created after the deploy timestamp
- `passwordCredentials` / `keyCredentials` on lab apps and on apps created after the deploy
- RBAC assignments at `/` and at subscription scope (`az role assignment list --scope / --all`)
- active `elevateAccess`

The step should remove these objects, or at least report them and exit non-zero. Add a "no lab users with Tier-0 roles outside state" check to `verify.ps1`. Optionally rotate the lab user passwords on `reset` (taint `random_password.user`). Document the mandatory manual cleanup procedure.

### H-4. AP07 publishes a long-lived, writable account SAS to the entire Internet

**Status:** Recommended
**Files:** `terraform/modules/azure-resources/ap07-storage.tf`, `terraform/modules/azure-resources/variables.tf`, `terraform/terraform.tfvars.example`, `docs/attack-paths/AP07-public-storage-leak.md`

**What it is.** AP07 creates a real **account** SAS signed with the account key:

- service: blob
- resource types: service, container, and object
- permissions: read, write, delete, list, add, create, update, process, tag, and filter
- lifetime: `sas_expiry_years = 10`
- IP restriction: none

It publishes this SAS in `backup-config.json` inside a container with `container_access_type = "container"` (anonymous listing), on an account with `allow_nested_items_to_be_public = true` and no `network_rules`. With `leak_mode = "account_key"`, the primary access key and connection string are published instead. They also cover queue, table, and file, and can sign new SAS tokens. The storage account name follows a predictable, public pattern. The credential is scoped to that single storage account and does not grant management-plane or subscription access. However, its audience is not "the student". It is anyone on the Internet. Public Azure containers are continuously indexed by bucket scanners and search engines. `terraform.tfvars.example` describes AP07's cost as roughly zero.

**Operator impact.** Third parties can upload arbitrary content (malware, phishing pages, illegal material) to `<account>.blob.core.windows.net` in the operator's subscription and serve it from there, or delete and tamper with existing content. The consequences are storage and egress charges, extra ingestion into an uncapped Log Analytics workspace (see M-5), abuse reports to Microsoft, possible suspension of the subscription, and legal exposure for the subscription owner. The risk lasts as long as AP07 stays deployed, and no auto-shutdown, budget, or alert stops it.

**Recommended fix.** Keep the lesson, but bound who can exploit it and for how long:
1. By default, add `network_rules { default_action = "Deny", ip_rules = [var.admin_source_cidr] }` to the AP07 storage account, and require `admin_source_cidr` when `enable_ap07 = true`. Network rules also filter anonymous access, so the lesson can still be demonstrated from the operator's or student's IP. Expose the account to the Internet only through an explicit opt-in such as `ap07_internet_exposed = true`.
2. Set `ip_addresses = var.admin_source_cidr` on the SAS data source.
3. Replace `sas_expiry_years` with `sas_expiry_hours` (default 24 to 72 hours).
4. Reduce the default SAS to read and list, or to read/list/write on the sensitive container via a service SAS. Drop `create`/`add`. Make the full over-scoped SAS and `account_key` leak modes explicit opt-ins.
5. Replace the "cost ~0" wording in `terraform.tfvars.example` and the AP07 doc with an explicit warning about write and egress abuse, and recommend running `destroy` as soon as the exercise ends.
6. Add an optional `azurerm_consumption_budget_resource_group` with alerts for the lab resource groups (see M-6).

### H-5. Local, unencrypted Terraform state contains a path to Global Administrator

**Status:** Recommended
**Files:** `terraform/providers.tf`, `azrange.ps1`, `docs/00-setup.md`, `README.md`

**What it is.** No `backend` block is declared, so the state is stored locally and unencrypted in `terraform/terraform.tfstate` and its `.backup`. It contains in cleartext:

1. The passwords of the Entra lab users (`random_password.user`, with `force_password_change = false`). `azrange-user1` is the **sole owner** of the AP03 role-assignable group and of the AP04 app and service principal that holds `RoleManagement.ReadWrite.Directory`.
2. The DC Enterprise Admin, DSRM, AP06 SSO, and sync passwords, the AP07 SAS or key, the AP02 service principal client secret, and the AP08 attacker password.

The lab user passwords are not exposed as outputs. The only way to read them is `terraform state show` or opening the JSON, which encourages copying or pasting the state. `.gitignore` correctly excludes `*.tfstate`. However, it does not protect against folder sync (OneDrive or Dropbox on Windows), backups, or local malware. The docs say to treat the state as toxic but offer no encrypted remote backend.

**Operator impact.** With AP03 or AP04 enabled, anyone who obtains the state (through a synced folder, a zip sent to a colleague, a backup, or a compromised laptop) can sign in as `azrange-user1` and escalate to Global Administrator of the **real** tenant where the lab was deployed. They also get Owner over the AP08 resource groups and control of the DC. This is the most valuable credential the operator handles, and it sits in plaintext inside the repository tree.

**Recommended fix.** Add an optional, commented-out `backend "azurerm"` block to `terraform/providers.tf`, with instructions in `docs/00-setup.md`: an encrypted storage account, no public access, `use_azuread_auth = true`, and minimal RBAC. Alternatively, recommend OpenTofu state encryption. In `Assert-Prereqs`, warn if the Terraform directory is under OneDrive, Dropbox, or Google Drive (check `$env:OneDrive` and the path). Expose the lab user passwords as `sensitive` outputs so nobody needs to open the state by hand. State explicitly in the README that the state is equivalent to Global Admin of the tenant when AP03 or AP04 is enabled.

### H-6. The `admin_source_cidr` guard only rejects the literal `0.0.0.0/0`

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/variables.tf`, `terraform/variables.tf`, `terraform/modules/hybrid-ad/main.tf`

**What it is.** The module validation is `var.admin_source_cidr == null || var.admin_source_cidr != "0.0.0.0/0"`, which is an exact string comparison. It does not check that the value is a valid CIDR, does not enforce `/32` (although the description says it should be one), and does not reject wildcards and service tags that the Azure NSG accepts in `source_address_prefix`: `*`, `Any`, `Internet`. Equivalent wide ranges such as `0.0.0.0/1`, `0.0.0.0/00`, or `0/0` also pass, and so does `""`. The value goes unchanged into the three allow rules for 3389, 5985, and 5986 (destination `*`) on a NIC with a static Standard public IP. The root variable has no validation of its own.

**Operator impact.** Some operators copy the AP02 pattern (`source_address_prefix = "*"`). Others type `Internet` or `*` to get around a connectivity problem. Both pass validation without a warning. The result is a domain controller running an Enterprise Root CA, with the built-in Administrator (Enterprise Admin) reachable over RDP and WinRM from the whole Internet, in the operator's subscription. The code and the docs (`docs/00-setup.md`, `terraform.tfvars.example`) tell the operator this cannot happen.

**Recommended fix.** Replace the check with a positive validation, for example:

```hcl
condition = var.admin_source_cidr == null || (
  can(cidrhost(var.admin_source_cidr, 0)) &&
  tonumber(split("/", var.admin_source_cidr)[1]) >= 24
)
```

Alternatively, require exactly `/32` with a regex. Either form implicitly rejects `*`, `Any`, `Internet`, `""`, and wide prefixes. Duplicate the validation in `terraform/variables.tf` so the error is raised at the root. If more than one source IP is needed, switch to `list(string)` with `source_address_prefixes` and validate each element.

### H-7. `reset`/`destroy` fail and leave billable resources when runtime-created resources exist in a lab resource group

**Status:** Recommended
**Files:** `terraform/providers.tf`, `azrange.ps1`, `scripts/verify.ps1`, `docs/attack-paths/AP08-automation-runbook-rbac.md`

**What it is.** `terraform/providers.tf` declares `provider "azurerm" { features {} }`. With azurerm 3.x, `resource_group.prevent_deletion_if_contains_resources` defaults to `true`. By design, runtime principals get write access to lab resource groups: the AP02 VM identity has Contributor on `<lab_prefix>-ap02-rg`, and in AP08 the identity has User Access Administrator or Owner on `<lab_prefix>-ap08-rg`, which the attacker escalates to Owner. `azrange.ps1` and the docs state that disabling AP08 destroys the resource group "and with it" everything created at runtime. With the provider default, the opposite happens. Terraform deletes what is in state, refuses to delete the resource group because it still contains unmanaged resources, and `Invoke-Tf` throws.

**Operator impact.** A student, the operator, or anyone who steals the managed identity token (which is exactly the exercise) may create a VM, disk, IP, or App Service plan inside a lab resource group. That resource survives `reset` and `destroy`, keeps billing, and never appears in `terraform state`. The operator sees an error at the end of `destroy`, may assume it is transient, and leaves behind exactly the kind of resource that costs the most (for example, crypto-mining VMs created with Contributor or Owner).

**Recommended fix.** Choose one approach and document it:
- **(a)** Set `features { resource_group { prevent_deletion_if_contains_resources = false } }` in `terraform/providers.tf`. This matches the promise of atomic deletion for disposable, prefixed lab resource groups.
- **(b)** Keep the default, but when `destroy` or `reset` fails, have `azrange.ps1` run `az resource list -g <lab_prefix>-apXX-rg` and print a prominent warning listing the resources that remain and are still billing.

In both cases, add a post-destroy check to `verify.ps1` that confirms no `<lab_prefix>-ap0*-rg` resource group remains.

---

## Medium

### M-1. `seed-ap01.ps1 -Remediate` wipes all consent policies instead of restoring the original

**Status:** Recommended
**Files:** `scripts/seed-ap01.ps1`

**What it is.** `-Remediate` sets `PermissionGrantPoliciesAssigned = @()`. It does not restore the value that was in place before the seed, because that value is never saved. Instead, it removes every assigned policy, including `ManagePermissionGrantsForOwnedResource.*` (resource-specific consent for Teams and chat owners) and any `microsoft-user-default-low` policy the tenant had.

**Operator impact.** In a test tenant also used for other work, `reset` silently changes the previous consent behavior. Teams resource-specific consent and apps that relied on low-risk consent stop working, and the original value cannot be recovered.

**Recommended fix.** Before seeding, save `(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned` to a local, gitignored file (for example `seed-output-ap01.json`, which `.gitignore` already covers), and restore it in `-Remediate`. If the file is missing, remove only `ManagePermissionGrantsForSelf.microsoft-user-default-legacy` from the list rather than emptying it.

### M-2. Terraform provider lockfile was not committed

**Status:** **Fixed in this release**
**Files:** `terraform/.terraform.lock.hcl`, `.gitignore`

**What it was.** `.gitignore` excluded `.terraform.lock.hcl`. `terraform/providers.tf` only uses pessimistic constraints (`~> 2.53`, `~> 3.116`, `~> 3.6`, `~> 2.6`, `~> 0.12`). As a result, each fresh clone resolved the newest provider versions in range without verifying known hashes. Those provider binaries run with the operator's `az` token, which `docs/00-setup.md` says must be Global Administrator and have subscription permissions.

**Operator impact.** A compromised or regressed provider release inside the allowed range would execute on the operator's machine with a token able to control the entire tenant and subscription.

**Fix applied.** `terraform/.terraform.lock.hcl` is now committed, and `.gitignore` no longer excludes it. Provider versions and hashes are pinned for every clone.

**Further hardening (recommended).**
- Run `terraform init -input=false -lockfile=readonly` in `azrange.ps1`.
- Add an upper bound to `required_version` (for example `>= 1.6, < 2.0`).
- Generate multi-platform hashes with `terraform providers lock -platform=windows_amd64 -platform=linux_amd64 -platform=darwin_arm64`.
- Note that `terraform/modules/hybrid-ad/dsc/AzRangeDC.ps1` marks PSGallery as Trusted on the DC. Module versions are pinned there, but their hashes are not verified.

### M-3. EA, SSO, and sync passwords are passed in cleartext via `az vm run-command` arguments

**Status:** Recommended
**Files:** `azrange.ps1` (AP05 and AP06 seeding), `terraform/variables.tf`

**What it is.** For AP05, `azrange.ps1` builds `--parameters "EaPassword=$eaPw"`. For AP06, it adds `"SsoPassword=$ssoPw"` and `"SyncPassword=$syncPw"`. The consequences:

1. On the operator's machine, `az` (`python.exe`) is launched with these values on its command line. They are visible to other processes run by the same user and recorded by process-creation telemetry (event 4688 with command line, Sysmon event 1, Defender for Endpoint `DeviceProcessEvents`).
2. Legacy run-command (`--command-id RunPowerShellScript`) has no protected parameters. The values reach the `RunCommandWindows` extension on the DC, which leaves artifacts under `C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\...`, and they also appear in the API response.
3. With `-o json`, the result is printed to the console if the DC returns an error.

The seed scripts themselves handle these values correctly: they only convert them to `SecureString` and never print them.

**Operator impact.** On a corporate-managed laptop with EDR, the lab's EA, SSO, and sync passwords end up in the company's SIEM or EDR and with the EDR vendor. If the operator set `dc_admin_password` to a value they reuse elsewhere, that credential is exposed outside the lab. Copies left on the DC also give students a shortcut to Enterprise Admin that bypasses ESC1.

**Recommended fix.** Switch to Managed Run Command (`az vm run-command create ... --protected-parameters`) and delete it afterward with `az vm run-command delete`. Alternatively, have the DC script read the secrets from a Key Vault in the lab resource group using the VM's managed identity. At minimum, pass secrets via stdin or a temporary ACL-restricted file that is deleted afterward, never via argv.

### M-4. Docs invite sending lab telemetry to the operator's existing Sentinel / Log Analytics workspace

**Status:** Recommended
**Files:** `terraform/variables.tf` (`existing_log_analytics_workspace_id`), `terraform/modules/hybrid-ad/monitoring.tf`, `terraform/modules/azure-resources/ap07-storage.tf`, `terraform/modules/azure-resources/ap08-automation.tf`, `terraform/terraform.tfvars.example`, `docs/00-setup.md`

**What it is.** `docs/00-setup.md` and `terraform.tfvars.example` suggest pointing `existing_log_analytics_workspace_id` at "your Sentinel". The variable feeds the AP05/AP06 data collection rule (DCR) and the AP07/AP08 diagnostic settings. Nothing checks that the workspace belongs to the lab's subscription or tenant. DC `SecurityEvent` records (DCSync, PKINIT), `StorageBlobLogs`, and Automation `JobStreams` from the lab are ingested there. `destroy` removes the DCR and diagnostic settings, but already ingested data remains for the workspace's retention period, and purging it is a separate, slow operation. AP05 and AP06 deliberately lead the student to Domain Admin or SYSTEM on a DC whose Azure Monitor Agent (AMA) writes into that workspace.

**Operator impact.** Production analytics rules and playbooks fire on lab activity (DCSync, ESC1, Golden and Silver tickets, RBAC escalation). This produces false incidents, ingestion cost, and possibly automated responses. Lab data remains in production and `destroy` cannot purge it. Anyone who controls the lab DC can also inject or pollute `SecurityEvent` data in the production workspace, which could help hide or forge real activity.

**Recommended fix.** Remove the "use your Sentinel" advice from the docs and recommend a dedicated, disposable lab workspace instead. Validate that the workspace belongs to the lab subscription, for example `startswith(var.existing_log_analytics_workspace_id, "/subscriptions/${var.expected_subscription_id}/")` (see C-1). At minimum, warn in `Assert-Prereqs` when the workspace ID points outside the lab subscription or resource groups. Document that pointing at a Sentinel-enabled workspace also incurs Sentinel's per-GB charge.

### M-5. Log Analytics workspaces have no daily cap, and AP06 enables unfiltered 4662 auditing

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/monitoring.tf`, `terraform/modules/azure-resources/ap07-storage.tf`, `terraform/modules/azure-resources/ap08-automation.tf`, `scripts/seed-ap06.ps1`, `terraform/variables.tf`

**What it is.** All three `azurerm_log_analytics_workspace` resources (AP05/06, AP07, AP08) use `PerGB2018` with 31-day retention and no `daily_quota_gb`. The default is `-1`, which means unlimited. The "< 0.1 to 0.3 GB/day" estimates in `terraform.tfvars.example` and the AP05/AP06 docs are not enforced by any limit. `seed-ap06.ps1` enables `Directory Service Access` auditing for success and failure. The DCR ingests **all** 4662 and 4769 events because its XPath filters only on event ID, not on the DS-Replication-Get-Changes property GUIDs. `collect_security_events`, `collect_storage_logs`, and `collect_automation_logs` default to `true`.

**Operator impact.** A DC with Directory Service access auditing enabled, combined with abuse of the AP07 SAS (logged in `StorageBlobLogs`), can drive ingestion up with no cap. The operator relies on the "a few euros per month" figure in the docs, while the code enforces no budget or limit.

**Recommended fix.** Add `daily_quota_gb` to all three workspaces through a variable such as `law_daily_cap_gb` (default `0.5`). Filter 4662 with a DCR transformation (`transform_kql` in `data_flow`) that keeps only events whose properties contain the DCSync GUIDs (`1131f6aa-`, `1131f6ad-`, `89e95b76-`).

### M-6. Auto-shutdown only deallocates the VMs. There is no budget, alert, or expiry

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/main.tf`, `terraform/modules/azure-resources/main.tf`, `docs/00-setup.md`, `azrange.ps1`

**What it is.** `azurerm_dev_test_global_vm_shutdown_schedule` only stops and deallocates the VMs. These resources keep billing:

- the DC's StandardSSD OS disk (127 GiB Windows image)
- the AP02 Standard_LRS disk
- two static Standard public IPs, which bill even while their VMs are stopped
- the DSC storage account
- the Log Analytics workspaces

The code contains no `azurerm_consumption_budget_*` resource and no expiry tag. A budget appears only as manual advice in `docs/00-setup.md`. `notification_settings.enabled = false`, so the operator receives no shutdown notice. The setup doc says the module "will enable" auto-shutdown, which suggests the costs are fully covered.

**Operator impact.** With "deploy and forget", compute stops at 22:00 CET, but a permanent residual cost of roughly EUR 15-20 per month remains. The operator may not notice it for months. If the lab is deployed after 22:00, the Windows VM runs for almost 24 hours before its first shutdown.

**Recommended fix.** Add an optional `azurerm_consumption_budget_subscription` or `azurerm_consumption_budget_resource_group` (variables `budget_amount` and `budget_email`) with alerts at 50%, 80%, and 100%. Add an `expires_on` tag to the lab resource groups. Make `azrange.ps1 deploy` print the estimated cost while deallocated and remind the operator to run `./azrange.ps1 destroy`. Consider enabling `notification_settings` with an email 30 minutes before shutdown.

### M-7. The secure default leaves the DC unreachable, and its public IP is always created

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/main.tf`, `terraform/modules/hybrid-ad/variables.tf`, `terraform/variables.tf`, `docs/00-setup.md`, `docs/attack-paths/AP05-adcs-esc1.md`, `docs/attack-paths/AP06-entra-connect-seamless-sso.md`

**What it is.** With `admin_source_cidr = null`, the NSG has no allow rules, which is correct. However, the variable descriptions, `docs/00-setup.md`, and `terraform.tfvars.example` promise access via "Bastion/serial console", and the repository deploys neither. There is no `azurerm_bastion_host`, and the DC VM has no `boot_diagnostics` block, which Azure Serial Console requires. AP05 and AP06 are written around RDP to the DC. Meanwhile, `azurerm_public_ip.ap05` is always created and attached to the DC NIC whenever the DC is deployed, even when no inbound rule uses it.

**Operator impact.** An operator who keeps the secure default cannot complete the lab. The fastest workaround is to set `admin_source_cidr`. An operator who does not know their IP (CGNAT, dynamic IP) is likely to enter a wide range or a wildcard, which H-6 does not stop. The unused static public IP also keeps the DC visible on the Internet, so any later NSG relaxation exposes it immediately. One example is the alternative approach in the AP05/AP06 docs that opens LDAP, Kerberos, or RPC.

**Recommended fix.**
1. Add `boot_diagnostics {}` (managed storage) to the DC VM so Serial Console works with `null`.
2. Create the public IP only when needed (`count = local.need_dc && var.admin_source_cidr != null ? 1 : 0`, and `public_ip_address_id = try(azurerm_public_ip.ap05[0].id, null)` on the NIC).
3. Offer an optional `enable_bastion` flag (Developer or Basic SKU), or document `az network bastion` and `az vm run-command` as the official access path.
4. Correct the text that promises Bastion or serial access that does not exist.

### M-8. The AP01 app is multi-tenant (`AzureADMultipleOrgs`)

**Status:** Recommended
**Files:** `terraform/modules/entra-identity/main.tf`, `README.md`, `docs/attack-paths/AP01-illicit-consent.md`

**What it is.** The AP01 decoy app ("NewsletterSync", requesting `Mail.Read`, `Files.Read.All`, and `offline_access`) uses `sign_in_audience = "AzureADMultipleOrgs"`. The consent URL output uses the operator's own tenant, so the lesson does not need a multi-tenant app.

**Operator impact.**
- **Cross-tenant residue.** If someone opens the consent URL in a browser session signed in to another tenant (typically the operator's or a student's corporate account), Entra creates a service principal and an `oauth2PermissionGrant` **in that tenant**. `terraform destroy` only removes the application object in the lab tenant. The orphaned service principal and its grants persist in the external tenant, where the security team will flag them as a real illicit consent and the operator must clean them up by hand.
- **Reputation.** Global Admin is reachable in the lab via AP03 or AP04, and a Global Admin can add a secret to this app. Whoever compromises the lab tenant then has a ready-made consent-phishing app, published under the operator's tenant, that works against users of other tenants. Microsoft may disable the app or the tenant, and the abuse can be attributed to the operator.

**Recommended fix.** Switch to `sign_in_audience = "AzureADMyOrg"`. The same-tenant illicit-consent flow teaches the same lesson. If a multi-tenant demonstration is wanted, put it behind an explicit variable that is off by default. Document the cross-tenant residue risk in the README and the AP01 doc, and advise using an InPrivate window signed in with the lab account.

---

## Low

### L-1. `.gitignore` did not cover plan files, SSH keys, token caches, and similar files

**Status:** **Fixed in this release**
**Files:** `.gitignore`

**What it was.** `.gitignore` already covered `*.tfstate`, `*.tfstate.*`, `.terraform/`, `*.tfvars` (except `*.tfvars.example`), certificate and key files, `.env`, `*.clixml`, and crash logs. It did not cover:

- `*.tfplan`, `tfplan`, `*.plan` (`terraform plan -out=...` writes state and sensitive values in cleartext)
- SSH keys without an extension (`id_rsa*`, `id_ed25519*`, `*_rsa`)
- `.azure/` and `msal_token_cache.*` (when `AZURE_CONFIG_DIR` points inside the repository)
- `.terraformrc` / `terraform.rc` (registry or Terraform Cloud tokens)
- `*.mof` (DSC compiled locally with plaintext passwords)

**Operator impact.** A plain `terraform plan -out=tfplan` followed by `git add .` would publish every lab credential, including the path to Global Admin.

**Fix applied.** `.gitignore` now covers these patterns.

**Further hardening (recommended).** Document a pre-commit secret scanner (gitleaks or trufflehog) in `CONTRIBUTING.md`.

### L-2. `seed-ap06.ps1` parse bug

**Status:** **Fixed in this release**
**Files:** `scripts/seed-ap06.ps1`

A parse error in `scripts/seed-ap06.ps1` has been corrected in this release.

### L-3. One DC password is reused for the VM local admin and Enterprise Admin, and is compiled into a plaintext DSC MOF

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/main.tf`, `terraform/modules/hybrid-ad/variables.tf`, `terraform/variables.tf`

**What it is.** `local.dc_admin_password = coalesce(var.dc_admin_password, random_password...)` is used both as the VM `admin_password` and as the DSC `AdminCredential` (domain Administrator / Enterprise Admin). The DSC configuration data sets `PSDscAllowPlainTextPassword = $true`. The credentials are encrypted in transit (`protected_settings`), but the MOF compiled on the DC (under `C:\Packages\Plugins\Microsoft.Powershell.DSC\...`) contains `AdminCredential`, `SafemodeCredential`, and `LowPrivCredential` in plaintext. `dc_admin_password` can be set by the operator, and only its description warns against using a real password. No validation enforces this.

**Operator impact.** If the operator reuses a personal password, anyone who reaches Domain Admin on the DC (the goal of AP05 and AP06) obtains it in cleartext from the MOF or via DCSync. If a non-admin user can read the MOF, there is also an unintended shortcut from the low-privilege user to Enterprise Admin that invalidates AP05 and AP06. The impact is mostly confined to the disposable forest.

**Recommended fix.** Remove the `dc_admin_password` override, or add validation that forces it to `null` (random). Use different passwords for the VM local admin and the domain Administrator. Encrypt MOF credentials with a DSC document-encryption certificate (`CertificateFile` / `Thumbprint` in configuration data) instead of `PSDscAllowPlainTextPassword`. Failing that, delete the compiled MOF at the end of configuration and verify the ACLs on `C:\Packages`.

### L-4. WinRM 5985/5986 are opened needlessly, and `dc_admin_password` has no strength validation

**Status:** Recommended
**Files:** `terraform/modules/hybrid-ad/main.tf`, `terraform/modules/hybrid-ad/variables.tf`, `terraform/variables.tf`

**What it is.** When `admin_source_cidr` is set, the NSG always opens 3389, 5985 (WinRM over HTTP), and 5986. The documented flows only use RDP, and seeding runs over `az vm run-command`, which needs no inbound port. DSC configures no HTTPS listener, so the 5986 rule is pure attack surface. The built-in domain Administrator (Enterprise Admin) and `ap05user` are therefore exposed to password spraying from the whole CIDR range. `dc_admin_password` has no length or complexity validation, and a freshly promoted DC has no account lockout policy.

**Operator impact.** If the CIDR is wider than a `/32` (an ISP `/24`, a shared office, CGNAT), or if the operator sets a weak `dc_admin_password`, others in that range can spray passwords against Enterprise Admin over RDP and WinRM without lockout. Success gives them the DC and the CA of a forest that has a managed identity and an AMA reporting into the operator's workspace.

**Recommended fix.** Open only 3389 by default. Put WinRM behind an optional `expose_winrm = false` flag, and when it is enabled, open only 5986 with a configured HTTPS listener. Add validation to `dc_admin_password` (`== null || length(...) >= 16`). Consider a lockout policy in DSC that does not interfere with the lab path.

### L-5. AP02 SSH is open to `*` with no option to restrict it, and its VM identity has Contributor on the RG

**Status:** Recommended
**Files:** `terraform/modules/azure-resources/main.tf`, `docs/attack-paths/AP02-managed-identity.md`

**What it is.** The `allow-ssh-inbound` rule uses `source_address_prefix = "*"`, password authentication is enabled, and the VM has a static public IP. The exposure is intentional (it is AP02's initial access), and the password is a 24-character random value, so guessing it is unlikely. However, unlike the DC, there is no variable to restrict the source to the operator, and the VM's managed identity has Contributor on the entire resource group.

**Operator impact.** Any Internet actor, not just the student, can attack the pivot host while the lab is up. If they compromise it, Contributor lets them create compute in the resource group (for example crypto-mining VMs) billed to the operator, and reach the Key Vault and service principal. Resources created this way also trigger H-7.

**Recommended fix.** Add an optional `ap02_ssh_source_cidr` variable. Keep the default `"*"` to preserve the design, and document setting it to the operator's IP as recommended hardening for personal deployments. Remind readers in the AP02 doc to destroy the resource group when finished and not to leave it running unattended.

### L-6. Lost local state orphans every billable resource, and there is no name-based purge

**Status:** Recommended
**Files:** `terraform/providers.tf`, `azrange.ps1`, `docs/00-setup.md`

**What it is.** There is no `backend` block, `*.tfstate` is gitignored, and `azrange.ps1 destroy` depends entirely on `terraform destroy`. No cleanup mode works by name or tag. The resource groups have deterministic names (`<lab_prefix>-ap02/05/07/08-rg`), which makes manual cleanup feasible, but no script performs it.

**Operator impact.** If the operator deletes or re-clones the repository, switches machines, or loses the disk while the lab is deployed, `./azrange.ps1 destroy` reports nothing to destroy. The Windows VM, disks, IPs, and workspaces keep billing until someone finds them in the portal.

**Recommended fix.** Add `./azrange.ps1 purge`, or a fallback in `destroy`, that runs `az group delete -n <lab_prefix>-apXX-rg --yes` for the known resource groups and lists the Entra objects that must be cleaned up. Document the optional remote `azurerm` backend in `docs/00-setup.md` for operators who use several machines (see H-5).

### L-7. The AP02 Key Vault stays soft-deleted for 7 days with the service principal secret inside

**Status:** Recommended
**Files:** `terraform/modules/azure-resources/main.tf`, `terraform/providers.tf`

**What it is.** The AP02 Key Vault uses `purge_protection_enabled = false` and `soft_delete_retention_days = 7`. The provider block uses `features {}` without an explicit `key_vault { purge_soft_delete_on_destroy = true }`, so the behavior depends on the provider default. After `destroy`, the vault and its `automation-sp-secret` may remain recoverable for 7 days by anyone with permissions on the subscription.

**Operator impact.** A small, temporary residue: a recoverable secret (although the service principal is already deleted) and an occupied vault name. This contradicts the claim that `destroy` removes everything.

**Recommended fix.** Declare `features { key_vault { purge_soft_delete_on_destroy = true  recover_soft_deleted_key_vaults = false } }` explicitly in `terraform/providers.tf`, or document the 7-day residue.

### L-8. Auto-shutdown time and time zone cannot be configured from the root module

**Status:** Recommended
**Files:** `terraform/main.tf`, `terraform/variables.tf`, `terraform/modules/hybrid-ad/variables.tf`, `terraform/modules/hybrid-ad/main.tf`, `terraform/modules/azure-resources/main.tf`

**What it is.** `modules/hybrid-ad/variables.tf` defines `auto_shutdown_time`, but the root module neither declares nor passes it. `modules/azure-resources/main.tf` hardcodes `daily_recurrence_time = "2200"`, and both modules hardcode `timezone = "W. Europe Standard Time"`, regardless of `var.location`.

**Operator impact.** Operators in the Americas or Asia cannot align shutdown with their working hours from `tfvars`. They either pay for the VM running through their local night or edit the modules, which breaks idempotency and upgrades. They also cannot bring the shutdown forward to cut billed Windows hours.

**Recommended fix.** Expose `auto_shutdown_time` and `auto_shutdown_timezone` in `terraform/variables.tf`, pass them to both modules, and remove the hardcoded values from `modules/azure-resources/main.tf`.

### L-9. The AP05 compute cost estimate appears to use Linux pricing and omits the cost of a deallocated VM

**Status:** Recommended
**Files:** `docs/attack-paths/AP05-adcs-esc1.md`, `docs/attack-paths/AP06-entra-connect-seamless-sso.md`, `docs/attack-paths/AP02-managed-identity.md`

**What it is.** The AP05 doc quotes about EUR 0.083/hour for `Standard_B2ms`. That figure resembles the Linux pay-as-you-go rate. A Windows Server 2022 Datacenter image without Azure Hybrid Benefit adds the hourly Windows license. The audit could not verify this against the pricing API (low confidence). The docs also do not explain what the lab costs between sessions while VMs are deallocated and `destroy` has not been run.

**Operator impact.** The operator may under-budget Windows hours and assume the cost is near zero after auto-shutdown.

**Recommended fix.** Check the figure with the Azure Retail Prices API for Windows B2ms/B2s in westeurope. Document `license_type` / Hybrid Benefit where applicable. Add a "cost per day while deallocated" line to the AP02, AP05, and AP06 docs.

---

## Operating this lab safely

Until the Recommended items above are applied, follow these practices:

- [ ] **Use a dedicated test tenant and a dedicated subscription.** Never deploy into a tenant with real users, a corporate subscription, or anything you cannot afford to lose. The lab creates real paths to Global Administrator.
- [ ] **Verify your context before every run.** Run `az account show` and `Get-MgContext`, check that both point at the lab tenant, and unset any `ARM_*` environment variables that point elsewhere. Avoid `-AutoApprove` unless you have just verified the context.
- [ ] **Connect to Graph explicitly.** Before running `seed-ap01.ps1` or `verify.ps1`, run `Connect-MgGraph -TenantId <lab-tenant-id>` from an InPrivate or otherwise isolated session.
- [ ] **Treat the Terraform state as toxic.** It is equivalent to Global Admin of the lab tenant. Keep the repository out of OneDrive, Dropbox, and Google Drive, never share or back it up unencrypted, and never commit it. Prefer an encrypted remote backend.
- [ ] **Scope `admin_source_cidr` to your own `/32`.** Never use `*`, `Any`, `Internet`, or a wide prefix. Leave it `null` when you do not need RDP.
- [ ] **Do not point the lab at your production Sentinel.** Use a dedicated, disposable Log Analytics workspace, and set a daily cap on it.
- [ ] **Never set `dc_admin_password` to a password you use anywhere else.** Leave it unset so a random value is generated.
- [ ] **Run `./azrange.ps1 destroy` as soon as you finish.** Auto-shutdown only deallocates the VMs. Disks, public IPs, storage, and workspaces keep billing, and AP07 stays exposed to the Internet while deployed.
- [ ] **After `destroy`, check for leftovers by hand:**
  - [ ] No `<lab_prefix>-ap0*-rg` resource groups remain (`az group list`).
  - [ ] The tenant user-consent policy is back to its previous value (run `seed-ap01.ps1 -Remediate` against the lab tenant if needed).
  - [ ] No directory role assignments, app credentials, or root (`/`) RBAC assignments created during the exercise remain, and `elevateAccess` is not active.
  - [ ] No orphaned AP01 service principal exists in any *other* tenant you signed in to during the exercise.
- [ ] **Set an Azure budget with email alerts** on the lab subscription before the first deploy.
- [ ] **Keep the committed `terraform/.terraform.lock.hcl`** and review provider version changes before accepting them.
