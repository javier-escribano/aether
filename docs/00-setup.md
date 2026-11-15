# 00 — Setup, Permissions, and Cost Control

## 1. Test Tenant and Subscription (mandatory)

Do not reuse your corporate tenant. Create a clean one:

1. Azure Portal → **Microsoft Entra ID** → *Manage tenants* → **Create** → type *Entra ID*.
   This gives you a `<something>.onmicrosoft.com` domain. That is `tenant_domain` in the tfvars.
2. Associate (or create) a dedicated **subscription**. Entra Free is enough for the identity-only tier;
   the hybrid tier requires pay-as-you-go.
3. Create a lab administrator user and make it **Global Administrator** of the test tenant.
   You will use it to run `az login` and the Graph seed.

## 2. Tooling (on your Windows 11)

```powershell
# Azure CLI
winget install -e --id Microsoft.AzureCLI

# Terraform >= 1.6
winget install -e --id HashiCorp.Terraform

# PowerShell Graph module (for the AP01 consents)
Install-Module Microsoft.Graph -Scope CurrentUser
```

Verify:
```powershell
az version; terraform version; (Get-Module Microsoft.Graph -ListAvailable)[0].Version
```

## 3. Authentication

```powershell
az login --tenant <YOUR_TEST_TENANT>.onmicrosoft.com
az account set --subscription "<TEST_SUBSCRIPTION_ID>"
```

Terraform's `azuread` provider reuses the `az login` context.
For the Graph steps (consents) the script runs `Connect-MgGraph` with the minimal scopes:
`Application.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Directory.ReadWrite.All`.

## 4. API Permissions the Seed Will Request

| Graph scope | Purpose | Path |
|-------------|---------|------|
| `Application.ReadWrite.All` | create/read app registrations and SPs | AP01, AP04 |
| `DelegatedPermissionGrant.ReadWrite.All` | seed the illicit consent | AP01 |
| `Policy.ReadWrite.Authorization` | configure the permissive user-consent policy | AP01 |
| `Directory.ReadWrite.All` | base users/groups | base |

> **AP03 requires Entra ID P1.** *Role-assignable* groups (`assignable_to_role`) do not exist in Entra Free: AP03 needs a tenant with P1 (dev/E5). In addition, the principal that runs `terraform apply` must hold **Privileged Role Administrator** or **Global Administrator** (and the `RoleManagement.ReadWrite.Directory` app role) to create the role-assignable group and assign PRA to it. The dollar cost is still ~0.

> **AP04 — admin-consent of a sensitive permission.** AP04 is identity-only and works on **Entra Free** (no P1 needed). But it grants `RoleManagement.ReadWrite.Directory` (a Graph application permission, `AdminConsentRequired = Yes`) declaratively, so the principal running `terraform apply` must be **Global Administrator** or **Privileged Role Administrator**; Application/Cloud Application Administrator are **not** enough to consent to this role-management permission. Dollar cost ~0.

> **AP05 — hybrid, bills compute (the most expensive AP).** AP05 **does not touch Entra**: it stands up a **Windows Server 2022 DC + Enterprise Root CA (AD CS)** on Azure IaaS. You need a **pay-as-you-go subscription** and the **Contributor** role over it (to create the VM, network, and Log Analytics); **no** Entra role and no P1. Specifics:
> - **Domain credential:** the (re)seed of the ESC1 template runs via `az vm run-command`, which executes as **SYSTEM** (the machine account, **not** Enterprise Admin). That is why `aether.ps1` passes it the domain `Administrator` password (`dc_admin_password`, = EA) as a parameter. Leave it `null` → the module generates a `random_password` (sensitive: it **lands in the state**, treat it as a secret). Never a real or reused password.
> - **Outbound HTTPS (443) to PSGallery** during `deploy`: the **DSC** extension installs `ActiveDirectoryDsc` and `ActiveDirectoryCSDsc` on the VM when compiling the MOF. In an air-gapped environment, bake those modules inside the DSC zip.
> - **Exposure:** RDP/WinRM open **only** to `admin_source_cidr` (your `/32`). If you leave it `null`, the module **opens no inbound port** (use Azure Bastion or serial console). **Never** `0.0.0.0/0`: this is a DC.
> - **End-to-end detection:** `collect_security_events = true` (default) provisions **AMA + DCR + Log Analytics** (a single-DC feed filtered to 5 EventIDs, « 0.1–0.3 GB/day) so that "🔵 Detect" is testable without a pre-existing SIEM. Set it to `false`, or point `existing_log_analytics_workspace_id` at a dedicated lab workspace (never your production Sentinel — lab activity would raise real incidents and ingestion cost), if you already ingest the DC's Security events.
> - **Isolation:** the `aether.lab` forest is throwaway; **do not** sync it to the tenant via real Entra Connect (that would turn the lab into a real risk; that scenario is covered by **AP06**, which shares this same DC). One of the cleanest resets in the range (on par with AP07/AP08): `enable_ap05 = false` destroys the VM and with it the template, the forged certs, and the CA database (cost → 0).

> **AP06 — Entra Connect / Seamless SSO (hybrid, bills compute; on-prem→cloud *bridge*).** AP06 is the 2nd hybrid path and **shares AP05's DC**: the gate `local.need_dc = enable_ap05 || enable_ap06` makes a single **Windows Server 2022 DC** serve both (with `enable_ap05 = true` the AP05 plan is **identical** to today's; AP06 only adds its own artifacts). You need a pay-as-you-go **subscription** and the **Contributor** role; **no** Entra role and no P1. Specifics:
> - **Shared substrate.** If you enable AP05 **and** AP06, **a single** DC is deployed (not two); the DC variables (`dc_admin_password`, `admin_source_cidr`, `vm_size`, `domain_fqdn`, `collect_security_events`…) are the same as AP05's. `AZUREADSSOACC$` and the sync account are **not** Terraform resources: they live in the DC's directory (like AP05's ESC1 template), seeded by `seed-ap06.ps1`.
> - **Seed (like AP05, not declarative).** `seed-ap06.ps1` runs via `az vm run-command` as **SYSTEM** and builds an EA `PSCredential` from `dc_admin_password`; it creates the machine account `AZUREADSSOACC$` with the Seamless SSO SPNs (`HTTP/autologon.microsoftazuread-sso.com`, `HTTP/aadg.windows.net.nsatc.net`) and a **known, never-rotated** key, plus the sync account with **DS-Replication-Get-Changes[-All]** ACEs (= DCSync). It fails loudly if it is not EA. Both passwords **land in the state** (sensitive).
> - **`sso_mode`** (tfvars): `"both"` (default; seeds both artifacts → enables the full chain sync → DCSync → `AZUREADSSOACC$` → silver ticket → cloud) | `"silver_ticket"` (only `AZUREADSSOACC$`) | `"sync_dcsync"` (only the sync account with DCSync).
> - **End-to-end detection:** reuses the **same** AMA/DCR pipeline as AP05; with `enable_ap06` the DCR's XPath adds **4662** (DCSync), **4769** (TGS for the Seamless SSO SPN), and **4741/4742** (`AZUREADSSOACC$`) — without altering the AP05-only filter. The **cloud** leg (the Seamless SSO `SigninLogs` in Entra) is **not** provisioned by the lab: it is declared as a boundary (hunt in your own tenant). A forged *silver ticket* may **not** generate a 4769 on the DC.
> - **Reset:** `enable_ap06 = false` **with** `enable_ap05 = false` → `need_dc` drops → the shared DC is destroyed (cost → 0; with it die `AZUREADSSOACC$`, the sync account, and the DCSync ACEs). **Selective case** (AP06 off **with** AP05 on): the DC **survives** (AP05 needs it) and AP06's AD objects **persist** → for the "Remediate," run `seed-ap06.ps1 -Remediate` (rotates the `AZUREADSSOACC$` key 2× + removes the DCSync ACEs + disables the sync account) **before** lowering the flag.

> **AP07 — Public storage / SAS leak (the cheapest infrastructure AP, ~0 €).** AP07 **does not touch Entra or deploy compute**: it creates a **storage account** with two deliberately-open anonymous access doors and an over-scoped credential leaked in a public blob. You need a pay-as-you-go **subscription** and the **Contributor** role (to create storage and, where applicable, Log Analytics); **no** Entra role and no P1. Specifics:
> - **100% declarative — no `seed`.** Unlike AP01/AP05, AP07 has no post-deploy script: `./aether.ps1 deploy` is just `terraform apply`. The leaked SAS/key is embedded in the blob by Terraform.
> - **`leak_mode`** (tfvars): `"sas"` (default) leaks a long-lived, over-scoped **account SAS** (uses the `hashicorp/time` provider so the expiry is stable and idempotent); `"account_key"` leaks the **account key** (more severe, full control). In **both**, the credential **lands in the state** (sensitive): treat the `tfstate` as toxic.
> - **Deliberate double anonymous door:** at the account level `allow_nested_items_to_be_public = true` **plus** the `public` container with `container` access (allows anonymous *listing*). Closing **either** of the two breaks the attack (defense in depth). **Caveat:** since ~Nov 2023 the *default* `allowBlobPublicAccess` for new accounts is `false`; the lab sets it to `true` **on purpose**.
> - **Synthetic data:** the crown jewel (`sensitive-data/customers.csv`) is **100% fictitious** PII (`.invalid` domains, fake tokens).
> - **End-to-end detection:** `collect_storage_logs = true` (default) provisions **diagnostic settings → `StorageBlobLogs`** in Log Analytics (ingestion « 0.1 GB/day) to see the anonymous/SAS access; the *misconfig* itself travels via `AzureActivity` with nothing to provision. Set it to `false`, or point `existing_log_analytics_workspace_id` at a dedicated lab workspace (never your production Sentinel — lab activity would raise real incidents and ingestion cost), if you already ingest those logs.
> - **Reset:** `enable_ap07 = false` destroys the entire account (with the leaked blob and the SAS) → cost 0, no *out-of-state* residue.

> **AP08 — Automation Account runbook → RBAC escalation (cost ~0, NO VM).** AP08 **does not touch the hybrid tier or deploy compute**: it creates an **Automation Account** with an over-privileged **system-assigned Managed Identity** (a role with `roleAssignments/write` over the RG) and a dedicated low-priv attacker that drives it. You need a pay-as-you-go **subscription** and the **Contributor** role over it (to create the Automation Account, the role assignments and, where applicable, Log Analytics); additionally the deployer must be able to **create the attacker `azuread_user`** (an Entra role such as *User Administrator*) and **assign RBAC over the RG** (be Owner or User Access Administrator of the AP08 RG). **No** P1. Specifics:
> - **100% declarative — no `seed` (like AP07).** `./aether.ps1 deploy` is just `terraform apply`: the runbook is embedded via `azurerm_automation_runbook.content`. **Running** the runbook (the "Exploit") is the student's action; Terraform **publishes the gun but NEVER fires it** (it creates no job or schedule).
> - **`runbook_mode`** (tfvars): `"poc_escalation"` (default; embeds a ready runbook that, running as the MI, self-grants **Owner of the RG** via `New-AzRoleAssignment` → immediate demo) | `"benign_probe"` (embeds a runbook that **only probes** the MI's identity/power —`Connect-AzAccount -Identity` + `Get-AzAccessToken` + `Get-AzRoleAssignment`— and the student writes the escalation) | `"none"` (no runbook; pure *misconfig*).
> - **`mi_role`** (tfvars): the MI's over-priv built-in role **over the RG** → `"UserAccessAdministrator"` (default; *minimum-that-escalates*: its only power is `roleAssignments/write` → the sharp lesson "even just UAA over an Automation MI = game over") | `"Owner"` (more realistic). **`Contributor` does not work**: it does not include `roleAssignments/write` (that is AP02's lane via `accessPolicies/write`).
> - **Reset-safety = RG-scoped ON PURPOSE.** The MI's role and the runtime escalation are scoped to AP08's **RG** (never the subscription). `enable_ap08 = false` destroys the RG and **with it every runtime role assignment** scoped to the RG (including the Owner self-grant the student runs) → zero *out-of-state* residue (on par with AP05/AP07). A subscription-level `-Scope` would **survive** the destroy and widen the blast radius: that is why the RG scope is a range security requirement (analogous to AP05's throwaway forest).
> - **Credential in the state:** the attacker's `random_password` **lands in the `tfstate`** (sensitive; only exposed via the sensitive output `ap08_attacker_password`). Treat the state as toxic; `.gitignore` already blocks `*.tfstate*`.
> - **End-to-end detection:** `collect_automation_logs = true` (default) provisions **diagnostic settings → `JobLogs`/`JobStreams`** (`AzureDiagnostics`) in Log Analytics (ingestion « 0.1 GB/day) to see the runbook execution; the **management plane** (`jobs/write`, and the `roleAssignments/write` **by the MI** —the golden signal—) travels via `AzureActivity` with nothing to provision. Set it to `false`, or point `existing_log_analytics_workspace_id` at a dedicated lab workspace (never your production Sentinel — lab activity would raise real incidents and ingestion cost), if you already ingest those logs.
> - **Runbook environment:** assumes `Az.Accounts`/`Az.Resources` are available in the Automation Account (current images ship them; if missing, import the `Az` module under *Shared Resources*).

## 5. Cost Control (no nasty surprises)

- **Budget + alert:** Portal → *Cost Management* → *Budgets* → create one of e.g. 20 €/month
  with alerts at 50/80/100%.
- **VM auto-shutdown** (hybrid only): the `hybrid-ad` module enables daily *auto-shutdown*;
  if you are not going to use it, leave its flags at `false`.
- **Teardown:** at the end of each session, `./aether.ps1 destroy`. The identity tier does not
  bill, but keep it clean anyway so you do not accumulate objects.

## 6. First Deployment

Go back to the [README](../README.md) → *Quickstart*. Start with **only AP01 enabled**
(`enable_ap01 = true`, the rest `false`) to validate the whole flow at no cost.
