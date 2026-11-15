# AETHER

> **A**zure **E**ntra **T**enant **H**acking & **E**xploitation **R**ange — a self-hostable, reproducible **Azure + Entra ID + hybrid Active Directory** cyber range, deployed as code.
> Every attack path ships with its exploit walkthrough, its remediation, and its detection.

AETHER is a training lab for red teamers, blue teamers, and purple teams who want to practise cloud identity attacks and defences in an environment they fully control. Think of it as **GOAD for Azure**: where GOAD gives you a vulnerable on-premises Active Directory forest, this project gives you a deliberately misconfigured Entra ID tenant, Azure subscription, and optional hybrid AD domain controller, all described in Terraform and brought up or torn down with a single command. It is aimed at practitioners preparing for cloud and AD certifications (CARTP, CARTE, CRTO, CRTE), detection engineers who need realistic telemetry, and instructors who need a lab that every student can rebuild identically.

> [!CAUTION]
> This project deploys **intentionally vulnerable** configurations. Deploy it **only** into a dedicated, throwaway **test** tenant and subscription that you own. **Never** point it at a production or corporate tenant. Read [Safety and cost](#safety-and-cost) and [SECURITY.md](SECURITY.md) before your first deployment.

---

## Table of contents

- [Why this is different](#why-this-is-different)
- [Attack-path catalog](#attack-path-catalog)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Safety and cost](#safety-and-cost)
- [Security of the operator](#security-of-the-operator)
- [Detections](#detections)
- [Continuous integration](#continuous-integration)
- [Repository layout](#repository-layout)
- [Extending the range](#extending-the-range)
- [Related projects](#related-projects)
- [Disclaimer](#disclaimer)

---

## Why this is different

Good cloud attack material exists, but it is usually either paid (training academies) or fragmented across single-purpose labs. This range combines three properties that are rarely found together:

1. **The Exploit / Remediate / Detect triad.** Every attack path is documented end to end: how the misconfiguration is abused, how to fix it properly, and how to detect it. Each path is mapped to MITRE ATT&CK techniques and to the relevant certification syllabi.
2. **Reproducible as code.** The entire environment is Terraform plus a small PowerShell orchestrator. Each vulnerability is an independent feature flag, so you can enable one path, a handful, or all of them, and get the same result every time. `destroy` removes everything.
3. **Detections included.** Every path ships with a KQL query (for Microsoft Sentinel / Log Analytics) and a Sigma rule, and the infrastructure paths provision the log pipeline they need, so the "Detect" step can be tested without a pre-existing SIEM.

---

## Attack-path catalog

Each path is enabled with its own flag (`enable_ap01` ... `enable_ap08`) in `terraform/terraform.tfvars` and documented in [`docs/attack-paths/`](docs/attack-paths/).

| ID | Attack path | Layer | MITRE ATT&CK | Certs | Cost |
|----|-------------|-------|--------------|-------|------|
| [AP01](docs/attack-paths/AP01-illicit-consent.md) | Illicit consent grant leading to Microsoft Graph token theft | Entra | T1528, T1098.003 | CARTP / CARTE | ~0 (Entra Free) |
| [AP02](docs/attack-paths/AP02-managed-identity.md) | Over-privileged managed identity exposes a Key Vault secret, enabling lateral movement | Azure | T1552.005, T1078.004, T1580, T1098 | CARTP / CARTE | Low (small VM, billed while running) |
| [AP03](docs/attack-paths/AP03-role-assignable-group.md) | Low-privilege owner of a role-assignable group escalates to Global Administrator | Entra | T1098, T1098.003, T1078.004 | CARTP / CARTE | ~0, **requires Entra ID P1** |
| [AP04](docs/attack-paths/AP04-app-credential-abuse.md) | App registration owner abuses a privileged service principal's credentials | Entra | T1098.001, T1098.003, T1078.004 | CRTO / CARTE | ~0 (Entra Free) |
| [AP05](docs/attack-paths/AP05-adcs-esc1.md) | AD CS ESC1 certificate template abuse on a hybrid domain controller | Hybrid | T1649, T1550, T1003.006 | CRTO / CRTE | **Bills compute** (Windows Server VM) |
| [AP06](docs/attack-paths/AP06-entra-connect-seamless-sso.md) | Entra Connect / Seamless SSO (`AZUREADSSOACC$`): the on-premises to cloud bridge | Hybrid | T1552, T1003.006, T1558.001, T1550 | CARTE / CRTE | **Bills compute** (shares the AP05 VM) |
| [AP07](docs/attack-paths/AP07-public-storage-leak.md) | Anonymous public storage leaks an over-scoped SAS, exposing a private container | Azure | T1530, T1619, T1552.001 | CARTP | ~0 (storage only) |
| [AP08](docs/attack-paths/AP08-automation-runbook-rbac.md) | Automation runbook running as an over-privileged managed identity escalates RBAC | Azure | T1651, T1098.003, T1078.004 | CARTP / CARTE | ~0 (no VM) |

**Layers:** *Entra* paths are identity-only; *Azure* paths create subscription resources; *Hybrid* paths deploy a Windows Server 2022 domain controller with AD DS and an Enterprise Root CA. AP05 and AP06 share a single domain controller.

---

## Architecture

```
            ./aether.ps1  (deploy | reset | destroy | verify | status)
                               |
                 terraform/ (root module, feature flags)
          ┌────────────────────┼─────────────────────┐
   entra-identity        azure-resources          hybrid-ad
   base users/groups     VM, managed identity,    Windows Server 2022 DC,
   AP01, AP03, AP04      Key Vault, storage,      AD DS, Enterprise Root CA,
                         Automation               AMA + DCR + Log Analytics
                         AP02, AP07, AP08         AP05, AP06
                               |
                 scripts/  (post-deploy seeds that Terraform cannot express)
                 detections/  (KQL + Sigma per path)
```

### Terraform modules

| Module | Scope | Paths |
|--------|-------|-------|
| `entra-identity` | Base lab users and groups, app registrations, consent and directory-role configuration | AP01, AP03, AP04 |
| `azure-resources` | Azure subscription resources: VM, managed identity, Key Vault, storage accounts, Automation Account, diagnostic settings | AP02, AP07, AP08 |
| `hybrid-ad` | Windows Server 2022 domain controller configured via DSC, AD DS, AD CS, plus an Azure Monitor Agent / data collection rule feeding Log Analytics | AP05, AP06 |

### The feature-flag pattern

Every vulnerability is gated behind a boolean variable (`enable_apXX`). Turning a flag on creates the misconfiguration; turning it off and re-applying removes it. Shared infrastructure is created only when needed: for example, the domain controller exists only when `enable_ap05 || enable_ap06` is true, so disabling both hybrid paths destroys the VM and drops compute cost to zero. Several paths expose additional tuning variables (for example `leak_mode`, `sso_mode`, `runbook_mode`, `mi_role`); see `terraform/terraform.tfvars.example` and the individual path documents.

Where Terraform cannot express a precondition cleanly (tenant consent policy, AD CS templates, objects inside the AD directory), a seed script in `scripts/` applies it after `terraform apply`. Seed scripts that support it also offer a `-Remediate` switch.

### Orchestrator verbs

| Command | What it does |
|---------|--------------|
| `./aether.ps1 deploy` | Runs `terraform apply` with your tfvars and then the seed scripts for the enabled paths. Idempotent. |
| `./aether.ps1 verify` | Runs `scripts/verify.ps1`, a health check confirming that each enabled path is in its expected state. |
| `./aether.ps1 status` | Shows what is currently deployed. |
| `./aether.ps1 reset` | Keeps the base environment but removes the vulnerabilities. |
| `./aether.ps1 destroy` | Tears down every resource the range created. |

---

## Prerequisites

### A dedicated test tenant and subscription

- A **new Entra ID tenant created only for this lab** (`<something>.onmicrosoft.com`). Never reuse a corporate or production tenant.
- A **dedicated Azure subscription** associated with that tenant. Entra Free is sufficient for the identity-only paths; the Azure and hybrid paths require a pay-as-you-go subscription.
- **AP03 requires Entra ID P1** (role-assignable groups do not exist in Entra Free). A developer or E5 trial tenant works.

### Tooling

| Tool | Version | Install (Windows) |
|------|---------|-------------------|
| Azure CLI | current | `winget install -e --id Microsoft.AzureCLI` |
| Terraform | **>= 1.6** | `winget install -e --id HashiCorp.Terraform` |
| PowerShell Microsoft.Graph module | current | `Install-Module Microsoft.Graph -Scope CurrentUser` |

### Deployer roles

The identity running `az login` and `terraform apply` needs:

| Paths enabled | Required role(s) |
|---------------|------------------|
| Base + AP01 | Directory write access to create users, groups, and apps; the seed requests the Graph scopes listed in [`docs/00-setup.md`](docs/00-setup.md) |
| AP03, AP04 | **Global Administrator** or **Privileged Role Administrator** in the test tenant (to create role-assignable groups and grant admin consent to role-management permissions) |
| AP02, AP05, AP06, AP07 | **Contributor** on the test subscription |
| AP08 | **Contributor** on the subscription, plus an Entra role able to create users (for example User Administrator), plus Owner or User Access Administrator on the AP08 resource group |

The simplest setup is a dedicated lab administrator that is Global Administrator of the test tenant and Owner of the test subscription. Full detail, including the Graph scopes and per-path notes, is in [`docs/00-setup.md`](docs/00-setup.md).

---

## Quickstart

```powershell
# 1. Clone
git clone https://github.com/javier-escribano/aether.git
cd aether

# 2. Sign in to your TEST tenant and select your TEST subscription
az login --tenant <YOUR_TEST_TENANT>.onmicrosoft.com
az account set --subscription "<TEST_SUBSCRIPTION_ID>"

# 3. Configure the deployment
cd terraform
cp terraform.tfvars.example terraform.tfvars
#    Edit terraform.tfvars: tenant, domain, and which enable_apXX flags to turn on
cd ..

# 4. Deploy (idempotent)
./aether.ps1 deploy

# 5. Confirm every enabled path is in the expected state
./aether.ps1 verify

# 6. When the session is over, tear everything down
./aether.ps1 destroy
```

> [!TIP]
> For your first run, enable **only AP01** (`enable_ap01 = true`, all other flags `false`). It is identity-only, costs nothing, and validates the full deploy, verify, and destroy cycle before you spend money on compute.

Then open the document for the path you enabled under [`docs/attack-paths/`](docs/attack-paths/) and work through the Exploit, Remediate, and Detect sections.

---

## Safety and cost

> [!WARNING]
> **Deploy only into a throwaway test tenant and subscription.** The range creates real, exploitable misconfigurations, including paths to Global Administrator and resource-group Owner. In a production tenant those would be real vulnerabilities.

- **Isolation.** Use a tenant and subscription that hold nothing of value. All users, mailboxes, secrets, and data seeded by the range are fictitious. Do not sync the lab AD forest to a real tenant with a real Entra Connect installation.
- **Network exposure.** The hybrid domain controller opens RDP/WinRM only to `admin_source_cidr` (your own `/32`). Leave it `null` to open no inbound ports and use Azure Bastion or the serial console instead. Never use `0.0.0.0/0`.
- **Cost.**
  - AP01, AP03, AP04, AP07, and AP08 cost approximately nothing (identity objects, storage, minimal log ingestion).
  - AP02 runs a small VM and public IP.
  - **AP05 and AP06 bill compute**: they run a Windows Server domain controller. The module enables daily auto-shutdown, but you should still destroy it when you are done.
  - Configure a **budget with alerts** in Cost Management (for example 20 USD/EUR per month with alerts at 50/80/100 percent).
- **Always run `./aether.ps1 destroy` when you finish a session.** Disabling a flag and re-deploying also removes that path's resources.
- **Treat Terraform state as toxic.** `terraform.tfstate` contains **cleartext credentials**: generated domain administrator passwords, lab user passwords, leaked SAS tokens or storage keys, and similar values. Keep it local or in a private, access-controlled backend, never commit it (the shipped `.gitignore` blocks `*.tfstate*` and `terraform.tfvars`; do not remove those entries), and delete it once the lab is destroyed.

---

## Security of the operator

> [!IMPORTANT]
> Running this range puts **you**, the operator, at risk if handled carelessly: the deployer holds highly privileged credentials, the state file holds secrets, and the lab exposes attackable endpoints. Read **[SECURITY.md](SECURITY.md)** for the operator-risk review, the hardening recommendations, and how to report a security issue in the project itself.

---

## Detections

Every attack path ships with detection content in [`detections/`](detections/):

| Format | Location | Use |
|--------|----------|-----|
| KQL | `detections/kql/APxx-*.kql` | Microsoft Sentinel / Log Analytics hunting and analytics rules |
| Sigma | `detections/sigma/APxx-*.yml` | Portable rules you can convert to your SIEM of choice |

Data sources used across the catalog include Entra `AuditLogs` and `SigninLogs`, `AzureActivity`, `StorageBlobLogs`, Automation `JobLogs`/`JobStreams` (`AzureDiagnostics`), and Windows `SecurityEvent` from the domain controller. The infrastructure paths provision the pipeline they need by default (diagnostic settings, Azure Monitor Agent and data collection rule, Log Analytics workspace). Set the corresponding `collect_*` variables to `false`, or set `existing_log_analytics_workspace_id` to your own Sentinel workspace, if you already ingest those logs. Each path document explains what telemetry is in scope and where the lab deliberately stops (for example, cloud-side sign-in logs for AP06 are left for you to hunt in your own tenant).

---

## Continuous integration

The GitHub Actions workflow in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request without any cloud credentials:

- `terraform fmt -check -recursive` for formatting.
- `terraform init -backend=false -lockfile=readonly` followed by `terraform validate` across a matrix of Terraform versions, using the committed `.terraform.lock.hcl`.
- An AST parse check of all PowerShell scripts plus a PSScriptAnalyzer pass.

CI validates the code only; it never deploys anything. Validating an actual `apply` requires your own test tenant.

---

## Repository layout

```
aether/
├─ README.md
├─ SECURITY.md                  operator-risk review and vulnerability reporting
├─ CONTRIBUTING.md              how to add a new attack path
├─ aether.ps1                   orchestrator: deploy | reset | destroy | verify | status
├─ .gitignore                   blocks Terraform state and secrets (do not remove)
├─ .github/workflows/ci.yml     fmt, validate, PowerShell lint
├─ docs/
│  ├─ 00-setup.md               prerequisites, permissions, cost control
│  └─ attack-paths/             AP01 ... AP08, each with Exploit / Remediate / Detect
├─ terraform/
│  ├─ providers.tf  variables.tf  main.tf  outputs.tf
│  ├─ terraform.tfvars.example
│  └─ modules/
│     ├─ entra-identity/        base identities, AP01, AP03, AP04
│     ├─ azure-resources/       AP02, AP07, AP08
│     └─ hybrid-ad/             domain controller, AD CS, monitoring, AP05, AP06
├─ scripts/
│  ├─ seed-ap01.ps1             tenant consent configuration via Microsoft Graph
│  ├─ seed-ap05.ps1             AD CS template seed / remediation
│  ├─ seed-ap06.ps1             Seamless SSO and sync account seed / remediation
│  └─ verify.ps1                range health check
└─ detections/
   ├─ kql/                      one .kql per path
   └─ sigma/                    one .yml per path
```

---

## Extending the range

The catalog is designed to grow. A new path (AP09 and beyond) consists of a feature flag, the Terraform resources in the appropriate module, an optional seed script, a document under `docs/attack-paths/` following the Exploit / Remediate / Detect template, and a KQL query plus a Sigma rule under `detections/`. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full checklist, naming conventions, and the requirement that every path be cleanly removable when its flag is turned off.

---

## Related projects

This range builds on ideas from, and is complementary to, other open labs: **GOAD** (on-premises AD), **BadZure** (Entra ID misconfigurations), **PurpleCloud** (Azure AD and hybrid lab infrastructure), **AzureGoat** (vulnerable Azure web infrastructure), **XMGoat** (Azure attack scenarios), and **SimuLand** (detection-focused simulation). Its contribution is to bring identity, Azure resources, and hybrid AD into one curated range where each path carries its own fix and detection.

---

## Disclaimer

AETHER is provided for **authorized educational, training, and purple-team use only**, on infrastructure you own or are explicitly permitted to test. The techniques documented here are publicly known and are included so that defenders can understand, remediate, and detect them. Do not use this project, or anything learned from it, against systems without authorization. The authors and contributors accept no liability for misuse or for cloud charges incurred by running the lab. Use it only in tenants and subscriptions you control, and destroy it when you are done.
