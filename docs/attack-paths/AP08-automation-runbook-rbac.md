# AP08 — Automation Account runbook -> the over-privileged Managed Identity escalates to RG Owner

- **Layer:** Azure (Automation Account - Managed Identity - RBAC — management plane / *cloud control plane*)
- **Cost:** **~0 — NO VM, no billed compute.** The Automation Account **has no fixed cost** and includes ~**500 min/month of free job runtime** (the exercise consumes seconds); `JobLogs`/`JobStreams` ingestion into Log Analytics stays well below 0.1 GB/day (cents/month, 31 days of retention included). `./aether.ps1 destroy` or `reset` -> 0. **Ties with AP07 at ~zero cost** (both deploy ARM without a VM); the *identity-only* AP01/AP03/AP04 are pure Entra (free, no ARM) and AP02/AP05 do bill compute (VM). *(It is not "the cheapest": it shares the cost floor with AP07.)*
- **MITRE ATT&CK:** [T1651](https://attack.mitre.org/techniques/T1651/) (Cloud Administration Command — **primary**: run commands via an Automation runbook) - [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles — the role assignment that grants the privileged role) - [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts — the attacker persists as RG Owner)
- **Maps to cert:** CARTP / CARTE
- **Precondition seeded by the range** (100% Terraform, `enable_ap08 = true`):
  - Automation Account `aether-ap08-aa-<rand>` (output `ap08_automation_account` — **`verify.ps1` sentinel**) with a **system-assigned managed identity**. That MI is the **effective actor** of the escalation, exactly as in AP02 the actor is the MI stolen via IMDS.
  - **The nuclear over-privilege:** the MI holds `mi_role` **over the RG** `aether-ap08-rg` (`azurerm_role_assignment`), by default **`User Access Administrator`** (switchable to `Owner`). **Both roles include `Microsoft.Authorization/roleAssignments/write`** -> the MI can **self-assign** (or assign to a third party) a higher role over that scope.
  - A dedicated **low-privilege** attacker `aether-ap08-attacker@<tenant_domain>` (output `ap08_attacker_upn`, password in `ap08_attacker_password` — **sensitive**) whose **only** Azure grant is **`Automation Contributor` over the RG** (`azurerm_role_assignment`, `principal_type = "User"`). `Automation Contributor` does **not** include `roleAssignments/write`: the attacker **cannot** escalate on their own — they must **drive the MI**.
  - **Embedded** PowerShell runbook `aether-ap08-maintenance` (**fixed** decoy name, anchors the detection), gated by `runbook_mode` (`poc_escalation` by default - `benign_probe` - `none`). It is the **"loaded gun"**: Terraform **publishes** it, but **never fires** it (it launches no job and creates no `azurerm_automation_schedule`).
  - **Automation data-plane** telemetry: an `azurerm_monitor_diagnostic_setting` (`aether-ap08-automation-diag`) over the Automation Account -> categories **`JobLogs` + `JobStreams`** -> `AzureDiagnostics` table (ResourceProvider `MICROSOFT.AUTOMATION`) in `aether-ap08-law` (output `ap08_law_name`) or in an external Sentinel (`existing_log_analytics_workspace_id`); gated by `collect_automation_logs` (default `true`).
  - **100% declarative: no `seed-ap08.ps1`, no `az vm run-command`, no post-apply hook** — entirely wired by Terraform, **embedded runbook included** (via inline `content`). It is **100% declarative like AP02/AP03/AP04/AP07** (no imperative *seed*), unlike AP01/AP05 which seed the *payload* with scripts (`seed-ap01.ps1` / `seed-ap05.ps1`). **What is NOT seeded:** no job execution, no schedule, no runtime role assignment — the **"exploit" is the student's action** (`Start-AzAutomationRunbook`).

> **Warning — the credential lands in the `tfstate`.** The attacker's `random_password` lives in the Terraform state **in clear text and marked sensitive** (it is only exposed via the sensitive output `ap08_attacker_password`). Treat the `tfstate` as **toxic**, just like the SP client secret in AP02 or `dc_admin_password` in AP05. The repo's `.gitignore` already blocks `*.tfstate*`. *(The embedded `poc_escalation` runbook is also "live": it grants Owner the moment it runs — but Terraform only **publishes** it, never runs it; see the Exploit section.)*

---

## Learning objective

Have the student internalize the **Azure Automation confused deputy**: *whoever can run a runbook is, in effect, the owner of the scope of the Automation Account's Managed Identity*. The real flaw is not publishing a runbook (a legitimate operation for an `Automation Contributor`), but that the **MI that executes that runbook inherits a role with `roleAssignments/write`** over a scope the attacker did not control. The scenario demonstrates the canonical CARTP/CARTE chain of the automation plane:

`low-priv identity (Automation Contributor) -> authors/imports a runbook and launches a job (T1651) -> the job runs AS the over-privileged MI -> the MI runs New-AzRoleAssignment (T1098.003) -> the attacker is RG Owner (T1078.004, persistence + full control)`.

The conceptual axis is identical in form to AP02's (**the MI is the actor, not the safe**) but through a **different primitive**: in AP02 the MI token is **stolen** from IMDS and `Contributor` includes `accessPolicies/write`; in AP08 **there is no token theft** — the attacker never sees the MI credential — but **indirect driving**: the `Connect-AzAccount -Identity` happens **inside** the runbook, in the Automation Account sandbox, and the attacker only needs the right to **launch the job**. The sharp lesson of the default `mi_role = "UserAccessAdministrator"` is that **even "just UAA"** over an Automation MI = *game over*: UAA reads no data, deploys nothing, its **only** power is to assign roles — and that is enough, because it can grant itself (or the attacker) a role **higher** than its own.

The second lesson is about **scope least-privilege**: the MI is bounded **to the RG**, not to the subscription. This is not convenience but a **security requirement of the range** (and of any real deployment): a runtime role assignment with a subscription `-Scope` would **survive** the RG destroy -> *out-of-state* residue + *blast radius* widened to the whole subscription. By bounding the MI and the escalation to the RG, **any** grant the student creates at runtime is a **child of the RG** and dies with it -> clean reset (exact analogue of AP05's **throwaway forest**). See the Remediate section and the reset note.

**Contrast with AP02 (its identity twin) — three design traits:**
1. **Same actor (the MI), different primitive:** AP02 **steals** the MI token via IMDS (T1552.005); AP08 **drives** the MI via a runbook without ever seeing its token (T1651). In both, the *self-grant* is signed by the MI, not by the human attacker.
2. **100% declarative**, embedded runbook included — like AP07 (and AP02/AP03/AP04), without the imperative post-deployment action of AP01/AP05.
3. **Cleaner reset residue than AP02:** the attacker's *self-grant* in AP02 stays **outside** the state and must be cleaned up by hand (it may be at subscription scope). In AP08 the *self-grant* is **also** outside the state, **but it is RG-scoped by design** -> it is destroyed atomically with the RG -> **zero *out-of-state* residue, tying with AP05/AP07** (it does not beat them: it is a three-way tie).

---

## Exploit (how it is exploited)

> Authorized training lab, in your own test tenant/subscription. Public reference tooling: **az cli** (+ the `automation` extension), **Az PowerShell** (`Az.Automation`, `Az.Accounts`, `Az.Resources`), **MicroBurst** / **PowerZure** (Automation abuse), **ROADtools**, **pacu** (`azure` module). The embedded runbook and the `ap08_attacker_hint` output yield the trigger *one-liner*, **with no secrets**.

The chain is `low-priv login -> (author/publish a runbook) -> Start-AzAutomationRunbook (job, T1651) -> the MI runs the runbook -> New-AzRoleAssignment (T1098.003) -> RG Owner (T1078.004)`. The "exploit" (launching the job) is **imperative and the student's**: Terraform left the gun loaded, but the student pulls the trigger.

### Step 1 — Authenticate as the low-privilege attacker

The pedagogical differentiator —*"I only had `Automation Contributor` and ended up Owner"*— lives in **launching the job as the low-priv**, not as the deployer. The state yields the credential:

```bash
UPN=$(terraform output -raw ap08_attacker_upn)         # aether-ap08-attacker@<tenant_domain>
PW=$(terraform output -raw ap08_attacker_password)     # sensitive (lives in the tfstate)
RG=$(terraform output -raw ap08_resource_group)        # aether-ap08-rg
AA=$(terraform output -raw ap08_automation_account)    # aether-ap08-aa-<rand>

az login -u "$UPN" -p "$PW"                             # ROPC: only without CA/MFA (see caveat)
```
```powershell
# Az PowerShell equivalent:
$cred = Get-Credential   # UPN + ap08_attacker_password
Connect-AzAccount -Credential $cred
```

> **Trigger caveat — CA/MFA vs. cloud-only account (AP02-style fallback).** The attacker is a freshly created **cloud-only** user; if the tenant enforces *Conditional Access* or MFA, the non-interactive login (ROPC) fails. **Deliberate fallback:** fire the runbook as the **deployer/Owner** (the *effective actor* is still the MI, just as in AP02 the actor is the MI even if the human changes). The low-priv user exists **for the fidelity of the lesson** (the real privilege jump), not as an obstacle: if CA blocks it, use it to *read* its role (`az role assignment list --assignee <oid> --scope <rg-id>` -> only `Automation Contributor`) and launch the job with an identity that can authenticate.

### Step 2 — Reconnaissance: the Automation Account and its loaded runbook

```bash
# The MI and its principalId (the object id that will sign the roleAssignments/write — the gold signal in the Detect section):
az automation account show -g "$RG" -n "$AA" --query identity.principalId -o tsv   # = ap08_mi_principal_id

# The decoy runbook already published by Terraform (runbook_mode != none):
az automation runbook list -g "$RG" --automation-account-name "$AA" -o table
#   -> aether-ap08-maintenance   PowerShell   Published
```

### Step 3 — Fire the job (T1651) — the "exploit"

**`poc_escalation` mode (default): the gun is loaded.** The embedded runbook already does `Connect-AzAccount -Identity` + `New-AzRoleAssignment` granting **RG Owner** to the attacker. Just launch it:

```powershell
# Az PowerShell (canonical and robust). Define the variables in THIS pwsh session
# (the bash vars from Step 1 do not cross into a new pwsh process):
$AA = terraform output -raw ap08_automation_account
$RG = terraform output -raw ap08_resource_group
$job = Start-AzAutomationRunbook -Name 'aether-ap08-maintenance' `
         -AutomationAccountName $AA -ResourceGroupName $RG
# Wait and read the job output (JobStreams: reveals the New-AzRoleAssignment text):
Get-AzAutomationJob -Id $job.JobId -AutomationAccountName $AA -ResourceGroupName $RG
Get-AzAutomationJobOutput -Id $job.JobId -Stream Any `
  -AutomationAccountName $AA -ResourceGroupName $RG | Select-Object -Expand Summary
#   -> [AP08] Running as the Automation Account MI: <mi-oid>
#   -> [AP08] Granting 'Owner' over <rg-id> to principal <attacker-oid>...
#   -> [AP08] Escalation complete: the low-priv is now RG Owner.
```
```bash
# az equivalent (automation extension):
az automation runbook start -g "$RG" --automation-account-name "$AA" --name aether-ap08-maintenance
```

**The key point:** the `New-AzRoleAssignment` is **not signed by the attacker** — it is signed by **the MI** inside the sandbox. The attacker, who only had `Automation Contributor`, has just exercised `roleAssignments/write` **by indirect delegation**.

### Step 4 — Confirm the trophy: RG Owner (persistence)

```bash
RGID=$(az group show -n "$RG" --query id -o tsv)
az role assignment list --assignee "$UPN" --scope "$RGID" -o table
#   -> Owner   aether-ap08-attacker@...   /subscriptions/.../resourceGroups/aether-ap08-rg
```
From here the attacker controls the entire RG (create/delete resources, grant more roles, persist). There is no `AETHER{...}` *flag*: **the trophy is the Owner grant itself** — the posture change from `Automation Contributor` to `Owner` **is** the demonstration.

> **Teachable note — opportunistic data plane, unsuppressible management plane.** The `poc_escalation` runbook does **not** suppress its output, so `JobStreams` reveals the literal text `New-AzRoleAssignment ... Owner`. A stealthy attacker would add `| Out-Null` and **that** data-plane trace would vanish. But the `Microsoft.Authorization/roleAssignments/write` the MI executes on the **management plane** (`AzureActivity`) **cannot be suppressed**: it is logged no matter what (see the Detect section). The data plane is a visibility *bonus*; the control plane is the detection anchor.

### Variants

**`runbook_mode` — what the Automation Account ships loaded with:**

| Mode | What Terraform embeds | What the student does | When |
|---|---|---|---|
| **`poc_escalation`** *(default)* | A runbook that does `Connect-AzAccount -Identity` + `New-AzRoleAssignment -RoleDefinitionName Owner -Scope <RG>` to the attacker. **Loaded gun.** | Only `Start-AzAutomationRunbook`. Immediate demo; parity with AP07's already-leaked credential. | Guided demo; `end-to-end` validation of the gold signal (`roleAssignments/write` by the MI). |
| **`benign_probe`** | A runbook that **only** tests identity/power: `Connect-AzAccount -Identity`, `Get-AzAccessToken` (does not print the token — hygiene), `Get-AzRoleAssignment -Scope <RG>` -> confirms the MI has UAA/Owner over the RG. **Does not escalate.** | **Writes the** `New-AzRoleAssignment` **himself** (edits the runbook or imports his own) and launches it. | Recommended default for **shared** deployments: the gun is not loaded, but the MI is still over-priv. |
| **`none`** | No runbook (pure misconfig). | **Authors everything**: `az automation runbook create` -> `replace-content` -> `publish` -> `start`. | "From scratch" exercise; maximum offensive fidelity. |

> In **no** mode does Terraform fire the escalation: `benign_probe` and `poc_escalation` only **publish**; `none` does not even publish. The difference is *how loaded* the gun is, never *who* pulls the trigger (always the student).

**`mi_role` — the MI's over-priv role over the RG:**

- **`UserAccessAdministrator`** *(default)* — **minimum-that-escalates**. Its **only** power is to assign roles; it reads no data, deploys nothing. Sharpest lesson: *even "just UAA"* over an Automation MI = full escalation, because it can grant Owner to itself or the attacker.
- **`Owner`** — more realistic/common in real tenants (an automation MI that "was given RG Owner so it could manage everything"). It also includes `roleAssignments/write`, so the chain is identical; only the realism of the pretext changes.
- **`Contributor` is EXCLUDED on purpose** (there is a `validation`): `Contributor` does **not** include `Microsoft.Authorization/roleAssignments/write` -> it does not escalate through this lane. (That is **AP02's** lane, where `Contributor` escalates via a Key Vault's `accessPolicies/write` in the *access-policy* model, not via RBAC.)

---

## Remediate (remediation)

Ordered from **root cause** (#1 kills the chain on its own) to **defense in depth** (#8 does **not** prevent, only detects). Apply them in depth.

1. **Remove from the MI the role that includes `roleAssignments/write` (root cause, the most effective).** If the Automation Account does not need to **write RBAC** —the normal case—, its MI must **not** hold UAA or Owner. Without the primitive there is no escalation.
   ```powershell
   Remove-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "User Access Administrator" `
     -Scope "/subscriptions/<sub>/resourceGroups/aether-ap08-rg"
   ```
   > In the range = **remove (or comment out) the `azurerm_role_assignment.ap08_mi` resource** (the MI's over-priv grant) and re-apply with `enable_ap08 = true`. *(Both accepted values of `mi_role` —`UserAccessAdministrator` and `Owner`— include `roleAssignments/write`, so the fix is not changing the variable but removing the assignment.)* **There is no `seed-ap08.ps1 -Remediate`**: the path is 100% declarative (like AP07), so "fixing in-place" is **editing the Terraform** and running `terraform apply`.

2. **If the MI must act on RBAC, a least-privilege *custom* role** that **excludes** `Microsoft.Authorization/roleAssignments/write` and `.../roleAssignments/delete` (+ `denyAssignments/*`); or the scoped **`Role Based Access Control Administrator`** role (delegation **with conditions**, e.g. only certain roles) instead of UAA/Owner.

3. **Scope containment (and what makes the reset clean).** **Never** grant the MI anything at the **subscription** or *management group* level; keep it **RG-scoped** or finer. Beyond reducing the *blast radius*, this is what guarantees a runtime grant dies with the RG (see reset).

4. **Minimum RBAC on the Automation Account itself: separate authoring from execution.** *Whoever can launch a job = whoever acts as the MI.* Restrict `Automation Contributor` and the `runbooks/write`, `draft/content/write`, `publish/action`, `jobs/write` actions; use **`Automation Operator`** (only **runs** already-approved runbooks, does not edit them) for operators, and reserve authoring to a reviewed pipeline.

5. **Identity architecture.** Prefer a **user-assigned MI** that is scoped (or **none**) over a system-assigned one loaded with a broad role. Do **not** use the **Run-As classic** pattern (retired Sep 2023): the system-assigned MI is the faithful 2024+ primitive.

6. **Harden the surface.** `local authentication` disabled, **Private Link** / `public_network_access_enabled = false`, and **source control integration** with review of runbook changes (no runbook reaches `Published` without *code review*).

7. **PIM / JIT** for any privileged role that is genuinely needed -> **no** identity with *standing* Owner/UAA; the MI (or the operator) elevates *just-in-time* and with approval.

8. **Telemetry + policy (defense in depth — does NOT prevent).** `JobLogs`+`JobStreams` -> Log Analytics (**OFF by default**); **alert** on `roleAssignments/write` whose `Caller` is the `principalId` of an Automation MI; **Azure Policy** that audits/denies granting Owner/UAA to automation identities; **Microsoft Defender for Cloud**.

### In-place remediation in the range (the "Remediate" exercise)

Like AP07 and unlike AP05, **there is no imperative seed**: the in-place fix is **declarative**. Remove (or comment out) `azurerm_role_assignment.ap08_mi` (the MI's over-priv grant) and re-apply with `enable_ap08 = true` — both `mi_role` values include `roleAssignments/write`, so the fix is removing the assignment, not changing the variable. The student re-launches the runbook and checks that `New-AzRoleAssignment` now **fails with `AuthorizationFailed`** from the MI.

> **Two reset levels — do not confuse them** (same pattern as AP07).
> **(1) In-place / pedagogical:** remove (or comment out) `azurerm_role_assignment.ap08_mi` + `terraform apply` (above) -> leaves the Automation Account and the telemetry standing to re-test attack and detection against the corrected state. **Important nuance:** this *flip* closes the **primitive** (the MI can no longer escalate), but does **not** revoke a role assignment the attacker **already** created at runtime — that Owner grant is *out-of-state*. To remove it you either delete it by hand (`az role assignment delete`) **or** use the hard reset (which destroys it with the RG — precisely because it is **RG-scoped**).
> **(2) Hard / cost->0:** `./aether.ps1 reset` re-applies with `enable_ap08 = false` (`count = 0`) -> Terraform **atomically destroys** the `aether-ap08-rg` RG and, **with it**, the Automation Account + the MI + its `role_assignment` + the runbook + the LAW **and any runtime role assignment scoped to the RG** (the student's Owner *self-grant*, which is a child of the RG). **Zero *out-of-state* residue, tying with AP05/AP07** as the cleanest resets in the range — and **cleaner than AP02**, whose *self-grant* stays outside the state and must be cleaned up by hand. The technical key is the **RG scope**: a subscription `-Scope` would **survive** the RG destroy -> *out-of-state* residue + widened *blast radius*. That is why the RG scope is a **security requirement**, not a convenience (analogous to AP05's throwaway forest).

---

## Detect

Two planes, two sources, two natures of telemetry (same cast as AP07/AP02):

- **Management plane (the chain itself)** -> the **`AzureActivity`** table, which **flows to the SIEM by default without provisioning anything**. It covers the runbook authoring, the **job launch** (= execution, T1651) and, above all, the **`roleAssignments/write` signed by the MI** (the gold signal).
- **Automation data plane (the runbook execution)** -> **`AzureDiagnostics`** (`ResourceProvider == "MICROSOFT.AUTOMATION"`, `Category in ("JobLogs","JobStreams")`), which **only exists if the range provisions the `diagnostic_setting`** over the Automation Account. `JobStreams` can reveal the **literal text** `New-AzRoleAssignment` / `Owner` if `log_verbose = true` and the runbook does not suppress its output.

| Signal | Table | What to look at |
|---|---|---|
| Runbook authoring | `AzureActivity` | `OperationNameValue has "Microsoft.Automation/automationAccounts/runbooks/write"` (and `.../runbooks/draft/content/write`, `.../runbooks/publish/action`) — the lab `apply` and the student in `none`/`benign_probe` mode fire them |
| **Job launch (T1651)** | `AzureActivity` | `OperationNameValue has "Microsoft.Automation/automationAccounts/jobs/write"` — **the execution**; `Caller` = the low-priv user (or the deployer in the *fallback*) |
| **Gold signal — `roleAssignments/write` by the MI** | `AzureActivity` | `OperationNameValue has "Microsoft.Authorization/roleAssignments/write"` **with `Caller == ap08_mi_principal_id`** (the object id of the system-assigned MI). A role assignment executed by an **automation identity** is a very high signal |
| **Full chain (high fidelity)** | `AzureActivity` | correlation by **time + RG**: a **`jobs/write`** (`Caller != MI`) followed, within a short window (~20 m) and the **same RG**, by a **`roleAssignments/write`** (`Caller == MI`) that grants a privileged role. Almost zero FP: it is exactly the pivot that remediation makes impossible |
| Runbook execution and output | `AzureDiagnostics` | `ResourceProvider == "MICROSOFT.AUTOMATION"`, `Category in ("JobLogs","JobStreams")`; `JobStreams` can contain the text `New-AzRoleAssignment`/`Owner` (if the output was not suppressed) |

- KQL (Sentinel / Defender XDR): [`detections/kql/AP08-automation-runbook-rbac.kql`](../../detections/kql/AP08-automation-runbook-rbac.kql) — `AzureActivity` (authoring + job + `roleAssignments/write` by the MI + **chain correlation by time+RG**) **and** `AzureDiagnostics` (`JobLogs`/`JobStreams`, **KQL-primary**).
- Sigma: [`detections/sigma/AP08-automation-runbook-rbac.yml`](../../detections/sigma/AP08-automation-runbook-rbac.yml) — `logsource product: azure, service: activitylogs` (UUID `a7d3f2b9-8c14-4e6a-b5f0-2d9c1e4a7b63`).

**Sigma vs KQL split (declared explicitly, as AP07 declared "anonymous blob access is not `activitylogs`" and AP05 "the SAN does not travel").** The **management plane** (authoring + `jobs/write` + `roleAssignments/write`, with a success filter by `properties.statusCode` **OR** `status contains "Succ"` — same pattern as AP02/AP07, never an `AND` that silently discards records populating only one of the fields) **does** fit a standard Sigma *logsource* (`azure/activitylogs`). The **data plane** (`JobLogs`/`JobStreams` in `AzureDiagnostics`) **is not a standard Sigma *logsource* -> it is KQL-primary.** Do not force the runbook streams into an `activitylogs` rule: they are not there.

> **Discriminating filter *deploy* vs. attack — by the `Caller`, not the beneficiary.** During the `apply`, the `azurerm_role_assignment.ap08_mi` (MI -> UAA/Owner) also generates a `roleAssignments/write`, but its `Caller` is the **deployer/IaC**. In the attack the grant's `Caller` is the **MI** (`ap08_mi_principal_id`). That is the gold distinction. The grant's **beneficiary** (the same low-priv user) does **not** reliably serialize in `AzureActivity` -> it is **annotated** from `JobStreams` with a `leftouter`, **never** as a filter that discards the chain (lesson from AP04/AP07: do not drop the event over a field that may be missing).

> **Caveat — `JobLogs`/`JobStreams` are NOT active by default.** Without the `diagnostic_setting` over the Automation Account, **the runbook execution exists in no SIEM** (exact analogue of "on-prem events do not exist without AMA+DCR" from AP05 and "`StorageBlobLogs` does not exist without the diagnostic setting" from AP07). That is why that row is only testable if the range ingests them (`collect_automation_logs = true`). The management plane —`jobs/write`, `roleAssignments/write`— **does** flow through `AzureActivity` without provisioning anything.

> **Caveat — Automation has no dedicated table.** Unlike AP07 (which uses `log_analytics_destination_type = "Dedicated"` -> `StorageBlobLogs`), the AP08 `diagnostic_setting` **omits** `log_analytics_destination_type` -> the logs land in **`AzureDiagnostics`** (shared schema). The KQL filters by `ResourceProvider == "MICROSOFT.AUTOMATION"`.

**Managed complement:** **Microsoft Defender for Cloud** (anomalous RBAC change detection) + **Azure Policy** that denies granting Owner/UAA to Automation MIs + **PIM** — recommended alongside these rules.

> **Ingestion cost.** The exercise's job seconds -> `JobLogs`/`JobStreams` well below 0.1 GB/day -> cents/month. Turned off with `collect_automation_logs = false` (assumes an external SIEM). The diagnostic setting's `metric { category = "AllMetrics"; enabled = false }` neutralizes the *perpetual-diff* when the API fills the `metric` block (AP07 idiom).

---

## Teachable caveat — the MI takes time to propagate in AAD

In the style of AP07's "`allowBlobPublicAccess` default = `false` post-2023" block: when creating `azurerm_role_assignment.ap08_mi`, the `principalId` of the **system-assigned MI** may **not have replicated** yet in Microsoft Entra ID -> the `apply` would fail with *PrincipalNotFound*. That is why the resource uses **`skip_service_principal_aad_check = true`** (identical to AP02). For the **attacker** user that flag does **not** apply (it is for SP/MI), so its `role_assignment` sets an explicit **`principal_type = "User"`**, preventing `azurerm` from trying to resolve the type via Graph for a freshly created user.

> **Idempotency caveat.** The runbook `content` references **stable state scalars** (`local.ap08_attacker_oid` = `object_id`, `local.ap08_rg_id` = the RG id), interpolated via a *short-circuit* ternary (never `[0]` directly, never `timestamp()`), so that `terraform plan` after `apply` = *No changes*. `random_string.ap08` is **its own** (it does not reuse AP02/AP07's, which are gated behind other flags). It is the same rigor that led AP07 to use `time_static`/`time_offset` for the SAS: deterministic state, no *perpetual-diff*.

> **Environment caveat (student runtime, not the `apply`).** The runbook assumes the Automation Account has the **`Az.Accounts` / `Az.Resources`** modules (`Connect-AzAccount -Identity`, `New-AzRoleAssignment`). Current Automation images ship them; if they were missing, the student imports them in *Shared Resources* (`Modules`). It is an execution *concern*, not a deployment one — analogous to "the VM must be powered on" from AP05. (If a *build* were to reject inline `content` without `publish_content_link`, just add an inert `publish_content_link { uri }`: valid in `azurerm ~3.116`.)

> **Caveat — `verify.ps1` confirms POSTURE, not an escalation.** The `ap08_automation_account` sentinel and the `verify.ps1` probes check that the Automation Account, the MI's over-priv role, the runbook and the attacker **are deployed** (the loaded gun), **not** that anything has been fired: in no mode does the `apply` run a job.

> **No colliding unique superlatives.** AP08 is 100% declarative **like AP02/AP03/AP04/AP07** (the declarative property is shared, no "first"/"second"). The ~0 cost **ties** with AP07 (no "the cheapest"). The reset cleanliness **ties** with AP05/AP07 (three-way tie, not "the cleanest").

---

## References

- Microsoft — [Use a system-assigned managed identity for an Azure Automation account](https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation) (the Automation Account MI; `Connect-AzAccount -Identity` from a runbook)
- Microsoft — [Retirement of Run As accounts (Sep 2023) — migrate to managed identities](https://learn.microsoft.com/en-us/azure/automation/migrate-run-as-accounts-managed-identity) (why the system-assigned MI is the faithful 2024+ primitive)
- Microsoft — [Azure built-in roles — User Access Administrator / Owner / Role Based Access Control Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) (all three include or constrain `Microsoft.Authorization/roleAssignments/write`)
- Microsoft — [Automation built-in roles — Automation Contributor / Automation Operator](https://learn.microsoft.com/en-us/azure/automation/automation-role-based-access-control) (separate authoring from execution; `jobs/write` = act as the MI)
- Microsoft — [Forward Azure Automation diagnostic logs to Azure Monitor (`JobLogs` / `JobStreams`)](https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics) (telemetry OFF by default; `AzureDiagnostics`)
- Microsoft — [Azure Policy for RBAC / deny privileged role assignments](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies) and [Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- MITRE ATT&CK — [T1651](https://attack.mitre.org/techniques/T1651/) (Cloud Administration Command), [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Additional Cloud Roles), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
- Compare with [AP02](./AP02-managed-identity.md) (same actor —the MI— through a different primitive: IMDS token theft vs. indirect driving via a runbook; *self-grant* outside the state) and with [AP07](./AP07-public-storage-leak.md) (100% declarative path, two-level reset, Sigma/KQL management-plane vs. data-plane split) and [AP05](./AP05-adcs-esc1.md) (throwaway forest: vulnerable surface on a disposable resource -> reset with no *out-of-state* residue).
