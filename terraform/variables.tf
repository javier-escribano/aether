# ------------------------------------------------------------------
# Range base config
# ------------------------------------------------------------------
variable "tenant_domain" {
  description = "TEST tenant domain (e.g. azrangelab.onmicrosoft.com). NEVER the corporate one."
  type        = string
}

variable "lab_prefix" {
  description = "Prefix for naming range objects (makes teardown easier)."
  type        = string
  default     = "azrange"
}

variable "user_count" {
  description = "Number of base dummy users."
  type        = number
  default     = 5
}

# ------------------------------------------------------------------
# Attack-path feature flags
#   Start with ONLY AP01 = true to validate the flow at no cost.
#   Add a new flag here for each path (see CONTRIBUTING.md).
# ------------------------------------------------------------------
variable "enable_ap01" {
  description = "AP01 — Illicit consent grant (Entra, ~zero cost)."
  type        = bool
  default     = true
}

variable "enable_ap02" {
  description = "AP02 — Over-privileged Managed Identity → Key Vault → lateral movement (Azure, low cost). NOTE: bills compute."
  type        = bool
  default     = false
}

variable "enable_ap03" {
  description = "AP03 — Low-privilege Owner over a role-assignable group holding the Privileged Role Administrator role → self-add → Global Admin (Entra, cost ~$0, REQUIRES Entra ID P1)."
  type        = bool
  default     = false
}

variable "enable_ap04" {
  description = "AP04 — Low-privilege Owner over an app registration whose SP carries RoleManagement.ReadWrite.Directory (admin-consented) → the owner adds a client secret → authenticates as the SP → self-assigns Global Administrator (Entra, cost ~$0, identity-only). The deployer needs Global Administrator or Privileged Role Administrator to grant the admin-consent."
  type        = bool
  default     = false
}

variable "enable_ap05" {
  description = "AP05 — AD CS ESC1 (Enrollee-Supplies-Subject) on a hybrid DC: low-priv → vulnerable template → PKINIT → Domain Admin → DCSync (hybrid on-prem). NOTE: BILLS COMPUTE (always-on Windows DC, the most expensive AP). auto-shutdown + destroy when done."
  type        = bool
  default     = false
}

variable "enable_ap06" {
  description = "AP06 — Entra Connect / Seamless SSO (AZUREADSSOACC$): on-prem→cloud bridge. 2nd hybrid path and the one that CLOSES the catalog. Shares the SAME DC as AP05 (shared substrate via need_dc): if enable_ap05=true, AP06 does NOT add a VM; if AP05 is off, AP06 brings up the DC on its own. NOTE: BILLS COMPUTE (like AP05). enable_ap06=false + enable_ap05=false → need_dc=false → destroys the VM."
  type        = bool
  default     = false
}

variable "sso_mode" {
  description = "AP06 — Entra Connect/Seamless SSO artifacts to seed: 'both' (default; full chain sync→DCSync→AZUREADSSOACC$ keys→silver ticket→cloud) | 'silver_ticket' (only AZUREADSSOACC$ with a fixed/non-rotated key + SPNs) | 'sync_dcsync' (only the MSOL_/Sync_ account with DCSync ACEs over the NC)."
  type        = string
  default     = "both"

  validation {
    condition     = contains(["silver_ticket", "sync_dcsync", "both"], var.sso_mode)
    error_message = "sso_mode must be 'silver_ticket', 'sync_dcsync', or 'both'."
  }
}

variable "sso_account_name" {
  description = "AP06 — sAMAccountName (without the $ suffix) of the Seamless SSO machine account. Real: AZUREADSSOACC. Must match the detections."
  type        = string
  default     = "AZUREADSSOACC"
}

variable "sync_account_name" {
  description = "AP06 — sAMAccountName of the Entra Connect sync account with DCSync rights (analogous to MSOL_/Sync_)."
  type        = string
  default     = "Sync_AZRANGE"
}

variable "sso_spns" {
  description = "AP06 — SPNs of the Seamless SSO account. The first (HTTP/autologon.microsoftazuread-sso.com) is the one Entra validates and the one the detections hunt for; the second (HTTP/aadg.windows.net.nsatc.net) completes the real footprint."
  type        = list(string)
  default     = ["HTTP/autologon.microsoftazuread-sso.com", "HTTP/aadg.windows.net.nsatc.net"]

  validation {
    condition     = length(var.sso_spns) > 0
    error_message = "sso_spns cannot be empty (ap06_attacker_hint indexes sso_spns[0])."
  }
}

variable "enable_ap07" {
  description = "AP07 — Public storage / SAS leak (Azure, ~zero cost, NO VM): account with anonymous access (allow_nested_items_to_be_public=true) + listable public container → leaked blob with an over-scoped credential → exfil of the private container. 100% declarative (no seed). The credential lands in STATE (sensitive)."
  type        = bool
  default     = false
}

variable "leak_mode" {
  description = "AP07 — credential leaked in backup-config.json: 'sas' (over-scoped account SAS, default; least-privilege lesson, uses hashicorp/time) or 'account_key' (primary_access_key = full control, more severe, no new provider)."
  type        = string
  default     = "sas"

  validation {
    condition     = contains(["sas", "account_key"], var.leak_mode)
    error_message = "leak_mode must be 'sas' or 'account_key'."
  }
}

variable "collect_storage_logs" {
  description = "AP07 — provisions StorageBlobLogs via a diagnostic setting (blobServices/default) → Log Analytics so that 'Detect' is testable end-to-end. false = no ingestion (zero cost; assumes an external SIEM)."
  type        = bool
  default     = true
}

variable "enable_ap08" {
  description = "AP08 — Automation Account runbook → RBAC escalation (Azure, ~zero cost, NO VM): an Automation Account with an over-privileged system-assigned MI (UAA/Owner over the RG) + a low-priv attacker (Automation Contributor) who starts a runbook running AS the MI → New-AzRoleAssignment self-grants Owner of the RG. 100% declarative (no seed); the 'gun' is left loaded but Terraform NEVER fires it. The attacker's password lands in STATE (sensitive)."
  type        = bool
  default     = false
}

variable "runbook_mode" {
  description = "AP08 — embedded runbook: 'poc_escalation' (default; loaded gun: Connect-AzAccount -Identity + New-AzRoleAssignment granting the attacker Owner of the RG → immediate demo) | 'benign_probe' (only tests the MI's identity/power; the student writes the escalation → safer for shared deployments) | 'none' (no runbook; pure misconfig). In NO mode does Terraform start a job."
  type        = string
  default     = "poc_escalation"

  validation {
    condition     = contains(["poc_escalation", "benign_probe", "none"], var.runbook_mode)
    error_message = "runbook_mode must be 'poc_escalation', 'benign_probe', or 'none'."
  }
}

variable "mi_role" {
  description = "AP08 — built-in over-priv role of the MI OVER THE RG: 'UserAccessAdministrator' (default; minimum-that-escalates: its ONLY power is roleAssignments/write → lesson 'even just UAA over an Automation MI = game over') | 'Owner' (more realistic). Contributor is EXCLUDED: it does not include roleAssignments/write (that lane is AP02's via accessPolicies/write)."
  type        = string
  default     = "UserAccessAdministrator"

  validation {
    condition     = contains(["UserAccessAdministrator", "Owner"], var.mi_role)
    error_message = "mi_role must be 'UserAccessAdministrator' or 'Owner' (Contributor does not include roleAssignments/write and does not escalate)."
  }
}

variable "collect_automation_logs" {
  description = "AP08 — provisions JobLogs + JobStreams via a diagnostic setting (Automation Account) → Log Analytics (AzureDiagnostics) so that 'Detect' is testable end-to-end. false = no ingestion (zero cost; assumes an external SIEM). These categories are NOT active by default → without this setting the runbook EXECUTION does not exist in any SIEM (the management plane DOES flow through AzureActivity)."
  type        = bool
  default     = true
}

# ------------------------------------------------------------------
# Azure-layer config (relevant if enable_ap02, enable_ap05, enable_ap07, or enable_ap08)
# ------------------------------------------------------------------
variable "location" {
  description = "Azure region for the AP02/AP05/AP07/AP08 resources (affects cost/latency)."
  type        = string
  default     = "westeurope"
}

# ------------------------------------------------------------------
# AP05-specific config (only relevant if enable_ap05 = true)
# ------------------------------------------------------------------
variable "dc_admin_password" {
  description = "AP05 — password of the domain built-in Administrator (= Enterprise Admin that seeds/remediates ESC1). Leave null/empty → random_password. NEVER a real or reused password. Lands in STATE: treat the state as sensitive."
  type        = string
  sensitive   = true
  default     = null
}

variable "admin_source_cidr" {
  description = "AP05 — operator /32 CIDR for RDP/WinRM to the DC. NEVER 0.0.0.0/0 (it's a DC). If null, NO inbound rule is opened (Bastion/serial-console)."
  type        = string
  default     = null
}

variable "domain_fqdn" {
  description = "AP05 — FQDN of the throwaway forest. Do NOT sync with the tenant via real Entra Connect (that would turn the lab into a real risk; AP06 would cover that)."
  type        = string
  default     = "azrange.lab"
}

variable "vm_size" {
  description = "AP05 — size of the DC+CA VM. Standard_B2ms by default; Standard_B2s as the floor."
  type        = string
  default     = "Standard_B2ms"
}

variable "collect_security_events" {
  description = "AP05 — provisions AMA+DCR+Log Analytics so that 'Detect' is testable end-to-end. false = no ingestion (zero cost; assumes an external SIEM)."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "AP05/AP07/AP08 — resource ID of an EXISTING Log Analytics/Sentinel to point the DCR (AP05), the blob diagnostic setting (AP07), and/or the Automation Account one (AP08) at. If provided, the modules do NOT create their own workspace."
  type        = string
  default     = null
}
