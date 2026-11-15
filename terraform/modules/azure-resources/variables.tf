# ------------------------------------------------------------------
# Variables for the azure-resources module (Azure resource layer).
# Typed and minimal: the module inherits context from the root (main.tf).
# ------------------------------------------------------------------
variable "lab_prefix" {
  description = "Prefix for naming the range objects (simplifies teardown)."
  type        = string
  default     = "azrange"
}

variable "location" {
  description = "Azure region for the AP02/AP07/AP08 resources (affects cost/latency)."
  type        = string
  default     = "westeurope"
}

variable "tenant_domain" {
  description = "AP08 - TEST tenant domain (e.g. azrangelab.onmicrosoft.com) for the UPN of the attacker azuread_user. Wired by the root; null when AP08 is unused (the module does not create the user with enable_ap08=false)."
  type        = string
  default     = null
}

variable "enable_ap02" {
  description = "AP02 - over-privileged Managed Identity -> Key Vault (Azure, low cost)."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------
# AP07 - Public storage / SAS leak (Azure, ~zero cost, no VM).
# ------------------------------------------------------------------
variable "enable_ap07" {
  description = "AP07 - Storage with anonymous access (account + container) -> leaked blob with over-scoped credential -> exfiltration of the private container (Azure, ~zero cost)."
  type        = bool
  default     = false
}

variable "leak_mode" {
  description = "AP07 - which credential leaks in backup-config.json: 'sas' (over-scoped account SAS, default; uses hashicorp/time) or 'account_key' (primary_access_key, more severe, no new provider)."
  type        = string
  default     = "sas"

  validation {
    condition     = contains(["sas", "account_key"], var.leak_mode)
    error_message = "leak_mode must be 'sas' or 'account_key'."
  }
}

variable "collect_storage_logs" {
  description = "AP07 - provisions StorageBlobLogs via a diagnostic setting on blobServices/default -> Log Analytics. false = no ingestion (zero cost; assumes an external SIEM)."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "AP07/AP08 - resource ID of an EXISTING Log Analytics/Sentinel to point the blob diagnostic setting (AP07) and/or the Automation Account diagnostic setting (AP08) at. If provided, the module does NOT create its own workspace (reuses the shared root variable with AP05)."
  type        = string
  default     = null
}

variable "sas_expiry_years" {
  description = "AP07 - lifetime (in years) of the leaked over-scoped account SAS; 10 by default to dramatize the 'long-lived SAS' lesson. Only used when leak_mode='sas'."
  type        = number
  default     = 10

  validation {
    condition     = var.sas_expiry_years > 0
    error_message = "sas_expiry_years must be greater than 0."
  }
}

# ------------------------------------------------------------------
# AP08 - Automation Account runbook -> RBAC escalation (Azure, ~zero cost, no VM).
# The Automation Account's system-assigned MI holds a role with
# roleAssignments/write ON THE RG; a low-priv with Automation Contributor
# launches a runbook that runs AS the MI and self-grants Owner of the RG.
# ------------------------------------------------------------------
variable "enable_ap08" {
  description = "AP08 - Automation Account with an over-privileged system-assigned MI (UAA/Owner on the RG) + low-priv attacker (Automation Contributor) -> runbook that runs as the MI -> self-grant of Owner of the RG (Azure, ~zero cost, no VM). Declarative (no seed); the gun is loaded but Terraform NEVER fires it."
  type        = bool
  default     = false
}

variable "runbook_mode" {
  description = "AP08 - which runbook is embedded: 'poc_escalation' (default; loaded gun: Connect-AzAccount -Identity + New-AzRoleAssignment granting Owner of the RG to the attacker -> immediate demo) | 'benign_probe' (only probes the MI's identity/power: Connect-AzAccount -Identity + Get-AzAccessToken + Get-AzRoleAssignment; the student writes the escalation) | 'none' (no embedded runbook; pure misconfig). In NO mode does Terraform launch a job."
  type        = string
  default     = "poc_escalation"

  validation {
    condition     = contains(["poc_escalation", "benign_probe", "none"], var.runbook_mode)
    error_message = "runbook_mode must be 'poc_escalation', 'benign_probe', or 'none'."
  }
}

variable "mi_role" {
  description = "AP08 - over-privileged built-in role of the Automation Account's MI ON THE RG: 'UserAccessAdministrator' (default; minimum-that-escalates: its ONLY power is roleAssignments/write -> sharp lesson 'even just UAA on an Automation MI = game over') | 'Owner' (more realistic). Contributor is EXCLUDED: it does NOT include roleAssignments/write (that lane is AP02's via accessPolicies/write), so it does not enable the RBAC escalation."
  type        = string
  default     = "UserAccessAdministrator"

  validation {
    condition     = contains(["UserAccessAdministrator", "Owner"], var.mi_role)
    error_message = "mi_role must be 'UserAccessAdministrator' or 'Owner' (Contributor does not include roleAssignments/write and does not escalate)."
  }
}

variable "collect_automation_logs" {
  description = "AP08 - provisions JobLogs + JobStreams via a diagnostic setting on the Automation Account -> Log Analytics (AzureDiagnostics). false = no ingestion (zero cost; assumes an external SIEM). PROPERTY: these categories are NOT active by default -> without this setting the runbook EXECUTION does NOT exist in any SIEM (the management plane DOES flow through AzureActivity)."
  type        = bool
  default     = true
}
