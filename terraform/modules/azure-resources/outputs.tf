# ------------------------------------------------------------------
# Outputs of the azure-resources module.
# AP01 conditional pattern: null when the flag is disabled.
# ------------------------------------------------------------------
output "ap02_vm_name" {
  description = "Name of the aether-ap02-web pivot host (null if AP02 is disabled)."
  value       = var.enable_ap02 ? azurerm_linux_virtual_machine.web[0].name : null
}

output "ap02_vm_public_ip" {
  description = "SSH public IP of the aether-ap02-web pivot host (null if AP02 is disabled)."
  value       = var.enable_ap02 ? azurerm_public_ip.ap02[0].ip_address : null
}

output "ap02_key_vault_name" {
  description = "Name of the Key Vault holding the loot secret (null if AP02 is disabled)."
  value       = var.enable_ap02 ? azurerm_key_vault.ap02[0].name : null
}

output "ap02_storage_account" {
  description = "Target storage account of the lateral movement (null if AP02 is disabled)."
  value       = var.enable_ap02 ? azurerm_storage_account.loot[0].name : null
}

# Hint for the attacker: IMDS token-theft primitive from the CARTP
# syllabus. Reveals no secrets; it orients step 3 of the path (T1552.005).
output "ap02_attacker_hint" {
  description = "Teaching hint for the first pivot of AP02 (null if AP02 is disabled)."
  value = var.enable_ap02 ? join("", [
    "SSH to ", azurerm_public_ip.ap02[0].ip_address, " as ", local.admin_username,
    " and steal the MI token: ",
    "curl -s -H 'Metadata: true' ",
    "'http://169.254.169.254/metadata/identity/oauth2/token",
    "?api-version=2018-02-01&resource=https://vault.azure.net'",
    " | then 'az keyvault set-policy' on ", azurerm_key_vault.ap02[0].name,
  ]) : null
}

# ==================================================================
# AP07 - Public storage / SAS leak. Outputs = ONLY non-secret pointers;
# all null if enable_ap07=false. The SAS/key is NEVER exposed here
# (it lives only in the tfstate, sensitive).
# ==================================================================
output "ap07_resource_group" {
  description = "AP07 resource group (null if AP07 is disabled)."
  value       = var.enable_ap07 ? azurerm_resource_group.ap07[0].name : null
}

output "ap07_storage_account" {
  description = "Name of the vulnerable AP07 storage account (null if AP07 is disabled). Sentinel for the AP07 block in verify.ps1."
  value       = var.enable_ap07 ? azurerm_storage_account.ap07[0].name : null
}

output "ap07_public_container_url" {
  description = "URL of the AP07 'public' public container (append ?restype=container&comp=list for anonymous enumeration T1619). Null if AP07 disabled."
  value       = var.enable_ap07 ? "https://${azurerm_storage_account.ap07[0].primary_blob_host}/public" : null
}

output "ap07_leaked_config_url" {
  description = "Anonymous URL of the leaked blob backup-config.json (NOT a secret; the secret is INSIDE). Null if AP07 disabled."
  value       = var.enable_ap07 ? "https://${azurerm_storage_account.ap07[0].primary_blob_host}/public/backup-config.json" : null
}

output "ap07_private_container" {
  description = "Name of the private container with the crown jewel (customers.csv). Null if AP07 disabled."
  value       = var.enable_ap07 ? azurerm_storage_container.ap07_sensitive[0].name : null
}

output "ap07_law_name" {
  description = "Name of the AP07 Log Analytics workspace (null if telemetry off or external workspace)."
  value       = local.ap07_law_name
}

# Teaching hint: anonymous enumeration -> download -> pivot. NEVER includes
# the token/key; only the T1619 -> T1552.001 -> T1530 chain.
output "ap07_attacker_hint" {
  description = "Teaching hint for the AP07 chain (null if AP07 is disabled)."
  value = var.enable_ap07 ? join("", [
    "Anonymous enum (T1619): curl -s 'https://", azurerm_storage_account.ap07[0].primary_blob_host,
    "/public?restype=container&comp=list'",
    "  ->  download /public/backup-config.json (T1552.001)",
    "  ->  extract the leaked credential and read /sensitive-data/customers.csv (T1530).",
  ]) : null
}

# ==================================================================
# AP08 - Automation Account runbook -> RBAC escalation. Outputs = POSTURE
# pointers (they do not reveal the runtime escalation, which the student fires);
# all null if enable_ap08=false. The attacker password lands in the tfstate
# (sensitive) and is ONLY exposed via the sensitive ap08_attacker_password output.
# ==================================================================
output "ap08_resource_group" {
  description = "AP08 resource group (null if AP08 is disabled). enable_ap08=false destroys it and with it every RG-scoped runtime role assignment."
  value       = var.enable_ap08 ? azurerm_resource_group.ap08[0].name : null
}

output "ap08_automation_account" {
  description = "Name of the vulnerable AP08 Automation Account (null if AP08 disabled). Sentinel for the AP08 block in verify.ps1."
  value       = var.enable_ap08 ? azurerm_automation_account.ap08[0].name : null
}

output "ap08_mi_principal_id" {
  description = "Object ID (principal) of the Automation Account's system-assigned MI = the effective ACTOR of the escalation. Detection pivot: a roleAssignments/write with Caller == this id is the golden signal. Null if AP08 disabled."
  value       = var.enable_ap08 ? azurerm_automation_account.ap08[0].identity[0].principal_id : null
}

output "ap08_mi_role" {
  description = "Over-privileged built-in role the MI holds ON THE AP08 RG (includes roleAssignments/write). Null if AP08 disabled."
  value       = var.enable_ap08 ? local.ap08_mi_role_name : null
}

output "ap08_runbook_name" {
  description = "Name of the embedded runbook (decoy aether-ap08-maintenance). Null if AP08 disabled or runbook_mode='none' (pure misconfig)."
  value       = local.ap08_runbook_name
}

output "ap08_attacker_upn" {
  description = "UPN of the low-priv attacker (Automation Contributor on the RG) = bootstrap credential to fire the runbook. Null if AP08 disabled."
  value       = var.enable_ap08 ? azuread_user.ap08_attacker[0].user_principal_name : null
}

output "ap08_attacker_password" {
  description = "Password of the AP08 low-priv attacker (bootstrap credential). Lands in the tfstate (sensitive)."
  value       = var.enable_ap08 ? random_password.ap08_attacker[0].result : null
  sensitive   = true
}

output "ap08_law_name" {
  description = "Name of the AP08 Log Analytics workspace (null if telemetry off or external workspace)."
  value       = local.ap08_law_name
}

# Teaching hint: drive the Automation Account's MI to self-grant Owner.
# NEVER includes the password; only the T1651 -> T1098.003 -> T1078.004 chain.
output "ap08_attacker_hint" {
  description = "Teaching hint for the AP08 chain (null if AP08 is disabled)."
  value = var.enable_ap08 ? join("", [
    "Authenticate as the low-priv ", azuread_user.ap08_attacker[0].user_principal_name,
    " (only Automation Contributor on the RG). Launch the Automation Account's runbook ",
    azurerm_automation_account.ap08[0].name, " (T1651): ",
    "Start-AzAutomationRunbook -AutomationAccountName ", azurerm_automation_account.ap08[0].name,
    " -ResourceGroupName ", azurerm_resource_group.ap08[0].name,
    local.ap08_runbook_name != null ? " -Name ${local.ap08_runbook_name}" : " -Name <author your own>",
    ". The job runs AS the MI (", local.ap08_mi_role_name, " on the RG) -> New-AzRoleAssignment ",
    "grants you Owner of the RG (T1098.003 -> T1078.004). Scope = the RG (reset-safe).",
  ]) : null
}
