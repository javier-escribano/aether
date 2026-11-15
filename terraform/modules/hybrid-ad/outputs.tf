# ------------------------------------------------------------------
# Outputs of the hybrid-ad module.
# AP02 conditional pattern: null when enable_ap05 = false.
# azrange.ps1 consumes ap05_resource_group / ap05_dc_vm_name /
# ap05_dc_admin_password / ap05_domain_* / ap05_ca_name /
# ap05_esc1_template_name for the seed run-command at deploy.
# ------------------------------------------------------------------
output "ap05_resource_group" {
  description = "AP05 resource group (null if AP05 disabled)."
  value       = var.enable_ap05 ? azurerm_resource_group.ap05[0].name : null
}

output "ap05_dc_vm_name" {
  description = "Name of the DC+CA VM (null if AP05 disabled). azrange.ps1 uses it as a sentinel and for the run-command."
  value       = var.enable_ap05 ? azurerm_windows_virtual_machine.dc[0].name : null
}

output "ap05_dc_public_ip" {
  description = "Public IP of the DC (RDP only from admin_source_cidr; null if AP05 disabled)."
  value       = var.enable_ap05 ? azurerm_public_ip.ap05[0].ip_address : null
}

output "ap05_domain_fqdn" {
  description = "FQDN of the throwaway forest (null if AP05 disabled)."
  value       = var.enable_ap05 ? var.domain_fqdn : null
}

output "ap05_domain_netbios" {
  description = "Domain NetBIOS (null if AP05 disabled)."
  value       = var.enable_ap05 ? var.domain_netbios : null
}

output "ap05_ca_name" {
  description = "Common Name of the Enterprise Root CA (null if AP05 disabled)."
  value       = var.enable_ap05 ? var.ca_common_name : null
}

output "ap05_esc1_template_name" {
  description = "Name of the vulnerable ESC1 template (must match the detections; null if AP05 disabled)."
  value       = var.enable_ap05 ? var.esc1_template_name : null
}

output "ap05_lowpriv_user_name" {
  description = "sAMAccountName of the low-priv user (null if AP05 disabled)."
  value       = var.enable_ap05 ? var.lowpriv_user_name : null
}

output "ap05_lowpriv_upn" {
  description = "UPN of the low-priv user = attacker's starting credential (null if AP05 disabled)."
  value       = var.enable_ap05 ? local.lowpriv_upn : null
}

output "ap05_law_name" {
  description = "Name of the module's own Log Analytics workspace (null if AP05 disabled, telemetry off, or external workspace)."
  value       = local.law_name
}

output "ap05_law_id" {
  description = "Resource ID of the telemetry workspace (own or external; null if telemetry off)."
  value       = local.law_id
}

# Non-sensitive hint (CRTO/CRTE syllabus). Reveals no secrets; orients the
# ESC1 path and reminds of the cost/destroy.
output "ap05_attacker_hint" {
  description = "AP05 teaching hint (null if AP05 disabled)."
  value = var.enable_ap05 ? join("", [
    "RDP to the DC ", try(azurerm_public_ip.ap05[0].ip_address, "<ip>"), " as the low-priv user ", local.lowpriv_upn,
    " and run Certify.exe/Rubeus.exe (or certipy if you open the AD ports to your CIDR): ",
    "Certify.exe find /vulnerable -> request the template ", var.esc1_template_name,
    " with SAN=UPN of a Domain Admin on the CA ", var.ca_common_name,
    " -> authenticate via PKINIT -> DA TGT -> DCSync. ",
    "COST NOTE: always-on Windows VM; `./azrange.ps1 destroy` (or enable_ap05=false) when you are done.",
  ]) : null
}

# ---- Secrets (sensitive) ----
output "ap05_dc_admin_password" {
  description = "Password of the domain built-in Administrator (= EA). Lands in STATE: treat state as sensitive."
  value       = local.dc_admin_password
  sensitive   = true
}

output "ap05_dsrm_password" {
  description = "DSRM (SafeMode) password of the DC."
  value       = var.enable_ap05 ? random_password.dsrm[0].result : null
  sensitive   = true
}

output "ap05_lowpriv_password" {
  description = "Password of the low-priv user (attacker's starting credential)."
  value       = var.enable_ap05 ? random_password.lowpriv[0].result : null
  sensitive   = true
}

# ==================================================================
# AP06 - Entra Connect / Seamless SSO (null if enable_ap06 = false).
# None of the ap05_* outputs above change: ap05_dc_vm_name still returns
# null when enable_ap05=false EVEN IF the shared VM exists because of AP06, so
# that the AP05 sentinel of azrange.ps1/verify.ps1 is NOT poisoned. AP06
# uses its OWN sentinel ap06_dc_vm_name.
# ==================================================================
output "ap06_dc_vm_name" {
  description = "Name of the shared DC VM as seen from AP06 (null if AP06 disabled). SENTINEL of azrange.ps1/verify.ps1 (does NOT reuse ap05_dc_vm_name)."
  value       = var.enable_ap06 ? azurerm_windows_virtual_machine.dc[0].name : null
}

output "ap06_resource_group" {
  description = "Resource group of the shared DC (null if AP06 disabled)."
  value       = var.enable_ap06 ? azurerm_resource_group.ap05[0].name : null
}

output "ap06_dc_public_ip" {
  description = "Public IP of the DC (null if AP06 disabled)."
  value       = var.enable_ap06 ? azurerm_public_ip.ap05[0].ip_address : null
}

output "ap06_domain_fqdn" {
  description = "FQDN of the forest (null if AP06 disabled)."
  value       = var.enable_ap06 ? var.domain_fqdn : null
}

output "ap06_domain_netbios" {
  description = "Domain NetBIOS (null if AP06 disabled)."
  value       = var.enable_ap06 ? var.domain_netbios : null
}

output "ap06_sso_account" {
  description = "Seamless SSO machine account (AZUREADSSOACC$; null if AP06 disabled)."
  value       = var.enable_ap06 ? "${var.sso_account_name}$" : null
}

output "ap06_sso_spns" {
  description = "Seamless SSO SPNs (null if AP06 disabled)."
  value       = var.enable_ap06 ? var.sso_spns : null
}

output "ap06_sync_account" {
  description = "Synchronization account with DCSync rights (null if AP06 disabled)."
  value       = var.enable_ap06 ? var.sync_account_name : null
}

output "ap06_sso_mode" {
  description = "AP06 seeding mode (null if AP06 disabled)."
  value       = var.enable_ap06 ? var.sso_mode : null
}

output "ap06_law_name" {
  description = "Name of the shared Log Analytics workspace as seen from AP06 (null if AP06 off, telemetry off, or external workspace)."
  value       = var.enable_ap06 ? local.law_name : null
}

# Non-sensitive hint (CARTE/CRTE syllabus). Reveals no secrets; orients the
# on-prem->cloud bridge and reminds of the cost/destroy.
output "ap06_attacker_hint" {
  description = "AP06 teaching hint (null if AP06 disabled)."
  value = var.enable_ap06 ? join("", [
    "AP06 bridge on-prem->cloud. You start from the sync credential '", var.sync_account_name,
    "' (seeded with DCSync). 1) DCSync -> extract the Kerberos keys of ", var.sso_account_name, "$ ",
    "(T1003.006). 2) Forge a SILVER TICKET for ", var.sso_spns[0],
    " impersonating any synchronized user (T1558.001). 3) Authenticate to the CLOUD as that user WITHOUT their password (T1550). ",
    "The key of ", var.sso_account_name, "$ NEVER rotates by default -> eternal persistence. ",
    "Remediate in-place: seed-ap06.ps1 -Remediate (rotates the key 2x + removes DCSync + disables sync). ",
    "COST NOTE: reuses the AP05 DC; if AP05 is off, it bills a VM. `./azrange.ps1 destroy` (or both flags false) when you are done.",
  ]) : null
}

# ---- Secrets (sensitive; land in STATE) ----
output "ap06_dc_admin_password" {
  description = "Password of the domain Administrator (= EA) as seen from AP06. MANDATORY for the seed when AP05 is off (ap05_dc_admin_password would return null due to its guard). Lands in STATE."
  value       = var.enable_ap06 ? local.dc_admin_password : null
  sensitive   = true
}

output "ap06_sso_password" {
  description = "FIXED password of AZUREADSSOACC$ (lets you derive its RC4 key = MD4(UTF16LE(pwd)) for the forge in silver_ticket mode). Lands in STATE."
  value       = var.enable_ap06 ? random_password.ap06_sso[0].result : null
  sensitive   = true
}

output "ap06_sync_password" {
  description = "Password of the synchronization account (attacker's starting credential for AP06). Lands in STATE."
  value       = var.enable_ap06 ? random_password.ap06_sync[0].result : null
  sensitive   = true
}
