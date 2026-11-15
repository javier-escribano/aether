output "lab_users" {
  description = "UPNs of the dummy users created."
  value       = module.entra_identity.user_principal_names
}

output "ap01_app_id" {
  description = "Client ID of the AP01 vulnerable app (null if AP01 is disabled)."
  value       = module.entra_identity.ap01_app_id
}

output "ap01_consent_url" {
  description = "Consent URL of the vulnerable app — the student observes the illicit consent flow."
  value       = module.entra_identity.ap01_consent_url
}

# --- AP02 (null if enable_ap02 = false) ---
output "ap02_vm_public_ip" {
  description = "SSH public IP of the azrange-ap02-web pivot host."
  value       = module.azure_resources.ap02_vm_public_ip
}

output "ap02_key_vault_name" {
  description = "Name of the Key Vault holding the loot secret."
  value       = module.azure_resources.ap02_key_vault_name
}

output "ap02_storage_account" {
  description = "Storage account targeted by the lateral movement."
  value       = module.azure_resources.ap02_storage_account
}

output "ap02_attacker_hint" {
  description = "Teaching hint for AP02's first pivot (token theft via IMDS)."
  value       = module.azure_resources.ap02_attacker_hint
}

# --- AP03 (null if enable_ap03 = false) ---
output "ap03_group_object_id" {
  description = "Object ID of AP03's role-assignable group."
  value       = module.entra_identity.ap03_group_object_id
}

output "ap03_target_role" {
  description = "Directory role carried by the AP03 group (the escalation loot)."
  value       = module.entra_identity.ap03_target_role
}

output "ap03_attacker_hint" {
  description = "Teaching hint for AP03's first step (self-add as owner)."
  value       = module.entra_identity.ap03_attacker_hint
}

# --- AP04 (null if enable_ap04 = false) ---
output "ap04_app_id" {
  description = "Client ID of AP04's vulnerable app registration (null if AP04 disabled)."
  value       = module.entra_identity.ap04_app_id
}

output "ap04_sp_object_id" {
  description = "Object ID of AP04's service principal (principal of the Graph app_role_assignment)."
  value       = module.entra_identity.ap04_sp_object_id
}

output "ap04_graph_app_role" {
  description = "Microsoft Graph app role carried by AP04's SP (the escalation loot)."
  value       = module.entra_identity.ap04_graph_app_role
}

output "ap04_attacker_hint" {
  description = "Teaching hint for AP04's first step (owner adds a credential to the app registration)."
  value       = module.entra_identity.ap04_attacker_hint
}

# --- AP05 (null if enable_ap05 = false) ---
output "ap05_resource_group" {
  description = "AP05 resource group (consumed by azrange.ps1 for the seed run-command)."
  value       = module.hybrid_ad.ap05_resource_group
}

output "ap05_dc_vm_name" {
  description = "Name of the DC+CA VM (AP05 sentinel; consumed by azrange.ps1)."
  value       = module.hybrid_ad.ap05_dc_vm_name
}

output "ap05_dc_public_ip" {
  description = "DC public IP (RDP only from admin_source_cidr)."
  value       = module.hybrid_ad.ap05_dc_public_ip
}

output "ap05_domain_fqdn" {
  description = "FQDN of AP05's throwaway forest."
  value       = module.hybrid_ad.ap05_domain_fqdn
}

output "ap05_domain_netbios" {
  description = "NetBIOS of AP05's domain (consumed by azrange.ps1 to qualify the EA credential)."
  value       = module.hybrid_ad.ap05_domain_netbios
}

output "ap05_ca_name" {
  description = "Common Name of AP05's Enterprise Root CA."
  value       = module.hybrid_ad.ap05_ca_name
}

output "ap05_esc1_template_name" {
  description = "Name of the vulnerable ESC1 template (matches the detections)."
  value       = module.hybrid_ad.ap05_esc1_template_name
}

output "ap05_lowpriv_upn" {
  description = "UPN of the low-priv user = AP05 attacker's starting credential."
  value       = module.hybrid_ad.ap05_lowpriv_upn
}

output "ap05_attacker_hint" {
  description = "Teaching hint for AP05 (ESC1 path + cost/destroy warning)."
  value       = module.hybrid_ad.ap05_attacker_hint
}

output "ap05_law_name" {
  description = "Name of AP05's Log Analytics workspace (null if telemetry off or external workspace)."
  value       = module.hybrid_ad.ap05_law_name
}

output "ap05_dc_admin_password" {
  description = "AP05 domain Administrator password (= EA)."
  value       = module.hybrid_ad.ap05_dc_admin_password
  sensitive   = true
}

output "ap05_lowpriv_password" {
  description = "AP05 low-priv user password (attacker's starting credential)."
  value       = module.hybrid_ad.ap05_lowpriv_password
  sensitive   = true
}

# --- AP06 (null if enable_ap06 = false) ---
# Entra Connect / Seamless SSO over the SAME DC as AP05 (shared substrate).
# OWN sentinel ap06_dc_vm_name (does NOT reuse AP05's): azrange.ps1/verify.ps1
# consume it for AP06's seed/health-check without poisoning AP05's.
output "ap06_dc_vm_name" {
  description = "Name of the shared DC VM as seen from AP06 (AP06 sentinel; consumed by azrange.ps1/verify.ps1)."
  value       = module.hybrid_ad.ap06_dc_vm_name
}

output "ap06_resource_group" {
  description = "Resource group of the shared DC as seen from AP06 (consumed by azrange.ps1 for the seed run-command)."
  value       = module.hybrid_ad.ap06_resource_group
}

output "ap06_dc_public_ip" {
  description = "DC public IP (RDP only from admin_source_cidr)."
  value       = module.hybrid_ad.ap06_dc_public_ip
}

output "ap06_domain_fqdn" {
  description = "FQDN of AP06's throwaway forest (consumed by azrange.ps1 for the seed)."
  value       = module.hybrid_ad.ap06_domain_fqdn
}

output "ap06_domain_netbios" {
  description = "NetBIOS of AP06's domain (consumed by azrange.ps1 to qualify the EA credential)."
  value       = module.hybrid_ad.ap06_domain_netbios
}

output "ap06_sso_account" {
  description = "Seamless SSO machine account (AZUREADSSOACC$)."
  value       = module.hybrid_ad.ap06_sso_account
}

output "ap06_sso_spns" {
  description = "Seamless SSO SPNs (the 1st validates Entra and is hunted by the detections)."
  value       = module.hybrid_ad.ap06_sso_spns
}

output "ap06_sync_account" {
  description = "Entra Connect sync account with DCSync rights."
  value       = module.hybrid_ad.ap06_sync_account
}

output "ap06_sso_mode" {
  description = "AP06 seeding mode (both / silver_ticket / sync_dcsync); consumed by azrange.ps1/verify.ps1."
  value       = module.hybrid_ad.ap06_sso_mode
}

output "ap06_law_name" {
  description = "Name of the shared Log Analytics workspace as seen from AP06 (null if telemetry off or external workspace)."
  value       = module.hybrid_ad.ap06_law_name
}

output "ap06_attacker_hint" {
  description = "Teaching hint for AP06 (on-prem→cloud bridge: sync cred → DCSync → silver ticket → cloud; cost/destroy warning)."
  value       = module.hybrid_ad.ap06_attacker_hint
}

output "ap06_dc_admin_password" {
  description = "Domain Administrator password as seen from AP06 (= EA). REQUIRED for the seed in AP06-only mode (enable_ap05=false). Lands in STATE (sensitive)."
  value       = module.hybrid_ad.ap06_dc_admin_password
  sensitive   = true
}

output "ap06_sso_password" {
  description = "FIXED password of AZUREADSSOACC$ (allows deriving its RC4 key to forge the silver ticket). Lands in STATE (sensitive)."
  value       = module.hybrid_ad.ap06_sso_password
  sensitive   = true
}

output "ap06_sync_password" {
  description = "Password of AP06's sync account (attacker's starting credential). Lands in STATE (sensitive)."
  value       = module.hybrid_ad.ap06_sync_password
  sensitive   = true
}

# --- AP07 (null if enable_ap07 = false) ---
# NON-secret pointers. The leaked SAS/key is NEVER exposed (lives only in the tfstate).
output "ap07_resource_group" {
  description = "AP07 resource group."
  value       = module.azure_resources.ap07_resource_group
}

output "ap07_storage_account" {
  description = "Name of AP07's vulnerable storage account (sentinel of the AP07 block in verify.ps1)."
  value       = module.azure_resources.ap07_storage_account
}

output "ap07_public_container_url" {
  description = "URL of the public 'public' container (append ?restype=container&comp=list for the anonymous T1619 enumeration)."
  value       = module.azure_resources.ap07_public_container_url
}

output "ap07_leaked_config_url" {
  description = "Anonymous URL of the leaked backup-config.json blob (NOT a secret; the credential is INSIDE)."
  value       = module.azure_resources.ap07_leaked_config_url
}

output "ap07_private_container" {
  description = "Name of the private container with the crown jewel (customers.csv)."
  value       = module.azure_resources.ap07_private_container
}

output "ap07_law_name" {
  description = "Name of AP07's Log Analytics workspace (null if telemetry off or external workspace)."
  value       = module.azure_resources.ap07_law_name
}

output "ap07_attacker_hint" {
  description = "Teaching hint for the AP07 chain (anonymous enum → download → SAS/key pivot)."
  value       = module.azure_resources.ap07_attacker_hint
}

# --- AP08 (null if enable_ap08 = false) ---
# POSTURE pointers. The attacker's password lands in the tfstate (sensitive)
# and is ONLY exposed via the sensitive output ap08_attacker_password.
output "ap08_resource_group" {
  description = "AP08 resource group (enable_ap08=false destroys it, and with it every RG-scoped runtime role assignment)."
  value       = module.azure_resources.ap08_resource_group
}

output "ap08_automation_account" {
  description = "Name of AP08's vulnerable Automation Account (sentinel of the AP08 block in verify.ps1)."
  value       = module.azure_resources.ap08_automation_account
}

output "ap08_mi_principal_id" {
  description = "Object ID of the Automation Account's system-assigned MI (= escalation actor). Detection pivot: roleAssignments/write with Caller == this id = golden signal."
  value       = module.azure_resources.ap08_mi_principal_id
}

output "ap08_mi_role" {
  description = "Over-priv role the MI holds over AP08's RG (User Access Administrator or Owner; both include roleAssignments/write)."
  value       = module.azure_resources.ap08_mi_role
}

output "ap08_runbook_name" {
  description = "Name of the embedded runbook (decoy azrange-ap08-maintenance). Null if runbook_mode='none' (pure misconfig)."
  value       = module.azure_resources.ap08_runbook_name
}

output "ap08_attacker_upn" {
  description = "UPN of the low-priv attacker (Automation Contributor) = starting credential to fire the runbook."
  value       = module.azure_resources.ap08_attacker_upn
}

output "ap08_attacker_password" {
  description = "AP08 low-priv attacker password (starting credential). Lands in STATE (sensitive)."
  value       = module.azure_resources.ap08_attacker_password
  sensitive   = true
}

output "ap08_law_name" {
  description = "Name of AP08's Log Analytics workspace (null if telemetry off or external workspace)."
  value       = module.azure_resources.ap08_law_name
}

output "ap08_attacker_hint" {
  description = "Teaching hint for the AP08 chain (authenticate as low-priv → start runbook → the job runs as the MI → self-grant Owner of the RG)."
  value       = module.azure_resources.ap08_attacker_hint
}
