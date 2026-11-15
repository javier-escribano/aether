# ------------------------------------------------------------------
# Variables for the hybrid-ad module (HYBRID layer: AD DS + AD CS on-prem
# on a Windows VM in Azure IaaS). AP05 = AD CS ESC1.
# Typed and minimal; the module inherits context from the root (main.tf).
# ------------------------------------------------------------------
variable "enable_ap05" {
  description = "AP05 - AD CS ESC1 on a hybrid DC. NOTE: BILLS COMPUTE (always-on Windows VM). enable_ap05=false -> count=0 -> destroys the VM (the cleanest reset of the range)."
  type        = bool
  default     = false
}

variable "lab_prefix" {
  description = "Prefix for naming the range objects (eases teardown)."
  type        = string
  default     = "azrange"
}

variable "location" {
  description = "Azure region for the DC VM (affects cost/latency). Same convention as azure-resources."
  type        = string
  default     = "westeurope"
}

variable "dc_admin_password" {
  description = "Password of the domain built-in Administrator (= the EA that seeds/remediates ESC1). Leave null -> random_password. NEVER a real or reused password."
  type        = string
  sensitive   = true
  default     = null
}

variable "domain_fqdn" {
  description = "FQDN of the throwaway forest (NEVER synchronize with the tenant via real Entra Connect: that is covered by AP06)."
  type        = string
  default     = "azrange.lab"
}

variable "domain_netbios" {
  description = "NetBIOS name of the domain. Used to qualify the EA credential (DOMAIN\\Administrator) in the seed and in the CA."
  type        = string
  default     = "AZRANGE"
}

variable "vm_size" {
  description = "Size of the DC+CA VM. Standard_B2ms by default (2 vCPU/8 GiB); Standard_B2s (4 GiB) as the floor. Constrained but sufficient for DC+ADCS."
  type        = string
  default     = "Standard_B2ms"
}

variable "vm_image_version" {
  description = "Windows Server 2022 image version. 'latest' for convenience; PIN a specific version if you want reproducibility against KB5014754 (a patch beyond Sep 2025 may break the Exploit leg)."
  type        = string
  default     = "latest"
}

variable "admin_source_cidr" {
  description = "Operator /32 CIDR for RDP/WinRM to the DC. NEVER 0.0.0.0/0 (it is a DC). If null, NO inbound rule is opened (Bastion/serial-console)."
  type        = string
  default     = null

  validation {
    condition     = var.admin_source_cidr == null || var.admin_source_cidr != "0.0.0.0/0"
    error_message = "admin_source_cidr cannot be 0.0.0.0/0: a DC is not exposed to the Internet. Use your /32 or leave null (Bastion/serial)."
  }
}

variable "lowpriv_user_name" {
  description = "sAMAccountName of the low-privilege user (attacker's starting credential; Domain Users only)."
  type        = string
  default     = "ap05user"
}

variable "ca_common_name" {
  description = "Common Name of the Enterprise Root CA."
  type        = string
  default     = "azrange-CA"
}

variable "esc1_template_name" {
  description = "Name (cn) of the vulnerable ESC1 template seeded by seed-ap05.ps1. Must match the detections (CertificateTemplate)."
  type        = string
  default     = "AzRangeAuthESC1"
}

variable "collect_security_events" {
  description = "Provisions the detection pipeline (AMA+DCR+Log Analytics) for end-to-end 'Detect'. false = no ingestion (zero cost; assumes an external SIEM). Unlike AP01-AP04, these on-prem events do NOT exist in any SIEM without this pipeline."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "Resource ID of an EXISTING Log Analytics/Sentinel to point the DCR at. If given, the module does NOT create its own workspace."
  type        = string
  default     = null
}

variable "auto_shutdown_time" {
  description = "Daily auto-shutdown time (HHmm, W. Europe Standard Time zone). Cost discipline (AP02 pattern). Deploy during the day so DCPromo is not cut off."
  type        = string
  default     = "2200"
}

variable "strong_cert_binding_mode" {
  description = "KB5014754 StrongCertificateBindingEnforcement in the KDC: 0=Disabled, 1=Compatibility (lab default, ESC1 exploitable), 2=Full Enforcement (rejects the forged SAN -> the real fix). The DSC deliberately sets it to 1."
  type        = number
  default     = 1
}

# ------------------------------------------------------------------
# AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$): 2nd hybrid path,
# CLOSES the catalog. On-prem -> cloud bridge. Shares the SAME DC as AP05
# via local.need_dc (main.tf): if enable_ap05 is already ON, AP06 does NOT add
# a VM; if AP05 is OFF, AP06 brings up the DC on its own (BILLS COMPUTE). The
# AD artifacts (AZUREADSSOACC$ + sync account with DCSync) are NOT azurerm
# resources: they are seeded by scripts/seed-ap06.ps1 (imperative, like the AP05 ESC1).
# ------------------------------------------------------------------
variable "enable_ap06" {
  description = "AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$) on the SAME hybrid DC as AP05 (shared substrate via need_dc). On-prem->cloud bridge. NOTE: BILLS COMPUTE if AP05 is not already active (reuses the VM if it is). enable_ap06=false + enable_ap05=false -> need_dc=false -> destroys the VM."
  type        = bool
  default     = false
}

variable "sso_mode" {
  description = "AP06 - Entra Connect/Seamless SSO artifacts to seed. 'silver_ticket' (only AZUREADSSOACC$ with a fixed/non-rotated key + SPNs; focus on forging the Seamless SSO TGS) | 'sync_dcsync' (only the MSOL_/Sync_ account with DCSync ACEs over the NC; focus on extracting the Entra Connect credential -> DCSync) | 'both' (both; enables the full chain sync->DCSync->AZUREADSSOACC$ keys->silver ticket->cloud)."
  type        = string
  default     = "both"

  validation {
    condition     = contains(["silver_ticket", "sync_dcsync", "both"], var.sso_mode)
    error_message = "sso_mode must be 'silver_ticket', 'sync_dcsync', or 'both'."
  }
}

variable "sso_account_name" {
  description = "AP06 - sAMAccountName (without the $ suffix) of the Seamless SSO machine account. Real: AZUREADSSOACC. Must match the detections."
  type        = string
  default     = "AZUREADSSOACC"
}

variable "sync_account_name" {
  description = "AP06 - sAMAccountName of the Entra Connect synchronization account with DCSync rights (analogous to MSOL_/Sync_)."
  type        = string
  default     = "Sync_AZRANGE"
}

variable "sso_spns" {
  description = "AP06 - SPNs of the Seamless SSO account. The first (HTTP/autologon.microsoftazuread-sso.com) is the one Entra validates and the one the detections hunt; the second (HTTP/aadg.windows.net.nsatc.net) completes the real footprint."
  type        = list(string)
  default     = ["HTTP/autologon.microsoftazuread-sso.com", "HTTP/aadg.windows.net.nsatc.net"]

  validation {
    condition     = length(var.sso_spns) > 0
    error_message = "sso_spns cannot be empty (ap06_attacker_hint indexes sso_spns[0])."
  }
}
