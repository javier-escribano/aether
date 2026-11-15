# ------------------------------------------------------------------
# Azure Attack Range — module orchestration
# ------------------------------------------------------------------
# Pattern: one module per DOMAIN (identity / Azure resources / hybrid).
# Vulnerabilities are FEATURE FLAGS inside the module they belong to,
# not standalone modules. So `reset` = set the flag to false and re-apply.
# ------------------------------------------------------------------

module "entra_identity" {
  source = "./modules/entra-identity"

  lab_prefix    = var.lab_prefix
  tenant_domain = var.tenant_domain
  user_count    = var.user_count

  # Attack paths that live in the identity layer
  enable_ap01 = var.enable_ap01
  enable_ap03 = var.enable_ap03
  enable_ap04 = var.enable_ap04
}

# ------------------------------------------------------------------
# Azure resource layer (AP02 + AP07 + AP08).
#   AP02 bills compute (VM) → `destroy` when done.
#   AP07 is ~zero cost (storage + a few KB of blobs + minimal ingestion), NO VM.
#   AP08 is ~zero cost (Automation Account + free job runtime), NO VM.
# ------------------------------------------------------------------
module "azure_resources" {
  source = "./modules/azure-resources"

  lab_prefix = var.lab_prefix
  location   = var.location
  # tenant_domain: used by AP08 for the UPN of the attacker azuread_user (Approach A).
  tenant_domain = var.tenant_domain

  # Attack paths that live in the Azure resource layer
  enable_ap02 = var.enable_ap02

  # AP07 — Public storage / SAS leak (~zero cost, no VM)
  enable_ap07          = var.enable_ap07
  leak_mode            = var.leak_mode
  collect_storage_logs = var.collect_storage_logs

  # AP08 — Automation Account runbook → RBAC escalation (~zero cost, no VM)
  enable_ap08             = var.enable_ap08
  runbook_mode            = var.runbook_mode
  mi_role                 = var.mi_role
  collect_automation_logs = var.collect_automation_logs

  # LAW shared with AP05: if provided, the module does not create its own workspace
  # (reused by the AP07 and AP08 diagnostic settings).
  existing_log_analytics_workspace_id = var.existing_log_analytics_workspace_id
}

# ------------------------------------------------------------------
# Hybrid layer (AP05 — AD CS ESC1; AP06 — Entra Connect / Seamless SSO).
# NOTE: bills compute (always-on Windows DC, the most expensive AP). AP05 and AP06
# SHARE the same DC (local.need_dc): if both flags are off → count=0 →
# destroys the entire VM (reset + cost→0); if one is on, the DC serves both.
# ------------------------------------------------------------------
module "hybrid_ad" {
  source = "./modules/hybrid-ad"

  lab_prefix = var.lab_prefix
  location   = var.location

  # AP05 — AD CS ESC1 (hybrid on-prem)
  enable_ap05                         = var.enable_ap05
  dc_admin_password                   = var.dc_admin_password
  admin_source_cidr                   = var.admin_source_cidr
  domain_fqdn                         = var.domain_fqdn
  vm_size                             = var.vm_size
  collect_security_events             = var.collect_security_events
  existing_log_analytics_workspace_id = var.existing_log_analytics_workspace_id

  # AP06 — Entra Connect / Seamless SSO (reuses the AP05 DC via need_dc).
  # domain_fqdn/domain_netbios are already inherited (domain_netbios uses the module
  # default 'AZRANGE', same as AP05).
  enable_ap06       = var.enable_ap06
  sso_mode          = var.sso_mode
  sso_account_name  = var.sso_account_name
  sync_account_name = var.sync_account_name
  sso_spns          = var.sso_spns
}
