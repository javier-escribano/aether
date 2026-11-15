# ------------------------------------------------------------------
# Caelum Range — orquestación de módulos
# ------------------------------------------------------------------
# Patrón: un módulo por DOMINIO (identidad / recursos Azure / híbrido).
# Las vulnerabilidades son FEATURE FLAGS dentro del módulo que corresponda,
# no módulos sueltos. Así `reset` = poner el flag a false y re-aplicar.
# ------------------------------------------------------------------

module "entra_identity" {
  source = "./modules/entra-identity"

  lab_prefix    = var.lab_prefix
  tenant_domain = var.tenant_domain
  user_count    = var.user_count

  # Rutas que viven en la capa de identidad
  enable_ap01 = var.enable_ap01
  enable_ap03 = var.enable_ap03
  enable_ap04 = var.enable_ap04
}

# ------------------------------------------------------------------
# Capa de recursos Azure (AP02 + AP07 + AP08).
#   AP02 factura cómputo (VM) → `destroy` al terminar.
#   AP07 es coste ~0 (storage + unos KB de blobs + ingesta mínima), SIN VM.
#   AP08 es coste ~0 (Automation Account + runtime gratuito de job), SIN VM.
# ------------------------------------------------------------------
module "azure_resources" {
  source = "./modules/azure-resources"

  lab_prefix = var.lab_prefix
  location   = var.location
  # tenant_domain: lo usa AP08 para el UPN del azuread_user atacante (Approach A).
  tenant_domain = var.tenant_domain

  # Rutas que viven en la capa de recursos Azure
  enable_ap02 = var.enable_ap02

  # AP07 — Public storage / SAS leak (coste ~0, sin VM)
  enable_ap07          = var.enable_ap07
  leak_mode            = var.leak_mode
  collect_storage_logs = var.collect_storage_logs

  # AP08 — Automation Account runbook → escalada RBAC (coste ~0, sin VM)
  enable_ap08             = var.enable_ap08
  runbook_mode            = var.runbook_mode
  mi_role                 = var.mi_role
  collect_automation_logs = var.collect_automation_logs

  # LAW compartido con AP05: si se da, el módulo no crea workspace propio
  # (lo reutilizan el diagnostic setting de AP07 y el de AP08).
  existing_log_analytics_workspace_id = var.existing_log_analytics_workspace_id
}

# ------------------------------------------------------------------
# Capa híbrida (AP05 — AD CS ESC1; AP06 — Entra Connect / Seamless SSO).
# OJO: factura cómputo (DC Windows always-on, el AP más caro). AP05 y AP06
# COMPARTEN el mismo DC (local.need_dc): si ambas flags off → count=0 →
# destruye la VM entera (reset + coste→0); si una está on, el DC sirve a ambas.
# ------------------------------------------------------------------
module "hybrid_ad" {
  source = "./modules/hybrid-ad"

  lab_prefix = var.lab_prefix
  location   = var.location

  # AP05 — AD CS ESC1 (híbrido on-prem)
  enable_ap05                         = var.enable_ap05
  dc_admin_password                   = var.dc_admin_password
  admin_source_cidr                   = var.admin_source_cidr
  domain_fqdn                         = var.domain_fqdn
  vm_size                             = var.vm_size
  collect_security_events             = var.collect_security_events
  existing_log_analytics_workspace_id = var.existing_log_analytics_workspace_id

  # AP06 — Entra Connect / Seamless SSO (reusa el DC de AP05 vía need_dc).
  # domain_fqdn/domain_netbios ya se heredan (domain_netbios usa el default
  # 'CAELUM' del módulo, igual que AP05).
  enable_ap06       = var.enable_ap06
  sso_mode          = var.sso_mode
  sso_account_name  = var.sso_account_name
  sync_account_name = var.sync_account_name
  sso_spns          = var.sso_spns
}
