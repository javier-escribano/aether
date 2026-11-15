# ------------------------------------------------------------------
# Outputs del modulo hybrid-ad.
# Patron condicional de AP02: null cuando enable_ap05 = false.
# caelum.ps1 consume ap05_resource_group / ap05_dc_vm_name /
# ap05_dc_admin_password / ap05_domain_* / ap05_ca_name /
# ap05_esc1_template_name para el run-command del seed en deploy.
# ------------------------------------------------------------------
output "ap05_resource_group" {
  description = "Resource group de AP05 (null si AP05 desactivado)."
  value       = var.enable_ap05 ? azurerm_resource_group.ap05[0].name : null
}

output "ap05_dc_vm_name" {
  description = "Nombre de la VM del DC+CA (null si AP05 desactivado). caelum.ps1 lo usa como centinela y para el run-command."
  value       = var.enable_ap05 ? azurerm_windows_virtual_machine.dc[0].name : null
}

output "ap05_dc_public_ip" {
  description = "IP publica del DC (RDP solo desde admin_source_cidr; null si AP05 desactivado)."
  value       = var.enable_ap05 ? azurerm_public_ip.ap05[0].ip_address : null
}

output "ap05_domain_fqdn" {
  description = "FQDN del bosque de usar-y-tirar (null si AP05 desactivado)."
  value       = var.enable_ap05 ? var.domain_fqdn : null
}

output "ap05_domain_netbios" {
  description = "NetBIOS del dominio (null si AP05 desactivado)."
  value       = var.enable_ap05 ? var.domain_netbios : null
}

output "ap05_ca_name" {
  description = "Common Name de la Enterprise Root CA (null si AP05 desactivado)."
  value       = var.enable_ap05 ? var.ca_common_name : null
}

output "ap05_esc1_template_name" {
  description = "Nombre de la plantilla vulnerable ESC1 (debe coincidir con las detecciones; null si AP05 desactivado)."
  value       = var.enable_ap05 ? var.esc1_template_name : null
}

output "ap05_lowpriv_user_name" {
  description = "sAMAccountName del usuario low-priv (null si AP05 desactivado)."
  value       = var.enable_ap05 ? var.lowpriv_user_name : null
}

output "ap05_lowpriv_upn" {
  description = "UPN del usuario low-priv = credencial de arranque del atacante (null si AP05 desactivado)."
  value       = var.enable_ap05 ? local.lowpriv_upn : null
}

output "ap05_law_name" {
  description = "Nombre del Log Analytics workspace propio (null si AP05 desactivado, telemetria off, o workspace externo)."
  value       = local.law_name
}

output "ap05_law_id" {
  description = "Resource ID del workspace de telemetria (propio o externo; null si telemetria off)."
  value       = local.law_id
}

# Pista no sensible (temario CRTO/CRTE). No revela secretos; orienta la ruta
# ESC1 y recuerda el coste/destroy.
output "ap05_attacker_hint" {
  description = "Pista didactica de AP05 (null si AP05 desactivado)."
  value = var.enable_ap05 ? join("", [
    "RDP al DC ", try(azurerm_public_ip.ap05[0].ip_address, "<ip>"), " como el usuario low-priv ", local.lowpriv_upn,
    " y ejecuta Certify.exe/Rubeus.exe (o certipy si abres los puertos AD a tu CIDR): ",
    "Certify.exe find /vulnerable -> solicita la plantilla ", var.esc1_template_name,
    " con SAN=UPN de un Domain Admin en la CA ", var.ca_common_name,
    " -> autentica por PKINIT -> TGT de DA -> DCSync. ",
    "OJO COSTE: VM Windows always-on; `./caelum.ps1 destroy` (o enable_ap05=false) al terminar.",
  ]) : null
}

# ---- Secretos (sensitive) ----
output "ap05_dc_admin_password" {
  description = "Password del built-in Administrator del dominio (= EA). Aterriza en el ESTADO: trata el estado como sensible."
  value       = local.dc_admin_password
  sensitive   = true
}

output "ap05_dsrm_password" {
  description = "Password DSRM (SafeMode) del DC."
  value       = var.enable_ap05 ? random_password.dsrm[0].result : null
  sensitive   = true
}

output "ap05_lowpriv_password" {
  description = "Password del usuario low-priv (credencial de arranque del atacante)."
  value       = var.enable_ap05 ? random_password.lowpriv[0].result : null
  sensitive   = true
}

# ==================================================================
# AP06 - Entra Connect / Seamless SSO (null si enable_ap06 = false).
# Ningun output ap05_* de arriba cambia: ap05_dc_vm_name sigue devolviendo
# null cuando enable_ap05=false AUNQUE la VM compartida exista por AP06, de
# modo que el centinela AP05 de caelum.ps1/verify.ps1 NO se envenena. AP06
# usa su PROPIO centinela ap06_dc_vm_name.
# ==================================================================
output "ap06_dc_vm_name" {
  description = "Nombre de la VM del DC compartido visto desde AP06 (null si AP06 desactivado). CENTINELA de caelum.ps1/verify.ps1 (NO reusa ap05_dc_vm_name)."
  value       = var.enable_ap06 ? azurerm_windows_virtual_machine.dc[0].name : null
}

output "ap06_resource_group" {
  description = "Resource group del DC compartido (null si AP06 desactivado)."
  value       = var.enable_ap06 ? azurerm_resource_group.ap05[0].name : null
}

output "ap06_dc_public_ip" {
  description = "IP publica del DC (null si AP06 desactivado)."
  value       = var.enable_ap06 ? azurerm_public_ip.ap05[0].ip_address : null
}

output "ap06_domain_fqdn" {
  description = "FQDN del bosque (null si AP06 desactivado)."
  value       = var.enable_ap06 ? var.domain_fqdn : null
}

output "ap06_domain_netbios" {
  description = "NetBIOS del dominio (null si AP06 desactivado)."
  value       = var.enable_ap06 ? var.domain_netbios : null
}

output "ap06_sso_account" {
  description = "Cuenta de maquina de Seamless SSO (AZUREADSSOACC$; null si AP06 desactivado)."
  value       = var.enable_ap06 ? "${var.sso_account_name}$" : null
}

output "ap06_sso_spns" {
  description = "SPNs de Seamless SSO (null si AP06 desactivado)."
  value       = var.enable_ap06 ? var.sso_spns : null
}

output "ap06_sync_account" {
  description = "Cuenta de sincronizacion con derechos DCSync (null si AP06 desactivado)."
  value       = var.enable_ap06 ? var.sync_account_name : null
}

output "ap06_sso_mode" {
  description = "Modo de siembra AP06 (null si AP06 desactivado)."
  value       = var.enable_ap06 ? var.sso_mode : null
}

output "ap06_law_name" {
  description = "Nombre del Log Analytics workspace compartido visto desde AP06 (null si AP06 off, telemetria off o workspace externo)."
  value       = var.enable_ap06 ? local.law_name : null
}

# Pista no sensible (temario CARTE/CRTE). No revela secretos; orienta el
# puente on-prem->cloud y recuerda el coste/destroy.
output "ap06_attacker_hint" {
  description = "Pista didactica de AP06 (null si AP06 desactivado)."
  value = var.enable_ap06 ? join("", [
    "AP06 bridge on-prem->cloud. Partes de la credencial de sync '", var.sync_account_name,
    "' (sembrada con DCSync). 1) DCSync -> extrae las claves Kerberos de ", var.sso_account_name, "$ ",
    "(T1003.006). 2) Forja un SILVER TICKET para ", var.sso_spns[0],
    " suplantando a cualquier usuario sincronizado (T1558.001). 3) Autentica a la NUBE como ese usuario SIN su password (T1550). ",
    "La clave de ", var.sso_account_name, "$ NUNCA rota por defecto -> persistencia eterna. ",
    "Arregla in-place: seed-ap06.ps1 -Remediate (rota la clave 2x + quita DCSync + deshabilita sync). ",
    "OJO COSTE: reusa el DC de AP05; si AP05 esta off, factura una VM. `./caelum.ps1 destroy` (o ambas flags false) al terminar.",
  ]) : null
}

# ---- Secretos (sensitive; aterrizan en el ESTADO) ----
output "ap06_dc_admin_password" {
  description = "Password del Administrator de dominio (= EA) visto desde AP06. OBLIGATORIO para el seed cuando AP05 esta off (ap05_dc_admin_password devolveria null por su guard). Aterriza en el ESTADO."
  value       = var.enable_ap06 ? local.dc_admin_password : null
  sensitive   = true
}

output "ap06_sso_password" {
  description = "Password FIJA de AZUREADSSOACC$ (permite derivar su clave RC4 = MD4(UTF16LE(pwd)) para el forge en modo silver_ticket). Aterriza en el ESTADO."
  value       = var.enable_ap06 ? random_password.ap06_sso[0].result : null
  sensitive   = true
}

output "ap06_sync_password" {
  description = "Password de la cuenta de sincronizacion (credencial de arranque del atacante de AP06). Aterriza en el ESTADO."
  value       = var.enable_ap06 ? random_password.ap06_sync[0].result : null
  sensitive   = true
}
