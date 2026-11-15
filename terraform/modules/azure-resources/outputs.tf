# ------------------------------------------------------------------
# Outputs del modulo azure-resources.
# Patron condicional de AP01: null cuando el flag esta desactivado.
# ------------------------------------------------------------------
output "ap02_vm_name" {
  description = "Nombre del host pivote caelum-ap02-web (null si AP02 esta desactivado)."
  value       = var.enable_ap02 ? azurerm_linux_virtual_machine.web[0].name : null
}

output "ap02_vm_public_ip" {
  description = "IP publica SSH del host pivote caelum-ap02-web (null si AP02 esta desactivado)."
  value       = var.enable_ap02 ? azurerm_public_ip.ap02[0].ip_address : null
}

output "ap02_key_vault_name" {
  description = "Nombre del Key Vault con el secreto botin (null si AP02 esta desactivado)."
  value       = var.enable_ap02 ? azurerm_key_vault.ap02[0].name : null
}

output "ap02_storage_account" {
  description = "Storage account objetivo del movimiento lateral (null si AP02 esta desactivado)."
  value       = var.enable_ap02 ? azurerm_storage_account.loot[0].name : null
}

# Pista para el atacante: primitiva de robo de token via IMDS del temario
# CARTP. No revela secretos; orienta el paso 3 de la ruta (T1552.005).
output "ap02_attacker_hint" {
  description = "Pista didactica del primer pivote de AP02 (null si AP02 esta desactivado)."
  value = var.enable_ap02 ? join("", [
    "SSH a ", azurerm_public_ip.ap02[0].ip_address, " como ", local.admin_username,
    " y roba el token de la MI: ",
    "curl -s -H 'Metadata: true' ",
    "'http://169.254.169.254/metadata/identity/oauth2/token",
    "?api-version=2018-02-01&resource=https://vault.azure.net'",
    " | luego 'az keyvault set-policy' sobre ", azurerm_key_vault.ap02[0].name,
  ]) : null
}

# ==================================================================
# AP07 - Public storage / SAS leak. Outputs = SOLO punteros NO-secreto;
# todos null si enable_ap07=false. La SAS/clave NUNCA se expone aqui
# (vive solo en el tfstate, sensible).
# ==================================================================
output "ap07_resource_group" {
  description = "Resource group de AP07 (null si AP07 esta desactivado)."
  value       = var.enable_ap07 ? azurerm_resource_group.ap07[0].name : null
}

output "ap07_storage_account" {
  description = "Nombre de la storage account vulnerable de AP07 (null si AP07 esta desactivado). Centinela del bloque AP07 en verify.ps1."
  value       = var.enable_ap07 ? azurerm_storage_account.ap07[0].name : null
}

output "ap07_public_container_url" {
  description = "URL del contenedor publico 'public' de AP07 (anade ?restype=container&comp=list para la enumeracion anonima T1619). Null si AP07 desactivado."
  value       = var.enable_ap07 ? "https://${azurerm_storage_account.ap07[0].primary_blob_host}/public" : null
}

output "ap07_leaked_config_url" {
  description = "URL anonima del blob filtrado backup-config.json (NO es secreto; el secreto esta DENTRO). Null si AP07 desactivado."
  value       = var.enable_ap07 ? "https://${azurerm_storage_account.ap07[0].primary_blob_host}/public/backup-config.json" : null
}

output "ap07_private_container" {
  description = "Nombre del contenedor privado con la joya (customers.csv). Null si AP07 desactivado."
  value       = var.enable_ap07 ? azurerm_storage_container.ap07_sensitive[0].name : null
}

output "ap07_law_name" {
  description = "Nombre del Log Analytics workspace de AP07 (null si telemetria off o workspace externo)."
  value       = local.ap07_law_name
}

# Pista didactica: enumeracion anonima -> descarga -> pivote. NUNCA incluye
# el token/clave; solo la cadena T1619 -> T1552.001 -> T1530.
output "ap07_attacker_hint" {
  description = "Pista didactica de la cadena de AP07 (null si AP07 esta desactivado)."
  value = var.enable_ap07 ? join("", [
    "Enum anonima (T1619): curl -s 'https://", azurerm_storage_account.ap07[0].primary_blob_host,
    "/public?restype=container&comp=list'",
    "  ->  descarga /public/backup-config.json (T1552.001)",
    "  ->  extrae la credencial filtrada y lee /sensitive-data/customers.csv (T1530).",
  ]) : null
}

# ==================================================================
# AP08 - Automation Account runbook -> escalada RBAC. Outputs = punteros de
# POSTURA (no revelan la escalada de runtime, que la dispara el alumno); todos
# null si enable_ap08=false. El password del atacante aterriza en el tfstate
# (sensible) y SOLO se expone via el output sensible ap08_attacker_password.
# ==================================================================
output "ap08_resource_group" {
  description = "Resource group de AP08 (null si AP08 esta desactivado). enable_ap08=false lo destruye y con el toda role assignment de runtime RG-scoped."
  value       = var.enable_ap08 ? azurerm_resource_group.ap08[0].name : null
}

output "ap08_automation_account" {
  description = "Nombre del Automation Account vulnerable de AP08 (null si AP08 desactivado). Centinela del bloque AP08 en verify.ps1."
  value       = var.enable_ap08 ? azurerm_automation_account.ap08[0].name : null
}

output "ap08_mi_principal_id" {
  description = "Object ID (principal) de la system-assigned MI del Automation Account = el ACTOR efectivo de la escalada. Pivote de deteccion: un roleAssignments/write con Caller == este id es la senal de oro. Null si AP08 desactivado."
  value       = var.enable_ap08 ? azurerm_automation_account.ap08[0].identity[0].principal_id : null
}

output "ap08_mi_role" {
  description = "Rol built-in over-priv que la MI ostenta SOBRE EL RG de AP08 (incluye roleAssignments/write). Null si AP08 desactivado."
  value       = var.enable_ap08 ? local.ap08_mi_role_name : null
}

output "ap08_runbook_name" {
  description = "Nombre del runbook incrustado (senuelo caelum-ap08-maintenance). Null si AP08 desactivado o runbook_mode='none' (misconfig pura)."
  value       = local.ap08_runbook_name
}

output "ap08_attacker_upn" {
  description = "UPN del atacante low-priv (Automation Contributor sobre el RG) = credencial de arranque para disparar el runbook. Null si AP08 desactivado."
  value       = var.enable_ap08 ? azuread_user.ap08_attacker[0].user_principal_name : null
}

output "ap08_attacker_password" {
  description = "Password del atacante low-priv de AP08 (credencial de arranque). Aterriza en el tfstate (sensible)."
  value       = var.enable_ap08 ? random_password.ap08_attacker[0].result : null
  sensitive   = true
}

output "ap08_law_name" {
  description = "Nombre del Log Analytics workspace de AP08 (null si telemetria off o workspace externo)."
  value       = local.ap08_law_name
}

# Pista didactica: conduce la MI del Automation Account para auto-concederte Owner.
# NUNCA incluye el password; solo la cadena T1651 -> T1098.003 -> T1078.004.
output "ap08_attacker_hint" {
  description = "Pista didactica de la cadena de AP08 (null si AP08 esta desactivado)."
  value = var.enable_ap08 ? join("", [
    "Autenticate como el low-priv ", azuread_user.ap08_attacker[0].user_principal_name,
    " (solo Automation Contributor sobre el RG). Lanza el runbook del Automation Account ",
    azurerm_automation_account.ap08[0].name, " (T1651): ",
    "Start-AzAutomationRunbook -AutomationAccountName ", azurerm_automation_account.ap08[0].name,
    " -ResourceGroupName ", azurerm_resource_group.ap08[0].name,
    local.ap08_runbook_name != null ? " -Name ${local.ap08_runbook_name}" : " -Name <autora el tuyo>",
    ". El job corre COMO la MI (", local.ap08_mi_role_name, " sobre el RG) -> New-AzRoleAssignment ",
    "te concede Owner del RG (T1098.003 -> T1078.004). Scope = el RG (reset-safe).",
  ]) : null
}
