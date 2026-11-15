output "lab_users" {
  description = "UPNs de los usuarios ficticios creados."
  value       = module.entra_identity.user_principal_names
}

output "ap01_app_id" {
  description = "Client ID del app vulnerable de AP01 (null si AP01 está desactivado)."
  value       = module.entra_identity.ap01_app_id
}

output "ap01_consent_url" {
  description = "URL de consentimiento del app vulnerable — el alumno observa el flujo de illicit consent."
  value       = module.entra_identity.ap01_consent_url
}

# --- AP02 (null si enable_ap02 = false) ---
output "ap02_vm_public_ip" {
  description = "IP pública SSH del host pivote caelum-ap02-web."
  value       = module.azure_resources.ap02_vm_public_ip
}

output "ap02_key_vault_name" {
  description = "Nombre del Key Vault con el secreto botín."
  value       = module.azure_resources.ap02_key_vault_name
}

output "ap02_storage_account" {
  description = "Storage account objetivo del movimiento lateral."
  value       = module.azure_resources.ap02_storage_account
}

output "ap02_attacker_hint" {
  description = "Pista didáctica del primer pivote de AP02 (robo de token vía IMDS)."
  value       = module.azure_resources.ap02_attacker_hint
}

# --- AP03 (null si enable_ap03 = false) ---
output "ap03_group_object_id" {
  description = "Object ID del grupo role-assignable de AP03."
  value       = module.entra_identity.ap03_group_object_id
}

output "ap03_target_role" {
  description = "Rol de directorio que el grupo de AP03 porta (botín de la escalada)."
  value       = module.entra_identity.ap03_target_role
}

output "ap03_attacker_hint" {
  description = "Pista didáctica del primer paso de AP03 (self-add como owner)."
  value       = module.entra_identity.ap03_attacker_hint
}

# --- AP04 (null si enable_ap04 = false) ---
output "ap04_app_id" {
  description = "Client ID del app registration vulnerable de AP04 (null si AP04 desactivado)."
  value       = module.entra_identity.ap04_app_id
}

output "ap04_sp_object_id" {
  description = "Object ID del service principal de AP04 (principal del app_role_assignment de Graph)."
  value       = module.entra_identity.ap04_sp_object_id
}

output "ap04_graph_app_role" {
  description = "App role de Microsoft Graph que porta el SP de AP04 (botín de la escalada)."
  value       = module.entra_identity.ap04_graph_app_role
}

output "ap04_attacker_hint" {
  description = "Pista didáctica del primer paso de AP04 (owner añade credencial al app registration)."
  value       = module.entra_identity.ap04_attacker_hint
}

# --- AP05 (null si enable_ap05 = false) ---
output "ap05_resource_group" {
  description = "Resource group de AP05 (lo consume caelum.ps1 para el run-command del seed)."
  value       = module.hybrid_ad.ap05_resource_group
}

output "ap05_dc_vm_name" {
  description = "Nombre de la VM del DC+CA (centinela de AP05; lo consume caelum.ps1)."
  value       = module.hybrid_ad.ap05_dc_vm_name
}

output "ap05_dc_public_ip" {
  description = "IP pública del DC (RDP solo desde admin_source_cidr)."
  value       = module.hybrid_ad.ap05_dc_public_ip
}

output "ap05_domain_fqdn" {
  description = "FQDN del bosque de usar-y-tirar de AP05."
  value       = module.hybrid_ad.ap05_domain_fqdn
}

output "ap05_domain_netbios" {
  description = "NetBIOS del dominio de AP05 (lo consume caelum.ps1 para cualificar la credencial EA)."
  value       = module.hybrid_ad.ap05_domain_netbios
}

output "ap05_ca_name" {
  description = "Common Name de la Enterprise Root CA de AP05."
  value       = module.hybrid_ad.ap05_ca_name
}

output "ap05_esc1_template_name" {
  description = "Nombre de la plantilla vulnerable ESC1 (coincide con las detecciones)."
  value       = module.hybrid_ad.ap05_esc1_template_name
}

output "ap05_lowpriv_upn" {
  description = "UPN del usuario low-priv = credencial de arranque del atacante de AP05."
  value       = module.hybrid_ad.ap05_lowpriv_upn
}

output "ap05_attacker_hint" {
  description = "Pista didáctica de AP05 (ruta ESC1 + aviso de coste/destroy)."
  value       = module.hybrid_ad.ap05_attacker_hint
}

output "ap05_law_name" {
  description = "Nombre del Log Analytics workspace de AP05 (null si telemetría off o workspace externo)."
  value       = module.hybrid_ad.ap05_law_name
}

output "ap05_dc_admin_password" {
  description = "Password del Administrator de dominio de AP05 (= EA)."
  value       = module.hybrid_ad.ap05_dc_admin_password
  sensitive   = true
}

output "ap05_lowpriv_password" {
  description = "Password del usuario low-priv de AP05 (credencial de arranque del atacante)."
  value       = module.hybrid_ad.ap05_lowpriv_password
  sensitive   = true
}

# --- AP06 (null si enable_ap06 = false) ---
# Entra Connect / Seamless SSO sobre el MISMO DC que AP05 (substrato compartido).
# Centinela PROPIO ap06_dc_vm_name (NO reusa el de AP05): caelum.ps1/verify.ps1
# lo consumen para el seed/health-check de AP06 sin envenenar el de AP05.
output "ap06_dc_vm_name" {
  description = "Nombre de la VM del DC compartido visto desde AP06 (centinela de AP06; lo consume caelum.ps1/verify.ps1)."
  value       = module.hybrid_ad.ap06_dc_vm_name
}

output "ap06_resource_group" {
  description = "Resource group del DC compartido visto desde AP06 (lo consume caelum.ps1 para el run-command del seed)."
  value       = module.hybrid_ad.ap06_resource_group
}

output "ap06_dc_public_ip" {
  description = "IP pública del DC (RDP solo desde admin_source_cidr)."
  value       = module.hybrid_ad.ap06_dc_public_ip
}

output "ap06_domain_fqdn" {
  description = "FQDN del bosque de usar-y-tirar de AP06 (lo consume caelum.ps1 para el seed)."
  value       = module.hybrid_ad.ap06_domain_fqdn
}

output "ap06_domain_netbios" {
  description = "NetBIOS del dominio de AP06 (lo consume caelum.ps1 para cualificar la credencial EA)."
  value       = module.hybrid_ad.ap06_domain_netbios
}

output "ap06_sso_account" {
  description = "Cuenta de máquina de Seamless SSO (AZUREADSSOACC$)."
  value       = module.hybrid_ad.ap06_sso_account
}

output "ap06_sso_spns" {
  description = "SPNs de Seamless SSO (el 1º valida Entra y lo cazan las detecciones)."
  value       = module.hybrid_ad.ap06_sso_spns
}

output "ap06_sync_account" {
  description = "Cuenta de sincronización de Entra Connect con derechos DCSync."
  value       = module.hybrid_ad.ap06_sync_account
}

output "ap06_sso_mode" {
  description = "Modo de siembra de AP06 (both / silver_ticket / sync_dcsync); lo consume caelum.ps1/verify.ps1."
  value       = module.hybrid_ad.ap06_sso_mode
}

output "ap06_law_name" {
  description = "Nombre del Log Analytics workspace compartido visto desde AP06 (null si telemetría off o workspace externo)."
  value       = module.hybrid_ad.ap06_law_name
}

output "ap06_attacker_hint" {
  description = "Pista didáctica de AP06 (puente on-prem→cloud: sync cred → DCSync → silver ticket → nube; aviso de coste/destroy)."
  value       = module.hybrid_ad.ap06_attacker_hint
}

output "ap06_dc_admin_password" {
  description = "Password del Administrator de dominio visto desde AP06 (= EA). OBLIGATORIO para el seed en modo AP06-solo (enable_ap05=false). Aterriza en el ESTADO (sensible)."
  value       = module.hybrid_ad.ap06_dc_admin_password
  sensitive   = true
}

output "ap06_sso_password" {
  description = "Password FIJA de AZUREADSSOACC$ (permite derivar su clave RC4 para el forge del silver ticket). Aterriza en el ESTADO (sensible)."
  value       = module.hybrid_ad.ap06_sso_password
  sensitive   = true
}

output "ap06_sync_password" {
  description = "Password de la cuenta de sincronización de AP06 (credencial de arranque del atacante). Aterriza en el ESTADO (sensible)."
  value       = module.hybrid_ad.ap06_sync_password
  sensitive   = true
}

# --- AP07 (null si enable_ap07 = false) ---
# Punteros NO-secreto. La SAS/clave filtrada NUNCA se expone (vive solo en el tfstate).
output "ap07_resource_group" {
  description = "Resource group de AP07."
  value       = module.azure_resources.ap07_resource_group
}

output "ap07_storage_account" {
  description = "Nombre de la storage account vulnerable de AP07 (centinela del bloque AP07 en verify.ps1)."
  value       = module.azure_resources.ap07_storage_account
}

output "ap07_public_container_url" {
  description = "URL del contenedor público 'public' (añade ?restype=container&comp=list para la enumeración anónima T1619)."
  value       = module.azure_resources.ap07_public_container_url
}

output "ap07_leaked_config_url" {
  description = "URL anónima del blob filtrado backup-config.json (NO es secreto; la credencial está DENTRO)."
  value       = module.azure_resources.ap07_leaked_config_url
}

output "ap07_private_container" {
  description = "Nombre del contenedor privado con la joya (customers.csv)."
  value       = module.azure_resources.ap07_private_container
}

output "ap07_law_name" {
  description = "Nombre del Log Analytics workspace de AP07 (null si telemetría off o workspace externo)."
  value       = module.azure_resources.ap07_law_name
}

output "ap07_attacker_hint" {
  description = "Pista didáctica de la cadena de AP07 (enum anónima → descarga → pivote SAS/clave)."
  value       = module.azure_resources.ap07_attacker_hint
}

# --- AP08 (null si enable_ap08 = false) ---
# Punteros de POSTURA. El password del atacante aterriza en el tfstate (sensible)
# y SOLO se expone vía el output sensible ap08_attacker_password.
output "ap08_resource_group" {
  description = "Resource group de AP08 (enable_ap08=false lo destruye, y con él toda role assignment de runtime RG-scoped)."
  value       = module.azure_resources.ap08_resource_group
}

output "ap08_automation_account" {
  description = "Nombre del Automation Account vulnerable de AP08 (centinela del bloque AP08 en verify.ps1)."
  value       = module.azure_resources.ap08_automation_account
}

output "ap08_mi_principal_id" {
  description = "Object ID de la system-assigned MI del Automation Account (= actor de la escalada). Pivote de detección: roleAssignments/write con Caller == este id = señal de oro."
  value       = module.azure_resources.ap08_mi_principal_id
}

output "ap08_mi_role" {
  description = "Rol over-priv que la MI ostenta sobre el RG de AP08 (User Access Administrator u Owner; ambos incluyen roleAssignments/write)."
  value       = module.azure_resources.ap08_mi_role
}

output "ap08_runbook_name" {
  description = "Nombre del runbook incrustado (señuelo caelum-ap08-maintenance). Null si runbook_mode='none' (misconfig pura)."
  value       = module.azure_resources.ap08_runbook_name
}

output "ap08_attacker_upn" {
  description = "UPN del atacante low-priv (Automation Contributor) = credencial de arranque para disparar el runbook."
  value       = module.azure_resources.ap08_attacker_upn
}

output "ap08_attacker_password" {
  description = "Password del atacante low-priv de AP08 (credencial de arranque). Aterriza en el ESTADO (sensible)."
  value       = module.azure_resources.ap08_attacker_password
  sensitive   = true
}

output "ap08_law_name" {
  description = "Nombre del Log Analytics workspace de AP08 (null si telemetría off o workspace externo)."
  value       = module.azure_resources.ap08_law_name
}

output "ap08_attacker_hint" {
  description = "Pista didáctica de la cadena de AP08 (autenticarse como low-priv → lanzar runbook → el job corre como la MI → self-grant de Owner del RG)."
  value       = module.azure_resources.ap08_attacker_hint
}
