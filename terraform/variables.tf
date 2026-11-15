# ------------------------------------------------------------------
# Config base del range
# ------------------------------------------------------------------
variable "tenant_domain" {
  description = "Dominio del tenant de TEST (p.ej. caelumlab.onmicrosoft.com). NUNCA el corporativo."
  type        = string
}

variable "lab_prefix" {
  description = "Prefijo para nombrar los objetos del range (facilita el teardown)."
  type        = string
  default     = "caelum"
}

variable "user_count" {
  description = "Número de usuarios ficticios base."
  type        = number
  default     = 5
}

# ------------------------------------------------------------------
# Feature flags de rutas de ataque
#   Empieza SOLO con AP01 = true para validar el flujo sin coste.
#   Añade un flag nuevo aquí por cada ruta (ver CONTRIBUTING.md).
# ------------------------------------------------------------------
variable "enable_ap01" {
  description = "AP01 — Illicit consent grant (Entra, ~0 coste)."
  type        = bool
  default     = true
}

variable "enable_ap02" {
  description = "AP02 — Managed Identity sobre-privilegiada → Key Vault → lateral (Azure, coste bajo). OJO: factura cómputo."
  type        = bool
  default     = false
}

variable "enable_ap03" {
  description = "AP03 — Owner de bajo privilegio sobre grupo role-assignable con rol Privileged Role Administrator → self-add → Global Admin (Entra, coste $ ~0, REQUIERE Entra ID P1)."
  type        = bool
  default     = false
}

variable "enable_ap04" {
  description = "AP04 — Owner de bajo privilegio sobre app registration cuyo SP porta RoleManagement.ReadWrite.Directory (admin-consented) → el owner añade un client secret → se autentica como el SP → self-asigna Global Administrator (Entra, coste $ ~0, identity-only). El deployer necesita Global Administrator o Privileged Role Administrator para conceder el admin-consent."
  type        = bool
  default     = false
}

variable "enable_ap05" {
  description = "AP05 — AD CS ESC1 (Enrollee-Supplies-Subject) en DC híbrido: low-priv → plantilla vulnerable → PKINIT → Domain Admin → DCSync (híbrido on-prem). OJO: FACTURA CÓMPUTO (DC Windows always-on, el AP más caro). auto-shutdown + destroy al terminar."
  type        = bool
  default     = false
}

variable "enable_ap06" {
  description = "AP06 — Entra Connect / Seamless SSO (AZUREADSSOACC$): puente on-prem→cloud. 2ª ruta híbrida y la que CIERRA el catálogo. Comparte el MISMO DC que AP05 (substrato compartido vía need_dc): si enable_ap05=true, AP06 NO añade VM; si AP05 está off, AP06 levanta el DC él solo. OJO: FACTURA CÓMPUTO (como AP05). enable_ap06=false + enable_ap05=false → need_dc=false → destruye la VM."
  type        = bool
  default     = false
}

variable "sso_mode" {
  description = "AP06 — artefactos de Entra Connect/Seamless SSO a sembrar: 'both' (default; cadena completa sync→DCSync→claves AZUREADSSOACC$→silver ticket→nube) | 'silver_ticket' (solo AZUREADSSOACC$ con clave fija/no-rotada + SPNs) | 'sync_dcsync' (solo la cuenta MSOL_/Sync_ con ACEs DCSync sobre el NC)."
  type        = string
  default     = "both"

  validation {
    condition     = contains(["silver_ticket", "sync_dcsync", "both"], var.sso_mode)
    error_message = "sso_mode debe ser 'silver_ticket', 'sync_dcsync' o 'both'."
  }
}

variable "sso_account_name" {
  description = "AP06 — sAMAccountName (sin el sufijo $) de la cuenta de máquina de Seamless SSO. Real: AZUREADSSOACC. Debe coincidir con las detecciones."
  type        = string
  default     = "AZUREADSSOACC"
}

variable "sync_account_name" {
  description = "AP06 — sAMAccountName de la cuenta de sincronización de Entra Connect con derechos DCSync (análoga a MSOL_/Sync_)."
  type        = string
  default     = "Sync_CAELUM"
}

variable "sso_spns" {
  description = "AP06 — SPNs de la cuenta de Seamless SSO. El primero (HTTP/autologon.microsoftazuread-sso.com) es el que valida Entra y el que cazan las detecciones; el segundo (HTTP/aadg.windows.net.nsatc.net) completa el footprint real."
  type        = list(string)
  default     = ["HTTP/autologon.microsoftazuread-sso.com", "HTTP/aadg.windows.net.nsatc.net"]

  validation {
    condition     = length(var.sso_spns) > 0
    error_message = "sso_spns no puede estar vacia (ap06_attacker_hint indexa sso_spns[0])."
  }
}

variable "enable_ap07" {
  description = "AP07 — Storage público / SAS leak (Azure, coste ~0, SIN VM): cuenta con acceso anónimo (allow_nested_items_to_be_public=true) + contenedor público listable → blob filtrado con credencial over-scoped → exfil del contenedor privado. 100% declarativo (sin seed). La credencial aterriza en el ESTADO (sensible)."
  type        = bool
  default     = false
}

variable "leak_mode" {
  description = "AP07 — credencial filtrada en backup-config.json: 'sas' (SAS de cuenta over-scoped, default; lección least-privilege, usa hashicorp/time) o 'account_key' (primary_access_key = control total, más severa, sin provider nuevo)."
  type        = string
  default     = "sas"

  validation {
    condition     = contains(["sas", "account_key"], var.leak_mode)
    error_message = "leak_mode debe ser 'sas' o 'account_key'."
  }
}

variable "collect_storage_logs" {
  description = "AP07 — provisiona StorageBlobLogs vía diagnostic setting (blobServices/default) → Log Analytics para que 'Detecta' sea testeable end-to-end. false = sin ingesta (coste cero; asume SIEM externo)."
  type        = bool
  default     = true
}

variable "enable_ap08" {
  description = "AP08 — Automation Account runbook → escalada RBAC (Azure, coste ~0, SIN VM): un Automation Account con system-assigned MI over-privilegiada (UAA/Owner sobre el RG) + un atacante low-priv (Automation Contributor) que lanza un runbook corriendo COMO la MI → New-AzRoleAssignment se auto-concede Owner del RG. 100% declarativo (sin seed); la 'gun' queda cargada pero Terraform NUNCA la dispara. El password del atacante aterriza en el ESTADO (sensible)."
  type        = bool
  default     = false
}

variable "runbook_mode" {
  description = "AP08 — runbook incrustado: 'poc_escalation' (default; gun cargada: Connect-AzAccount -Identity + New-AzRoleAssignment concediendo Owner del RG al atacante → demo inmediata) | 'benign_probe' (solo prueba identidad/poder de la MI; el alumno escribe la escalada → más seguro para despliegues compartidos) | 'none' (sin runbook; misconfig pura). En NINGÚN modo Terraform lanza un job."
  type        = string
  default     = "poc_escalation"

  validation {
    condition     = contains(["poc_escalation", "benign_probe", "none"], var.runbook_mode)
    error_message = "runbook_mode debe ser 'poc_escalation', 'benign_probe' o 'none'."
  }
}

variable "mi_role" {
  description = "AP08 — rol built-in over-priv de la MI SOBRE EL RG: 'UserAccessAdministrator' (default; mínimo-que-escala: su ÚNICO poder es roleAssignments/write → lección 'incluso solo UAA sobre una MI de Automation = game over') | 'Owner' (más realista). Contributor queda EXCLUIDO: no incluye roleAssignments/write (ese carril es el de AP02 vía accessPolicies/write)."
  type        = string
  default     = "UserAccessAdministrator"

  validation {
    condition     = contains(["UserAccessAdministrator", "Owner"], var.mi_role)
    error_message = "mi_role debe ser 'UserAccessAdministrator' u 'Owner' (Contributor no incluye roleAssignments/write y no escala)."
  }
}

variable "collect_automation_logs" {
  description = "AP08 — provisiona JobLogs + JobStreams vía diagnostic setting (Automation Account) → Log Analytics (AzureDiagnostics) para que 'Detecta' sea testeable end-to-end. false = sin ingesta (coste cero; asume SIEM externo). Estas categorías NO están activas por defecto → sin este setting la EJECUCIÓN del runbook NO existe en ningún SIEM (el plano de gestión SÍ fluye por AzureActivity)."
  type        = bool
  default     = true
}

# ------------------------------------------------------------------
# Config de la capa Azure (relevante si enable_ap02, enable_ap05, enable_ap07 o enable_ap08)
# ------------------------------------------------------------------
variable "location" {
  description = "Región de Azure para los recursos de AP02/AP05/AP07/AP08 (afecta coste/latencia)."
  type        = string
  default     = "westeurope"
}

# ------------------------------------------------------------------
# Config específica de AP05 (solo relevante si enable_ap05 = true)
# ------------------------------------------------------------------
variable "dc_admin_password" {
  description = "AP05 — password del built-in Administrator del dominio (= Enterprise Admin que siembra/remedia ESC1). Deja null/vacío → random_password. NUNCA una password real ni reutilizada. Aterriza en el ESTADO: trata el estado como sensible."
  type        = string
  sensitive   = true
  default     = null
}

variable "admin_source_cidr" {
  description = "AP05 — CIDR /32 del operador para RDP/WinRM al DC. NUNCA 0.0.0.0/0 (es un DC). Si es null, NO se abre ninguna regla inbound (Bastion/serial-console)."
  type        = string
  default     = null
}

variable "domain_fqdn" {
  description = "AP05 — FQDN del bosque de usar-y-tirar. NO sincronizar con el tenant vía Entra Connect real (eso convertiría el lab en riesgo real; lo cubriría AP06)."
  type        = string
  default     = "caelum.lab"
}

variable "vm_size" {
  description = "AP05 — tamaño de la VM del DC+CA. Standard_B2ms por defecto; Standard_B2s como suelo."
  type        = string
  default     = "Standard_B2ms"
}

variable "collect_security_events" {
  description = "AP05 — provisiona AMA+DCR+Log Analytics para que 'Detecta' sea testeable end-to-end. false = sin ingesta (coste cero; asume SIEM externo)."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "AP05/AP07/AP08 — resource ID de un Log Analytics/Sentinel EXISTENTE al que apuntar el DCR (AP05), el diagnostic setting del blob (AP07) y/o el del Automation Account (AP08). Si se da, los módulos NO crean workspace propio."
  type        = string
  default     = null
}
