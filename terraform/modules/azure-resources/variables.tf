# ------------------------------------------------------------------
# Variables del modulo azure-resources (capa de recursos Azure).
# Tipadas y minimas: el modulo hereda contexto del root (main.tf).
# ------------------------------------------------------------------
variable "lab_prefix" {
  description = "Prefijo para nombrar los objetos del range (facilita el teardown)."
  type        = string
  default     = "caelum"
}

variable "location" {
  description = "Region de Azure para los recursos de AP02/AP07/AP08 (afecta coste/latencia)."
  type        = string
  default     = "westeurope"
}

variable "tenant_domain" {
  description = "AP08 - dominio del tenant de TEST (p.ej. caelumlab.onmicrosoft.com) para el UPN del azuread_user atacante. Lo cablea el root; null si no se usa AP08 (el modulo no crea el user con enable_ap08=false)."
  type        = string
  default     = null
}

variable "enable_ap02" {
  description = "AP02 - Managed Identity sobre-privilegiada -> Key Vault (Azure, coste bajo)."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------
# AP07 - Public storage / SAS leak (Azure, coste ~0, SIN VM).
# ------------------------------------------------------------------
variable "enable_ap07" {
  description = "AP07 - Storage con acceso anonimo (cuenta + contenedor) -> blob filtrado con credencial over-scoped -> exfil del contenedor privado (Azure, coste ~0)."
  type        = bool
  default     = false
}

variable "leak_mode" {
  description = "AP07 - que credencial se filtra en backup-config.json: 'sas' (SAS de cuenta over-scoped, default; usa hashicorp/time) o 'account_key' (primary_access_key, mas severa, sin provider nuevo)."
  type        = string
  default     = "sas"

  validation {
    condition     = contains(["sas", "account_key"], var.leak_mode)
    error_message = "leak_mode debe ser 'sas' o 'account_key'."
  }
}

variable "collect_storage_logs" {
  description = "AP07 - provisiona StorageBlobLogs via diagnostic setting sobre blobServices/default -> Log Analytics. false = sin ingesta (coste cero; asume SIEM externo)."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "AP07/AP08 - resource ID de un Log Analytics/Sentinel EXISTENTE al que apuntar el diagnostic setting del blob (AP07) y/o del Automation Account (AP08). Si se da, el modulo NO crea workspace propio (reutiliza la var raiz compartida con AP05)."
  type        = string
  default     = null
}

variable "sas_expiry_years" {
  description = "AP07 - vida (en anios) de la SAS de cuenta over-scoped filtrada; 10 por defecto para dramatizar la leccion 'SAS de larga vida'. Solo se usa si leak_mode='sas'."
  type        = number
  default     = 10

  validation {
    condition     = var.sas_expiry_years > 0
    error_message = "sas_expiry_years debe ser mayor que 0."
  }
}

# ------------------------------------------------------------------
# AP08 - Automation Account runbook -> escalada RBAC (Azure, coste ~0, SIN VM).
# La MI system-assigned del Automation Account ostenta un rol con
# roleAssignments/write SOBRE EL RG; un low-priv con Automation Contributor
# lanza un runbook que corre COMO la MI y se auto-concede Owner del RG.
# ------------------------------------------------------------------
variable "enable_ap08" {
  description = "AP08 - Automation Account con system-assigned MI over-privilegiada (UAA/Owner sobre el RG) + atacante low-priv (Automation Contributor) -> runbook que corre como la MI -> self-grant de Owner del RG (Azure, coste ~0, SIN VM). Declarativo (sin seed); la 'gun' queda cargada pero Terraform NUNCA la dispara."
  type        = bool
  default     = false
}

variable "runbook_mode" {
  description = "AP08 - que runbook se incrusta: 'poc_escalation' (default; gun cargada: Connect-AzAccount -Identity + New-AzRoleAssignment concediendo Owner del RG al atacante -> demo inmediata) | 'benign_probe' (solo prueba identidad/poder de la MI: Connect-AzAccount -Identity + Get-AzAccessToken + Get-AzRoleAssignment; el alumno escribe la escalada) | 'none' (sin runbook incrustado; misconfig pura). En NINGUN modo Terraform lanza un job."
  type        = string
  default     = "poc_escalation"

  validation {
    condition     = contains(["poc_escalation", "benign_probe", "none"], var.runbook_mode)
    error_message = "runbook_mode debe ser 'poc_escalation', 'benign_probe' o 'none'."
  }
}

variable "mi_role" {
  description = "AP08 - rol built-in over-priv de la MI del Automation Account SOBRE EL RG: 'UserAccessAdministrator' (default; minimo-que-escala: su UNICO poder es roleAssignments/write -> leccion afilada 'incluso solo UAA sobre una MI de Automation = game over') | 'Owner' (mas realista). Contributor queda EXCLUIDO: NO incluye roleAssignments/write (ese carril es el de AP02 via accessPolicies/write), por lo que no habilita la escalada RBAC."
  type        = string
  default     = "UserAccessAdministrator"

  validation {
    condition     = contains(["UserAccessAdministrator", "Owner"], var.mi_role)
    error_message = "mi_role debe ser 'UserAccessAdministrator' u 'Owner' (Contributor no incluye roleAssignments/write y no escala)."
  }
}

variable "collect_automation_logs" {
  description = "AP08 - provisiona JobLogs + JobStreams via diagnostic setting sobre el Automation Account -> Log Analytics (AzureDiagnostics). false = sin ingesta (coste cero; asume SIEM externo). PROPIEDAD: estas categorias NO estan activas por defecto -> sin este setting la EJECUCION del runbook NO existe en ningun SIEM (el plano de gestion SI fluye por AzureActivity)."
  type        = bool
  default     = true
}
