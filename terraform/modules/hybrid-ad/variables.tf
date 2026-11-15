# ------------------------------------------------------------------
# Variables del modulo hybrid-ad (capa HIBRIDA: AD DS + AD CS on-prem
# sobre una VM Windows en Azure IaaS). AP05 = AD CS ESC1.
# Tipadas y minimas; el modulo hereda contexto del root (main.tf).
# ------------------------------------------------------------------
variable "enable_ap05" {
  description = "AP05 - AD CS ESC1 sobre DC hibrido. OJO: FACTURA COMPUTO (VM Windows always-on). enable_ap05=false -> count=0 -> destruye la VM (reset mas limpio del range)."
  type        = bool
  default     = false
}

variable "lab_prefix" {
  description = "Prefijo para nombrar los objetos del range (facilita el teardown)."
  type        = string
  default     = "caelum"
}

variable "location" {
  description = "Region de Azure para la VM del DC (afecta coste/latencia). Misma convencion que azure-resources."
  type        = string
  default     = "westeurope"
}

variable "dc_admin_password" {
  description = "Password del built-in Administrator del dominio (= EA que siembra/remedia ESC1). Deja null -> random_password. NUNCA una password real ni reutilizada."
  type        = string
  sensitive   = true
  default     = null
}

variable "domain_fqdn" {
  description = "FQDN del bosque de usar-y-tirar (NUNCA sincronizar con el tenant via Entra Connect real: eso lo cubriria AP06)."
  type        = string
  default     = "caelum.lab"
}

variable "domain_netbios" {
  description = "Nombre NetBIOS del dominio. Se usa para cualificar la credencial EA (DOMINIO\\Administrator) en el seed y en la CA."
  type        = string
  default     = "CAELUM"
}

variable "vm_size" {
  description = "Tamano de la VM del DC+CA. Standard_B2ms por defecto (2 vCPU/8 GiB); Standard_B2s (4 GiB) como suelo. Contenido pero suficiente para DC+ADCS."
  type        = string
  default     = "Standard_B2ms"
}

variable "vm_image_version" {
  description = "Version de la imagen de Windows Server 2022. 'latest' por comodidad; PINEA una version concreta si quieres reproducibilidad frente a KB5014754 (un parche mas alla de sep-2025 puede romper la pata Rompe)."
  type        = string
  default     = "latest"
}

variable "admin_source_cidr" {
  description = "CIDR /32 del operador para RDP/WinRM al DC. NUNCA 0.0.0.0/0 (es un DC). Si es null, NO se abre ninguna regla inbound (Bastion/serial-console)."
  type        = string
  default     = null

  validation {
    condition     = var.admin_source_cidr == null || var.admin_source_cidr != "0.0.0.0/0"
    error_message = "admin_source_cidr no puede ser 0.0.0.0/0: un DC no se expone a Internet. Usa tu /32 o deja null (Bastion/serial)."
  }
}

variable "lowpriv_user_name" {
  description = "sAMAccountName del usuario de bajo privilegio (credencial de arranque del atacante; solo Domain Users)."
  type        = string
  default     = "ap05user"
}

variable "ca_common_name" {
  description = "Common Name de la Enterprise Root CA."
  type        = string
  default     = "caelum-CA"
}

variable "esc1_template_name" {
  description = "Nombre (cn) de la plantilla vulnerable ESC1 que siembra seed-ap05.ps1. Debe coincidir con las detecciones (CertificateTemplate)."
  type        = string
  default     = "CaelumAuthESC1"
}

variable "collect_security_events" {
  description = "Provisiona el pipeline de deteccion (AMA+DCR+Log Analytics) para 'Detecta' end-to-end. false = sin ingesta (coste cero; asume SIEM externo). A diferencia de AP01-AP04, estos eventos on-prem NO existen en ningun SIEM sin este pipeline."
  type        = bool
  default     = true
}

variable "existing_log_analytics_workspace_id" {
  description = "Resource ID de un Log Analytics/Sentinel EXISTENTE al que apuntar el DCR. Si se da, el modulo NO crea workspace propio."
  type        = string
  default     = null
}

variable "auto_shutdown_time" {
  description = "Hora de apagado automatico diario (HHmm, zona W. Europe Standard Time). Disciplina de coste (patron AP02). Despliega de dia para no cortar el DCPromo."
  type        = string
  default     = "2200"
}

variable "strong_cert_binding_mode" {
  description = "KB5014754 StrongCertificateBindingEnforcement en el KDC: 0=Disabled, 1=Compatibility (default del lab, ESC1 explotable), 2=Full Enforcement (rechaza el SAN forjado -> el fix real). La DSC lo fija deliberadamente a 1."
  type        = number
  default     = 1
}

# ------------------------------------------------------------------
# AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$): 2a ruta hibrida,
# CIERRA el catalogo. Puente on-prem -> cloud. Comparte el MISMO DC que AP05
# via local.need_dc (main.tf): si enable_ap05 ya esta ON, AP06 NO anade VM;
# si AP05 esta OFF, AP06 levanta el DC el solo (FACTURA COMPUTO). Los
# artefactos AD (AZUREADSSOACC$ + cuenta de sync con DCSync) NO son recursos
# azurerm: los siembra scripts/seed-ap06.ps1 (imperativo, como la ESC1 de AP05).
# ------------------------------------------------------------------
variable "enable_ap06" {
  description = "AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$) sobre el MISMO DC hibrido que AP05 (substrato compartido via need_dc). Puente on-prem->cloud. OJO: FACTURA COMPUTO si AP05 no esta ya activo (reusa la VM si lo esta). enable_ap06=false + enable_ap05=false -> need_dc=false -> destruye la VM."
  type        = bool
  default     = false
}

variable "sso_mode" {
  description = "AP06 - artefactos de Entra Connect/Seamless SSO a sembrar. 'silver_ticket' (solo AZUREADSSOACC$ con clave fija/no-rotada + SPNs; foco en forjar el TGS Seamless SSO) | 'sync_dcsync' (solo la cuenta MSOL_/Sync_ con ACEs DCSync sobre el NC; foco en la extraccion de la cred de Entra Connect -> DCSync) | 'both' (ambos; habilita la cadena completa sync->DCSync->claves AZUREADSSOACC$->silver ticket->nube)."
  type        = string
  default     = "both"

  validation {
    condition     = contains(["silver_ticket", "sync_dcsync", "both"], var.sso_mode)
    error_message = "sso_mode debe ser 'silver_ticket', 'sync_dcsync' o 'both'."
  }
}

variable "sso_account_name" {
  description = "AP06 - sAMAccountName (sin el sufijo $) de la cuenta de maquina de Seamless SSO. Real: AZUREADSSOACC. Debe coincidir con las detecciones."
  type        = string
  default     = "AZUREADSSOACC"
}

variable "sync_account_name" {
  description = "AP06 - sAMAccountName de la cuenta de sincronizacion de Entra Connect con derechos DCSync (analoga a MSOL_/Sync_)."
  type        = string
  default     = "Sync_CAELUM"
}

variable "sso_spns" {
  description = "AP06 - SPNs de la cuenta de Seamless SSO. El primero (HTTP/autologon.microsoftazuread-sso.com) es el que valida Entra y el que cazan las detecciones; el segundo (HTTP/aadg.windows.net.nsatc.net) completa el footprint real."
  type        = list(string)
  default     = ["HTTP/autologon.microsoftazuread-sso.com", "HTTP/aadg.windows.net.nsatc.net"]

  validation {
    condition     = length(var.sso_spns) > 0
    error_message = "sso_spns no puede estar vacia (ap06_attacker_hint indexa sso_spns[0])."
  }
}
