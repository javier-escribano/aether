# ==================================================================
# AP05 detection pipeline (gated on enable_ap05 && collect_security_events).
#
# Unlike AP01-AP04 (Entra logs that already flow to their SIEM), the Windows
# Security events from the DC/CA do NOT exist in any SIEM without this
# pipeline: AMA (Azure Monitor Windows Agent) -> DCR -> Log Analytics.
# That is why 'Detect' is only testable end-to-end if the range ingests them.
#
# The DCR xPath FILTERS to 5 EventIDs (4886/4887/4899/4900/4768): an unfiltered
# Security channel triggers the ingestion cost. ENABLING the auditing
# (certutil AuditFilter + auditpol) is done by the BASE DSC, not here.
# ==================================================================

locals {
  # Active telemetry sub-stack. need_dc (AP05 || AP06): the workspace/DCR/
  # AMA are provisioned if the shared DC exists and telemetry is ON.
  collect_events = local.need_dc && var.collect_security_events

  # LITERAL AP05 XPath (byte-for-byte today's; do NOT rebuild via interpolation).
  # 4886/4887 CA request/issue; 4899/4900 template/security change;
  # 4768 Kerberos TGT (PKINIT with Certificate Information).
  xpath_ap05 = "Security!*[System[(EventID=4886 or EventID=4887 or EventID=4899 or EventID=4900 or EventID=4768)]]"

  # AP06 XPath: 4662 (DS-Replication/DCSync) + 4769 (Seamless SSO TGS) +
  # 4741/4742 (creation/change of AZUREADSSOACC$). Only added with enable_ap06.
  xpath_ap06 = "Security!*[System[(EventID=4662 or EventID=4769 or EventID=4741 or EventID=4742)]]"

  # Own workspace, or the external one if existing_log_analytics_workspace_id is given.
  law_id = local.collect_events ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap05[0].id
  ) : null

  law_name = local.collect_events && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap05[0].name : null
}

# Own workspace (OMITTED if the operator points at an external Sentinel).
resource "azurerm_log_analytics_workspace" "ap05" {
  count               = local.collect_events && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap05-law"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
  daily_quota_gb      = var.law_daily_cap_gb
}

# DCR: collects ONLY the 5 relevant EventIDs from the DC/CA Security channel.
resource "azurerm_monitor_data_collection_rule" "ap05" {
  count               = local.collect_events ? 1 : 0
  name                = "${var.lab_prefix}-ap05-dcr"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name

  destinations {
    log_analytics {
      name                  = "aether-ap05-law-dest"
      workspace_resource_id = local.law_id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["aether-ap05-law-dest"]
  }

  data_sources {
    windows_event_log {
      name    = "ap05-securityevents"
      streams = ["Microsoft-SecurityEvent"]
      # Filter composed by flag: AP05 contributes its 5-EventID filter; AP06 adds
      # its own (4662/4769/4741/4742) ONLY when enable_ap06. In AP05-only this
      # evaluates to [local.xpath_ap05]: a single-element list IDENTICAL to today's (the
      # AP05 filter stays byte-for-byte). AP06-only -> [xpath_ap06]. Both -> the two.
      x_path_queries = concat(
        var.enable_ap05 ? [local.xpath_ap05] : [],
        var.enable_ap06 ? [local.xpath_ap06] : [],
      )
    }
  }
}

# VM <-> DCR association. Depends on the DSC so it is not associated before the
# DC exists.
resource "azurerm_monitor_data_collection_rule_association" "ap05" {
  count                   = local.collect_events ? 1 : 0
  name                    = "${var.lab_prefix}-ap05-dcra"
  target_resource_id      = azurerm_windows_virtual_machine.dc[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.ap05[0].id
  depends_on              = [azurerm_virtual_machine_extension.dsc]
}

# Azure Monitor Windows Agent. Depends on the DSC (DependsOn) so it is not
# installed before the DC/CA/auditing exist.
resource "azurerm_virtual_machine_extension" "ama" {
  count                      = local.collect_events ? 1 : 0
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc[0].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  depends_on                 = [azurerm_virtual_machine_extension.dsc]
}
