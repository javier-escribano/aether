# ==================================================================
# Pipeline de deteccion de AP05 (gated enable_ap05 && collect_security_events).
#
# A diferencia de AP01-AP04 (logs de Entra que ya fluyen a su SIEM), los
# eventos de Seguridad de Windows del DC/CA NO existen en ningun SIEM sin
# este pipeline: AMA (Azure Monitor Windows Agent) -> DCR -> Log Analytics.
# Por eso 'Detecta' solo es testeable end-to-end si el range los ingiere.
#
# El xPath del DCR FILTRA a 5 EventID (4886/4887/4899/4900/4768): un canal
# Security sin filtrar dispara el coste de ingesta. La HABILITACION de la
# auditoria (certutil AuditFilter + auditpol) la hace la DSC BASE, no aqui.
# ==================================================================

locals {
  # Sub-stack de telemetria activo. need_dc (AP05 || AP06): el workspace/DCR/
  # AMA se provisionan si existe el DC compartido y la telemetria esta ON.
  collect_events = local.need_dc && var.collect_security_events

  # XPath AP05 LITERAL (byte-a-byte el de hoy; NO reconstruir por interpolacion).
  # 4886/4887 solicitud/emision CA; 4899/4900 cambio plantilla/seguridad;
  # 4768 TGT Kerberos (PKINIT con Certificate Information).
  xpath_ap05 = "Security!*[System[(EventID=4886 or EventID=4887 or EventID=4899 or EventID=4900 or EventID=4768)]]"

  # XPath AP06: 4662 (DS-Replication/DCSync) + 4769 (TGS Seamless SSO) +
  # 4741/4742 (creacion/cambio de AZUREADSSOACC$). Solo se anade con enable_ap06.
  xpath_ap06 = "Security!*[System[(EventID=4662 or EventID=4769 or EventID=4741 or EventID=4742)]]"

  # Workspace propio, o el externo si se da existing_log_analytics_workspace_id.
  law_id = local.collect_events ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap05[0].id
  ) : null

  law_name = local.collect_events && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap05[0].name : null
}

# Workspace propio (se OMITE si el operador apunta a un Sentinel externo).
resource "azurerm_log_analytics_workspace" "ap05" {
  count               = local.collect_events && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap05-law"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
}

# DCR: recoge SOLO los 5 EventID relevantes del canal Security del DC/CA.
resource "azurerm_monitor_data_collection_rule" "ap05" {
  count               = local.collect_events ? 1 : 0
  name                = "${var.lab_prefix}-ap05-dcr"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name

  destinations {
    log_analytics {
      name                  = "caelum-ap05-law-dest"
      workspace_resource_id = local.law_id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["caelum-ap05-law-dest"]
  }

  data_sources {
    windows_event_log {
      name    = "ap05-securityevents"
      streams = ["Microsoft-SecurityEvent"]
      # Filtro compuesto por flag: AP05 aporta su filtro de 5 EventID; AP06 anade
      # los suyos (4662/4769/4741/4742) SOLO cuando enable_ap06. En AP05-solo esto
      # evalua a [local.xpath_ap05]: lista de un elemento IDENTICA a la de hoy (el
      # filtro AP05 queda byte-a-byte). AP06-solo -> [xpath_ap06]. Ambas -> los dos.
      x_path_queries = concat(
        var.enable_ap05 ? [local.xpath_ap05] : [],
        var.enable_ap06 ? [local.xpath_ap06] : [],
      )
    }
  }
}

# Asociacion VM <-> DCR. Depende de la DSC para no asociarse antes de que el
# DC exista.
resource "azurerm_monitor_data_collection_rule_association" "ap05" {
  count                   = local.collect_events ? 1 : 0
  name                    = "${var.lab_prefix}-ap05-dcra"
  target_resource_id      = azurerm_windows_virtual_machine.dc[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.ap05[0].id
  depends_on              = [azurerm_virtual_machine_extension.dsc]
}

# Azure Monitor Windows Agent. Depende de la DSC (DependsOn) para no
# instalarse antes de que el DC/CA/auditoria existan.
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
