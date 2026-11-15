# ==================================================================
# Modulo: hybrid-ad  (capa HIBRIDA on-prem-en-Azure)
#
# AP05 - AD CS ESC1 (Enrollee-Supplies-Subject):
#   VM Windows Server 2022 -> DC (bosque de usar-y-tirar) -> Enterprise
#   Root CA -> plantilla vulnerable 'CaelumAuthESC1' + usuario low-priv.
#   El atacante (low-priv) solicita un cert especificando SAN=UPN de un
#   Domain Admin, autentica por PKINIT -> TGT de DA -> DCSync.
#
# Patron (igual que azure-resources/AP02): cada recurso va envuelto en
#   count = local.need_dc ? 1 : 0
# de modo que `reset` (apply con enable_ap05=false) destruye la VM entera
# y, atomicamente, la plantilla ESC1 + certs forjados + CA DB. La plantilla
# NO es un recurso azurerm (azurerm no gestiona plantillas AD CS: viven en
# el Configuration NC del DC) -> esa es justo la propiedad que da el reset
# limpio. La siembra/remediacion imperativa la hace scripts/seed-ap05.ps1.
#
# Reboot de DCPromo: lo posee el LCM de la DSC (RebootNodeIfNeeded +
# ActionAfterReboot='ContinueConfiguration'); `terraform apply` bloquea en
# la extension DSC hasta que bosque+CA+auditoria quedan Compliant.
# ==================================================================

locals {
  # ----------------------------------------------------------------
  # SUBSTRATO COMPARTIDO (AP05 + AP06). El DC/CA es un unico bloque que
  # sirve a AMBAS rutas hibridas. need_dc = enable_ap05 || enable_ap06:
  # cuando enable_ap05=true, need_dc es IDENTICAMENTE true con independencia
  # de enable_ap06 -> toda expresion reescrita de var.enable_ap05 a
  # local.need_dc evalua igual en el escenario AP05-solo (mismo count, mismos
  # [0], plan cero-diff). Los artefactos AP05 (CA/ESC1) siguen gated en
  # enable_ap05 (seed-ap05); los AP06 (AZUREADSSOACC$/cuenta de sync) en
  # enable_ap06 (seed-ap06). Reset con AMBAS flags false -> need_dc=false ->
  # destruye el unico DC y con el todos los objetos AD de AP05+AP06.
  # ----------------------------------------------------------------
  need_dc = var.enable_ap05 || var.enable_ap06

  # Conditional short-circuit: no indexa [0] cuando el DC no existe.
  suffix = local.need_dc ? random_string.suffix[0].result : ""

  rg_name = "${var.lab_prefix}-ap05-rg"
  vm_name = "${var.lab_prefix}-ap05-dc"
  # Storage del paquete DSC: 3-24 lowercase alfanumerico, SIN guiones.
  sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap05dsc${local.suffix}"

  # Azure prohibe 'Administrator' como admin de la VM; este admin SAM local
  # DESAPARECE al promover el DC (por eso la DSC set+enable el built-in).
  admin_username = "caelumadmin"

  lowpriv_upn = "${var.lowpriv_user_name}@${var.domain_fqdn}"

  # Password del DA: override por dc_admin_password (sensitive) o random.
  # try() protege el [0] cuando random_password.dc_admin tiene count 0.
  dc_admin_password = local.need_dc ? coalesce(var.dc_admin_password, try(random_password.dc_admin[0].result, null)) : null

  # Reglas NSG solo si el operador da un CIDR (secure-by-default). Nunca 0.0.0.0/0.
  nsg_rules = local.need_dc && var.admin_source_cidr != null ? [
    { name = "allow-rdp-inbound", priority = 1001, port = "3389" },
    { name = "allow-winrm-inbound", priority = 1002, port = "5985" },
    { name = "allow-winrms-inbound", priority = 1003, port = "5986" },
  ] : []
}

# ------------------------------------------------------------------
# Sufijo global unico (el storage account es namespace global).
# ------------------------------------------------------------------
resource "random_string" "suffix" {
  count   = local.need_dc ? 1 : 0
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# ------------------------------------------------------------------
# Secretos (nunca hardcode). Set Windows-safe + 4 categorias garantizadas
# para no fallar la complejidad de Azure en el recurso VM.
#   - dc_admin : solo si no se pasa dc_admin_password (override sensitive).
#   - dsrm     : SafeMode Administrator Password del DC.
#   - lowpriv  : password del usuario de arranque del atacante.
# ------------------------------------------------------------------
resource "random_password" "dc_admin" {
  count            = local.need_dc && var.dc_admin_password == null ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

resource "random_password" "dsrm" {
  count            = local.need_dc ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

resource "random_password" "lowpriv" {
  count            = local.need_dc ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

# ------------------------------------------------------------------
# Resource group contenedor (blast radius acotado al RG; reset = destroy).
# ------------------------------------------------------------------
resource "azurerm_resource_group" "ap05" {
  count    = local.need_dc ? 1 : 0
  name     = local.rg_name
  location = var.location

  tags = {
    range       = var.lab_prefix
    attack_path = "AP05"
  }
}

# ==================================================================
# Red del DC: VNet 10.105.0.0/16 + subnet + IP publica Standard estatica
# + NSG (sin SSH abierto: un DC no se expone a Internet) + NIC.
# ==================================================================
resource "azurerm_virtual_network" "ap05" {
  count               = local.need_dc ? 1 : 0
  name                = "${var.lab_prefix}-ap05-vnet"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  address_space       = ["10.105.0.0/16"]
}

resource "azurerm_subnet" "ap05" {
  count                = local.need_dc ? 1 : 0
  name                 = "${var.lab_prefix}-ap05-subnet"
  resource_group_name  = azurerm_resource_group.ap05[0].name
  virtual_network_name = azurerm_virtual_network.ap05[0].name
  address_prefixes     = ["10.105.1.0/24"]
}

resource "azurerm_public_ip" "ap05" {
  count               = local.need_dc ? 1 : 0
  name                = "${var.lab_prefix}-ap05-pip"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# NSG: divergencia DELIBERADA vs el SSH abierto de AP02. RDP/WinRM SOLO al
# CIDR del operador; si admin_source_cidr es null, NINGUNA regla allow
# (acceso por Bastion/serial-console). NUNCA 0.0.0.0/0 (validado en var).
resource "azurerm_network_security_group" "ap05" {
  count               = local.need_dc ? 1 : 0
  name                = "${var.lab_prefix}-ap05-nsg"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name

  dynamic "security_rule" {
    for_each = local.nsg_rules
    content {
      name                       = security_rule.value.name
      priority                   = security_rule.value.priority
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value.port
      source_address_prefix      = var.admin_source_cidr
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_network_interface" "ap05" {
  count               = local.need_dc ? 1 : 0
  name                = "${var.lab_prefix}-ap05-nic"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.ap05[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.ap05[0].id
  }
}

resource "azurerm_network_interface_security_group_association" "ap05" {
  count                     = local.need_dc ? 1 : 0
  network_interface_id      = azurerm_network_interface.ap05[0].id
  network_security_group_id = azurerm_network_security_group.ap05[0].id
}

# ==================================================================
# VM del DC+CA: Windows Server 2022 Datacenter Gen2, Standard_B2ms.
# admin 'caelumadmin' (SAM local que desaparece al promover: por eso la
# DSC set+enable el built-in Administrator con dc_admin_password).
# ==================================================================
resource "azurerm_windows_virtual_machine" "dc" {
  count               = local.need_dc ? 1 : 0
  name                = local.vm_name
  computer_name       = "DC01"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  size                = var.vm_size

  admin_username = local.admin_username
  admin_password = local.dc_admin_password

  network_interface_ids = [azurerm_network_interface.ap05[0].id]

  # Managed identity (system-assigned): el Azure Monitor Agent (AMA, en
  # monitoring.tf) se autentica contra Azure Monitor con la MI de la VM. SIN
  # ella AMA se instala pero NO puede enviar los SecurityEvent al DCR/workspace
  # -> 'Detecta' quedaria roto EN SILENCIO (apply OK pero cero ingesta, que es
  # la UNICA via por la que estos eventos on-prem llegan a un SIEM). El DC no la
  # necesita para el ataque; AMA si.
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-g2"
    version   = var.vm_image_version
  }
}

# ------------------------------------------------------------------
# Auto-shutdown diario: disciplina de coste (AP05 es, con AP02, el unico
# AP que factura computo, y el mas caro). Patron identico a AP02.
# Despliega de dia: un apagado en mitad del DCPromo rompe el bootstrap.
# ------------------------------------------------------------------
resource "azurerm_dev_test_global_vm_shutdown_schedule" "dc" {
  count              = local.need_dc ? 1 : 0
  virtual_machine_id = azurerm_windows_virtual_machine.dc[0].id
  location           = azurerm_resource_group.ap05[0].location
  enabled            = true

  daily_recurrence_time = var.auto_shutdown_time
  timezone              = "W. Europe Standard Time"

  notification_settings {
    enabled = false
  }
}

# ==================================================================
# Empaquetado de la configuracion DSC (patron storage de AP02).
#   archive_file zipea dsc/ (solo CaelumDC.ps1) -> storage -> blob -> SAS
#   -> extension. El configurationData.psd1 (allow domain-user/plaintext,
#   necesario porque la CA enterprise usa credencial de dominio cualificada)
#   se sube como blob source_content APARTE -> el zip conserva SOLO el .ps1.
#   output_path va a la RAIZ del modulo (hermano de dsc/, sin auto-inclusion
#   recursiva): un subdir .dsc-build/ puede no existir y algunas versiones de
#   hashicorp/archive NO crean el directorio padre -> fallo en plan/apply. El
#   .zip generado esta en .gitignore.
# ==================================================================
data "archive_file" "dsc" {
  count       = local.need_dc ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/dsc"
  output_path = "${path.module}/CaelumDC.zip"
}

resource "azurerm_storage_account" "dsc" {
  count                           = local.need_dc ? 1 : 0
  name                            = local.sa_name
  resource_group_name             = azurerm_resource_group.ap05[0].name
  location                        = azurerm_resource_group.ap05[0].location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "dsc" {
  count                 = local.need_dc ? 1 : 0
  name                  = "dsc"
  storage_account_name  = azurerm_storage_account.dsc[0].name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "dsc" {
  count                  = local.need_dc ? 1 : 0
  name                   = "CaelumDC.zip"
  storage_account_name   = azurerm_storage_account.dsc[0].name
  storage_container_name = azurerm_storage_container.dsc[0].name
  type                   = "Block"
  source                 = data.archive_file.dsc[0].output_path
  content_md5            = data.archive_file.dsc[0].output_md5
}

# ConfigurationData: habilita credencial de dominio y evita el guard de
# plaintext al compilar la MOF en la VM. Blob aparte (no va en el zip).
resource "azurerm_storage_blob" "dsc_configdata" {
  count                  = local.need_dc ? 1 : 0
  name                   = "CaelumDC.ConfigData.psd1"
  storage_account_name   = azurerm_storage_account.dsc[0].name
  storage_container_name = azurerm_storage_container.dsc[0].name
  type                   = "Block"
  source_content         = <<-PSD1
    @{
        AllNodes = @(
            @{
                NodeName                    = "localhost"
                PSDscAllowPlainTextPassword = $true
                PSDscAllowDomainUser        = $true
            }
        )
    }
  PSD1
}

# SAS de lectura para que la extension descargue los blobs. Fechas ESTATICAS
# (no timestamp()) para no regenerar protected_settings y re-ejecutar la
# extension en cada apply. Ventana amplia: solo se usa en el deploy.
data "azurerm_storage_account_sas" "dsc" {
  count             = local.need_dc ? 1 : 0
  connection_string = azurerm_storage_account.dsc[0].primary_connection_string
  https_only        = true
  start             = "2024-01-01T00:00:00Z"
  expiry            = "2034-01-01T00:00:00Z"

  resource_types {
    service   = false
    container = true
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }

  permissions {
    read    = true
    list    = true
    add     = false
    create  = false
    write   = false
    delete  = false
    update  = false
    process = false
    tag     = false
    filter  = false
  }
}

# ==================================================================
# Extension DSC (UNICA opcion reboot-aware). type="DSC",
# publisher="Microsoft.Powershell". La config levanta SOLO la BASE BENIGNA
# (bosque + Enterprise Root CA + auditoria + usuario low-priv +
# StrongCertificateBindingEnforcement). La plantilla ESC1 la siembra
# seed-ap05.ps1 (post-apply, via az vm run-command).
#
# Credenciales por protected_settings.configurationArguments (CIFRADO),
# NUNCA en settings en claro. timeouts para que un DSC colgado FALLE
# (failure mode conocido) en vez de colgar `terraform apply`.
# ==================================================================
resource "azurerm_virtual_machine_extension" "dsc" {
  count                      = local.need_dc ? 1 : 0
  name                       = "CaelumDC"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc[0].id
  publisher                  = "Microsoft.Powershell"
  type                       = "DSC"
  type_handler_version       = "2.83"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    wmfVersion = "latest"
    configuration = {
      url      = azurerm_storage_blob.dsc[0].url
      script   = "CaelumDC.ps1"
      function = "CaelumDC"
    }
    configurationData = {
      url = azurerm_storage_blob.dsc_configdata[0].url
    }
    configurationArguments = {
      DomainFqdn            = var.domain_fqdn
      DomainNetbios         = var.domain_netbios
      LowPrivUser           = var.lowpriv_user_name
      CaCommonName          = var.ca_common_name
      StrongCertBindingMode = tostring(var.strong_cert_binding_mode)
    }
  })

  protected_settings = jsonencode({
    configurationUrlSasToken     = data.azurerm_storage_account_sas.dsc[0].sas
    configurationDataUrlSasToken = data.azurerm_storage_account_sas.dsc[0].sas
    configurationArguments = {
      AdminCredential    = { UserName = "Administrator", Password = local.dc_admin_password }
      SafemodeCredential = { UserName = "Administrator", Password = random_password.dsrm[0].result }
      LowPrivCredential  = { UserName = var.lowpriv_user_name, Password = random_password.lowpriv[0].result }
    }
  })

  timeouts {
    create = "90m"
    update = "90m"
    delete = "30m"
  }
}
