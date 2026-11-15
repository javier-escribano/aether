# ==================================================================
# Module: hybrid-ad  (HYBRID on-prem-in-Azure layer)
#
# AP05 - AD CS ESC1 (Enrollee-Supplies-Subject):
#   Windows Server 2022 VM -> DC (throwaway forest) -> Enterprise
#   Root CA -> vulnerable template 'AetherAuthESC1' + low-priv user.
#   The (low-priv) attacker requests a cert specifying SAN=UPN of a
#   Domain Admin, authenticates via PKINIT -> DA TGT -> DCSync.
#
# Pattern (same as azure-resources/AP02): every resource is wrapped in
#   count = local.need_dc ? 1 : 0
# so that `reset` (apply with enable_ap05=false) destroys the entire VM
# and, atomically, the ESC1 template + forged certs + CA DB. The template
# is NOT an azurerm resource (azurerm does not manage AD CS templates: they
# live in the DC's Configuration NC) -> that is exactly the property that
# gives the clean reset. Imperative seeding/remediation is done by
# scripts/seed-ap05.ps1.
#
# DCPromo reboot: owned by the DSC LCM (RebootNodeIfNeeded +
# ActionAfterReboot='ContinueConfiguration'); `terraform apply` blocks on
# the DSC extension until forest+CA+auditing become Compliant.
# ==================================================================

locals {
  # ----------------------------------------------------------------
  # SHARED SUBSTRATE (AP05 + AP06). The DC/CA is a single block that
  # serves BOTH hybrid paths. need_dc = enable_ap05 || enable_ap06:
  # when enable_ap05=true, need_dc is IDENTICALLY true regardless of
  # enable_ap06 -> every expression rewritten from var.enable_ap05 to
  # local.need_dc evaluates the same in the AP05-only scenario (same count,
  # same [0], zero-diff plan). The AP05 artifacts (CA/ESC1) stay gated on
  # enable_ap05 (seed-ap05); the AP06 ones (AZUREADSSOACC$/sync account) on
  # enable_ap06 (seed-ap06). Reset with BOTH flags false -> need_dc=false ->
  # destroys the single DC and with it every AD object of AP05+AP06.
  # ----------------------------------------------------------------
  need_dc = var.enable_ap05 || var.enable_ap06

  # Conditional short-circuit: does not index [0] when the DC does not exist.
  suffix = local.need_dc ? random_string.suffix[0].result : ""

  rg_name = "${var.lab_prefix}-ap05-rg"
  vm_name = "${var.lab_prefix}-ap05-dc"
  # DSC package storage: 3-24 lowercase alphanumeric, NO hyphens.
  sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap05dsc${local.suffix}"

  # Azure forbids 'Administrator' as the VM admin; this local SAM admin
  # DISAPPEARS when the DC is promoted (which is why the DSC set+enables the built-in).
  admin_username = "aetheradmin"

  lowpriv_upn = "${var.lowpriv_user_name}@${var.domain_fqdn}"

  # DA password: override via dc_admin_password (sensitive) or random.
  # try() protects the [0] when random_password.dc_admin has count 0.
  dc_admin_password = local.need_dc ? coalesce(var.dc_admin_password, try(random_password.dc_admin[0].result, null)) : null

  # SEPARATE password for the VM's local admin (aetheradmin), which disappears on DC
  # promotion. Distinct from the domain EA so one leak is not both. [SECURITY.md L-3]
  vm_local_admin_password = local.need_dc ? try(random_password.vm_admin[0].result, null) : null

  # NSG rules only if the operator supplies a CIDR (secure-by-default). Never 0.0.0.0/0.
  # RDP (3389) only by default; WinRM (5985/5986) is NOT needed for seeding (that goes
  # through az vm run-command, control plane) and stays behind expose_winrm. [SECURITY.md L-4]
  nsg_rules = local.need_dc && var.admin_source_cidr != null ? concat(
    [{ name = "allow-rdp-inbound", priority = 1001, port = "3389" }],
    var.expose_winrm ? [
      { name = "allow-winrm-inbound", priority = 1002, port = "5985" },
      { name = "allow-winrms-inbound", priority = 1003, port = "5986" },
    ] : []
  ) : []
}

# ------------------------------------------------------------------
# Globally unique suffix (the storage account is a global namespace).
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
# Secrets (never hardcoded). Windows-safe set + 4 guaranteed categories
# so the VM resource does not fail Azure's complexity requirement.
#   - dc_admin : only if dc_admin_password is not supplied (sensitive override).
#   - dsrm     : SafeMode Administrator Password of the DC.
#   - lowpriv  : password of the attacker's starting user.
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

# VM local admin (aetheradmin), distinct from the domain EA. [SECURITY.md L-3]
resource "random_password" "vm_admin" {
  count            = local.need_dc ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

# ------------------------------------------------------------------
# Container resource group (blast radius scoped to the RG; reset = destroy).
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
# DC network: VNet 10.105.0.0/16 + subnet + static Standard public IP
# + NSG (no open SSH: a DC is not exposed to the Internet) + NIC.
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

# Public IP only when the operator supplies admin_source_cidr (i.e. wants RDP). With
# the null default there is NO public IP: seeding/verify go through az vm run-command
# (control plane), and the serial console works via boot_diagnostics. [SECURITY.md M-7]
resource "azurerm_public_ip" "ap05" {
  count               = local.need_dc && var.admin_source_cidr != null ? 1 : 0
  name                = "${var.lab_prefix}-ap05-pip"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# NSG: DELIBERATE divergence vs AP02's open SSH. RDP/WinRM ONLY to the
# operator's CIDR; if admin_source_cidr is null, NO allow rule at all
# (access via Bastion/serial-console). NEVER 0.0.0.0/0 (validated in var).
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
    public_ip_address_id          = var.admin_source_cidr != null ? azurerm_public_ip.ap05[0].id : null
  }
}

resource "azurerm_network_interface_security_group_association" "ap05" {
  count                     = local.need_dc ? 1 : 0
  network_interface_id      = azurerm_network_interface.ap05[0].id
  network_security_group_id = azurerm_network_security_group.ap05[0].id
}

# ==================================================================
# DC+CA VM: Windows Server 2022 Datacenter Gen2, Standard_B2ms.
# admin 'aetheradmin' (local SAM that disappears on promotion: which is why
# the DSC set+enables the built-in Administrator with dc_admin_password).
# ==================================================================
resource "azurerm_windows_virtual_machine" "dc" {
  count               = local.need_dc ? 1 : 0
  name                = local.vm_name
  computer_name       = "DC01"
  location            = azurerm_resource_group.ap05[0].location
  resource_group_name = azurerm_resource_group.ap05[0].name
  size                = var.vm_size

  admin_username = local.admin_username
  admin_password = local.vm_local_admin_password

  network_interface_ids = [azurerm_network_interface.ap05[0].id]

  # Serial console / boot diagnostics (managed storage), so the DC is reachable
  # even with admin_source_cidr=null and no public IP. [SECURITY.md M-7]
  boot_diagnostics {}

  # Managed identity (system-assigned): the Azure Monitor Agent (AMA, in
  # monitoring.tf) authenticates to Azure Monitor with the VM's MI. WITHOUT
  # it AMA installs but CANNOT ship the SecurityEvents to the DCR/workspace
  # -> 'Detect' would be broken SILENTLY (apply OK but zero ingestion, which is
  # the ONLY path by which these on-prem events reach a SIEM). The DC does not
  # need it for the attack; AMA does.
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
# Daily auto-shutdown: cost discipline (AP05 is, together with AP02, the only
# AP that bills compute, and the most expensive). Pattern identical to AP02.
# Deploy during the day: a shutdown mid-DCPromo breaks the bootstrap.
# ------------------------------------------------------------------
resource "azurerm_dev_test_global_vm_shutdown_schedule" "dc" {
  count              = local.need_dc ? 1 : 0
  virtual_machine_id = azurerm_windows_virtual_machine.dc[0].id
  location           = azurerm_resource_group.ap05[0].location
  enabled            = true

  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

# ==================================================================
# DSC configuration packaging (AP02 storage pattern).
#   archive_file zips dsc/ (only AetherDC.ps1) -> storage -> blob -> SAS
#   -> extension. The configurationData.psd1 (allow domain-user/plaintext,
#   needed because the enterprise CA uses a qualified domain credential)
#   is uploaded as a SEPARATE source_content blob -> the zip keeps ONLY the .ps1.
#   output_path goes to the module ROOT (sibling of dsc/, without recursive
#   auto-inclusion): a .dsc-build/ subdir may not exist and some versions of
#   hashicorp/archive do NOT create the parent directory -> failure at plan/apply.
#   The generated .zip is in .gitignore.
# ==================================================================
data "archive_file" "dsc" {
  count       = local.need_dc ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/dsc"
  output_path = "${path.module}/AetherDC.zip"
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
  name                   = "AetherDC.zip"
  storage_account_name   = azurerm_storage_account.dsc[0].name
  storage_container_name = azurerm_storage_container.dsc[0].name
  type                   = "Block"
  source                 = data.archive_file.dsc[0].output_path
  content_md5            = data.archive_file.dsc[0].output_md5
}

# ConfigurationData: enables the domain credential and bypasses the plaintext
# guard when compiling the MOF on the VM. Separate blob (not in the zip).
resource "azurerm_storage_blob" "dsc_configdata" {
  count                  = local.need_dc ? 1 : 0
  name                   = "AetherDC.ConfigData.psd1"
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

# Read SAS so the extension can download the blobs. STATIC dates
# (not timestamp()) so protected_settings is not regenerated and the
# extension is not re-run on every apply. Wide window: only used during deploy.
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
# DSC extension (the ONLY reboot-aware option). type="DSC",
# publisher="Microsoft.Powershell". The config brings up ONLY the BENIGN BASE
# (forest + Enterprise Root CA + auditing + low-priv user +
# StrongCertificateBindingEnforcement). The ESC1 template is seeded by
# seed-ap05.ps1 (post-apply, via az vm run-command).
#
# Credentials via protected_settings.configurationArguments (ENCRYPTED),
# NEVER in cleartext settings. timeouts so a hung DSC FAILS
# (known failure mode) instead of hanging `terraform apply`.
# ==================================================================
resource "azurerm_virtual_machine_extension" "dsc" {
  count                      = local.need_dc ? 1 : 0
  name                       = "AetherDC"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc[0].id
  publisher                  = "Microsoft.Powershell"
  type                       = "DSC"
  type_handler_version       = "2.83"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    wmfVersion = "latest"
    configuration = {
      url      = azurerm_storage_blob.dsc[0].url
      script   = "AetherDC.ps1"
      function = "AetherDC"
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
