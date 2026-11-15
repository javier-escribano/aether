# ==================================================================
# Module: azure-resources
# Azure resource layer of the range + AP02 via the enable_ap02 flag.
#
# AP02 - over-privileged system-assigned Managed Identity on a Linux
# VM -> token theft via IMDS (169.254.169.254) -> self-grant on a
# Key Vault in access-policy mode -> theft of a service principal's
# client secret -> lateral movement to storage.
#
# Pattern: every VULNERABLE resource is wrapped in
#   count = var.enable_ap02 ? 1 : 0
# so that `reset` (apply with enable_ap02=false) reverts the declared
# state, including the access policy the attacker modifies OUTSIDE
# Terraform with `az keyvault set-policy`.
#
# 100% declarative deployment: no post-deployment seed
# (orchestrator_hook = "none"). The initial access (lab credential on
# the VM), the secret, the loot blob, and the role assignments are all
# wired by Terraform.
# ==================================================================

# Principal running Terraform (for the KV data access policy and the
# vault's tenant_id). Gated by enable_ap02: an AP01-ONLY (identity)
# deployment does not evaluate an azurerm context.
data "azurerm_client_config" "current" {
  count = var.enable_ap02 ? 1 : 0
}

locals {
  # --- Names (spec VERBATIM) ----------------------------------------
  # DNS-safe suffix reused by Key Vault and the storage account.
  # Conditional short-circuit: does not index [0] when the flag is false.
  suffix = var.enable_ap02 ? random_string.suffix[0].result : ""

  rg_name = "${var.lab_prefix}-ap02-rg"
  vm_name = "${var.lab_prefix}-ap02-web"
  sp_name = "${var.lab_prefix}-ap02-automation"

  # Key Vault: base 'azrange-ap02-kv-' (16) + suffix 4-6 => <=24 chars.
  kv_name = "${var.lab_prefix}-ap02-kv-${local.suffix}"

  # Storage: 3-24 lowercase alphanumeric, NO hyphens.
  sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap02data${local.suffix}"

  secret_name = "automation-sp-secret"

  # Initial access to the VM (represents a prior RCE/webshell, teaching
  # level). Port 22 is opened to the Internet on purpose.
  admin_username = "azrangeadmin"
}

# ------------------------------------------------------------------
# Unique global suffix (Key Vault + storage are global namespaces).
# length 4-6, lower+numeric, no hyphens => no consecutive hyphens.
# ------------------------------------------------------------------
resource "random_string" "suffix" {
  count   = var.enable_ap02 ? 1 : 0
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# ------------------------------------------------------------------
# Resource group containing the whole path (bounded blast radius).
# ------------------------------------------------------------------
resource "azurerm_resource_group" "ap02" {
  count    = var.enable_ap02 ? 1 : 0
  name     = local.rg_name
  location = var.location

  tags = {
    range       = var.lab_prefix
    attack_path = "AP02"
  }
}

# ==================================================================
# Minimal network for the pivot host: VNet + subnet + Standard public IP
# + NSG with SSH/22 open (teaching) + associated NIC.
# ==================================================================
resource "azurerm_virtual_network" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = "${var.lab_prefix}-ap02-vnet"
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  address_space       = ["10.102.0.0/16"]
}

resource "azurerm_subnet" "ap02" {
  count                = var.enable_ap02 ? 1 : 0
  name                 = "${var.lab_prefix}-ap02-subnet"
  resource_group_name  = azurerm_resource_group.ap02[0].name
  virtual_network_name = azurerm_virtual_network.ap02[0].name
  address_prefixes     = ["10.102.1.0/24"]
}

resource "azurerm_public_ip" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = "${var.lab_prefix}-ap02-pip"
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  # The Standard SKU requires static allocation.
  allocation_method = "Static"
  sku               = "Standard"
}

resource "azurerm_network_security_group" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = "${var.lab_prefix}-ap02-nsg"
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name

  # Teaching MISCONFIG: SSH exposed to the Internet (remediation: restrict
  # to admin IPs or use Bastion).
  security_rule {
    name                       = "allow-ssh-inbound"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.ap02_ssh_source_cidr # default "*" (teaching); set your /32 to lock it down [SECURITY.md L-5]
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = "${var.lab_prefix}-ap02-nic"
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.ap02[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.ap02[0].id
  }
}

resource "azurerm_network_interface_security_group_association" "ap02" {
  count                     = var.enable_ap02 ? 1 : 0
  network_interface_id      = azurerm_network_interface.ap02[0].id
  network_security_group_id = azurerm_network_security_group.ap02[0].id
}

# ------------------------------------------------------------------
# Lab credential for the host (seeded initial access).
# ------------------------------------------------------------------
resource "random_password" "vm" {
  count   = var.enable_ap02 ? 1 : 0
  length  = 24
  special = true
}

# ==================================================================
# Pivot host azrange-ap02-web: Ubuntu 22.04 LTS, Standard_B1s (cheapest
# SKU), with a system-assigned Managed Identity.
# ==================================================================
resource "azurerm_linux_virtual_machine" "web" {
  count               = var.enable_ap02 ? 1 : 0
  name                = local.vm_name
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  size                = "Standard_B1s"

  admin_username                  = local.admin_username
  admin_password                  = random_password.vm[0].result
  disable_password_authentication = false # password access (lab)

  network_interface_ids = [azurerm_network_interface.ap02[0].id]

  # Vulnerable primitive: system-assigned identity. This MI's token is
  # what the attacker steals against IMDS (169.254.169.254).
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # the cheapest disk
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

# ------------------------------------------------------------------
# Auto-shutdown: cost discipline (this is the only AP that bills compute).
# ------------------------------------------------------------------
resource "azurerm_dev_test_global_vm_shutdown_schedule" "web" {
  count              = var.enable_ap02 ? 1 : 0
  virtual_machine_id = azurerm_linux_virtual_machine.web[0].id
  location           = azurerm_resource_group.ap02[0].location
  enabled            = true

  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

# ==================================================================
# PRIVILEGE EXCESS (core of AP02):
# the VM's system-assigned MI is granted Contributor over the WHOLE RG.
# Contributor includes Microsoft.KeyVault/vaults/accessPolicies/write =>
# the MI can rewrite the Key Vault access policy and self-grant itself
# data permission on the secrets (self-grant).
# Correct minimal role: 'Key Vault Secrets User' on a SINGLE secret.
# ==================================================================
resource "azurerm_role_assignment" "vm_contributor" {
  count                = var.enable_ap02 ? 1 : 0
  scope                = azurerm_resource_group.ap02[0].id
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.web[0].identity[0].principal_id

  # The freshly created MI may not have replicated in AAD yet when the role
  # assignment is created -> avoids intermittent apply failures (PrincipalNotFound).
  skip_service_principal_aad_check = true
}

# ==================================================================
# Key Vault in ACCESS-POLICY mode (legacy). The VM's MI does NOT have
# a data access policy on purpose: it must self-grant one by abusing
# Contributor. purge_protection=false and soft_delete=7 days for a
# clean redeploy (plus the random suffix avoids name collisions).
#
# Documented remediation: enable_rbac_authorization = true -> under RBAC
# Contributor does NOT grant the data plane NOR allow self-assigning data
# roles; the self-grant disappears.
# ==================================================================
resource "azurerm_key_vault" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = local.kv_name
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  tenant_id           = data.azurerm_client_config.current[0].tenant_id
  sku_name            = "standard"

  # Access model per the spec:
  enable_rbac_authorization = false

  # Clean teardown/redeploy:
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # Access policy ONLY for the principal deploying Terraform, so that it
  # can plant the loot secret. The VM's MI is deliberately left out (that
  # is the weak point the student exploits).
  access_policy {
    tenant_id = data.azurerm_client_config.current[0].tenant_id
    object_id = data.azurerm_client_config.current[0].object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Purge",
      "Recover",
    ]
  }
}

# ==================================================================
# Lateral-pivot identity: service principal azrange-ap02-automation.
# Its client secret is wired declaratively into the Key Vault. Stealing it
# yields a reusable IDENTITY of broader scope than the VM's ephemeral MI.
# ==================================================================
resource "azuread_application" "automation" {
  count        = var.enable_ap02 ? 1 : 0
  display_name = local.sp_name
}

resource "azuread_service_principal" "automation" {
  count     = var.enable_ap02 ? 1 : 0
  client_id = azuread_application.automation[0].client_id
}

# azuread ~>2.53: the app password uses application_object_id.
resource "azuread_application_password" "automation" {
  count                 = var.enable_ap02 ? 1 : 0
  application_object_id = azuread_application.automation[0].object_id
  display_name          = "azrange-ap02-automation-secret"
}

# ------------------------------------------------------------------
# Loot secret: the value IS the automation SP's client secret.
#   data plane VM->MI->KV->SP->storage.
# ------------------------------------------------------------------
resource "azurerm_key_vault_secret" "automation" {
  count        = var.enable_ap02 ? 1 : 0
  name         = local.secret_name
  value        = azuread_application_password.automation[0].value
  key_vault_id = azurerm_key_vault.ap02[0].id
}

# ==================================================================
# Lateral-movement target: storage account + loot blob.
# The automation SP is granted 'Storage Blob Data Contributor' on the
# storage; stealing the SP's secret enables reading flag.txt.
# ==================================================================
resource "azurerm_storage_account" "loot" {
  count                    = var.enable_ap02 ? 1 : 0
  name                     = local.sa_name
  resource_group_name      = azurerm_resource_group.ap02[0].name
  location                 = azurerm_resource_group.ap02[0].location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "loot" {
  count                 = var.enable_ap02 ? 1 : 0
  name                  = "loot"
  storage_account_name  = azurerm_storage_account.loot[0].name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "flag" {
  count                  = var.enable_ap02 ? 1 : 0
  name                   = "flag.txt"
  storage_account_name   = azurerm_storage_account.loot[0].name
  storage_container_name = azurerm_storage_container.loot[0].name
  type                   = "Block"
  source_content         = "AZRANGE{ap02_vm_mi_to_keyvault_to_sp_to_storage}\n"
}

# SP data permission on the storage (closes the lateral chain).
resource "azurerm_role_assignment" "automation_blob" {
  count                = var.enable_ap02 ? 1 : 0
  scope                = azurerm_storage_account.loot[0].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azuread_service_principal.automation[0].object_id

  # The SP is created in the SAME apply; without this flag Microsoft.Authorization
  # may reject the assignment due to slow AAD replication (PrincipalNotFound).
  skip_service_principal_aad_check = true
}
