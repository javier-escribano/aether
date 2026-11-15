# ==================================================================
# Modulo: azure-resources
# Capa de recursos Azure del range + AP02 por flag enable_ap02.
#
# AP02 - Managed Identity (system-assigned) sobre-privilegiada en una
# VM Linux -> robo de token via IMDS (169.254.169.254) -> self-grant
# sobre un Key Vault en modo access-policy -> robo del client secret
# de un service principal -> movimiento lateral a storage.
#
# Patron: cada recurso VULNERABLE va envuelto en
#   count = var.enable_ap02 ? 1 : 0
# de modo que `reset` (apply con enable_ap02=false) revierte el estado
# declarado, incluida la access policy que el atacante modifica FUERA
# de Terraform con `az keyvault set-policy`.
#
# Despliegue 100% declarativo: sin seed de post-despliegue
# (orchestrator_hook = "none"). El acceso inicial (credencial de
# laboratorio en la VM), el secreto, el blob botin y las role
# assignments los cablea Terraform.
# ==================================================================

# Principal que ejecuta Terraform (para la access policy de datos del KV y el
# tenant_id del vault). Gated por enable_ap02: un despliegue SOLO-AP01 (identidad)
# no evalua contexto azurerm.
data "azurerm_client_config" "current" {
  count = var.enable_ap02 ? 1 : 0
}

locals {
  # --- Nombres (spec VERBATIM) --------------------------------------
  # Sufijo DNS-safe reutilizado por Key Vault y storage account.
  # Conditional short-circuit: no indexa [0] cuando el flag esta a false.
  suffix = var.enable_ap02 ? random_string.suffix[0].result : ""

  rg_name = "${var.lab_prefix}-ap02-rg"
  vm_name = "${var.lab_prefix}-ap02-web"
  sp_name = "${var.lab_prefix}-ap02-automation"

  # Key Vault: base 'caelum-ap02-kv-' (15) + sufijo 4-6 => <=24 chars.
  kv_name = "${var.lab_prefix}-ap02-kv-${local.suffix}"

  # Storage: 3-24 lowercase alfanumerico, SIN guiones.
  sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap02data${local.suffix}"

  secret_name = "automation-sp-secret"

  # Acceso inicial a la VM (representa un RCE/webshell previo, nivel
  # didactico). El puerto 22 se abre a Internet a proposito.
  admin_username = "caelumadmin"
}

# ------------------------------------------------------------------
# Sufijo global unico (Key Vault + storage son namespaces globales).
# length 4-6, lower+numeric, sin guiones => sin guiones consecutivos.
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
# Resource group contenedor de toda la ruta (blast radius acotado).
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
# Red minima para el host pivote: VNet + subnet + IP publica Standard
# + NSG con SSH/22 abierto (didactico) + NIC asociada.
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
  # SKU Standard exige asignacion estatica.
  allocation_method = "Static"
  sku               = "Standard"
}

resource "azurerm_network_security_group" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = "${var.lab_prefix}-ap02-nsg"
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name

  # MISCONFIG didactica: SSH expuesto a Internet (remediacion: restringir
  # a IPs de administracion o usar Bastion).
  security_rule {
    name                       = "allow-ssh-inbound"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
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
# Credencial de laboratorio del host (acceso inicial sembrado).
# ------------------------------------------------------------------
resource "random_password" "vm" {
  count   = var.enable_ap02 ? 1 : 0
  length  = 24
  special = true
}

# ==================================================================
# Host pivote caelum-ap02-web: Ubuntu 22.04 LTS, Standard_B1s (SKU mas
# barata), con system-assigned Managed Identity.
# ==================================================================
resource "azurerm_linux_virtual_machine" "web" {
  count               = var.enable_ap02 ? 1 : 0
  name                = local.vm_name
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  size                = "Standard_B1s"

  admin_username                  = local.admin_username
  admin_password                  = random_password.vm[0].result
  disable_password_authentication = false # acceso por password (lab)

  network_interface_ids = [azurerm_network_interface.ap02[0].id]

  # Primitiva vulnerable: identidad asignada por el sistema. El token de
  # esta MI es lo que el atacante roba contra el IMDS (169.254.169.254).
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # el disco mas barato
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

# ------------------------------------------------------------------
# Auto-shutdown: disciplina de coste (es el unico AP que factura computo).
# ------------------------------------------------------------------
resource "azurerm_dev_test_global_vm_shutdown_schedule" "web" {
  count              = var.enable_ap02 ? 1 : 0
  virtual_machine_id = azurerm_linux_virtual_machine.web[0].id
  location           = azurerm_resource_group.ap02[0].location
  enabled            = true

  daily_recurrence_time = "2200"
  timezone              = "W. Europe Standard Time"

  notification_settings {
    enabled = false
  }
}

# ==================================================================
# EXCESO DE PRIVILEGIO (nucleo de AP02):
# la system-assigned MI de la VM recibe Contributor sobre TODO el RG.
# Contributor incluye Microsoft.KeyVault/vaults/accessPolicies/write =>
# la MI puede reescribir la access policy del Key Vault y auto-
# concederse permiso de datos sobre los secretos (self-grant).
# Rol minimo correcto: 'Key Vault Secrets User' sobre UN solo secreto.
# ==================================================================
resource "azurerm_role_assignment" "vm_contributor" {
  count                = var.enable_ap02 ? 1 : 0
  scope                = azurerm_resource_group.ap02[0].id
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.web[0].identity[0].principal_id

  # La MI recien creada puede no haberse replicado aun en AAD al crear la role
  # assignment -> evita fallos intermitentes de apply (PrincipalNotFound).
  skip_service_principal_aad_check = true
}

# ==================================================================
# Key Vault en modo ACCESS-POLICY (legacy). La MI de la VM NO tiene
# access policy de datos a proposito: debe auto-concedersela abusando
# de Contributor. purge_protection=false y soft_delete=7 dias para
# redeploy limpio (ademas el sufijo random evita colisiones de nombre).
#
# Remediacion documentada: enable_rbac_authorization = true -> en RBAC
# Contributor NO otorga plano de datos NI permite auto-asignarse roles
# de datos; el self-grant desaparece.
# ==================================================================
resource "azurerm_key_vault" "ap02" {
  count               = var.enable_ap02 ? 1 : 0
  name                = local.kv_name
  location            = azurerm_resource_group.ap02[0].location
  resource_group_name = azurerm_resource_group.ap02[0].name
  tenant_id           = data.azurerm_client_config.current[0].tenant_id
  sku_name            = "standard"

  # Modelo de acceso de la spec:
  enable_rbac_authorization = false

  # Teardown/redeploy limpio:
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # Access policy SOLO para el principal que despliega Terraform, de modo
  # que pueda plantar el secreto botin. La MI de la VM queda deliberada-
  # mente fuera (ese es el punto debil que el alumno explota).
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
# Identidad de pivote lateral: service principal caelum-ap02-automation.
# Su client secret se cablea declarativamente al Key Vault. Robarlo da
# una IDENTIDAD reutilizable de mayor alcance que la MI efimera de la VM.
# ==================================================================
resource "azuread_application" "automation" {
  count        = var.enable_ap02 ? 1 : 0
  display_name = local.sp_name
}

resource "azuread_service_principal" "automation" {
  count     = var.enable_ap02 ? 1 : 0
  client_id = azuread_application.automation[0].client_id
}

# azuread ~>2.53: el password del app usa application_object_id.
resource "azuread_application_password" "automation" {
  count                 = var.enable_ap02 ? 1 : 0
  application_object_id = azuread_application.automation[0].object_id
  display_name          = "caelum-ap02-automation-secret"
}

# ------------------------------------------------------------------
# Secreto botin: el valor ES el client secret del SP automation.
#   plano de datos VM->MI->KV->SP->storage.
# ------------------------------------------------------------------
resource "azurerm_key_vault_secret" "automation" {
  count        = var.enable_ap02 ? 1 : 0
  name         = local.secret_name
  value        = azuread_application_password.automation[0].value
  key_vault_id = azurerm_key_vault.ap02[0].id
}

# ==================================================================
# Objetivo del movimiento lateral: storage account + blob botin.
# El SP automation recibe 'Storage Blob Data Contributor' sobre el
# storage; el robo del secreto del SP habilita leer flag.txt.
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
  source_content         = "CAELUM{ap02_vm_mi_to_keyvault_to_sp_to_storage}\n"
}

# Permiso de datos del SP sobre el storage (cierre de la cadena lateral).
resource "azurerm_role_assignment" "automation_blob" {
  count                = var.enable_ap02 ? 1 : 0
  scope                = azurerm_storage_account.loot[0].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azuread_service_principal.automation[0].object_id

  # El SP se crea en el MISMO apply; sin este flag Microsoft.Authorization puede
  # rechazar la asignacion por replicacion AAD lenta (PrincipalNotFound).
  skip_service_principal_aad_check = true
}
