# ==================================================================
# Módulo: entra-identity
# Base de identidad del range + AP01 (illicit consent) por flag.
# ==================================================================

locals {
  # Microsoft Graph (resource app id fijo en todos los tenants)
  graph_app_id = "00000003-0000-0000-c000-000000000000"

  # IDs de permisos DELEGADOS de Graph que pedirá el app vulnerable de AP01.
  # Alto valor a propósito: lectura de correo y ficheros + refresh token.
  ap01_delegated_scopes = {
    "User.Read"      = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
    "offline_access" = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
    "Mail.Read"      = "570282fd-fa5c-430d-a7fd-fc8dc98a9dca"
    "Files.Read.All" = "df85f4d6-205c-4ac5-a5ea-6bf408dba283"
  }

  ap01_redirect = "https://localhost/caelum-ap01"
}

# ---- Usuarios ficticios base -------------------------------------
resource "random_password" "user" {
  count   = var.user_count
  length  = 20
  special = true
}

resource "azuread_user" "lab" {
  count = var.user_count

  user_principal_name   = "${var.lab_prefix}-user${count.index + 1}@${var.tenant_domain}"
  display_name          = "Caelum Lab User ${count.index + 1}"
  mail_nickname         = "${var.lab_prefix}-user${count.index + 1}"
  password              = random_password.user[count.index].result
  force_password_change = false
}

resource "azuread_group" "staff" {
  display_name     = "${var.lab_prefix}-staff"
  security_enabled = true
  members          = azuread_user.lab[*].object_id
}

# ==================================================================
# AP01 — app "NewsletterSync" (nombre señuelo) que pide scopes peligrosos.
# La condición vulnerable se completa en scripts/seed-ap01.ps1:
#   - fija la user-consent policy permisiva (deja que cualquier usuario consienta)
#   - (opcional) pre-crea el grant delegado para ver el token abuse directo.
# ==================================================================
resource "azuread_application" "ap01" {
  count        = var.enable_ap01 ? 1 : 0
  display_name = "${var.lab_prefix}-ap01-NewsletterSync"

  sign_in_audience = "AzureADMultipleOrgs"

  required_resource_access {
    resource_app_id = local.graph_app_id

    dynamic "resource_access" {
      for_each = local.ap01_delegated_scopes
      content {
        id   = resource_access.value
        type = "Scope" # delegado
      }
    }
  }

  web {
    redirect_uris = [local.ap01_redirect]
  }
}

resource "azuread_service_principal" "ap01" {
  count     = var.enable_ap01 ? 1 : 0
  client_id = azuread_application.ap01[0].client_id
}
