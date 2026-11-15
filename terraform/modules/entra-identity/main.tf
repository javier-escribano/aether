# ==================================================================
# Module: entra-identity
# Range identity baseline + AP01 (illicit consent) behind a flag.
# ==================================================================

locals {
  # Microsoft Graph (resource app id, fixed across all tenants)
  graph_app_id = "00000003-0000-0000-c000-000000000000"

  # Graph DELEGATED permission IDs that the AP01 vulnerable app will request.
  # Deliberately high value: mail and file read access + refresh token.
  ap01_delegated_scopes = {
    "User.Read"      = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
    "offline_access" = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
    "Mail.Read"      = "570282fd-fa5c-430d-a7fd-fc8dc98a9dca"
    "Files.Read.All" = "df85f4d6-205c-4ac5-a5ea-6bf408dba283"
  }

  ap01_redirect = "https://localhost/aether-ap01"
}

# ---- Base synthetic users ----------------------------------------
resource "random_password" "user" {
  count   = var.user_count
  length  = 20
  special = true
}

resource "azuread_user" "lab" {
  count = var.user_count

  user_principal_name   = "${var.lab_prefix}-user${count.index + 1}@${var.tenant_domain}"
  display_name          = "AETHER Lab User ${count.index + 1}"
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
# AP01 — "NewsletterSync" app (decoy name) that requests dangerous scopes.
# The vulnerable condition is completed in scripts/seed-ap01.ps1:
#   - sets the permissive user-consent policy (lets any user consent)
#   - (optional) pre-creates the delegated grant to show the token abuse directly.
# ==================================================================
resource "azuread_application" "ap01" {
  count        = var.enable_ap01 ? 1 : 0
  display_name = "${var.lab_prefix}-ap01-NewsletterSync"

  # Single-tenant: the illicit-consent lesson works entirely within the lab tenant,
  # and this avoids leaving a consent-phishing app + SP/grants in OTHER tenants if
  # someone opens the consent URL while signed into a different org. [SECURITY.md M-8]
  sign_in_audience = "AzureADMyOrg"

  required_resource_access {
    resource_app_id = local.graph_app_id

    dynamic "resource_access" {
      for_each = local.ap01_delegated_scopes
      content {
        id   = resource_access.value
        type = "Scope" # delegated
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
