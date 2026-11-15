output "user_principal_names" {
  value = azuread_user.lab[*].user_principal_name
}

output "ap01_app_id" {
  value = var.enable_ap01 ? azuread_application.ap01[0].client_id : null
}

output "ap01_consent_url" {
  value = var.enable_ap01 ? join("", [
    "https://login.microsoftonline.com/${var.tenant_domain}/oauth2/v2.0/authorize",
    "?client_id=${azuread_application.ap01[0].client_id}",
    "&response_type=code",
    "&redirect_uri=https%3A%2F%2Flocalhost%2Fcaelum-ap01",
    "&response_mode=query",
    "&scope=offline_access%20Mail.Read%20Files.Read.All"
  ]) : null
}

# --- AP03 (null si enable_ap03 = false) ---
output "ap03_group_object_id" {
  value = var.enable_ap03 ? azuread_group.ap03_role_admins[0].object_id : null
}

output "ap03_target_role" {
  value = var.enable_ap03 ? local.ap03_target_role_name : null
}

output "ap03_attacker_hint" {
  value = var.enable_ap03 ? join("", [
    "Eres OWNER del grupo role-assignable ", azuread_group.ap03_role_admins[0].display_name, ". ",
    "Auto-anadete como miembro (POST /groups/<id>/members/$ref), re-autentica para heredar ",
    "Privileged Role Administrator y auto-asignate Global Administrator."
  ]) : null
}

# --- AP04 (null si enable_ap04 = false) ---
output "ap04_app_id" {
  value = var.enable_ap04 ? azuread_application.ap04_app[0].client_id : null
}

output "ap04_sp_object_id" {
  value = var.enable_ap04 ? azuread_service_principal.ap04_app[0].object_id : null
}

output "ap04_graph_app_role" {
  value = var.enable_ap04 ? local.ap04_graph_app_role_name : null
}

output "ap04_attacker_hint" {
  value = var.enable_ap04 ? join("", [
    "Eres OWNER del app registration ", azuread_application.ap04_app[0].display_name, ". ",
    "Anade un client secret (az ad app credential reset --id ", azuread_application.ap04_app[0].client_id, "), ",
    "autenticate como el SP via client_credentials y, con RoleManagement.ReadWrite.Directory, ",
    "POST /roleManagement/directory/roleAssignments asignando Global Administrator (62e90394-69f5-4237-9190-012177145e10)."
  ]) : null
}
