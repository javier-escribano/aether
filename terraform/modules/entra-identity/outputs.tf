output "user_principal_names" {
  value = azuread_user.lab[*].user_principal_name
}

output "lab_user_credentials" {
  description = "UPN -> password for the base lab users. SENSITIVE output so you can read them with 'terraform output -json lab_user_credentials' instead of dumping the whole (toxic) state. [SECURITY.md H-5]"
  sensitive   = true
  value       = { for i, u in azuread_user.lab : u.user_principal_name => random_password.user[i].result }
}

output "ap01_app_id" {
  value = var.enable_ap01 ? azuread_application.ap01[0].client_id : null
}

output "ap01_consent_url" {
  value = var.enable_ap01 ? join("", [
    "https://login.microsoftonline.com/${var.tenant_domain}/oauth2/v2.0/authorize",
    "?client_id=${azuread_application.ap01[0].client_id}",
    "&response_type=code",
    "&redirect_uri=https%3A%2F%2Flocalhost%2Faether-ap01",
    "&response_mode=query",
    "&scope=offline_access%20Mail.Read%20Files.Read.All"
  ]) : null
}

# --- AP03 (null when enable_ap03 = false) ---
output "ap03_group_object_id" {
  value = var.enable_ap03 ? azuread_group.ap03_role_admins[0].object_id : null
}

output "ap03_target_role" {
  value = var.enable_ap03 ? local.ap03_target_role_name : null
}

output "ap03_attacker_hint" {
  value = var.enable_ap03 ? join("", [
    "You are the OWNER of the role-assignable group ", azuread_group.ap03_role_admins[0].display_name, ". ",
    "Add yourself as a member (POST /groups/<id>/members/$ref), re-authenticate to inherit ",
    "Privileged Role Administrator, and assign yourself Global Administrator."
  ]) : null
}

# --- AP04 (null when enable_ap04 = false) ---
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
    "You are the OWNER of the app registration ", azuread_application.ap04_app[0].display_name, ". ",
    "Add a client secret (az ad app credential reset --id ", azuread_application.ap04_app[0].client_id, "), ",
    "authenticate as the SP via client_credentials and, with RoleManagement.ReadWrite.Directory, ",
    "POST /roleManagement/directory/roleAssignments to assign Global Administrator (62e90394-69f5-4237-9190-012177145e10)."
  ]) : null
}
