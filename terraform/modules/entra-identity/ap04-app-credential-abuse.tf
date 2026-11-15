# ==================================================================
# AP04 — App registration with a dangerous Microsoft Graph APPLICATION
# permission + low-privilege owner (credential abuse / service
# principal persistence).
#
# 100% DECLARATIVE core (no seed, needs_seed=none). The vulnerable
# combination is three facts that Terraform sets:
#   (a) azuread_user.lab[0] (aether-user1), a LOW-privilege user, is
#       the ONLY owner of the app registration (owners = [...]) -> by
#       default in Entra, an app owner can ADD credentials (client
#       secret / certificate) to that app,
#   (b) the app's service principal carries the Graph app role
#       (APPLICATION permission, app-only) RoleManagement.ReadWrite.Directory,
#       granted with ADMIN CONSENT via azuread_app_role_assignment, and
#   (c) that app role is Tier-0: it GUARANTEES single-hop escalation to
#       Global Administrator (SpecterOps documents it as one of the only
#       two Graph app roles that guarantee it; the other is
#       AppRoleAssignment.ReadWrite.All).
#
# The EXPLOITATION STEP is NOT seeded: it is DEFAULT Entra behavior. The
# owner adds a secret to the app (az ad app credential reset --append /
# Add-MgApplicationPassword), authenticates as the SP via OAuth2
# client_credentials -> an app-only Graph token carrying
# RoleManagement.ReadWrite.Directory, and POST
# /roleManagement/directory/roleAssignments assigns themselves Global
# Administrator (roleDefinitionId 62e90394-69f5-4237-9190-012177145e10,
# directoryScopeId '/'). The added secret remains as a persistent
# app-only BACKDOOR (it survives the user's password reset and MFA; SPs
# do not enforce it). This is the canonical AZOwns -> app registration ->
# AZMGRoleManagement_ReadWrite_Directory edge from BloodHound/AzureHound.
#
# MITRE ATT&CK: T1098.001 (Account Manipulation: Additional Cloud
# Credentials) -CORE- -> T1098.003 (Additional Cloud Roles) ->
# T1078.004 (Valid Accounts: Cloud Accounts). Recon: T1087.004.
#
# CONTRAST with AP03 (same class, different object): AP03 = ownership of
# a role-assignable GROUP (directory role inheritance); AP04 = ownership
# of an APP REGISTRATION (abuse of the Graph application permission +
# credentials). Both are Tier-0 ownership abuse.
#
# PRECONDITIONS (deploy permissions, NOT a magic vulnerable state):
#   - DEPLOY PERMISSIONS: RoleManagement.ReadWrite.Directory has
#     AdminConsentRequired=Yes. The principal running `terraform apply`
#     must hold Global Administrator or Privileged Role Administrator (and
#     the RoleManagement.ReadWrite.Directory app role on the deployer) to
#     grant that admin-consent declaratively. Application Administrator +
#     Cloud Application Administrator are NOT enough to consent to this
#     sensitive role-management permission.
#   - LICENSE: identity-only, cost ~$0; Entra Free is enough for the app +
#     SP (unlike AP03, which requires P1 for the role-assignable group).
#   - LATENCY: after the admin-consent / credential creation there may be
#     directory propagation -> retry the app-only token issuance (noted
#     in the 'Exploit' doc).
#
# TEARDOWN: `./aether.ps1 reset` re-applies with enable_ap04=false
# (count = 0) -> destroys app + SP + app_role_assignment. The client
# secret/cert that the student adds out-of-band and the objects created
# after escalating to GA stay OUTSIDE the Terraform state and are cleaned
# up by hand (same out-of-state scope caveat as AP02/AP03).
#
# Documentation note (equivalent Tier-0 variants, not implemented here;
# see docs/attack-paths): AppRoleAssignment.ReadWrite.All
# (06b708a9-e830-4db3-a914-8e69da51d44f, self-promotes by granting itself
# other app roles) and Application.ReadWrite.All
# (1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9, credential persistence in
# other apps).
# ==================================================================

locals {
  # Microsoft Graph app role (APPLICATION / app-only permission) carried
  # by the vulnerable app's SP = loot of the chain. Tier-0: lets you
  # assign ANY directory role, Global Administrator included. GUID =
  # Application variant of RoleManagement.ReadWrite.Directory (the
  # delegated one is d01b97e9-cbc0-49fe-810a-750afd5527a3; both
  # AdminConsentRequired=Yes). Graph's resource_app_id is reused from
  # local.graph_app_id (defined in main.tf) to avoid duplicating the local.
  ap04_graph_app_role_id   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
  ap04_graph_app_role_name = "RoleManagement.ReadWrite.Directory"
}

# Microsoft Graph service principal in THIS tenant. It is the `resource`
# the app role is granted on (the recipient of the admin-consent).
data "azuread_service_principal" "msgraph" {
  client_id = local.graph_app_id
}

# ---- Vulnerable app registration (decoy name resembling a directory
# sync connector) --------------------------------------------------
resource "azuread_application" "ap04_app" {
  count            = var.enable_ap04 ? 1 : 0
  display_name     = "${var.lab_prefix}-ap04-GraphSyncEngine"
  sign_in_audience = "AzureADMyOrg"

  # MISCONFIG (the misconfigured link): the low-privilege user
  # aether-user1 is the ONLY owner. By default, an app owner can ADD
  # credentials (secret/cert) to THAT app -> exploitable primitive.
  owners = [azuread_user.lab[0].object_id]

  # Graph APPLICATION permission (type="Role", app-only). The actual
  # consent is materialized by the azuread_app_role_assignment below;
  # this block declares the intent in the app manifest.
  required_resource_access {
    resource_app_id = local.graph_app_id

    resource_access {
      id   = local.ap04_graph_app_role_id
      type = "Role" # application (app-only), NOT delegated
    }
  }
}

# Service principal of the vulnerable app: it is the principal that carries
# the app role and the one the attacker authenticates as (client_credentials).
# inline owner = aether-user1 (persistence angle; azuread does NOT expose
# an azuread_service_principal_owner resource, owners go in `owners`).
resource "azuread_service_principal" "ap04_app" {
  count     = var.enable_ap04 ? 1 : 0
  client_id = azuread_application.ap04_app[0].client_id
  owners    = [azuread_user.lab[0].object_id]
}

# DECLARATIVE ADMIN-CONSENT: grants the Graph app role to the SP of the
# vulnerable app. THIS resource IS the admin-consent of the application
# permission, expressed as code (needs Global Administrator / Privileged
# Role Administrator on the deployer; see header). It is what turns the
# owner's secret-creation into escalation to Global Administrator.
resource "azuread_app_role_assignment" "ap04_rmrwd" {
  count               = var.enable_ap04 ? 1 : 0
  app_role_id         = local.ap04_graph_app_role_id
  principal_object_id = azuread_service_principal.ap04_app[0].object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# NOTE: the client secret / certificate is NOT created in Terraform on
# purpose. Seeding it would falsify the lab: the owner-adds-a-credential
# step is the EXPLOITABLE PRIMITIVE (Entra default) that the student
# runs (az ad app credential reset --id <appId> --append /
# Add-MgApplicationPassword). To demonstrate the secret already
# materialized (e.g. for a screenshot), uncomment:
#
# resource "azuread_application_password" "ap04_backdoor" {
#   count             = var.enable_ap04 ? 1 : 0
#   application_id    = azuread_application.ap04_app[0].id
#   display_name      = "aether-ap04-owner-backdoor"
#   end_date_relative = "17520h" # ~2 years (attacker TTL). Do NOT use
#   # timeadd(timestamp(), ...): timestamp() is re-evaluated on EVERY plan
#   # -> perpetual diff / credential recreation. end_date_relative is
#   # computed by the provider once at create time (no drift).
# }
