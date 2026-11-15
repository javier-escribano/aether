# ==================================================================
# AP04 — App registration con permiso de APLICACION peligroso de
# Microsoft Graph + owner de bajo privilegio (abuso de credenciales /
# persistencia de service principal).
#
# Nucleo 100% DECLARATIVO (sin seed, needs_seed=none). La combinacion
# vulnerable son tres hechos que fija Terraform:
#   (a) azuread_user.lab[0] (caelum-user1), usuario de BAJO privilegio,
#       es el UNICO owner del app registration (owners = [...]) -> por
#       defecto en Entra, el owner de una app puede ANADIR credenciales
#       (client secret / certificado) a esa app,
#   (b) el service principal de la app porta el app role (permiso de
#       APLICACION, app-only) de Graph RoleManagement.ReadWrite.Directory,
#       concedido con ADMIN CONSENT via azuread_app_role_assignment, y
#   (c) ese app role es Tier-0: GARANTIZA escalada a Global Administrator
#       de un solo salto (SpecterOps lo documenta como uno de los dos
#       unicos app roles de Graph que lo garantizan; el otro es
#       AppRoleAssignment.ReadWrite.All).
#
# El PASO DE EXPLOTACION NO se siembra: es comportamiento POR DEFECTO de
# Entra. El owner anade un secret a la app (az ad app credential reset
# --append / Add-MgApplicationPassword), se autentica como el SP via
# OAuth2 client_credentials -> token app-only de Graph que porta
# RoleManagement.ReadWrite.Directory, y POST
# /roleManagement/directory/roleAssignments se auto-asigna Global
# Administrator (roleDefinitionId 62e90394-69f5-4237-9190-012177145e10,
# directoryScopeId '/'). El secret anadido queda como BACKDOOR app-only
# persistente (sobrevive a reset de contrasena del user y a MFA; los SP
# no la aplican). Es la arista canonica AZOwns -> app registration ->
# AZMGRoleManagement_ReadWrite_Directory de BloodHound/AzureHound.
#
# MITRE ATT&CK: T1098.001 (Account Manipulation: Additional Cloud
# Credentials) -NUCLEO- -> T1098.003 (Additional Cloud Roles) ->
# T1078.004 (Valid Accounts: Cloud Accounts). Recon: T1087.004.
#
# CONTRASTE con AP03 (misma clase, distinto objeto): AP03 = ownership de
# un GRUPO role-assignable (herencia de rol de directorio); AP04 =
# ownership de una APP REGISTRATION (abuso del permiso de aplicacion de
# Graph + credenciales). Ambos son ownership abuse Tier-0.
#
# PRECONDICIONES (de permisos de deploy, NO de estado vulnerable magico):
#   - PERMISOS DE DEPLOY: RoleManagement.ReadWrite.Directory tiene
#     AdminConsentRequired=Yes. El principal que ejecuta `terraform apply`
#     debe poseer Global Administrator o Privileged Role Administrator (y
#     el app-role RoleManagement.ReadWrite.Directory sobre el deployer)
#     para conceder ese admin-consent declarativamente. Application
#     Administrator + Cloud Application Administrator NO bastan para
#     consentir este permiso sensible de gestion de roles.
#   - LICENCIA: identity-only, coste $ ~0; Entra Free basta para la app +
#     SP (a diferencia de AP03, que exige P1 para el grupo role-assignable).
#   - LATENCIA: tras el admin-consent / alta de credencial puede haber
#     propagacion de directorio -> reintentar la emision del token app-only
#     (anotado en la doc 'Rompe').
#
# TEARDOWN: `./caelum.ps1 reset` re-aplica con enable_ap04=false
# (count = 0) -> destruye app + SP + app_role_assignment. El client
# secret/cert que el alumno anade out-of-band y los objetos creados tras
# escalar a GA quedan FUERA del estado de Terraform y se limpian a mano
# (mismo caveat de scope out-of-state que AP02/AP03).
#
# NOTA documental (variantes Tier-0 equivalentes, no implementadas aqui;
# ver docs/attack-paths): AppRoleAssignment.ReadWrite.All
# (06b708a9-e830-4db3-a914-8e69da51d44f, se auto-promociona concediendose
# otros app roles) y Application.ReadWrite.All
# (1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9, persistencia de credenciales en
# otras apps).
# ==================================================================

locals {
  # App role (permiso de APLICACION / app-only) de Microsoft Graph que
  # porta el SP de la app vulnerable = botin de la cadena. Tier-0:
  # permite asignar CUALQUIER rol de directorio, Global Administrator
  # incluido. GUID = variante Application de RoleManagement.ReadWrite.Directory
  # (la delegada es d01b97e9-cbc0-49fe-810a-750afd5527a3; ambas
  # AdminConsentRequired=Yes). resource_app_id de Graph se reutiliza de
  # local.graph_app_id (definido en main.tf) para no duplicar el local.
  ap04_graph_app_role_id   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
  ap04_graph_app_role_name = "RoleManagement.ReadWrite.Directory"
}

# Service principal de Microsoft Graph en ESTE tenant. Es el `resource`
# sobre el que se concede el app role (el destinatario del admin-consent).
data "azuread_service_principal" "msgraph" {
  client_id = local.graph_app_id
}

# ---- App registration vulnerable (nombre senuelo tipo conector de
# sincronizacion de directorio) ------------------------------------
resource "azuread_application" "ap04_app" {
  count            = var.enable_ap04 ? 1 : 0
  display_name     = "${var.lab_prefix}-ap04-GraphSyncEngine"
  sign_in_audience = "AzureADMyOrg"

  # MISCONFIG (eslabon mal configurado): el usuario de bajo privilegio
  # caelum-user1 es el UNICO owner. Por defecto, un owner de la app puede
  # ANADIR credenciales (secret/cert) a ESA app -> primitivo explotable.
  owners = [azuread_user.lab[0].object_id]

  # Permiso de APLICACION (type="Role", app-only) de Graph. El consent
  # real se materializa con el azuread_app_role_assignment de abajo; este
  # bloque declara la intencion en el manifiesto de la app.
  required_resource_access {
    resource_app_id = local.graph_app_id

    resource_access {
      id   = local.ap04_graph_app_role_id
      type = "Role" # aplicacion (app-only), NO delegado
    }
  }
}

# Service principal de la app vulnerable: es el principal que porta el
# app role y como quien se autentica el atacante (client_credentials).
# owner inline = caelum-user1 (angulo de persistencia; azuread NO expone
# un recurso azuread_service_principal_owner, los owners van en `owners`).
resource "azuread_service_principal" "ap04_app" {
  count     = var.enable_ap04 ? 1 : 0
  client_id = azuread_application.ap04_app[0].client_id
  owners    = [azuread_user.lab[0].object_id]
}

# ADMIN-CONSENT DECLARATIVO: concede el app role de Graph al SP de la app
# vulnerable. ESTE recurso ES el admin-consent del permiso de aplicacion,
# expresado como codigo (necesita Global Administrator / Privileged Role
# Administrator en el deployer; ver cabecera). Es lo que convierte el
# alta-de-secret del owner en escalada a Global Administrator.
resource "azuread_app_role_assignment" "ap04_rmrwd" {
  count               = var.enable_ap04 ? 1 : 0
  app_role_id         = local.ap04_graph_app_role_id
  principal_object_id = azuread_service_principal.ap04_app[0].object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# NOTA: el client secret / certificado NO se crea en Terraform a
# proposito. Sembrarlo falsearia el lab: el alta-de-credencial-por-owner
# es el PRIMITIVO EXPLOTABLE (default de Entra) que ejecuta el alumno
# (az ad app credential reset --id <appId> --append /
# Add-MgApplicationPassword). Si se quisiera demostrar el secret ya
# materializado (p.ej. para una captura), descomentar:
#
# resource "azuread_application_password" "ap04_backdoor" {
#   count             = var.enable_ap04 ? 1 : 0
#   application_id    = azuread_application.ap04_app[0].id
#   display_name      = "caelum-ap04-owner-backdoor"
#   end_date_relative = "17520h" # ~2 anos (TTL del atacante). NO usar
#   # timeadd(timestamp(), ...): timestamp() se reevalua en CADA plan ->
#   # diff perpetuo / recreacion de la credencial. end_date_relative lo
#   # calcula el provider una sola vez en create (sin drift).
# }
