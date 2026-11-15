# ==================================================================
# AP03 — Grupo role-assignable + owner de bajo privilegio.
#
# Núcleo 100% DECLARATIVO (sin seed, needs_seed=none). La combinación
# vulnerable son dos hechos que fija Terraform:
#   (a) azuread_user.lab[0] (caelum-user1), usuario de BAJO privilegio,
#       es el ÚNICO owner del grupo (owners = [...]), y
#   (b) el grupo es role-assignable (assignable_to_role = true) y porta
#       el rol de directorio 'Privileged Role Administrator' (PRA) vía
#       azuread_directory_role_assignment.
#
# El PASO DE EXPLOTACIÓN NO se siembra: es comportamiento POR DEFECTO de
# Entra. La membership de un grupo role-assignable solo la pueden
# modificar tres principals -> Global Administrator, Privileged Role
# Administrator y los OWNERS del grupo. Por tanto el owner de bajo
# privilegio puede AUTO-AÑADIRSE a la membership sin rol admin, sin tocar
# políticas de tenant y sin depender de ningún atributo self-writable
# (department/jobTitle son admin-only por defecto). Al entrar en el grupo
# hereda PRA y, con él, puede auto-asignarse Global Administrator = toma
# del tenant. Es la arista canónica AZOwns -> grupo role-assignable ->
# rol de BloodHound/AzureHound.
#
# MITRE ATT&CK: T1098 (Account Manipulation) -> T1098.003 (Additional
# Cloud Roles) -> T1078.004 (Valid Accounts: Cloud Accounts).
#
# PRECONDICIONES (de permisos/licencia, NO de estado vulnerable sembrado):
#   - LICENCIA: los grupos role-assignable exigen Entra ID P1. Coste $ ~0
#     pero requiere tenant dev/E5 con P1, NO Entra Free puro como AP01.
#   - PERMISOS DE DEPLOY: el principal que ejecuta `terraform apply` debe
#     poseer Privileged Role Administrator o Global Administrator (y el
#     app-role RoleManagement.ReadWrite.Directory) para crear el grupo
#     role-assignable y asignarle PRA.
#   - LATENCIA: tras el self-add hay que re-autenticar para que el token
#     recoja el rol heredado (anotado en la doc 'Rompe').
#
# TEARDOWN: `./caelum.ps1 reset` re-aplica con enable_ap03=false
# (count = 0) -> destruye grupo + asignación de rol y revierte el
# self-add; members = [] lo revierte también en cualquier re-apply
# intermedio. Los objetos creados tras escalar a GA quedan FUERA del
# estado de Terraform y se limpian a mano (mismo caveat de scope que AP02).
#
# AP03-bis (solo documental, NO implementado): la variante de regla de
# membresía dinámica + attribute-injection no se usa como base porque
# Entra PROHÍBE la membresía dinámica en grupos role-assignable
# precisamente para impedir esta escalada; ver docs/attack-paths.
# ==================================================================

locals {
  # Rol de directorio Entra que porta el grupo (botín intermedio de la
  # cadena). PRA puede conceder CUALQUIER rol, Global Administrator
  # incluido -> trátalo como Tier-0.
  ap03_target_role_name = "Privileged Role Administrator"
}

# Instancia el rol de directorio PRA en el tenant (idempotente; si ya
# estaba activado, azuread lo adopta). Expone template_id/object_id.
resource "azuread_directory_role" "ap03_pra" {
  count        = var.enable_ap03 ? 1 : 0
  display_name = local.ap03_target_role_name
}

# Grupo PRIVILEGIADO role-assignable con un único owner de bajo privilegio.
resource "azuread_group" "ap03_role_admins" {
  count            = var.enable_ap03 ? 1 : 0
  display_name     = "${var.lab_prefix}-ap03-role-admins"
  security_enabled = true

  # role-assignable: habilita que el grupo porte roles de directorio.
  # Exige Entra ID P1. Fuerza membership ESTÁTICA (Assigned): Entra
  # bloquea reglas dinámicas en estos grupos (de ahí AP03-bis).
  assignable_to_role = true

  # MISCONFIG (eslabón mal configurado): el usuario de bajo privilegio
  # caelum-user1 es el ÚNICO owner. Por defecto, un owner puede editar
  # la membership de SU grupo role-assignable -> self-add.
  owners = [azuread_user.lab[0].object_id]

  # Membership estática VACÍA: el atacante se auto-añade en tiempo de
  # explotación (fuera de Terraform). members=[] también revierte el
  # self-add en cualquier re-apply.
  members = []
}

# Binding privilegiado: asigna PRA AL GRUPO (no a un usuario) -> todos
# sus miembros heredan el rol. Esto es lo que convierte el self-add en
# escalada a Privileged Role Administrator -> Global Administrator.
resource "azuread_directory_role_assignment" "ap03_pra" {
  count               = var.enable_ap03 ? 1 : 0
  role_id             = azuread_directory_role.ap03_pra[0].template_id
  principal_object_id = azuread_group.ap03_role_admins[0].object_id
}
