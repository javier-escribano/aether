# ==================================================================
# AP03 — Role-assignable group + low-privilege owner.
#
# 100% DECLARATIVE core (no seed, needs_seed=none). The vulnerable
# combination is two facts that Terraform sets:
#   (a) azuread_user.lab[0] (aether-user1), a LOW-privilege user,
#       is the ONLY owner of the group (owners = [...]), and
#   (b) the group is role-assignable (assignable_to_role = true) and
#       carries the 'Privileged Role Administrator' (PRA) directory
#       role via azuread_directory_role_assignment.
#
# The EXPLOITATION STEP is NOT seeded: it is DEFAULT Entra behavior.
# The membership of a role-assignable group can only be modified by
# three principals -> Global Administrator, Privileged Role
# Administrator and the group's OWNERS. Therefore the low-privilege
# owner can ADD THEMSELVES to the membership without an admin role,
# without touching tenant policies and without relying on any
# self-writable attribute (department/jobTitle are admin-only by
# default). On joining the group they inherit PRA and, with it, can
# assign themselves Global Administrator = tenant takeover. This is
# the canonical AZOwns -> role-assignable group -> role edge from
# BloodHound/AzureHound.
#
# MITRE ATT&CK: T1098 (Account Manipulation) -> T1098.003 (Additional
# Cloud Roles) -> T1078.004 (Valid Accounts: Cloud Accounts).
#
# PRECONDITIONS (permission/license, NOT a seeded vulnerable state):
#   - LICENSE: role-assignable groups require Entra ID P1. Cost ~$0
#     but requires a dev/E5 tenant with P1, NOT pure Entra Free like AP01.
#   - DEPLOY PERMISSIONS: the principal running `terraform apply` must
#     hold Privileged Role Administrator or Global Administrator (and
#     the RoleManagement.ReadWrite.Directory app role) to create the
#     role-assignable group and assign it PRA.
#   - LATENCY: after the self-add you must re-authenticate so the token
#     picks up the inherited role (noted in the 'Exploit' doc).
#
# TEARDOWN: `./aether.ps1 reset` re-applies with enable_ap03=false
# (count = 0) -> destroys the group + role assignment and reverts the
# self-add; members = [] also reverts it on any intermediate re-apply.
# Objects created after escalating to GA stay OUTSIDE the Terraform
# state and are cleaned up by hand (same scope caveat as AP02).
#
# AP03-bis (documentation only, NOT implemented): the dynamic
# membership rule + attribute-injection variant is not used as a base
# because Entra FORBIDS dynamic membership in role-assignable groups
# precisely to prevent this escalation; see docs/attack-paths.
# ==================================================================

locals {
  # Entra directory role carried by the group (intermediate loot of the
  # chain). PRA can grant ANY role, Global Administrator included ->
  # treat it as Tier-0.
  ap03_target_role_name = "Privileged Role Administrator"
}

# Instantiate the PRA directory role in the tenant (idempotent; if it was
# already activated, azuread adopts it). Exposes template_id/object_id.
resource "azuread_directory_role" "ap03_pra" {
  count        = var.enable_ap03 ? 1 : 0
  display_name = local.ap03_target_role_name
}

# PRIVILEGED role-assignable group with a single low-privilege owner.
resource "azuread_group" "ap03_role_admins" {
  count            = var.enable_ap03 ? 1 : 0
  display_name     = "${var.lab_prefix}-ap03-role-admins"
  security_enabled = true

  # role-assignable: lets the group carry directory roles. Requires
  # Entra ID P1. Forces STATIC membership (Assigned): Entra blocks
  # dynamic rules on these groups (hence AP03-bis).
  assignable_to_role = true

  # MISCONFIG (the misconfigured link): the low-privilege user
  # aether-user1 is the ONLY owner. By default, an owner can edit the
  # membership of THEIR role-assignable group -> self-add.
  owners = [azuread_user.lab[0].object_id]

  # EMPTY static membership: the attacker adds themselves at exploitation
  # time (outside Terraform). members=[] also reverts the self-add on
  # any re-apply.
  members = []
}

# Privileged binding: assigns PRA TO THE GROUP (not to a user) -> all of
# its members inherit the role. This is what turns the self-add into
# escalation to Privileged Role Administrator -> Global Administrator.
resource "azuread_directory_role_assignment" "ap03_pra" {
  count               = var.enable_ap03 ? 1 : 0
  role_id             = azuread_directory_role.ap03_pra[0].template_id
  principal_object_id = azuread_group.ap03_role_admins[0].object_id
}
