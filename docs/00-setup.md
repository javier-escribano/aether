# 00 — Setup, permisos y control de coste

## 1. Tenant y subscription de test (obligatorio)

No reutilices tu tenant corporativo. Crea uno limpio:

1. Portal Azure → **Microsoft Entra ID** → *Manage tenants* → **Create** → tipo *Entra ID*.
   Te da un dominio `<algo>.onmicrosoft.com`. Ese es `tenant_domain` en el tfvars.
2. Asocia (o crea) una **subscription** dedicada. Para la capa identity-only basta Entra Free;
   para el híbrido necesitas pago por uso.
3. Crea un usuario administrador de laboratorio y hazlo **Global Administrator** del tenant de test.
   Con él harás `az login` y correrás el seed de Graph.

## 2. Herramientas (en tu Windows 11)

```powershell
# Azure CLI
winget install -e --id Microsoft.AzureCLI

# Terraform >= 1.6
winget install -e --id HashiCorp.Terraform

# Módulo Graph de PowerShell (para los consents de AP01)
Install-Module Microsoft.Graph -Scope CurrentUser
```

Verifica:
```powershell
az version; terraform version; (Get-Module Microsoft.Graph -ListAvailable)[0].Version
```

## 3. Autenticación

```powershell
az login --tenant <TU_TENANT_DE_TEST>.onmicrosoft.com
az account set --subscription "<ID_SUBSCRIPTION_TEST>"
```

El provider `azuread` de Terraform reutiliza el contexto de `az login`.
Para los pasos de Graph (consents) el script hace `Connect-MgGraph` con los scopes mínimos:
`Application.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Directory.ReadWrite.All`.

## 4. Permisos de API que pedirá el seed

| Scope Graph | Para qué | Ruta |
|-------------|----------|------|
| `Application.ReadWrite.All` | crear/leer app registrations y SPs | AP01, AP04 |
| `DelegatedPermissionGrant.ReadWrite.All` | sembrar el consent ilícito | AP01 |
| `Policy.ReadWrite.Authorization` | configurar la user-consent policy permisiva | AP01 |
| `Directory.ReadWrite.All` | usuarios/grupos base | base |

> **AP03 requiere Entra ID P1.** Los grupos *role-assignable* (`assignable_to_role`) no existen en Entra Free: AP03 necesita un tenant con P1 (dev/E5). Además, el principal que ejecuta `terraform apply` debe tener **Privileged Role Administrator** o **Global Administrator** (y el app-role `RoleManagement.ReadWrite.Directory`) para crear el grupo role-assignable y asignarle PRA. El coste en dólares sigue siendo ~0.

> **AP04 — admin-consent de un permiso sensible.** AP04 es identity-only y funciona en **Entra Free** (no necesita P1). Pero concede `RoleManagement.ReadWrite.Directory` (permiso de aplicación de Graph, `AdminConsentRequired = Yes`) de forma declarativa, así que el principal que ejecuta `terraform apply` debe tener **Global Administrator** o **Privileged Role Administrator**; Application/Cloud Application Administrator **no** bastan para consentir este permiso de gestión de roles. Coste en dólares ~0.

> **AP05 — híbrido, factura cómputo (el AP más caro).** AP05 **no toca Entra**: levanta un **DC Windows Server 2022 + Enterprise Root CA (AD CS)** en Azure IaaS. Necesitas una **subscription de pago por uso** y rol **Contributor** sobre ella (crear VM, red y Log Analytics); **ningún** rol de Entra ni P1. Puntos propios:
> - **Credencial de dominio:** la (re)siembra de la plantilla ESC1 corre vía `az vm run-command`, que se ejecuta como **SYSTEM** (cuenta de máquina, **no** Enterprise Admin). Por eso `caelum.ps1` le pasa la password del `Administrator` de dominio (`dc_admin_password`, = EA) como parámetro. Déjala en `null` → el módulo genera un `random_password` (sensible: **aterriza en el estado**, trátalo como secreto). Nunca una password real ni reutilizada.
> - **Salida HTTPS (443) a PSGallery** en el `deploy`: la extensión **DSC** instala `ActiveDirectoryDsc` y `ActiveDirectoryCSDsc` en la VM al compilar la MOF. En entorno air-gapped, hornea esos módulos dentro del zip de la DSC.
> - **Exposición:** RDP/WinRM se abren **solo** a `admin_source_cidr` (tu `/32`). Si lo dejas en `null`, el módulo **no abre ningún puerto inbound** (usa Azure Bastion o serial console). **Nunca** `0.0.0.0/0`: es un DC.
> - **Detección end-to-end:** `collect_security_events = true` (por defecto) provisiona **AMA + DCR + Log Analytics** (feed de 1 DC filtrado a 5 EventID, « 0,1–0,3 GB/día) para que "🔵 Detecta" sea testeable sin SIEM previo. Ponlo a `false`, o apunta `existing_log_analytics_workspace_id` a tu Sentinel, si ya ingieres los eventos de Seguridad del DC.
> - **Aislamiento:** el bosque `caelum.lab` es de usar y tirar; **no** lo sincronices con el tenant vía Entra Connect real (eso convertiría el lab en riesgo real; ese escenario lo cubre **AP06**, que comparte este mismo DC). Uno de los resets más limpios del range (empata con AP07/AP08): `enable_ap05 = false` destruye la VM y con ella la plantilla, los certs forjados y la base de datos de la CA (coste → 0).

> **AP06 — Entra Connect / Seamless SSO (híbrido, factura cómputo; *bridge* on-prem→cloud).** AP06 es la 2ª ruta híbrida y **comparte el DC de AP05**: el gate `local.need_dc = enable_ap05 || enable_ap06` hace que un único **DC Windows Server 2022** sirva a ambas (con `enable_ap05 = true` el plan de AP05 es **idéntico** al de hoy; AP06 solo añade sus artefactos). Necesitas **subscription** de pago por uso y rol **Contributor**; **ningún** rol de Entra ni P1. Puntos propios:
> - **Substrato compartido.** Si activas AP05 **y** AP06 se despliega **un solo** DC (no dos); las variables del DC (`dc_admin_password`, `admin_source_cidr`, `vm_size`, `domain_fqdn`, `collect_security_events`…) son las mismas de AP05. `AZUREADSSOACC$` y la cuenta de sync **no** son recursos de Terraform: viven en el directorio del DC (como la plantilla ESC1 de AP05), sembrados por `seed-ap06.ps1`.
> - **Seed (como AP05, no declarativo).** `seed-ap06.ps1` corre vía `az vm run-command` como **SYSTEM** y construye un `PSCredential` EA desde `dc_admin_password`; crea la cuenta de máquina `AZUREADSSOACC$` con los SPN de Seamless SSO (`HTTP/autologon.microsoftazuread-sso.com`, `HTTP/aadg.windows.net.nsatc.net`) y clave **conocida y nunca-rotada**, y la cuenta de sync con ACEs **DS-Replication-Get-Changes[-All]** (= DCSync). Falla ruidosa si no es EA. Ambas passwords **aterrizan en el estado** (sensibles).
> - **`sso_mode`** (tfvars): `"both"` (default; siembra ambos artefactos → habilita la cadena completa sync → DCSync → `AZUREADSSOACC$` → silver ticket → nube) | `"silver_ticket"` (solo `AZUREADSSOACC$`) | `"sync_dcsync"` (solo la cuenta de sync con DCSync).
> - **Detección end-to-end:** reutiliza el **mismo** pipeline AMA/DCR de AP05; con `enable_ap06` el XPath del DCR añade **4662** (DCSync), **4769** (TGS del SPN de Seamless SSO) y **4741/4742** (`AZUREADSSOACC$`) — sin alterar el filtro de AP05-solo. La pata **cloud** (los `SigninLogs` de Seamless SSO en Entra) **no** la provisiona el lab: se declara como límite (hunt en tu tenant). Un *silver ticket* forjado puede **no** generar un 4769 en el DC.
> - **Reset:** `enable_ap06 = false` **con** `enable_ap05 = false` → `need_dc` cae → se destruye el DC compartido (coste → 0; con él mueren `AZUREADSSOACC$`, la cuenta de sync y los ACEs DCSync). **Caso selectivo** (AP06 off **con** AP05 on): el DC **sobrevive** (lo necesita AP05) y los objetos AD de AP06 **persisten** → para el «Arregla» corre `seed-ap06.ps1 -Remediate` (rota la clave de `AZUREADSSOACC$` 2× + quita los ACEs DCSync + deshabilita la cuenta de sync) **antes** de bajar la flag.

> **AP07 — Storage público / SAS leak (el AP de infraestructura más barato, ~0 €).** AP07 **no toca Entra ni despliega cómputo**: crea una **storage account** con dos puertas de acceso anónimo abiertas a propósito y una credencial over-scoped filtrada en un blob público. Necesitas una **subscription** de pago por uso y rol **Contributor** (crear storage y, si procede, Log Analytics); **ningún** rol de Entra ni P1. Puntos propios:
> - **100 % declarativo — sin `seed`.** A diferencia de AP01/AP05, AP07 no tiene script de post-despliegue: `./caelum.ps1 deploy` es solo `terraform apply`. La SAS/clave filtrada la incrusta Terraform en el blob.
> - **`leak_mode`** (tfvars): `"sas"` (por defecto) filtra una **SAS de cuenta** over-scoped de larga vida (usa el provider `hashicorp/time` para que la expiración sea estable e idempotente); `"account_key"` filtra la **clave de cuenta** (más severa, control total). En **ambos**, la credencial **aterriza en el estado** (sensible): trata el `tfstate` como tóxico.
> - **Doble puerta anónima deliberada:** a nivel de cuenta `allow_nested_items_to_be_public = true` **más** el contenedor `public` con acceso `container` (permite *listar* anónimamente). Cerrar **cualquiera** de las dos corta el ataque (defensa en profundidad). **Caveat:** desde ~nov-2023 el *default* de `allowBlobPublicAccess` para cuentas nuevas es `false`; el lab lo pone a `true` **a propósito**.
> - **Datos sintéticos:** la joya (`sensitive-data/customers.csv`) es PII **100 % ficticia** (dominios `.invalid`, tokens falsos).
> - **Detección end-to-end:** `collect_storage_logs = true` (por defecto) provisiona **diagnostic settings → `StorageBlobLogs`** en Log Analytics (ingesta « 0,1 GB/día) para ver el acceso anónimo/SAS; el *misconfig* en sí viaja por `AzureActivity` sin provisionar nada. Ponlo a `false`, o apunta `existing_log_analytics_workspace_id` a tu Sentinel, si ya ingieres esos logs.
> - **Reset:** `enable_ap07 = false` destruye la cuenta entera (con el blob filtrado y la SAS) → coste 0, sin residuo *out-of-state*.

> **AP08 — Automation Account runbook → escalada RBAC (coste ~0, SIN VM).** AP08 **no toca el híbrido ni despliega cómputo**: crea un **Automation Account** con una **Managed Identity system-assigned over-privilegiada** (rol con `roleAssignments/write` sobre el RG) y un atacante low-priv dedicado que la conduce. Necesitas una **subscription** de pago por uso y rol **Contributor** sobre ella (crear el Automation Account, los role assignments y, si procede, Log Analytics); además el deployer debe poder **crear el `azuread_user` atacante** (un rol de Entra como *User Administrator*) y **asignar RBAC sobre el RG** (ser Owner o User Access Administrator del RG de AP08). **Ningún** P1. Puntos propios:
> - **100 % declarativo — sin `seed` (como AP07).** `./caelum.ps1 deploy` es solo `terraform apply`: el runbook se incrusta vía `azurerm_automation_runbook.content`. **Correr** el runbook (el "rompe") es acción del alumno; Terraform **publica la *gun* pero NUNCA la dispara** (no crea job ni schedule).
> - **`runbook_mode`** (tfvars): `"poc_escalation"` (default; incrusta un runbook listo que, corriendo como la MI, se auto-concede **Owner del RG** vía `New-AzRoleAssignment` → demo inmediata) | `"benign_probe"` (incrusta un runbook que **solo prueba** identidad/poder de la MI —`Connect-AzAccount -Identity` + `Get-AzAccessToken` + `Get-AzRoleAssignment`— y el alumno escribe la escalada) | `"none"` (sin runbook; *misconfig* pura).
> - **`mi_role`** (tfvars): rol built-in over-priv de la MI **sobre el RG** → `"UserAccessAdministrator"` (default; *mínimo-que-escala*: su único poder es `roleAssignments/write` → lección afilada «incluso solo UAA sobre una MI de Automation = game over») | `"Owner"` (más realista). **`Contributor` no vale**: no incluye `roleAssignments/write` (ese es el carril de AP02 vía `accessPolicies/write`).
> - **Reset-safety = RG-scoped A PROPÓSITO.** El rol de la MI y la escalada de runtime se acotan al **RG** de AP08 (nunca a la subscription). `enable_ap08 = false` destruye el RG y **con él toda role assignment de runtime** scoped al RG (incluido el self-grant de Owner que ejecuta el alumno) → cero residuo *out-of-state* (empata con AP05/AP07). Un `-Scope` de subscription **sobreviviría** al destroy y ampliaría el blast radius: por eso el scope-RG es un requisito de seguridad del range (análogo al bosque usar-y-tirar de AP05).
> - **Credencial en el estado:** el `random_password` del atacante **aterriza en el `tfstate`** (sensible; solo se expone vía el output sensible `ap08_attacker_password`). Trata el estado como tóxico; `.gitignore` ya bloquea `*.tfstate*`.
> - **Detección end-to-end:** `collect_automation_logs = true` (por defecto) provisiona **diagnostic settings → `JobLogs`/`JobStreams`** (`AzureDiagnostics`) en Log Analytics (ingesta « 0,1 GB/día) para ver la ejecución del runbook; el **plano de gestión** (`jobs/write`, y el `roleAssignments/write` **por la MI** —la señal de oro—) viaja por `AzureActivity` sin provisionar nada. Ponlo a `false`, o apunta `existing_log_analytics_workspace_id` a tu Sentinel, si ya ingieres esos logs.
> - **Entorno del runbook:** asume `Az.Accounts`/`Az.Resources` disponibles en el Automation Account (las imágenes actuales los traen; si faltan, importa el módulo `Az` en *Shared Resources*).

## 5. Control de coste (no te lleves sustos)

- **Budget + alerta:** Portal → *Cost Management* → *Budgets* → crea uno de p.ej. 20 €/mes
  con alerta al 50/80/100 %.
- **Auto-shutdown de VMs** (solo híbrido): el módulo `hybrid-ad` activará *auto-shutdown*
  diario; si no vas a usarlo, deja sus flags en `false`.
- **Teardown:** al acabar cada sesión, `./caelum.ps1 destroy`. La capa identity no factura,
  pero déjala limpia igualmente para no acumular objetos.

## 6. Primer despliegue

Vuelve al [README](../README.md) → *Quickstart*. Empieza con **solo AP01 activo**
(`enable_ap01 = true`, el resto `false`) para validar el flujo entero sin coste.
