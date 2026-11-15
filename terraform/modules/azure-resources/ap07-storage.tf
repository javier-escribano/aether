# ==================================================================
# AP07 - Public storage / SAS leak (Azure, coste ~0, SIN VM).
#
# Ruta de EXFILTRACION DE DATOS en el plano de almacenamiento de Azure.
# MITRE: T1530 (Data from Cloud Storage, primario) + T1619 (Cloud Storage
# Object Discovery) + T1552.001 (Credentials In Files). Temario CARTP.
#
# Escenario (DOS puertas de acceso anonimo abiertas a proposito):
#   1) A nivel de CUENTA: allow_nested_items_to_be_public = true.
#      (azurerm ~3.116; renombrada desde allow_blob_public_access. OJO:
#      desde ~nov-2023 el DEFAULT de plataforma para cuentas nuevas es
#      false, por eso el lab lo pone EXPLICITO a true para ser vulnerable.)
#   2) A nivel de CONTENEDOR: "public" con container_access_type="container"
#      -> permite LISTAR blobs de forma anonima (?restype=container&comp=list),
#      no solo leer -> habilita el descubrimiento T1619.
#
# Cadena del atacante:
#   1. Enum anonima:  GET https://<cuenta>.blob.core.windows.net/public
#                         ?restype=container&comp=list  -> ve backup-config.json
#   2. Descarga anon: GET .../public/backup-config.json -> extrae la credencial
#                         SOBRE-PERMISIONADA (SAS de cuenta de larga vida).
#   3. Pivote auth:   usa la SAS para leer /sensitive-data/customers.csv
#                         (contenedor PRIVADO de la MISMA cuenta) -> exfiltra
#                         la joya CAELUM{...}. La SAS trae escritura/borrado
#                         -> rama de escalada/manipulacion demostrable.
#
# Patron feature-flag del repo: cada recurso vulnerable va con
#   count = var.enable_ap07 ? 1 : 0
# reset = apply con enable_ap07=false -> count=0 -> destruye TODO AP07
# (RG + cuenta + contenedores + blob filtrado + SAS + LAW) de forma atomica.
# AP07 es la PRIMERA ruta 100% DECLARATIVA del repo: SIN seed-ap07.ps1, SIN
# run-command, SIN hook post-apply. Todo (incluida la credencial incrustada
# via source_content) lo cablea Terraform -> reset sin residuo out-of-state.
#
# Bifurcacion leak_mode (variable, default "sas", conmutable por el instructor):
#   - "sas"         : la credencial filtrada es una SAS de CUENTA over-scoped
#                     (data.azurerm_storage_account_sas). Expiracion estable y
#                     reset-safe via hashicorp/time (time_static + time_offset),
#                     analogo a como AP05 anadio hashicorp/archive. Remediacion:
#                     user-delegation SAS (Entra, minima) + SAS expiration policy.
#   - "account_key" : la credencial es la primary_access_key (control total).
#                     Mas severa, sin provider nuevo. Remediacion:
#                     shared_access_key_enabled=false (plano de datos por Entra).
#
# CAVEAT (como el bloque KB5014754 de AP05): la SAS/clave ATERRIZA EN EL
# tfstate como sensible (data.azurerm_storage_account_sas, primary_connection_
# string, primary_access_key y el source_content del blob filtrado). Trata el
# estado como toxico (ya lo es por el SP de AP02 y dc_admin_password de AP05);
# .gitignore ya bloquea *.tfstate. La SAS/clave NUNCA se expone como output.
# ==================================================================

locals {
  # --- Nombres -------------------------------------------------------
  # Conditional short-circuit (espejo de local.suffix de AP02): NO indexa
  # [0] cuando enable_ap07=false, de modo que random_string.ap07 (count=0)
  # no se evalua. El ternario de Terraform no evalua la rama no tomada.
  ap07_suffix = var.enable_ap07 ? random_string.ap07[0].result : ""

  ap07_rg_name = "${var.lab_prefix}-ap07-rg"

  # Storage: 3-24 lowercase alfanumerico, SIN guiones (estilo AP02).
  # "caelum" (6) + "ap07" (4) + sufijo (5) = 15 chars con el prefijo por defecto.
  ap07_sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap07${local.ap07_suffix}"

  # --- Gate secundario del modo SAS ---------------------------------
  # Los recursos time_* y el data SAS existen SOLO en leak_mode="sas".
  # En "account_key" su count=0 (el provider time queda declarado-sin-uso,
  # coste nulo) y la credencial es la primary_access_key, ya en estado.
  ap07_sas_mode = var.enable_ap07 && var.leak_mode == "sas"

  # --- Telemetria (calca local.collect_events de hybrid-ad/monitoring.tf) ---
  ap07_collect_logs = var.enable_ap07 && var.collect_storage_logs

  # Workspace propio, o el externo si se da existing_log_analytics_workspace_id.
  ap07_law_id = local.ap07_collect_logs ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap07[0].id
  ) : null

  ap07_law_name = local.ap07_collect_logs && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap07[0].name : null
}

# ------------------------------------------------------------------
# Sufijo global PROPIO (la cuenta de storage es un namespace global).
# NO reutiliza random_string.suffix de AP02: ese esta gateado en
# enable_ap02, e indexar [0] con AP02 off y AP07 on reventaria el apply.
# length 5, lower+numeric, sin guiones.
# ------------------------------------------------------------------
resource "random_string" "ap07" {
  count   = var.enable_ap07 ? 1 : 0
  length  = 5
  lower   = true
  numeric = true
  upper   = false
  special = false
}

# ------------------------------------------------------------------
# Resource group contenedor de toda la ruta (blast radius acotado).
# ------------------------------------------------------------------
resource "azurerm_resource_group" "ap07" {
  count    = var.enable_ap07 ? 1 : 0
  name     = local.ap07_rg_name
  location = var.location

  tags = {
    range       = var.lab_prefix
    attack_path = "AP07"
  }
}

# ==================================================================
# MISCONFIG #1 (puerta de CUENTA): allow_nested_items_to_be_public = true.
# Este bloque es el INVERSO EXACTO del bloque seguro ya existente
# azurerm_storage_account.dsc (modules/hybrid-ad/main.tf): mismos
# account_tier/replication y min_tls_version="TLS1_2", pero el flag de
# acceso publico puesto a TRUE (vs el false seguro de aquel bloque) ->
# confirma el nombre de atributo para azurerm ~3.116.
#
# NOTA: secure transport NO mitiga la fuga (el endpoint blob es https
# igualmente), por eso min_tls_version se mantiene en el valor seguro a
# proposito: la leccion aisla la causa (la vuln es el ACCESO PUBLICO).
#
# shared_access_key_enabled=true (default) es necesario para que el data
# source de la SAS de cuenta (y la primary_access_key) funcionen; la
# remediacion #5 lo pone a false -> plano de datos SOLO por Entra RBAC.
# ==================================================================
resource "azurerm_storage_account" "ap07" {
  count                    = var.enable_ap07 ? 1 : 0
  name                     = local.ap07_sa_name
  resource_group_name      = azurerm_resource_group.ap07[0].name
  location                 = azurerm_resource_group.ap07[0].location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Firma de SAS de cuenta y primary_access_key (remediacion: =false).
  shared_access_key_enabled = true

  # ===== MISCONFIG explicita (inverso del bloque azurerm_storage_account.dsc) =====
  allow_nested_items_to_be_public = true
}

# ==================================================================
# MISCONFIG #2 (puerta de CONTENEDOR): "public" con access "container".
# "container" permite LISTAR anonimamente (?restype=container&comp=list),
# no solo leer. Es lo que habilita el descubrimiento T1619 sin adivinar
# el nombre del blob. (Con "blob" se podria LEER si adivinas el nombre,
# pero no LISTAR: load-bearing.)
# ==================================================================
resource "azurerm_storage_container" "ap07_public" {
  count                 = var.enable_ap07 ? 1 : 0
  name                  = "public"
  storage_account_name  = azurerm_storage_account.ap07[0].name
  container_access_type = "container"
}

# Contenedor PRIVADO con la joya de la corona. Defensa en profundidad:
# cerrar CUALQUIERA de las dos puertas (cuenta o contenedor) corta el ataque.
resource "azurerm_storage_container" "ap07_sensitive" {
  count                 = var.enable_ap07 ? 1 : 0
  name                  = "sensitive-data"
  storage_account_name  = azurerm_storage_account.ap07[0].name
  container_access_type = "private"
}

# ------------------------------------------------------------------
# Joya de la corona: customers.csv en el contenedor PRIVADO.
# PII 100% SINTETICA (dominios .invalid, tokens ficticios). El objetivo
# del pivote autenticado (paso 3). Contiene la flag CAELUM{...}.
# ------------------------------------------------------------------
resource "azurerm_storage_blob" "ap07_jewel" {
  count                  = var.enable_ap07 ? 1 : 0
  name                   = "customers.csv"
  storage_account_name   = azurerm_storage_account.ap07[0].name
  storage_container_name = azurerm_storage_container.ap07_sensitive[0].name
  type                   = "Block"
  content_type           = "text/csv"

  # Heredoc NO indentado (a columna 0): sin recorte de whitespace -> celdas CSV
  # limpias sin espacios iniciales (evita la ambiguedad del recorte de <<-).
  source_content = <<CSV
id,full_name,email,city,plan,last_payment_token,notes
1001,Alice Ficticia,alice@example.invalid,Madrid,enterprise,tok_0000111122223333,CAELUM{ap07_public_blob_to_sas_to_private_exfil}
1002,Bruno Imaginario,bruno@example.invalid,Lisboa,pro,tok_4444555566667777,registro sintetico - sin PII real
1003,Carla Inventada,carla@example.invalid,Paris,free,tok_8888999900001111,registro sintetico - sin PII real
1004,Diego Ejemplo,diego@example.invalid,Roma,pro,tok_2222333344445555,registro sintetico - sin PII real
CSV
}

# ==================================================================
# [leak_mode="sas"] Expiracion estable y RESET-SAFE de la SAS.
#
# hashicorp/time fija el start una sola vez (time_static, persistido en
# estado -> no deriva) y calcula el expiry = start + sas_expiry_years
# (time_offset, tambien persistido). Con inputs estables (start/expiry pin
# + primary_connection_string estable, pues Terraform no rota la clave) el
# data.azurerm_storage_account_sas produce un token DETERMINISTA -> el blob
# backup-config.json es estable -> `terraform plan` tras apply = "No changes".
#
# GOTCHA documentado: NO usar timestamp()/timeadd(timestamp(),...) para
# start/expiry -> recalcularia el HMAC en cada apply y re-renderizaria el
# blob (perpetual-diff que rompe la idempotencia de CONTRIBUTING). Ese es el
# motivo tecnico que justifica el provider nuevo (precedente: AP05/archive).
# ==================================================================
resource "time_static" "ap07" {
  count = local.ap07_sas_mode ? 1 : 0
}

resource "time_offset" "ap07_expiry" {
  count        = local.ap07_sas_mode ? 1 : 0
  base_rfc3339 = time_static.ap07[0].rfc3339
  offset_years = var.sas_expiry_years
}

# ------------------------------------------------------------------
# [leak_mode="sas"] SAS de CUENTA deliberadamente SOBRE-SCOPED:
#   resource_types service+container+object, services blob,
#   permissions r/w/d/l/a/c/u/p (+tag/filter, requeridos por el schema).
# Da escritura/borrado en TODA la cuenta -> la rama de escalada se demuestra.
#
# GOTCHA de dependencia: el data source LEE la clave -> requiere
# shared_access_key_enabled=true (default). Aplicar la remediacion #5 con
# enable_ap07=true hace fallar este data source: CORRECTO por diseno (el
# estado seguro es el default, el vulnerable es explicito; no es un bug).
# ------------------------------------------------------------------
data "azurerm_storage_account_sas" "ap07" {
  count             = local.ap07_sas_mode ? 1 : 0
  connection_string = azurerm_storage_account.ap07[0].primary_connection_string
  https_only        = true

  resource_types {
    service   = true
    container = true
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }

  # Pin estable (persistido en estado) -> token determinista -> idempotente.
  start  = time_static.ap07[0].rfc3339
  expiry = time_offset.ap07_expiry[0].rfc3339

  # SOBRE-SCOPE deliberado (least-privilege INVERTIDO). tag/filter van
  # explicitos porque el schema del data source los exige.
  permissions {
    read    = true
    write   = true
    delete  = true
    list    = true
    add     = true
    create  = true
    update  = true
    process = true
    tag     = true
    filter  = true
  }
}

# ==================================================================
# Blob FILTRADO: backup-config.json en el contenedor PUBLICO.
# El artefacto "olvidado" con la credencial over-permisionada incrustada
# (T1552.001). El source_content conmuta por leak_mode:
#   - "sas"         : incrusta la sasUrl ya montada (el .sas NO lleva el
#                     "?" inicial, por eso se construye ".../sensitive-data?${sas}").
#   - "account_key" : incrusta la primary_access_key + connection string.
#
# Short-circuit (mismo mecanismo que local.ap07_suffix): la rama "sas"
# referencia data.azurerm_storage_account_sas.ap07[0] y SOLO se toma cuando
# leak_mode=="sas" (que es justo cuando ese data source tiene count=1). En
# "account_key" la rama no se toma -> no se indexa [0] del data source (count=0).
# ==================================================================
resource "azurerm_storage_blob" "ap07_leaked" {
  count                  = var.enable_ap07 ? 1 : 0
  name                   = "backup-config.json"
  storage_account_name   = azurerm_storage_account.ap07[0].name
  storage_container_name = azurerm_storage_container.ap07_public[0].name
  type                   = "Block"
  content_type           = "application/json"

  source_content = var.leak_mode == "sas" ? jsonencode({
    storageAccount = azurerm_storage_account.ap07[0].name
    container      = "sensitive-data"
    sasUrl         = "https://${azurerm_storage_account.ap07[0].primary_blob_host}/sensitive-data?${data.azurerm_storage_account_sas.ap07[0].sas}"
    note           = "nightly backup job connection - rotate before prod"
    }) : jsonencode({
    storageAccount   = azurerm_storage_account.ap07[0].name
    accountKey       = azurerm_storage_account.ap07[0].primary_access_key
    connectionString = azurerm_storage_account.ap07[0].primary_connection_string
    note             = "nightly backup job connection - rotate before prod"
  })
}

# ==================================================================
# TELEMETRIA (gated local.ap07_collect_logs = enable_ap07 && collect_storage_logs).
#
# Primer azurerm_monitor_diagnostic_setting del repo (monitoring.tf usa
# DCR/AMA, que es para el canal de eventos de una VM Windows, NO para el
# plano de datos de storage). Los logs del PLANO DE DATOS cuelgan del
# sub-recurso blobServices/default, no de la cuenta.
#
# Propiedad a destacar: StorageBlobLogs NO esta activo por defecto -> sin
# este diagnostic setting la cadena (acceso anonimo + pivote SAS) NO existe
# en NINGUN SIEM (analogo exacto a "los eventos on-prem no existen sin
# AMA+DCR" de AP05). El plano de GESTION (el misconfig) viaja por
# AzureActivity, que ya fluye sin provisionar nada (como en AP02).
# Ingesta << 0,1 GB/dia (unos KB de blobs + operaciones del ejercicio).
# ==================================================================

# Workspace propio (se OMITE si el operador apunta a un LAW/Sentinel externo
# via existing_log_analytics_workspace_id). Calca azurerm_log_analytics_workspace.ap05.
resource "azurerm_log_analytics_workspace" "ap07" {
  count               = local.ap07_collect_logs && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap07-law"
  location            = azurerm_resource_group.ap07[0].location
  resource_group_name = azurerm_resource_group.ap07[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
}

# Diagnostic setting sobre blobServices/default -> StorageBlobLogs.
#   - log_analytics_destination_type="Dedicated" -> tabla resource-specific
#     StorageBlobLogs (esquema rico: AuthenticationType, OperationName, Uri,
#     CallerIpAddress, StatusCode, RequesterObjectId) contra la que se escribe
#     el KQL; sin "Dedicated" caeria en AzureDiagnostics legacy.
#   - metric{Transaction, enabled=false}: evita el perpetual-diff conocido
#     cuando la API devuelve el bloque metric (idempotencia en CI).
# Nombre unico (${lab_prefix}-ap07-blob-diag) para no colisionar si el LAW
# externo es el mismo que usa AP05.
resource "azurerm_monitor_diagnostic_setting" "ap07_blob" {
  count                          = local.ap07_collect_logs ? 1 : 0
  name                           = "${var.lab_prefix}-ap07-blob-diag"
  target_resource_id             = "${azurerm_storage_account.ap07[0].id}/blobServices/default"
  log_analytics_workspace_id     = local.ap07_law_id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = false
  }
}
