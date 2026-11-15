# ==================================================================
# AP07 - Public storage / SAS leak (Azure, ~zero cost, no VM).
#
# DATA EXFILTRATION path in Azure's storage plane.
# MITRE: T1530 (Data from Cloud Storage, primary) + T1619 (Cloud Storage
# Object Discovery) + T1552.001 (Credentials In Files). CARTP syllabus.
#
# Scenario (TWO anonymous-access doors opened on purpose):
#   1) At the ACCOUNT level: allow_nested_items_to_be_public = true.
#      (azurerm ~3.116; renamed from allow_blob_public_access. NOTE:
#      since ~nov-2023 the platform DEFAULT for new accounts is false,
#      which is why the lab sets it EXPLICITLY to true to be vulnerable.)
#   2) At the CONTAINER level: "public" with container_access_type="container"
#      -> allows anonymous LISTING of blobs (?restype=container&comp=list),
#      not just reading -> enables T1619 discovery.
#
# Attacker chain:
#   1. Anonymous enum: GET https://<account>.blob.core.windows.net/public
#                         ?restype=container&comp=list  -> sees backup-config.json
#   2. Anonymous download: GET .../public/backup-config.json -> extracts the
#                         OVER-PERMISSIONED credential (long-lived account SAS).
#   3. Auth pivot:    uses the SAS to read /sensitive-data/customers.csv
#                         (PRIVATE container of the SAME account) -> exfiltrates
#                         the AETHER{...} jewel. The SAS carries write/delete
#                         -> demonstrable escalation/tampering branch.
#
# Repo feature-flag pattern: every vulnerable resource carries
#   count = var.enable_ap07 ? 1 : 0
# reset = apply with enable_ap07=false -> count=0 -> destroys ALL of AP07
# (RG + account + containers + leaked blob + SAS + LAW) atomically.
# AP07 is the repo's FIRST 100% DECLARATIVE path: NO seed-ap07.ps1, NO
# run-command, NO post-apply hook. Everything (including the credential embedded
# via source_content) is wired by Terraform -> reset with no out-of-state residue.
#
# leak_mode fork (variable, default "sas", switchable by the instructor):
#   - "sas"         : the leaked credential is an over-scoped ACCOUNT SAS
#                     (data.azurerm_storage_account_sas). Stable, reset-safe
#                     expiry via hashicorp/time (time_static + time_offset),
#                     analogous to how AP05 added hashicorp/archive. Remediation:
#                     user-delegation SAS (Entra, minimal) + SAS expiration policy.
#   - "account_key" : the credential is the primary_access_key (full control).
#                     More severe, no new provider. Remediation:
#                     shared_access_key_enabled=false (data plane via Entra).
#
# CAVEAT (like AP05's KB5014754 block): the SAS/key LANDS IN THE
# tfstate as sensitive (data.azurerm_storage_account_sas, primary_connection_
# string, primary_access_key, and the leaked blob's source_content). Treat the
# state as toxic (it already is, due to AP02's SP and AP05's dc_admin_password);
# .gitignore already blocks *.tfstate. The SAS/key is NEVER exposed as an output.
# ==================================================================

locals {
  # --- Names ---------------------------------------------------------
  # Conditional short-circuit (mirror of AP02's local.suffix): does NOT index
  # [0] when enable_ap07=false, so random_string.ap07 (count=0) is not
  # evaluated. Terraform's ternary does not evaluate the untaken branch.
  ap07_suffix = var.enable_ap07 ? random_string.ap07[0].result : ""

  ap07_rg_name = "${var.lab_prefix}-ap07-rg"

  # Storage: 3-24 lowercase alphanumeric, NO hyphens (AP02 style).
  # "aether" (7) + "ap07" (4) + suffix (5) = 16 chars with the default prefix.
  ap07_sa_name = "${lower(replace(var.lab_prefix, "-", ""))}ap07${local.ap07_suffix}"

  # --- Secondary gate for the SAS mode ------------------------------
  # The time_* resources and the SAS data source exist ONLY in leak_mode="sas".
  # In "account_key" their count=0 (the time provider stays declared-but-unused,
  # zero cost) and the credential is the primary_access_key, already in state.
  ap07_sas_mode = var.enable_ap07 && var.leak_mode == "sas"

  # --- Telemetry (mirrors local.collect_events in hybrid-ad/monitoring.tf) ---
  ap07_collect_logs = var.enable_ap07 && var.collect_storage_logs

  # Own workspace, or the external one if existing_log_analytics_workspace_id is set.
  ap07_law_id = local.ap07_collect_logs ? (
    var.existing_log_analytics_workspace_id != null ? var.existing_log_analytics_workspace_id : azurerm_log_analytics_workspace.ap07[0].id
  ) : null

  ap07_law_name = local.ap07_collect_logs && var.existing_log_analytics_workspace_id == null ? azurerm_log_analytics_workspace.ap07[0].name : null
}

# ------------------------------------------------------------------
# OWN global suffix (the storage account is a global namespace).
# Does NOT reuse random_string.suffix from AP02: that one is gated on
# enable_ap02, and indexing [0] with AP02 off and AP07 on would blow up the apply.
# length 5, lower+numeric, no hyphens.
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
# Resource group containing the whole path (bounded blast radius).
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
# MISCONFIG #1 (ACCOUNT door): allow_nested_items_to_be_public = true.
# This block is the EXACT INVERSE of the existing secure block
# azurerm_storage_account.dsc (modules/hybrid-ad/main.tf): same
# account_tier/replication and min_tls_version="TLS1_2", but the public-
# access flag set to TRUE (vs the secure false of that block) ->
# confirms the attribute name for azurerm ~3.116.
#
# NOTE: secure transport does NOT mitigate the leak (the blob endpoint is https
# anyway), which is why min_tls_version is kept at the secure value on
# purpose: the lesson isolates the cause (the vuln is PUBLIC ACCESS).
#
# shared_access_key_enabled=true (default) is needed for the account SAS data
# source (and primary_access_key) to work; remediation #5 sets it to false ->
# data plane ONLY via Entra RBAC.
# ==================================================================
resource "azurerm_storage_account" "ap07" {
  count                    = var.enable_ap07 ? 1 : 0
  name                     = local.ap07_sa_name
  resource_group_name      = azurerm_resource_group.ap07[0].name
  location                 = azurerm_resource_group.ap07[0].location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Account SAS signing and primary_access_key (remediation: =false).
  shared_access_key_enabled = true

  # ===== Explicit MISCONFIG (inverse of the azurerm_storage_account.dsc block) =====
  allow_nested_items_to_be_public = true

  # OPERATOR GUARD [SECURITY.md H-4]: scope the (deliberately) anonymous access to the
  # operator's own IP, so the lesson is still demonstrable from your machine but the whole
  # Internet cannot abuse the account. Set ap07_internet_exposed=true to drop the firewall.
  dynamic "network_rules" {
    for_each = var.ap07_internet_exposed ? [] : [1]
    content {
      default_action = "Deny"
      ip_rules       = var.admin_source_cidr != null ? [trimsuffix(var.admin_source_cidr, "/32")] : []
      bypass         = ["AzureServices"]
    }
  }

  lifecycle {
    precondition {
      condition     = var.ap07_internet_exposed || var.admin_source_cidr != null
      error_message = "AP07: set admin_source_cidr to your public IP (scopes the anonymous-access lesson to you) or ap07_internet_exposed=true to expose it to the Internet on purpose."
    }
  }
}

# ==================================================================
# MISCONFIG #2 (CONTAINER door): "public" with access "container".
# "container" allows anonymous LISTING (?restype=container&comp=list),
# not just reading. That is what enables T1619 discovery without guessing
# the blob name. (With "blob" you could READ if you guess the name,
# but not LIST: load-bearing.)
# ==================================================================
resource "azurerm_storage_container" "ap07_public" {
  count                 = var.enable_ap07 ? 1 : 0
  name                  = "public"
  storage_account_name  = azurerm_storage_account.ap07[0].name
  container_access_type = "container"
}

# PRIVATE container with the crown jewel. Defense in depth:
# closing EITHER of the two doors (account or container) cuts the attack.
resource "azurerm_storage_container" "ap07_sensitive" {
  count                 = var.enable_ap07 ? 1 : 0
  name                  = "sensitive-data"
  storage_account_name  = azurerm_storage_account.ap07[0].name
  container_access_type = "private"
}

# ------------------------------------------------------------------
# Crown jewel: customers.csv in the PRIVATE container.
# 100% SYNTHETIC PII (.invalid domains, fictitious tokens). The target
# of the authenticated pivot (step 3). Contains the AETHER{...} flag.
# ------------------------------------------------------------------
resource "azurerm_storage_blob" "ap07_jewel" {
  count                  = var.enable_ap07 ? 1 : 0
  name                   = "customers.csv"
  storage_account_name   = azurerm_storage_account.ap07[0].name
  storage_container_name = azurerm_storage_container.ap07_sensitive[0].name
  type                   = "Block"
  content_type           = "text/csv"

  # Heredoc NOT indented (at column 0): no whitespace trimming -> clean CSV
  # cells with no leading spaces (avoids the <<- trimming ambiguity).
  source_content = <<CSV
id,full_name,email,city,plan,last_payment_token,notes
1001,Alice Ficticia,alice@example.invalid,Madrid,enterprise,tok_0000111122223333,AETHER{ap07_public_blob_to_sas_to_private_exfil}
1002,Bruno Imaginario,bruno@example.invalid,Lisbon,pro,tok_4444555566667777,synthetic record - no real PII
1003,Carla Inventada,carla@example.invalid,Paris,free,tok_8888999900001111,synthetic record - no real PII
1004,Diego Ejemplo,diego@example.invalid,Rome,pro,tok_2222333344445555,synthetic record - no real PII
CSV
}

# ==================================================================
# [leak_mode="sas"] Stable, RESET-SAFE expiry for the SAS.
#
# hashicorp/time pins the start once (time_static, persisted in state ->
# no drift) and computes expiry = start + sas_expiry_years (time_offset,
# also persisted). With stable inputs (start/expiry pin + stable
# primary_connection_string, since Terraform does not rotate the key) the
# data.azurerm_storage_account_sas produces a DETERMINISTIC token -> the blob
# backup-config.json is stable -> `terraform plan` after apply = "No changes".
#
# Documented GOTCHA: do NOT use timestamp()/timeadd(timestamp(),...) for
# start/expiry -> it would recompute the HMAC on every apply and re-render the
# blob (perpetual-diff that breaks the idempotency in CONTRIBUTING). That is the
# technical reason that justifies the new provider (precedent: AP05/archive).
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
# [leak_mode="sas"] Deliberately OVER-SCOPED ACCOUNT SAS:
#   resource_types service+container+object, services blob,
#   permissions r/w/d/l/a/c/u/p (+tag/filter, required by the schema).
# Grants write/delete across the WHOLE account -> the escalation branch is demonstrable.
#
# Dependency GOTCHA: the data source READS the key -> requires
# shared_access_key_enabled=true (default). Applying remediation #5 with
# enable_ap07=true makes this data source fail: CORRECT by design (the
# secure state is the default, the vulnerable one is explicit; not a bug).
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

  # Stable pin (persisted in state) -> deterministic token -> idempotent.
  start  = time_static.ap07[0].rfc3339
  expiry = time_offset.ap07_expiry[0].rfc3339

  # Deliberate OVER-SCOPE (least-privilege INVERTED). tag/filter are
  # explicit because the data source schema requires them.
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
# LEAKED blob: backup-config.json in the PUBLIC container.
# The "forgotten" artifact with the over-permissioned credential embedded
# (T1552.001). The source_content switches on leak_mode:
#   - "sas"         : embeds the already-assembled sasUrl (the .sas does NOT carry
#                     the leading "?", which is why it is built as ".../sensitive-data?${sas}").
#   - "account_key" : embeds the primary_access_key + connection string.
#
# Short-circuit (same mechanism as local.ap07_suffix): the "sas" branch
# references data.azurerm_storage_account_sas.ap07[0] and is ONLY taken when
# leak_mode=="sas" (which is exactly when that data source has count=1). In
# "account_key" the branch is not taken -> the data source's [0] is not indexed (count=0).
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
# TELEMETRY (gated local.ap07_collect_logs = enable_ap07 && collect_storage_logs).
#
# The repo's first azurerm_monitor_diagnostic_setting (monitoring.tf uses
# DCR/AMA, which is for a Windows VM's event channel, NOT for the storage
# data plane). The DATA PLANE logs hang off the blobServices/default
# sub-resource, not the account.
#
# Property to highlight: StorageBlobLogs is NOT active by default -> without
# this diagnostic setting the chain (anonymous access + SAS pivot) does NOT exist
# in ANY SIEM (exact analogue of "on-prem events do not exist without
# AMA+DCR" in AP05). The MANAGEMENT plane (the misconfig) travels through
# AzureActivity, which already flows without provisioning anything (as in AP02).
# Ingestion << 0.1 GB/day (a few KB of blobs + the exercise's operations).
# ==================================================================

# Own workspace (OMITTED if the operator points at an external LAW/Sentinel
# via existing_log_analytics_workspace_id). Mirrors azurerm_log_analytics_workspace.ap05.
resource "azurerm_log_analytics_workspace" "ap07" {
  count               = local.ap07_collect_logs && var.existing_log_analytics_workspace_id == null ? 1 : 0
  name                = "${var.lab_prefix}-ap07-law"
  location            = azurerm_resource_group.ap07[0].location
  resource_group_name = azurerm_resource_group.ap07[0].name
  sku                 = "PerGB2018"
  retention_in_days   = 31
  daily_quota_gb      = var.law_daily_cap_gb
}

# Diagnostic setting on blobServices/default -> StorageBlobLogs.
#   - log_analytics_destination_type="Dedicated" -> resource-specific table
#     StorageBlobLogs (rich schema: AuthenticationType, OperationName, Uri,
#     CallerIpAddress, StatusCode, RequesterObjectId) that the KQL is written
#     against; without "Dedicated" it would fall into legacy AzureDiagnostics.
#   - metric{Transaction, enabled=false}: avoids the known perpetual-diff
#     when the API returns the metric block (idempotency in CI).
# Unique name (${lab_prefix}-ap07-blob-diag) so it does not collide if the
# external LAW is the same one AP05 uses.
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
