# Caelum Range

> Cyber range **Azure + Entra ID + AD híbrido** desplegable como código.
> Una ruta de ataque, su fix y su detección — en un solo comando, reproducible, destruible.

`Caelum` es un nombre de trabajo (cielo/nube en latín). Renómbralo si quieres.

---

## Por qué existe (el hueco)

Para on-prem ya tenemos **GOAD**. Para la nube, el material bueno o es de pago (academias) o está fragmentado:

| Proyecto | Cubre | Limitación |
|----------|-------|------------|
| **BadZure** (M. Velazco) | Entra ID identity misconfigs | solo identidad, sin Azure resources ni híbrido, sin capa de detección curada |
| **PurpleCloud** (J. Ostrom) | Azure AD + híbrido pentest lab | orientado a infra, poca guía pedagógica por ruta |
| **AzureGoat** (INE) | Infra Azure vulnerable (web) | enfoque app web, no identity/red-team path |
| **XMGoat** | Escenarios de ataque Azure | escenarios sueltos, sin "arregla/detecta" |
| **SimuLand** (MS) | Detección | foco defensivo, no range de aprendizaje ofensivo |

**Caelum** no reinventa esos — toma sus patrones y los integra en **un único range curado** con tres cosas que ninguno junta:

1. **Un comando** levanta Entra + Azure (+ híbrido opcional) con misconfigs reales activables por *feature flag*.
2. Cada ruta trae la terna completa **rompe → arregla → detecta** (Sigma + KQL), mapeada a **MITRE ATT&CK** y al temario de certs (CARTP/CARTE/CRTO/CRTE).
3. **Otros lo clonan y extienden**: `CONTRIBUTING.md` define cómo añadir una ruta nueva en < 1 hora.

---

## ⚠️ Antes de desplegar nada — léelo

Esto crea **configuraciones deliberadamente vulnerables**. Trátalas como tóxicas.

- **Tenant dedicado de test. NUNCA el corporativo.** Crea un tenant Entra nuevo y una subscription aislada solo para esto.
- **Sin datos reales.** Usuarios, correos y secretos son ficticios y sembrados por el range.
- **Coste:** la capa *identity-only* (AP01, AP03, AP04) es prácticamente gratis (Entra Free). Las VMs del híbrido (AP05/AP06) sí facturan — usa `caelum.ps1 destroy` al terminar y activa *billing alerts* (ver `docs/00-setup.md`).
- **Teardown siempre disponible:** `caelum.ps1 destroy` elimina todo; `reset` deja la base y quita las vulns.
- Uso educativo / entrenamiento autorizado en infraestructura propia. Es lo mismo que hacen GOAD/BadZure/AzureGoat.

---

## Quickstart

```powershell
# 1. Requisitos (ver docs/00-setup.md): Azure CLI, Terraform >= 1.6, módulo Microsoft.Graph de PowerShell
az login --tenant <TU_TENANT_DE_TEST>.onmicrosoft.com

# 2. Configura tu despliegue
cd terraform
cp terraform.tfvars.example terraform.tfvars   # edita: tenant, dominio, qué rutas activar

# 3. Despliega (idempotente)
cd ..
./caelum.ps1 deploy

# 4. Comprueba estado
./caelum.ps1 verify

# 5. Al terminar la sesión de entrenamiento
./caelum.ps1 destroy
```

---

## Catálogo de rutas de ataque

Activables por *flag* en `terraform.tfvars`. ✅ = incluida en este esqueleto · 🟡 = scaffolding · ⬜ = roadmap.

| ID | Ruta | Capa | Coste | MITRE | Cert |
|----|------|------|-------|-------|------|
| **AP01** ✅ | Illicit consent grant → robo de token Graph | Entra | ~0 | T1528, T1098.003 | CARTP/CARTE |
| **AP02** ✅ | Managed Identity sobre-privilegiada → secreto en Key Vault → lateral | Azure | bajo | T1552.005, T1078.004 | CARTP/CARTE |
| **AP03** ✅ | Owner de bajo privilegio sobre grupo role-assignable (Privileged Role Administrator) → self-add → Global Admin | Entra | ~0 (P1) | T1098, T1098.003, T1078.004 | CARTP/CARTE |
| **AP04** ✅ | Owner de bajo privilegio sobre app registration (SP con RoleManagement.ReadWrite.Directory) → add secret → Global Admin | Entra | ~0 | T1098.001, T1098.003, T1078.004 | CRTO/CARTE |
| **AP05** ✅ | Usuario de bajo privilegio enrola plantilla AD CS ESC1 (enrollee-supplies-subject) → cert con SAN de Domain Admin → PKINIT → DCSync | Híbrido | VM | T1649, T1550, T1003.006 | CRTO/CRTE |
| **AP06** ✅ | Credencial de sync de Entra Connect (DCSync) → extrae la clave Kerberos nunca-rotada de `AZUREADSSOACC$` → forja un silver ticket de Seamless SSO → autentica a la nube como cualquier usuario sincronizado (bridge on-prem→cloud) | Híbrido | VM | T1552, T1003.006, T1558.001, T1550 | CARTE/CRTE |
| **AP07** ✅ | Usuario anónimo lista un contenedor público → descarga `backup-config.json` → usa la SAS over-scoped filtrada para leer el contenedor privado (exfiltración de datos) | Azure | ~0 | T1530, T1619, T1552.001 | CARTP |
| **AP08** ✅ | Low-priv con *Automation Contributor* lanza un runbook que corre como la Managed Identity over-privilegiada del Automation Account → `New-AzRoleAssignment` → Owner del RG | Azure | ~0 | T1651, T1098.003, T1078.004 | CARTP/CARTE |

Cada ruta vive en `docs/attack-paths/APxx-*.md` con la terna **rompe / arregla / detecta**.

---

## Estructura

```
caelum-range/
├─ README.md                  ← estás aquí
├─ caelum.ps1                 ← orquestador: deploy | reset | destroy | verify | status
├─ .gitignore                 ← bloquea tfstate y secretos (NO lo quites)
├─ CONTRIBUTING.md            ← cómo añadir una ruta nueva (para que otros extiendan)
├─ docs/
│  ├─ 00-setup.md             ← requisitos, permisos, control de coste
│  └─ attack-paths/
│     ├─ AP01-illicit-consent.md       ← ruta completa de ejemplo (plantilla)
│     ├─ AP02-managed-identity.md       ← Managed Identity → Key Vault → lateral
│     ├─ AP03-role-assignable-group.md  ← owner → self-add → PRA → Global Admin
│     ├─ AP04-app-credential-abuse.md   ← owner de app → add secret → Global Admin
│     ├─ AP05-adcs-esc1.md              ← AD CS ESC1 → PKINIT como Domain Admin → DCSync (híbrido)
│     ├─ AP06-entra-connect-seamless-sso.md ← Entra Connect: DCSync AZUREADSSOACC$ → silver ticket Seamless SSO → nube (híbrido)
│     ├─ AP07-public-storage-leak.md    ← blob público → SAS filtrada → exfil del contenedor privado
│     └─ AP08-automation-runbook-rbac.md ← runbook como MI over-priv → New-AzRoleAssignment → Owner del RG
├─ terraform/
│  ├─ providers.tf  variables.tf  main.tf  outputs.tf
│  ├─ terraform.tfvars.example
│  └─ modules/
│     ├─ entra-identity/      ← base + AP01 (consent) + AP03 (grupo) + AP04 (app reg) por flag
│     ├─ azure-resources/     ← capa Azure (VM/MI/Key Vault/storage/Automation) + AP02 + AP07 + AP08 por flag; ap07-storage.tf, ap08-automation.tf
│     └─ hybrid-ad/           ← DC Windows Server 2022 + AD DS + Enterprise Root CA + AMA/DCR; DC compartido (local.need_dc) por AP05 (ESC1) + AP06 (Entra Connect/SSO) por flag; ap06-entra-connect.tf, dsc/CaelumDC.ps1
├─ scripts/
│  ├─ seed-ap01.ps1           ← lo que Terraform no cubre bien (consents vía Graph)
│  ├─ seed-ap05.ps1           ← siembra / remedia (-Remediate) la plantilla ESC1 (vía az vm run-command)
│  ├─ seed-ap06.ps1           ← siembra / remedia AZUREADSSOACC$ + cuenta de sync con DCSync (vía az vm run-command)
│  └─ verify.ps1              ← health-check del range
└─ detections/
   ├─ kql/   AP01-illicit-consent.kql · AP02-managed-identity.kql · AP03-role-assignable-group.kql · AP04-app-credential-abuse.kql · AP05-adcs-esc1.kql · AP06-entra-connect-seamless-sso.kql · AP07-public-storage-leak.kql · AP08-automation-runbook-rbac.kql
   └─ sigma/ AP01-illicit-consent.yml · AP02-managed-identity.yml · AP03-role-assignable-group.yml · AP04-app-credential-abuse.yml · AP05-adcs-esc1.yml · AP06-entra-connect-seamless-sso.yml · AP07-public-storage-leak.yml · AP08-automation-runbook-rbac.yml
```

---

## Estado de este esqueleto

Esto es el **andamiaje + las ocho rutas verticales completas: el catálogo entero (AP01 + AP02 + AP03 + AP04 + AP05 + AP06 + AP07 + AP08)**. Lo que ya está:

- Estructura, orquestador, control de coste/seguridad y pauta de contribución.
- Terraform base de identidad (usuarios/grupos/app) con AP01 activable por flag.
- AP01 (Entra, ~0 coste) de punta a punta: despliegue → doc rompe/arregla/detecta → KQL + Sigma.
- AP02 (Azure, coste bajo) de punta a punta: módulo `azure-resources` (VM + MI + Key Vault + storage) → doc → KQL + Sigma.
- AP03 (Entra, ~0 pero requiere P1) de punta a punta: owner de grupo role-assignable → self-add → Privileged Role Administrator → Global Admin; doc → KQL + Sigma.
- AP04 (Entra, ~0, Entra Free) de punta a punta: owner de app registration cuyo SP porta RoleManagement.ReadWrite.Directory → add secret → token del SP → Global Admin; doc → KQL + Sigma.
- AP05 (Híbrido, **factura cómputo**) de punta a punta: módulo `hybrid-ad` (VM Windows Server 2022 + AD DS + Enterprise Root CA) con la plantilla ESC1 `CaelumAuthESC1` sembrada por `seed-ap05.ps1`; usuario de bajo privilegio → cert con SAN de Domain Admin → PKINIT → TGT de DA → DCSync; doc → KQL + Sigma (`SecurityEvent` vía AMA/DCR). **Reset-safe:** `enable_ap05 = false` destruye la VM y con ella la plantilla (reset sin residuo *out-of-state*, tan limpio como AP07/AP08).
- AP06 (Híbrido, **factura cómputo**) de punta a punta: 2ª ruta híbrida y la que **cierra el catálogo**. **Comparte el DC de AP05** — gate `local.need_dc = enable_ap05 || enable_ap06`, un único DC/CA sirve a ambas (con `enable_ap05 = true` el plan de AP05 es idéntico). `seed-ap06.ps1` siembra la cuenta de máquina `AZUREADSSOACC$` (SPNs de Seamless SSO + clave **nunca-rotada**) y la cuenta de sincronización de Entra Connect con derechos **DCSync**. Cadena **bridge on-prem→cloud** (lo que la distingue de AP05, que acaba on-prem): cred de sync → DCSync de `AZUREADSSOACC$` (T1003.006) → **silver ticket** de Seamless SSO (T1558.001) → autenticación a la **nube** como cualquier usuario sincronizado (T1550); la clave no-rotada = persistencia eterna. Telemetría `SecurityEvent` (4662 DCSync / 4769 / 4741-4742) por el mismo AMA/DCR de AP05 (XPath extendido **solo** con `enable_ap06`); doc → KQL + Sigma. **Reset-safe:** con las dos flags híbridas en false, `need_dc` cae y el DC compartido se destruye (coste → 0); el caso selectivo (AP06 off, AP05 on) se remedia in-place con `seed-ap06.ps1 -Remediate`.
- AP07 (Azure, **coste ~0**, **100 % declarativa — sin `seed`**) de punta a punta: en el módulo `azure-resources`, `ap07-storage.tf` levanta una storage account con doble puerta anónima (cuenta `allow_nested_items_to_be_public = true` + contenedor `public` tipo `container`); un `backup-config.json` legible sin autenticar filtra una **SAS de cuenta over-scoped** (idempotente vía `hashicorp/time`) hacia el contenedor privado `sensitive-data`. Cadena: enumeración anónima → descarga → SAS → exfil de `customers.csv` (PII sintética). Telemetría `StorageBlobLogs` (diagnostic settings → Log Analytics); doc → KQL + Sigma. **Reset-safe:** `enable_ap07 = false` destruye la cuenta entera (blob filtrado y SAS incluidos).
- AP08 (Azure, **coste ~0**, **declarativa — sin `seed`**) de punta a punta: en el módulo `azure-resources`, `ap08-automation.tf` crea un Automation Account con **Managed Identity system-assigned over-privilegiada** (`User Access Administrator`/`Owner` sobre el RG) y un atacante low-priv dedicado (`azuread_user` + `Automation Contributor` sobre el RG); el alumno lanza un runbook incrustado (`runbook_mode`: `poc_escalation`/`benign_probe`/`none`) que corre **como la MI** → `New-AzRoleAssignment` → **Owner del RG**. Cadena: Automation Contributor → job como MI (T1651) → self-grant de rol (T1098.003) → Owner (T1078.004). Telemetría `JobLogs`/`JobStreams` (diagnostic setting → Log Analytics) + `AzureActivity`; doc → KQL + Sigma. **Reset-safe (RG-scoped):** `enable_ap08 = false` destruye el RG y con él toda role assignment de runtime scoped al RG (tan limpio como AP05/AP07).

Lo que **tú** iteras después (requiere tu tenant de test para probar `terraform apply`):
- Validar el `apply` contra un tenant real: AP01 necesita permisos de Graph; AP02 y AP05 necesitan subscription y **facturan cómputo** (AP05 es una VM Windows always-on → disciplina de `destroy`/auto-shutdown + salida 443 a PSGallery para los módulos DSC); AP03 necesita **Entra ID P1**; AP03/AP04 necesitan un deployer con Privileged Role Administrator/Global Admin (para el admin-consent / la asignación de rol); AP07 necesita subscription con rol **Contributor** pero **coste ~0** (storage + ingesta mínima de logs, sin cómputo); AP08 necesita subscription con **Contributor** + permiso para crear el `azuread_user` atacante (rol Entra, p. ej. *User Administrator*) y para asignar RBAC sobre su RG (Owner/UAA del RG), también **coste ~0** y sin cómputo; AP06 **comparte la VM de AP05** (misma factura de cómputo y disciplina de `destroy`/auto-shutdown) y su `seed-ap06.ps1` corre vía `az vm run-command` con la credencial EA del DC.
- **El catálogo base (AP01–AP08) está completo.** Extiéndelo con rutas nuevas (AP09+) siguiendo `CONTRIBUTING.md` (< 1 h por ruta).
- Validar el IaC en CI: `terraform fmt -check -recursive` y `terraform init -backend=false && terraform validate` (el repo entero pasa `validate` con Terraform 1.17).
- Conectar `detections/` a tu Log Analytics / Sentinel.

---

_Range de entrenamiento. Despliega solo en tenants y subscriptions de test que controles._
