<#
.SYNOPSIS
    Completes (or remediates) the AP06 vulnerable condition - Entra Connect / Seamless SSO.

.DESCRIPTION
    AP06 is the 2nd HYBRID attack path in the catalog and the one that CLOSES it: the
    on-prem -> cloud bridge. It reuses the SAME hybrid DC as AP05 (shared substrate
    via local.need_dc in Terraform). The base DSC already stood up the forest; this piece
    seeds (seed) or neutralizes (-Remediate) the two directory artifacts that
    enable the chain, which are NOT azurerm resources (like the ESC1 template in
    AP05, they live in the directory and are created imperatively):

      1) AZUREADSSOACC$  -> the Seamless SSO MACHINE account. Its Kerberos key is
         SHARED with Entra ID. A client requests a TGS for the SPN
         HTTP/autologon.microsoftazuread-sso.com encrypted with the AZUREADSSOACC$
         key, and Entra validates it. HEADLINE WEAKNESS: the AZUREADSSOACC$
         password NEVER rotates by default (unlike normal machine accounts, which
         rotate every 30 days) -> its hash, once stolen, is valid FOREVER =
         eternal persistence. The RC4/NT key is deterministic:
         MD4(UTF16LE(password)); with a FIXED/known password the key is
         reproducible and a SILVER TICKET can be forged (T1558.001).

      2) SYNC account (analogous to Entra Connect's MSOL_/Sync_) with DCSync
         rights over the defaultNamingContext. It represents "you have
         compromised the Entra Connect server and dumped the sync credential"
         (T1552). With DCSync (T1003.006) the attacker extracts the Kerberos keys
         of AZUREADSSOACC$ and, with them, forges the silver ticket that
         authenticates to the CLOUD as any synced user WITHOUT their password (T1550).

    Exploit chain (what sets AP06 apart from AP05, which ends at on-prem DCSync):
      sync cred (T1552) -> DCSync (T1003.006) -> AZUREADSSOACC$ keys
      -> SILVER TICKET for HTTP/autologon.microsoftazuread-sso.com (T1558.001)
      -> cloud authentication as a privileged user (T1550).

    Default mode (seed): creates AZUREADSSOACC$ + sync account with DCSync
                         according to -SsoMode (idempotent).
    -Remediate         : rotates the AZUREADSSOACC$ key TWICE (MS fix),
                         removes the DCSync ACEs and disables the sync account.

    -SsoMode:
      silver_ticket -> ONLY AZUREADSSOACC$ (+ SPNs, fixed/unrotated key).
      sync_dcsync   -> ONLY the sync account with DCSync ACEs over the NC.
      both          -> both (full chain; default, honors T1552+T1558).

    CONTEXT: `az vm run-command` runs as SYSTEM (the DC's machine account),
    which is NOT Enterprise Admin and CANNOT create the SSO machine account nor
    write the naming context's nTSecurityDescriptor. This script builds an
    EA PSCredential (DOMAIN\Administrator) from -EaPassword and uses -Credential on
    ALL AD calls. FAILS LOUDLY if it lacks EA rights.

    Exact symmetry with seed-ap05.ps1 (SYSTEM->EA, loud preflight, idempotent,
    -Remediate reset-safe). It touches ONLY these objects: NEVER the CA nor the
    ESC1 template of AP05 (they share the DC but not artifacts).

.NOTES
    Requires the ActiveDirectory module (RSAT-AD-PowerShell, installed by the DSC).
    Enabling auditing of EventID 4662/4769/4741/4742 is done by THIS seed
    (gated by enable_ap06 from outside), NOT by the shared DSC -> AP05 intact.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$DomainFqdn,
    [Parameter(Mandatory = $true)] [string]$DomainNetbios,
    [string]$EaUser = 'Administrator',
    [Parameter(Mandatory = $true)] [string]$EaPassword,
    [ValidateSet('silver_ticket', 'sync_dcsync', 'both')]
    [string]$SsoMode = 'both',
    [string]$SsoAccountName  = 'AZUREADSSOACC',
    [string]$SyncAccountName = 'Sync_AZRANGE',
    # Known passwords (they land in the Terraform state and are passed here).
    # Required in seed mode; NOT in -Remediate (which generates fresh passwords).
    [string]$SsoPassword,
    [string]$SyncPassword,
    [string[]]$SsoSpns = @('HTTP/autologon.microsoftazuread-sso.com', 'HTTP/aadg.windows.net.nsatc.net'),
    [bool]$Remediate = $false
)

$ErrorActionPreference = 'Stop'

# GUIDs of the directory REPLICATION extended rights. The TWO together = the
# complete DCSync primitive; one alone is NOT enough for a functional DCSync.
#   DS-Replication-Get-Changes      -> read replication changes.
#   DS-Replication-Get-Changes-All  -> includes the SECRETS (hashes/Kerberos keys).
$REPL_GET_CHANGES     = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$REPL_GET_CHANGES_ALL = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

Import-Module ActiveDirectory -ErrorAction Stop

# --- Password generator WITHOUT dependencies (System.Web does not auto-load) ---
# Windows PowerShell 5.1 (where `az vm run-command` runs) does NOT auto-load the
# System.Web assembly, so [System.Web.Security.Membership]::GeneratePassword
# throws 'Unable to find type' and, with ErrorActionPreference=Stop, WOULD ABORT the
# -Remediate before removing the DCSync ACEs and disabling the sync account.
# This helper depends on no external assembly and guarantees AD complexity
# (>=2 of each category, shuffled). The password is single-use: it only serves
# to INVALIDATE the AZUREADSSOACC$ key; we never need to know it.
function New-ComplexPassword {
    param([int]$Length = 32)
    $upper   = 65..90
    $lower   = 97..122
    $digit   = 48..57
    $special = 33, 35, 36, 37, 42, 40, 41, 45, 95, 61, 43
    $all     = $upper + $lower + $digit + $special
    $chars   = @()
    $chars  += $upper   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $lower   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $digit   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $special | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $remaining = [Math]::Max(0, $Length - $chars.Count)
    if ($remaining -gt 0) {
        $chars += 1..$remaining | ForEach-Object { [char]($all | Get-Random) }
    }
    # Shuffle so the categories do not stay in fixed positions.
    -join ($chars | Get-Random -Count $chars.Count)
}

# --- Qualified EA credential (run-command = SYSTEM, not EA) ------------------
# ESSENTIAL from -EaPassword (= dc_admin_password / ap06_dc_admin_password),
# NOT from SsoPassword: the run-command's SYSTEM context cannot create the SSO
# machine account nor write the naming context's security descriptor.
$sec = ConvertTo-SecureString $EaPassword -AsPlainText -Force
$EA  = New-Object System.Management.Automation.PSCredential("$DomainNetbios\$EaUser", $sec)

$defaultNC = (Get-ADRootDSE -Server $DomainFqdn -Credential $EA).defaultNamingContext
$ssoSam    = "$SsoAccountName`$"   # a machine account's sAMAccountName carries '$'

# --- Preflight: requires EA rights; fails loudly if SYSTEM/non-EA ------------
try {
    Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -ErrorAction Stop | Out-Null
} catch {
    throw "[AP06] Cannot read the naming context '$defaultNC' as '$DomainNetbios\$EaUser'. " +
          "az vm run-command runs as SYSTEM (not EA): pass EaPassword = the DOMAIN Administrator " +
          "password (dc_admin_password / ap06_dc_admin_password). Detail: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
function Get-SsoComputer {
    Get-ADComputer -Filter "sAMAccountName -eq '$ssoSam'" -Server $DomainFqdn -Credential $EA `
        -Properties servicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
}

function Get-SyncUser {
    Get-ADUser -Filter "sAMAccountName -eq '$SyncAccountName'" -Server $DomainFqdn -Credential $EA `
        -Properties SID -ErrorAction SilentlyContinue
}

# ===========================================================================
# -Remediate: cuts the on-prem->cloud chain. Any one of the three cuts
# is enough (defense in depth); we apply all three, reset-safe/idempotent.
# ===========================================================================
if ($Remediate) {
    Write-Host "[*] Remediating AP06 (Entra Connect / Seamless SSO) ..." -ForegroundColor Green
    $didSomething = $false

    # (A) Rotate the AZUREADSSOACC$ Kerberos key TWICE. Microsoft's official fix
    # is to roll the Seamless SSO decryption key TWICE: it invalidates the
    # already-stolen hash AND the silver tickets already forged with the previous
    # key. A single rotation leaves a window where the previous key is still accepted.
    $sso = Get-SsoComputer
    if ($sso) {
        foreach ($i in 1, 2) {
            $fresh = New-ComplexPassword -Length 32
            Set-ADAccountPassword -Identity $sso.DistinguishedName -Reset `
                -NewPassword (ConvertTo-SecureString $fresh -AsPlainText -Force) `
                -Server $DomainFqdn -Credential $EA
            Write-Host "[+] $ssoSam key rotated (pass $i/2)." -ForegroundColor Green
        }
        $didSomething = $true
    } else {
        Write-Host "[i] $ssoSam does not exist: no Seamless SSO key to rotate." -ForegroundColor DarkGray
    }

    # (B) Remove the sync account's DCSync ACEs over the naming context.
    $sync = Get-SyncUser
    if ($sync) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sync.SID)
        $obj = Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -Properties nTSecurityDescriptor
        $sd  = $obj.nTSecurityDescriptor
        $removed = $false
        foreach ($guid in @($REPL_GET_CHANGES, $REPL_GET_CHANGES_ALL)) {
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow, $guid)
            if ($sd.RemoveAccessRule($ace)) { $removed = $true }
        }
        if ($removed) {
            # Same binary gotcha as seed-ap05: Set-ADObject expects the descriptor
            # in its NATIVE form (octet-string). Passing the ActiveDirectorySecurity
            # object does not serialize reliably and, with ErrorActionPreference=Stop, would abort.
            Set-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA `
                -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }
            Write-Host "[+] DCSync ACEs (Get-Changes + Get-Changes-All) removed from $SyncAccountName." -ForegroundColor Green
        } else {
            Write-Host "[i] $SyncAccountName had no DCSync ACEs to remove (idempotent)." -ForegroundColor DarkGray
        }

        # (C) Disable the sync account (secure/decommission the compromised Entra
        # Connect credential). It is disabled, not deleted, to leave a forensic
        # trail; switch to Remove-ADUser if you want a full purge.
        Disable-ADAccount -Identity $sync.DistinguishedName -Server $DomainFqdn -Credential $EA
        Write-Host "[+] Sync account $SyncAccountName disabled." -ForegroundColor Green
        $didSomething = $true
    } else {
        Write-Host "[i] $SyncAccountName does not exist: no sync cred to neutralize." -ForegroundColor DarkGray
    }

    if ($didSomething) {
        Write-Host "[+] AP06 remediated: Seamless SSO key rotated 2x + DCSync removed + sync disabled." -ForegroundColor Green
        Write-Host "[i] The AZUREADSSOACC$ machine account is kept (disabling it breaks real SSO); what kills the persistence is the DOUBLE rotation of its key." -ForegroundColor Cyan
    } else {
        Write-Host "[i] Nothing to remediate: neither AZUREADSSOACC$ nor $SyncAccountName present." -ForegroundColor DarkGray
    }
    return
}

# ===========================================================================
# seed (default): seeds the AP06 artifacts according to -SsoMode. Idempotent.
# ===========================================================================

# Enable auditing (GATED HERE, not in the shared DSC -> AP05 intact).
# The AP06 KQL/Sigma detections depend on these EventIDs; without the subcategory
# active (and, for 4662, a SACL on the NC) the signatures fire into the void.
# auditpol is idempotent (setting an already-set value is a no-op).
Write-Host "[*] Enabling auditing for the AP06 detections ..." -ForegroundColor Yellow
auditpol /set /subcategory:"Directory Service Access"          /success:enable /failure:enable | Out-Null  # 4662 (DCSync)
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable                 | Out-Null  # 4769 (TGS of the SSO SPN)
auditpol /set /subcategory:"Computer Account Management"        /success:enable                 | Out-Null  # 4741/4742 (AZUREADSSOACC$)
Write-Host "[+] Auditing 4662/4769/4741/4742 enabled." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# (1) AZUREADSSOACC$ : Seamless SSO MACHINE account (modes silver_ticket|both).
# ---------------------------------------------------------------------------
if ($SsoMode -eq 'silver_ticket' -or $SsoMode -eq 'both') {
    $sso = Get-SsoComputer
    if ($sso) {
        Write-Host "[i] $ssoSam already exists: idempotent seed, not recreating." -ForegroundColor DarkGray
        # Ensure the SPNs even if the account already existed (idempotent).
        foreach ($spn in $SsoSpns) {
            if ($sso.servicePrincipalName -notcontains $spn) {
                Set-ADComputer -Identity $sso.DistinguishedName -ServicePrincipalNames @{ Add = $spn } `
                    -Server $DomainFqdn -Credential $EA
                Write-Host "[+] SPN added to $ssoSam : $spn" -ForegroundColor Yellow
            }
        }
    } else {
        if (-not $SsoPassword) {
            throw "[AP06] Mode '$SsoMode' requires -SsoPassword (the FIXED/known password of $ssoSam). " +
                  "It must come from the sensitive output ap06_sso_password."
        }
        Write-Host "[*] Seeding the Seamless SSO account $ssoSam ..." -ForegroundColor Yellow

        # The password is known/fixed -> its RC4/NT Kerberos key is deterministic
        # (MD4(UTF16LE(pwd))) and therefore reproducible to forge the silver ticket.
        # The "unrotated" aspect is STRUCTURAL: no entity rotates AZUREADSSOACC$, so
        # its PasswordLastSet stays fixed/old = the signature of the non-rotation.
        # It is a COMPUTER object (sAMAccountName AZUREADSSOACC$), NOT a user.
        $ssoSec = ConvertTo-SecureString $SsoPassword -AsPlainText -Force
        New-ADComputer -Name $SsoAccountName -SAMAccountName $ssoSam `
            -ServicePrincipalNames $SsoSpns `
            -AccountPassword $ssoSec -PasswordNeverExpires:$true -Enabled $true `
            -Description 'Seamless SSO computer account (Azure Attack Range AP06; key NOT rotated by design)' `
            -Server $DomainFqdn -Credential $EA

        $spnList = $SsoSpns -join ', '
        Write-Host "[+] $ssoSam created with SPNs: $spnList (fixed/unrotated key -> forgeable silver ticket)." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# (2) SYNC account with DCSync (modes sync_dcsync|both).
# ---------------------------------------------------------------------------
if ($SsoMode -eq 'sync_dcsync' -or $SsoMode -eq 'both') {
    $sync = Get-SyncUser
    if ($sync) {
        Write-Host "[i] $SyncAccountName already exists: idempotent seed, not recreating." -ForegroundColor DarkGray
    } else {
        if (-not $SyncPassword) {
            throw "[AP06] Mode '$SsoMode' requires -SyncPassword (the sync account password). " +
                  "It must come from the sensitive output ap06_sync_password."
        }
        Write-Host "[*] Seeding the synchronization account $SyncAccountName ..." -ForegroundColor Yellow
        $syncSec = ConvertTo-SecureString $SyncPassword -AsPlainText -Force
        New-ADUser -Name $SyncAccountName -SamAccountName $SyncAccountName `
            -AccountPassword $syncSec -Enabled $true -PasswordNeverExpires $true `
            -Description 'Entra Connect sync account (Azure Attack Range AP06; on-prem DCSync)' `
            -Server $DomainFqdn -Credential $EA
        Write-Host "[+] $SyncAccountName created." -ForegroundColor Yellow
        $sync = Get-SyncUser
    }

    # Grant DCSync = DS-Replication-Get-Changes (+ -All) ACEs over the ROOT NC
    # (defaultNamingContext, NOT the config NC: the config NC would be something else). The
    # TWO extended rights are needed for a functional DCSync (the second brings
    # the secrets). if-contains guards => idempotent.
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sync.SID)
    $obj = Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -Properties nTSecurityDescriptor
    $sd  = $obj.nTSecurityDescriptor
    # The ACEs read from nTSecurityDescriptor expose IdentityReference as a
    # SecurityIdentifier, not as an NTAccount: we normalize BOTH sides to SID so
    # a re-run detects the ACEs already present (true idempotency = no-op).
    $existing = $sd.Access | Where-Object {
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
        ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $sid)
    }
    $added = $false
    foreach ($guid in @($REPL_GET_CHANGES, $REPL_GET_CHANGES_ALL)) {
        $already = $existing | Where-Object { $_.ObjectType -eq $guid }
        if (-not $already) {
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow, $guid)
            $sd.AddAccessRule($ace)
            $added = $true
        }
    }
    if ($added) {
        # Same binary gotcha as seed-ap05: write the descriptor in its NATIVE
        # form (octet-string), not the ActiveDirectorySecurity object.
        Set-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA `
            -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }
        Write-Host "[+] DCSync granted to $SyncAccountName over $defaultNC (Get-Changes + Get-Changes-All)." -ForegroundColor Yellow
    } else {
        Write-Host "[i] $SyncAccountName already had both DCSync ACEs (idempotent)." -ForegroundColor DarkGray
    }
}

Write-Host "`n[+] AP06 seeded (mode=$SsoMode). Chain: sync cred -> DCSync -> $ssoSam keys -> silver ticket -> CLOUD." -ForegroundColor Green
Write-Host "[i] Attack path in docs/attack-paths/AP06-entra-connect-seamless-sso.md" -ForegroundColor Cyan
Write-Host "[i] In-place remediation: seed-ap06.ps1 -Remediate (rotates the $ssoSam key 2x + removes DCSync + disables sync)." -ForegroundColor Cyan
