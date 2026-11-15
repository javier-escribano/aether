<#
.SYNOPSIS
    AETHER health-check: confirms that the baseline and the active paths exist
    and reports the state of each vulnerable condition.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$TfDir = Join-Path $PSScriptRoot '..\terraform'

function Test-Ok($label, [bool]$ok, $detail = '') {
    $tag = if ($ok) { '[ OK ]' } else { '[FAIL]' }
    $col = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("{0} {1} {2}" -f $tag, $label, $detail) -ForegroundColor $col
}

function Get-TfRaw($name) {
    Push-Location $TfDir
    try {
        $out = terraform output -raw $name 2>$null
        if ($LASTEXITCODE -eq 0 -and $out -and $out -ne 'null') { return $out }
        return $null
    } finally { Pop-Location }
}

Write-Host '=== AETHER - verify ===' -ForegroundColor Cyan

# 1. Terraform outputs present
Push-Location $TfDir
try {
    $users = terraform output -json lab_users 2>$null | ConvertFrom-Json
    $appId = terraform output -raw ap01_app_id 2>$null
} finally { Pop-Location }

Test-Ok 'Base users created' ($users -and $users.Count -gt 0) "($($users.Count) users)"

# 2. AP01: app + consent policy
if ($appId -and $appId -ne 'null') {
    try { Import-Module Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -ErrorAction Stop } catch {}
    # Pin Graph to the active az tenant so we never read a different tenant's
    # consent policy (the Graph token cache is independent of az). [SECURITY.md H-1]
    $azTid = az account show --query tenantId -o tsv 2>$null
    $ctx = Get-MgContext
    if (-not $ctx -or ($azTid -and $ctx.TenantId -ne $azTid)) {
        $cArgs = @{ Scopes = @('Application.Read.All', 'Policy.Read.All'); NoWelcome = $true }
        if ($azTid) { $cArgs['TenantId'] = $azTid }
        Connect-MgGraph @cArgs
    }
    $app = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
    Test-Ok 'AP01 app deployed' ($null -ne $app) "appId=$appId"

    $pol      = Get-MgPolicyAuthorizationPolicy
    $perms    = @($pol.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
    $isVuln   = $perms -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
    Test-Ok 'AP01 vulnerable condition (permissive user-consent)' $isVuln `
        $(if ($isVuln) { '-> exploitable' } else { '-> remediated/safe' })
} else {
    Write-Host '[i] AP01 disabled (enable_ap01=false).' -ForegroundColor DarkGray
}

# 3. AP05: hybrid DC + ESC1 template (gated on the output ap05_dc_vm_name)
$dcVm = Get-TfRaw 'ap05_dc_vm_name'
if ($dcVm) {
    $rg       = Get-TfRaw 'ap05_resource_group'
    $fqdn     = Get-TfRaw 'ap05_domain_fqdn'
    $caName   = Get-TfRaw 'ap05_ca_name'
    $template = Get-TfRaw 'ap05_esc1_template_name'
    $lowUpn   = Get-TfRaw 'ap05_lowpriv_upn'

    Test-Ok 'AP05 DC deployed'           ($null -ne $dcVm)     "vm=$dcVm rg=$rg"
    Test-Ok 'AP05 domain defined'        ($null -ne $fqdn)     "fqdn=$fqdn"
    Test-Ok 'AP05 CA defined'            ($null -ne $caName)   "ca=$caName"
    Test-Ok 'AP05 ESC1 template defined' ($null -ne $template) "template=$template"
    Test-Ok 'AP05 low-priv user'         ($null -ne $lowUpn)   "upn=$lowUpn"

    # Optional: confirm on the DC that the template is published and marked ESC1
    # and that the CA audits (AuditFilter=127). Requires az and the VM powered on.
    if ($rg -and (Get-Command az -ErrorAction SilentlyContinue)) {
        try {
            $probe = @(
                "certutil -template $template 2>&1 | Select-String -Pattern 'ENROLLEE_SUPPLIES_SUBJECT','$template' | Out-String",
                "certutil -getreg CA\AuditFilter 2>&1 | Out-String"
            ) -join "`n"
            $res = az vm run-command invoke -g $rg -n $dcVm --command-id RunPowerShellScript --scripts $probe -o json 2>$null | ConvertFrom-Json
            $msg = ($res.value | ForEach-Object { $_.message }) -join "`n"
            Test-Ok 'AP05 ESC1 template published (certutil)' ($msg -match [regex]::Escape($template)) '-> requestable'
            Test-Ok 'AP05 CA auditing enabled (AuditFilter=127)' ($msg -match '0x7f|127') '-> Detect operational'
        } catch {
            Write-Host '[i] AP05: could not probe the DC (VM deallocated by auto-shutdown?).' -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host '[i] AP05 disabled (enable_ap05=false).' -ForegroundColor DarkGray
}

# 3b. AP06: Entra Connect / Seamless SSO (gated on the output ap06_dc_vm_name).
# Its OWN sentinel: does not reuse ap05_dc_vm_name (which is null with enable_ap05=false
# even if the shared VM exists via AP06).
$dc06 = Get-TfRaw 'ap06_dc_vm_name'
if ($dc06) {
    $rg06    = Get-TfRaw 'ap06_resource_group'
    $ssoAcc  = Get-TfRaw 'ap06_sso_account'
    $syncAcc = Get-TfRaw 'ap06_sync_account'
    $mode06  = Get-TfRaw 'ap06_sso_mode'

    Test-Ok 'AP06 DC (shared) deployed'      ($null -ne $dc06)    "vm=$dc06 rg=$rg06"
    Test-Ok 'AP06 Seamless SSO account def.' ($null -ne $ssoAcc)  "acct=$ssoAcc"
    Test-Ok 'AP06 sync account def.'         ($null -ne $syncAcc) "acct=$syncAcc"
    Test-Ok 'AP06 sso_mode'                  ($null -ne $mode06)  "mode=$mode06"

    # Optional probe (requires az and the VM powered on): confirms on the DC that
    # AZUREADSSOACC$ exists with its Seamless SSO SPN and/or that the sync account
    # is present, according to the seeded mode.
    if ($rg06 -and (Get-Command az -ErrorAction SilentlyContinue)) {
        try {
            $probe = @(
                "Import-Module ActiveDirectory;",
                "`$c = Get-ADComputer -Filter `"sAMAccountName -eq 'AZUREADSSOACC`$'`" -Properties PasswordLastSet,servicePrincipalName -ErrorAction SilentlyContinue;",
                "if (`$c) { 'SSOACCT_PRESENT'; `$c.servicePrincipalName -join ';'; 'PWDLASTSET=' + `$c.PasswordLastSet } else { 'SSOACCT_ABSENT' }",
                "`$u = Get-ADUser -Filter `"sAMAccountName -eq '$syncAcc'`" -ErrorAction SilentlyContinue;",
                "if (`$u) { 'SYNC_PRESENT' } else { 'SYNC_ABSENT' }"
            ) -join "`n"
            $res = az vm run-command invoke -g $rg06 -n $dc06 --command-id RunPowerShellScript --scripts $probe -o json 2>$null | ConvertFrom-Json
            $m = ($res.value | ForEach-Object { $_.message }) -join "`n"
            if ($mode06 -ne 'sync_dcsync') {
                Test-Ok 'AP06 AZUREADSSOACC$ present + SPN' ($m -match 'SSOACCT_PRESENT' -and $m -match 'autologon.microsoftazuread-sso.com') '-> forgeable silver ticket'
            }
            if ($mode06 -ne 'silver_ticket') {
                Test-Ok 'AP06 sync account present (DCSync)' ($m -match 'SYNC_PRESENT') '-> DCSync primitive'
            }
        } catch {
            Write-Host '[i] AP06: could not probe the DC (VM deallocated by auto-shutdown?).' -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host '[i] AP06 disabled (enable_ap06=false).' -ForegroundColor DarkGray
}

# 4. AP07: public storage / SAS leak (gated on the output ap07_storage_account)
$ap07Sa = Get-TfRaw 'ap07_storage_account'
if ($ap07Sa) {
    $ap07Rg     = Get-TfRaw 'ap07_resource_group'
    $ap07PubUrl = Get-TfRaw 'ap07_public_container_url'
    $ap07CfgUrl = Get-TfRaw 'ap07_leaked_config_url'
    $ap07Priv   = Get-TfRaw 'ap07_private_container'
    $ap07Law    = Get-TfRaw 'ap07_law_name'

    Test-Ok 'AP07 storage deployed'      ($null -ne $ap07Sa)   "sa=$ap07Sa rg=$ap07Rg"
    Test-Ok 'AP07 private container def.' ($null -ne $ap07Priv) "container=$ap07Priv"

    # Anonymous probe (requires neither az nor credentials): confirms the end-to-end chain.
    # Invoke-WebRequest degrades gracefully if there is no network or the account has not propagated DNS yet.
    if ($ap07PubUrl) {
        try {
            $listUrl = "$($ap07PubUrl)?restype=container&comp=list"
            $resp = Invoke-WebRequest -Uri $listUrl -UseBasicParsing -TimeoutSec 20
            # The double open door (account allow=true AND container=container) allows
            # anonymous LISTING: the XML must name backup-config.json (T1619).
            Test-Ok 'AP07 anonymous enumeration (public LIST)' ($resp.Content -match 'backup-config\.json') '-> double open door (T1619)'
        } catch {
            Write-Host '[i] AP07: could not probe the public container (network / DNS propagation / remediated).' -ForegroundColor DarkGray
        }
    }

    if ($ap07CfgUrl) {
        try {
            $cfg = Invoke-WebRequest -Uri $ap07CfgUrl -UseBasicParsing -TimeoutSec 20
            # Anonymous download of the leaked artifact with the credential (T1552.001).
            Test-Ok 'AP07 anonymous download of backup-config.json' ($cfg.StatusCode -eq 200) '-> leaked credential (T1552.001)'
        } catch {
            Write-Host '[i] AP07: backup-config.json not anonymously accessible (remediated?).' -ForegroundColor DarkGray
        }
    }

    # The private container must NOT be anonymously listable (confirms private).
    $privListable = $false
    try {
        $privListUrl = 'https://{0}.blob.core.windows.net/{1}?restype=container&comp=list' -f $ap07Sa, $ap07Priv
        $null = Invoke-WebRequest -Uri $privListUrl -UseBasicParsing -TimeoutSec 20
        $privListable = $true   # 2xx => bad (sensitive-data would be public)
    } catch {
        $privListable = $false  # 4xx / denied => good (private)
    }
    Test-Ok 'AP07 private container NOT anon. listable' (-not $privListable) '-> sensitive-data = private'

    if ($ap07Law) {
        Test-Ok 'AP07 telemetry (StorageBlobLogs -> LAW)' ($null -ne $ap07Law) "law=$ap07Law"
    } else {
        Write-Host '[i] AP07: telemetry off or external LAW (collect_storage_logs=false / existing_log_analytics_workspace_id).' -ForegroundColor DarkGray
    }
} else {
    Write-Host '[i] AP07 disabled (enable_ap07=false).' -ForegroundColor DarkGray
}

# 5. AP08: Automation Account runbook -> RBAC escalation (gated on the output ap08_automation_account)
$ap08Aa = Get-TfRaw 'ap08_automation_account'
if ($ap08Aa) {
    $ap08Rg      = Get-TfRaw 'ap08_resource_group'
    $ap08Mi      = Get-TfRaw 'ap08_mi_principal_id'
    $ap08Role    = Get-TfRaw 'ap08_mi_role'
    $ap08Runbook = Get-TfRaw 'ap08_runbook_name'
    $ap08Upn     = Get-TfRaw 'ap08_attacker_upn'
    $ap08Law     = Get-TfRaw 'ap08_law_name'

    Test-Ok 'AP08 Automation Account deployed' ($null -ne $ap08Aa)  "aa=$ap08Aa rg=$ap08Rg"
    Test-Ok 'AP08 system-assigned MI present'  ($null -ne $ap08Mi)  "mi=$ap08Mi role=$ap08Role"
    Test-Ok 'AP08 low-priv attacker defined'   ($null -ne $ap08Upn) "upn=$ap08Upn"
    if ($ap08Runbook) {
        Test-Ok 'AP08 embedded runbook (loaded gun)' ($null -ne $ap08Runbook) "runbook=$ap08Runbook"
    } else {
        Write-Host '[i] AP08: runbook_mode=none (pure misconfig, no embedded runbook).' -ForegroundColor DarkGray
    }

    # POSTURE probe (optional, requires az): confirms that the MI holds the
    # over-priv role (UAA/Owner) OVER THE RG - the primitive that enables the escalation.
    # It does NOT confirm a runtime escalation: the apply fires nothing (the "gun"
    # is fired by the student). verify validates the POSTURE, not a runtime grant.
    if ($ap08Rg -and $ap08Mi -and (Get-Command az -ErrorAction SilentlyContinue)) {
        try {
            $rgId = az group show -n $ap08Rg --query id -o tsv 2>$null
            if ($rgId) {
                $raRaw = az role assignment list --assignee $ap08Mi --scope $rgId -o json 2>$null
                $roles = @()
                try { $roles = @($raRaw | ConvertFrom-Json) | ForEach-Object { $_.roleDefinitionName } } catch {}
                $hasOverPriv = @($roles | Where-Object { $_ -in @('Owner', 'User Access Administrator') }).Count -gt 0
                Test-Ok 'AP08 MI holds over-priv role over the RG' $hasOverPriv "-> roleAssignments/write (roles=$(@($roles) -join ', '))"
            }
        } catch {
            Write-Host '[i] AP08: could not probe the MI role assignment (network / permissions / AAD propagation).' -ForegroundColor DarkGray
        }
    }

    if ($ap08Law) {
        Test-Ok 'AP08 telemetry (JobLogs+JobStreams -> LAW)' ($null -ne $ap08Law) "law=$ap08Law"
    } else {
        Write-Host '[i] AP08: telemetry off or external LAW (collect_automation_logs=false / existing_log_analytics_workspace_id).' -ForegroundColor DarkGray
    }
} else {
    Write-Host '[i] AP08 disabled (enable_ap08=false).' -ForegroundColor DarkGray
}

Write-Host "`nVerification finished." -ForegroundColor Cyan
