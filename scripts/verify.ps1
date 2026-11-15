<#
.SYNOPSIS
    Health-check del Caelum Range: comprueba que la base y las rutas activas existen
    y reporta el estado de cada condición vulnerable.
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

Write-Host '=== Caelum Range — verify ===' -ForegroundColor Cyan

# 1. Outputs de Terraform presentes
Push-Location $TfDir
try {
    $users = terraform output -json lab_users 2>$null | ConvertFrom-Json
    $appId = terraform output -raw ap01_app_id 2>$null
} finally { Pop-Location }

Test-Ok 'Usuarios base creados' ($users -and $users.Count -gt 0) "($($users.Count) usuarios)"

# 2. AP01: app + policy de consentimiento
if ($appId -and $appId -ne 'null') {
    try { Import-Module Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -ErrorAction Stop } catch {}
    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes 'Application.Read.All', 'Policy.Read.All' -NoWelcome
    }
    $app = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
    Test-Ok 'AP01 app desplegada' ($null -ne $app) "appId=$appId"

    $pol      = Get-MgPolicyAuthorizationPolicy
    $perms    = @($pol.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
    $isVuln   = $perms -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
    Test-Ok 'AP01 condición vulnerable (user-consent permisivo)' $isVuln `
        $(if ($isVuln) { '-> explotable' } else { '-> remediado/seguro' })
} else {
    Write-Host '[i] AP01 desactivado (enable_ap01=false).' -ForegroundColor DarkGray
}

# 3. AP05: DC híbrido + plantilla ESC1 (gated en el output ap05_dc_vm_name)
$dcVm = Get-TfRaw 'ap05_dc_vm_name'
if ($dcVm) {
    $rg       = Get-TfRaw 'ap05_resource_group'
    $fqdn     = Get-TfRaw 'ap05_domain_fqdn'
    $caName   = Get-TfRaw 'ap05_ca_name'
    $template = Get-TfRaw 'ap05_esc1_template_name'
    $lowUpn   = Get-TfRaw 'ap05_lowpriv_upn'

    Test-Ok 'AP05 DC desplegado'           ($null -ne $dcVm)     "vm=$dcVm rg=$rg"
    Test-Ok 'AP05 dominio definido'        ($null -ne $fqdn)     "fqdn=$fqdn"
    Test-Ok 'AP05 CA definida'             ($null -ne $caName)   "ca=$caName"
    Test-Ok 'AP05 plantilla ESC1 definida' ($null -ne $template) "template=$template"
    Test-Ok 'AP05 usuario low-priv'        ($null -ne $lowUpn)   "upn=$lowUpn"

    # Opcional: confirmar en el DC que la plantilla está publicada y marcada ESC1
    # y que la CA audita (AuditFilter=127). Requiere az y que la VM esté encendida.
    if ($rg -and (Get-Command az -ErrorAction SilentlyContinue)) {
        try {
            $probe = @(
                "certutil -template $template 2>&1 | Select-String -Pattern 'ENROLLEE_SUPPLIES_SUBJECT','$template' | Out-String",
                "certutil -getreg CA\AuditFilter 2>&1 | Out-String"
            ) -join "`n"
            $res = az vm run-command invoke -g $rg -n $dcVm --command-id RunPowerShellScript --scripts $probe -o json 2>$null | ConvertFrom-Json
            $msg = ($res.value | ForEach-Object { $_.message }) -join "`n"
            Test-Ok 'AP05 plantilla ESC1 publicada (certutil)' ($msg -match [regex]::Escape($template)) '-> solicitable'
            Test-Ok 'AP05 auditoría CA habilitada (AuditFilter=127)' ($msg -match '0x7f|127') '-> Detecta operativo'
        } catch {
            Write-Host '[i] AP05: no se pudo sondear el DC (¿VM deallocada por auto-shutdown?).' -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host '[i] AP05 desactivado (enable_ap05=false).' -ForegroundColor DarkGray
}

# 3b. AP06: Entra Connect / Seamless SSO (gated en el output ap06_dc_vm_name).
# Centinela PROPIO: no reusa ap05_dc_vm_name (que es null con enable_ap05=false
# aunque la VM compartida exista por AP06).
$dc06 = Get-TfRaw 'ap06_dc_vm_name'
if ($dc06) {
    $rg06    = Get-TfRaw 'ap06_resource_group'
    $ssoAcc  = Get-TfRaw 'ap06_sso_account'
    $syncAcc = Get-TfRaw 'ap06_sync_account'
    $mode06  = Get-TfRaw 'ap06_sso_mode'

    Test-Ok 'AP06 DC (compartido) desplegado' ($null -ne $dc06)    "vm=$dc06 rg=$rg06"
    Test-Ok 'AP06 cuenta Seamless SSO def.'   ($null -ne $ssoAcc)  "acct=$ssoAcc"
    Test-Ok 'AP06 cuenta de sync def.'        ($null -ne $syncAcc) "acct=$syncAcc"
    Test-Ok 'AP06 sso_mode'                   ($null -ne $mode06)  "mode=$mode06"

    # Sonda opcional (requiere az y la VM encendida): confirma en el DC que
    # AZUREADSSOACC$ existe con su SPN de Seamless SSO y/o que la cuenta de sync
    # está presente, según el modo sembrado.
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
                Test-Ok 'AP06 AZUREADSSOACC$ presente + SPN' ($m -match 'SSOACCT_PRESENT' -and $m -match 'autologon.microsoftazuread-sso.com') '-> silver ticket forjable'
            }
            if ($mode06 -ne 'silver_ticket') {
                Test-Ok 'AP06 cuenta de sync presente (DCSync)' ($m -match 'SYNC_PRESENT') '-> primitiva DCSync'
            }
        } catch {
            Write-Host '[i] AP06: no se pudo sondear el DC (¿VM deallocada por auto-shutdown?).' -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host '[i] AP06 desactivado (enable_ap06=false).' -ForegroundColor DarkGray
}

# 4. AP07: storage público / SAS leak (gated en el output ap07_storage_account)
$ap07Sa = Get-TfRaw 'ap07_storage_account'
if ($ap07Sa) {
    $ap07Rg     = Get-TfRaw 'ap07_resource_group'
    $ap07PubUrl = Get-TfRaw 'ap07_public_container_url'
    $ap07CfgUrl = Get-TfRaw 'ap07_leaked_config_url'
    $ap07Priv   = Get-TfRaw 'ap07_private_container'
    $ap07Law    = Get-TfRaw 'ap07_law_name'

    Test-Ok 'AP07 storage desplegada'      ($null -ne $ap07Sa)   "sa=$ap07Sa rg=$ap07Rg"
    Test-Ok 'AP07 contenedor privado def.' ($null -ne $ap07Priv) "container=$ap07Priv"

    # Sonda anónima (no requiere az ni credenciales): confirma la cadena end-to-end.
    # Invoke-WebRequest degrada con gracia si no hay red o la cuenta aún no propagó DNS.
    if ($ap07PubUrl) {
        try {
            $listUrl = "$($ap07PubUrl)?restype=container&comp=list"
            $resp = Invoke-WebRequest -Uri $listUrl -UseBasicParsing -TimeoutSec 20
            # La doble puerta abierta (cuenta allow=true Y contenedor=container) deja
            # LISTAR anónimamente: el XML debe nombrar backup-config.json (T1619).
            Test-Ok 'AP07 enumeración anónima (LIST público)' ($resp.Content -match 'backup-config\.json') '-> doble puerta abierta (T1619)'
        } catch {
            Write-Host '[i] AP07: no se pudo sondear el contenedor público (red / propagación DNS / remediado).' -ForegroundColor DarkGray
        }
    }

    if ($ap07CfgUrl) {
        try {
            $cfg = Invoke-WebRequest -Uri $ap07CfgUrl -UseBasicParsing -TimeoutSec 20
            # Descarga anónima del artefacto filtrado con la credencial (T1552.001).
            Test-Ok 'AP07 descarga anónima backup-config.json' ($cfg.StatusCode -eq 200) '-> credencial filtrada (T1552.001)'
        } catch {
            Write-Host '[i] AP07: backup-config.json no accesible anónimamente (¿remediado?).' -ForegroundColor DarkGray
        }
    }

    # El contenedor privado NO debe ser listable anónimamente (confirma private).
    $privListable = $false
    try {
        $privListUrl = 'https://{0}.blob.core.windows.net/{1}?restype=container&comp=list' -f $ap07Sa, $ap07Priv
        $null = Invoke-WebRequest -Uri $privListUrl -UseBasicParsing -TimeoutSec 20
        $privListable = $true   # 2xx => mal (sensitive-data sería público)
    } catch {
        $privListable = $false  # 4xx / denegado => bien (private)
    }
    Test-Ok 'AP07 contenedor privado NO listable anón.' (-not $privListable) '-> sensitive-data = private'

    if ($ap07Law) {
        Test-Ok 'AP07 telemetría (StorageBlobLogs -> LAW)' ($null -ne $ap07Law) "law=$ap07Law"
    } else {
        Write-Host '[i] AP07: telemetría off o LAW externo (collect_storage_logs=false / existing_log_analytics_workspace_id).' -ForegroundColor DarkGray
    }
} else {
    Write-Host '[i] AP07 desactivado (enable_ap07=false).' -ForegroundColor DarkGray
}

# 5. AP08: Automation Account runbook → escalada RBAC (gated en el output ap08_automation_account)
$ap08Aa = Get-TfRaw 'ap08_automation_account'
if ($ap08Aa) {
    $ap08Rg      = Get-TfRaw 'ap08_resource_group'
    $ap08Mi      = Get-TfRaw 'ap08_mi_principal_id'
    $ap08Role    = Get-TfRaw 'ap08_mi_role'
    $ap08Runbook = Get-TfRaw 'ap08_runbook_name'
    $ap08Upn     = Get-TfRaw 'ap08_attacker_upn'
    $ap08Law     = Get-TfRaw 'ap08_law_name'

    Test-Ok 'AP08 Automation Account desplegada' ($null -ne $ap08Aa)  "aa=$ap08Aa rg=$ap08Rg"
    Test-Ok 'AP08 MI system-assigned presente'   ($null -ne $ap08Mi)  "mi=$ap08Mi rol=$ap08Role"
    Test-Ok 'AP08 atacante low-priv definido'    ($null -ne $ap08Upn) "upn=$ap08Upn"
    if ($ap08Runbook) {
        Test-Ok 'AP08 runbook incrustado (gun cargada)' ($null -ne $ap08Runbook) "runbook=$ap08Runbook"
    } else {
        Write-Host '[i] AP08: runbook_mode=none (misconfig pura, sin runbook incrustado).' -ForegroundColor DarkGray
    }

    # Sonda de POSTURA (opcional, requiere az): confirma que la MI ostenta el rol
    # over-priv (UAA/Owner) SOBRE EL RG — la primitiva que habilita la escalada.
    # NO confirma una escalada de runtime: en el apply no se dispara nada (la "gun"
    # la dispara el alumno). verify valida la POSTURA, no un grant de runtime.
    if ($ap08Rg -and $ap08Mi -and (Get-Command az -ErrorAction SilentlyContinue)) {
        try {
            $rgId = az group show -n $ap08Rg --query id -o tsv 2>$null
            if ($rgId) {
                $raRaw = az role assignment list --assignee $ap08Mi --scope $rgId -o json 2>$null
                $roles = @()
                try { $roles = @($raRaw | ConvertFrom-Json) | ForEach-Object { $_.roleDefinitionName } } catch {}
                $hasOverPriv = @($roles | Where-Object { $_ -in @('Owner', 'User Access Administrator') }).Count -gt 0
                Test-Ok 'AP08 MI ostenta rol over-priv sobre el RG' $hasOverPriv "-> roleAssignments/write (roles=$(@($roles) -join ', '))"
            }
        } catch {
            Write-Host '[i] AP08: no se pudo sondear el role assignment de la MI (red / permisos / propagación AAD).' -ForegroundColor DarkGray
        }
    }

    if ($ap08Law) {
        Test-Ok 'AP08 telemetría (JobLogs+JobStreams -> LAW)' ($null -ne $ap08Law) "law=$ap08Law"
    } else {
        Write-Host '[i] AP08: telemetría off o LAW externo (collect_automation_logs=false / existing_log_analytics_workspace_id).' -ForegroundColor DarkGray
    }
} else {
    Write-Host '[i] AP08 desactivado (enable_ap08=false).' -ForegroundColor DarkGray
}

Write-Host "`nVerificación terminada." -ForegroundColor Cyan
