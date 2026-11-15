<#
.SYNOPSIS
    Orquestador del Caelum Range. Idempotente.

.DESCRIPTION
    Envuelve Terraform + los scripts de seed de Graph en un flujo único.

    deploy   : terraform init+apply y completa las condiciones vulnerables (seed).
    reset    : quita las vulnerabilidades y deja la base limpia (sin destruir el tenant lab).
    destroy  : elimina TODO lo que creó el range.
    verify   : health-check del range (ver scripts/verify.ps1).
    status   : muestra los outputs de Terraform.

.EXAMPLE
    ./caelum.ps1 deploy
    ./caelum.ps1 verify
    ./caelum.ps1 destroy
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('deploy', 'reset', 'destroy', 'verify', 'status')]
    [string]$Action,

    # Salta la confirmación interactiva de apply/destroy.
    [switch]$AutoApprove
)

$ErrorActionPreference = 'Stop'
$script:Root    = $PSScriptRoot
$script:TfDir   = Join-Path $Root 'terraform'
$script:Scripts = Join-Path $Root 'scripts'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

function Assert-Prereqs {
    foreach ($tool in 'az', 'terraform') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "Falta '$tool' en el PATH. Ver docs/00-setup.md."
        }
    }
    if (-not (Test-Path (Join-Path $TfDir 'terraform.tfvars'))) {
        throw "No existe terraform/terraform.tfvars. Copia terraform.tfvars.example y edítalo."
    }
    # Aviso de seguridad: confirma el tenant activo antes de tocar nada.
    $acct = az account show --query '{tenant:tenantId, name:name}' -o json 2>$null | ConvertFrom-Json
    if ($acct) {
        Write-Warn "Tenant/subscription activos: $($acct.name) ($($acct.tenant))"
        Write-Warn "Confirma que es tu tenant de TEST (ver README, sección de seguridad)."
    }
}

function Invoke-Tf {
    param([string[]]$TfArgs)
    Push-Location $TfDir
    try { & terraform @TfArgs; if ($LASTEXITCODE -ne 0) { throw "terraform $($TfArgs -join ' ') falló ($LASTEXITCODE)." } }
    finally { Pop-Location }
}

function Get-TfRaw {
    param([string]$Name)
    Push-Location $TfDir
    try {
        $out = terraform output -raw $Name 2>$null
        if ($LASTEXITCODE -eq 0 -and $out -and $out -ne 'null') { return $out }
        return $null
    } finally { Pop-Location }
}

function Get-Ap01AppId { return (Get-TfRaw 'ap01_app_id') }

# Centinela de AP05: null si el DC no está desplegado (espejo de Get-Ap01AppId).
function Get-Ap05Dc { return (Get-TfRaw 'ap05_dc_vm_name') }

# Centinela PROPIO de AP06: null si AP06 está off. NO reusa ap05_dc_vm_name,
# que devuelve null con enable_ap05=false aunque la VM compartida exista por AP06.
function Get-Ap06Dc { return (Get-TfRaw 'ap06_dc_vm_name') }

switch ($Action) {

    'deploy' {
        Assert-Prereqs
        Write-Step 'terraform init'
        Invoke-Tf @('init', '-input=false')

        Write-Step 'terraform apply'
        $applyArgs = @('apply', '-input=false')
        if ($AutoApprove) { $applyArgs += '-auto-approve' }
        Invoke-Tf $applyArgs

        $appId = Get-Ap01AppId
        if ($appId) {
            Write-Step "AP01 activo — completando condición vulnerable (seed Graph)"
            & (Join-Path $Scripts 'seed-ap01.ps1') -AppId $appId
        } else {
            Write-Warn 'AP01 desactivado: no se ejecuta seed-ap01.'
        }

        # AP05: siembra la plantilla ESC1 vía az vm run-command (seed idempotente,
        # espejo del seed-ap01 en deploy). El run-command corre como SYSTEM, por eso
        # se le pasa la credencial del Administrator de DOMINIO (dc_admin_password).
        $dcVm = Get-Ap05Dc
        if ($dcVm) {
            Write-Step "AP05 activo — sembrando la plantilla ESC1 en el DC (seed-ap05 vía run-command)"
            $rg       = Get-TfRaw 'ap05_resource_group'
            $eaPw     = Get-TfRaw 'ap05_dc_admin_password'
            $fqdn     = Get-TfRaw 'ap05_domain_fqdn'
            $netbios  = Get-TfRaw 'ap05_domain_netbios'
            $template = Get-TfRaw 'ap05_esc1_template_name'
            $caName   = Get-TfRaw 'ap05_ca_name'
            if ($rg -and $eaPw -and $fqdn -and $netbios -and $template -and $caName) {
                $seedPath = Join-Path $Scripts 'seed-ap05.ps1'
                # Argumentos en array: cada 'clave=valor' viaja como UN token argv
                # (la password puede llevar caracteres especiales). -o json para
                # inspeccionar el resultado: run-command devuelve exit 0 aunque el
                # script lance una excepción en el DC (no-EA, fallo de ACL/publicación),
                # así que $LASTEXITCODE por sí solo enmascara un seed fallido.
                $azArgs = @(
                    'vm', 'run-command', 'invoke',
                    '-g', $rg, '-n', $dcVm,
                    '--command-id', 'RunPowerShellScript',
                    '--scripts', "@$seedPath",
                    '-o', 'json',
                    '--parameters',
                    "EaPassword=$eaPw",
                    "DomainFqdn=$fqdn",
                    "DomainNetbios=$netbios",
                    "TemplateName=$template",
                    "CaCommonName=$caName"
                )
                $seedRaw = & az @azArgs
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "seed-ap05 (run-command) devolvió exit $LASTEXITCODE. ¿VM deallocada por auto-shutdown? Ejecuta deploy de día."
                } else {
                    # Inspecciona stdout/stderr del DC (.value[].message) buscando señales
                    # de excepción, equiparando la detección de fallos a la de un seed-ap01
                    # invocado directamente (run-command enmascara el error con exit 0).
                    $seedMsg = ''
                    try {
                        $seedOut = $seedRaw | ConvertFrom-Json
                        $seedMsg = ($seedOut.value | ForEach-Object { $_.message }) -join "`n"
                    } catch { $seedMsg = [string]$seedRaw }
                    if ($seedMsg -match 'Exception|FullyQualifiedErrorId|\[AP05\]') {
                        Write-Warn 'seed-ap05 se ejecutó pero el DC reportó un ERROR (¿credencial no-EA, fallo de ACL o de publicación?). Detalle del DC:'
                        Write-Host $seedMsg -ForegroundColor Yellow
                    } else {
                        Write-Host '[+] seed-ap05: plantilla ESC1 sembrada en el DC.' -ForegroundColor Green
                    }
                }
            } else {
                Write-Warn 'AP05: faltan outputs para el seed (¿apply incompleto?). Revisa terraform output.'
            }
        } else {
            Write-Warn 'AP05 desactivado: no se ejecuta seed-ap05.'
        }

        # AP06: siembra Entra Connect/Seamless SSO (AZUREADSSOACC$ + cuenta de
        # sync con DCSync) vía az vm run-command (seed idempotente, espejo de
        # seed-ap05). Centinela PROPIO ap06_dc_vm_name. El run-command corre como
        # SYSTEM: se le pasa la credencial del Administrator de DOMINIO (EA).
        $dc06 = Get-Ap06Dc
        if ($dc06) {
            Write-Step "AP06 activo — sembrando Entra Connect/Seamless SSO en el DC (seed-ap06 vía run-command)"
            $rg06    = Get-TfRaw 'ap06_resource_group'
            $eaPw06  = Get-TfRaw 'ap06_dc_admin_password'
            $fqdn06  = Get-TfRaw 'ap06_domain_fqdn'
            $nb06    = Get-TfRaw 'ap06_domain_netbios'
            $mode06  = Get-TfRaw 'ap06_sso_mode'
            $ssoPw   = Get-TfRaw 'ap06_sso_password'
            $syncPw  = Get-TfRaw 'ap06_sync_password'
            $syncAcc = Get-TfRaw 'ap06_sync_account'
            if ($rg06 -and $eaPw06 -and $fqdn06 -and $nb06 -and $mode06 -and $ssoPw -and $syncPw) {
                $seed06 = Join-Path $Scripts 'seed-ap06.ps1'
                # Argumentos en array: cada 'clave=valor' viaja como UN token argv.
                # SsoAccountName fijo 'AZUREADSSOACC' (nombre real, debe coincidir con
                # las detecciones). -o json para inspeccionar el resultado (run-command
                # devuelve exit 0 aunque el script lance una excepción en el DC).
                $az06 = @(
                    'vm', 'run-command', 'invoke',
                    '-g', $rg06, '-n', $dc06,
                    '--command-id', 'RunPowerShellScript',
                    '--scripts', "@$seed06",
                    '-o', 'json',
                    '--parameters',
                    "EaPassword=$eaPw06",
                    "DomainFqdn=$fqdn06",
                    "DomainNetbios=$nb06",
                    "SsoMode=$mode06",
                    "SsoAccountName=AZUREADSSOACC",
                    "SyncAccountName=$syncAcc",
                    "SsoPassword=$ssoPw",
                    "SyncPassword=$syncPw"
                )
                $raw06 = & az @az06
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "seed-ap06 (run-command) devolvió exit $LASTEXITCODE. ¿VM deallocada por auto-shutdown? Ejecuta deploy de día."
                } else {
                    $msg06 = ''
                    try {
                        $o06 = $raw06 | ConvertFrom-Json
                        $msg06 = ($o06.value | ForEach-Object { $_.message }) -join "`n"
                    } catch { $msg06 = [string]$raw06 }
                    if ($msg06 -match 'Exception|FullyQualifiedErrorId|\[AP06\]') {
                        Write-Warn 'seed-ap06 se ejecutó pero el DC reportó un ERROR (¿credencial no-EA, fallo de ACL DCSync o de creación de AZUREADSSOACC$?). Detalle del DC:'
                        Write-Host $msg06 -ForegroundColor Yellow
                    } else {
                        Write-Host '[+] seed-ap06: AZUREADSSOACC$ + cuenta de sync (DCSync) sembrados en el DC.' -ForegroundColor Green
                    }
                }
            } else {
                Write-Warn 'AP06: faltan outputs para el seed (¿apply incompleto?). Revisa terraform output.'
            }
        } else {
            Write-Warn 'AP06 desactivado: no se ejecuta seed-ap06.'
        }

        Write-Step 'Despliegue completo. Siguiente: ./caelum.ps1 verify'
    }

    'reset' {
        Assert-Prereqs
        $appId = Get-Ap01AppId
        if ($appId) {
            Write-Step 'Remediando AP01 (restaura user-consent policy segura)'
            & (Join-Path $Scripts 'seed-ap01.ps1') -AppId $appId -Remediate
        }
        # AP05 NO se pre-remedia por run-command (divergencia deliberada vs AP01):
        # la vuln vive en la VM y enable_ap05=false la DESTRUYE entera (la plantilla
        # muere con el DC); además la VM puede estar deallocada por auto-shutdown.
        # El ejercicio "Arregla" in-place es seed-ap05.ps1 -Remediate (ver doc).
        # AP06 tampoco se pre-remedia (mismo motivo): AP05 y AP06 COMPARTEN el DC,
        # así que SOLO con AMBAS flags a false (enable_ap05=false Y enable_ap06=false)
        # need_dc=false → count=0 → se destruye el único DC y con él AZUREADSSOACC$ +
        # la cuenta de sync + los ACEs DCSync (viven en el directorio, no en el state).
        # CAVEAT: apagar SOLO AP06 (enable_ap06=false, enable_ap05=true) deja el DC
        # vivo y los objetos AD de AP06 persisten → usa seed-ap06.ps1 -Remediate para
        # el "Arregla" in-place (rota la clave de AZUREADSSOACC$ 2x + quita DCSync +
        # deshabilita la cuenta de sync).
        Write-Step 'Re-aplicando con las vulnerabilidades desactivadas'
        # AP07 no tiene seed ni acción de atacante fuera del estado: enable_ap07=false
        # → count=0 → destruye atómicamente RG+cuenta+contenedores+blob filtrado+SAS+LAW
        # (cero residuo out-of-state, más limpio que AP02).
        # AP08 tampoco: es declarativo (sin seed; la "gun" la dispara el alumno, no el
        # deploy). enable_ap08=false → count=0 → destruye el RG y CON ÉL el Automation
        # Account + MI + runbook + LAW Y cualquier role assignment creada en RUNTIME
        # que esté RG-scoped (el self-grant de Owner del alumno). Por eso el rol de la
        # MI y la escalada son RG-scoped A PROPÓSITO: un -Scope de subscription
        # sobreviviría al destroy (residuo out-of-state) — reset limpio como AP05/AP07.
        $resetArgs = @('apply', '-input=false', '-var', 'enable_ap01=false', '-var', 'enable_ap02=false', '-var', 'enable_ap03=false', '-var', 'enable_ap04=false', '-var', 'enable_ap05=false', '-var', 'enable_ap06=false', '-var', 'enable_ap07=false', '-var', 'enable_ap08=false')
        if ($AutoApprove) { $resetArgs += '-auto-approve' }
        Invoke-Tf $resetArgs
        Write-Step 'Reset hecho: base intacta, vulnerabilidades retiradas (AP05+AP06: con ambas flags a false need_dc=false → el DC compartido se destruye, coste→0, y con él ESC1 + AZUREADSSOACC$ + cuenta de sync; AP07: storage+credencial destruidos; AP08: Automation Account+MI+runbook y toda role assignment RG-scoped de runtime destruidos).'
    }

    'destroy' {
        Assert-Prereqs
        Write-Warn 'Esto elimina TODOS los objetos del range en el tenant activo.'
        Write-Step 'terraform destroy'
        $destroyArgs = @('destroy', '-input=false')
        if ($AutoApprove) { $destroyArgs += '-auto-approve' }
        Invoke-Tf $destroyArgs
        Write-Step 'Range destruido.'
    }

    'verify' {
        & (Join-Path $Scripts 'verify.ps1')
    }

    'status' {
        Invoke-Tf @('output')
    }
}
