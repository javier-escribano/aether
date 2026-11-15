<#
.SYNOPSIS
    Azure Attack Range orchestrator. Idempotent.

.DESCRIPTION
    Wraps Terraform plus the Graph seed scripts into a single flow.

    deploy   : terraform init+apply and completes the vulnerable conditions (seed).
    reset    : removes the vulnerabilities and leaves a clean baseline (without destroying the lab tenant).
    destroy  : removes EVERYTHING the range created.
    verify   : range health-check (see scripts/verify.ps1).
    status   : shows the Terraform outputs.

.EXAMPLE
    ./azrange.ps1 deploy
    ./azrange.ps1 verify
    ./azrange.ps1 destroy
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('deploy', 'reset', 'destroy', 'verify', 'status')]
    [string]$Action,

    # Skip the interactive apply/destroy confirmation.
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
            throw "'$tool' is missing from PATH. See docs/00-setup.md."
        }
    }
    if (-not (Test-Path (Join-Path $TfDir 'terraform.tfvars'))) {
        throw "terraform/terraform.tfvars does not exist. Copy terraform.tfvars.example and edit it."
    }
    # Safety notice: confirm the active tenant before touching anything.
    $acct = az account show --query '{tenant:tenantId, name:name}' -o json 2>$null | ConvertFrom-Json
    if ($acct) {
        Write-Warn "Active tenant/subscription: $($acct.name) ($($acct.tenant))"
        Write-Warn "Confirm this is your TEST tenant (see README, security section)."
    }
}

function Invoke-Tf {
    param([string[]]$TfArgs)
    Push-Location $TfDir
    try { & terraform @TfArgs; if ($LASTEXITCODE -ne 0) { throw "terraform $($TfArgs -join ' ') failed ($LASTEXITCODE)." } }
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

# AP05 sentinel: null if the DC is not deployed (mirror of Get-Ap01AppId).
function Get-Ap05Dc { return (Get-TfRaw 'ap05_dc_vm_name') }

# AP06's OWN sentinel: null if AP06 is off. Does NOT reuse ap05_dc_vm_name,
# which returns null with enable_ap05=false even if the shared VM exists via AP06.
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
            Write-Step "AP01 active - completing the vulnerable condition (Graph seed)"
            & (Join-Path $Scripts 'seed-ap01.ps1') -AppId $appId
        } else {
            Write-Warn 'AP01 disabled: seed-ap01 is not run.'
        }

        # AP05: seeds the ESC1 template via az vm run-command (idempotent seed,
        # mirror of seed-ap01 in deploy). The run-command runs as SYSTEM, which is
        # why the DOMAIN Administrator credential (dc_admin_password) is passed to it.
        $dcVm = Get-Ap05Dc
        if ($dcVm) {
            Write-Step "AP05 active - seeding the ESC1 template on the DC (seed-ap05 via run-command)"
            $rg       = Get-TfRaw 'ap05_resource_group'
            $eaPw     = Get-TfRaw 'ap05_dc_admin_password'
            $fqdn     = Get-TfRaw 'ap05_domain_fqdn'
            $netbios  = Get-TfRaw 'ap05_domain_netbios'
            $template = Get-TfRaw 'ap05_esc1_template_name'
            $caName   = Get-TfRaw 'ap05_ca_name'
            if ($rg -and $eaPw -and $fqdn -and $netbios -and $template -and $caName) {
                $seedPath = Join-Path $Scripts 'seed-ap05.ps1'
                # Arguments as an array: each 'key=value' travels as ONE argv token
                # (the password may contain special characters). -o json to
                # inspect the result: run-command returns exit 0 even if the
                # script throws an exception on the DC (non-EA, ACL/publishing
                # failure), so $LASTEXITCODE on its own masks a failed seed.
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
                    Write-Warn "seed-ap05 (run-command) returned exit $LASTEXITCODE. VM deallocated by auto-shutdown? Run deploy during the day."
                } else {
                    # Inspect the DC's stdout/stderr (.value[].message) for signs of
                    # an exception, matching the failure detection of a seed-ap01
                    # invoked directly (run-command masks the error with exit 0).
                    $seedMsg = ''
                    try {
                        $seedOut = $seedRaw | ConvertFrom-Json
                        $seedMsg = ($seedOut.value | ForEach-Object { $_.message }) -join "`n"
                    } catch { $seedMsg = [string]$seedRaw }
                    if ($seedMsg -match 'Exception|FullyQualifiedErrorId|\[AP05\]') {
                        Write-Warn 'seed-ap05 ran but the DC reported an ERROR (non-EA credential, ACL or publishing failure?). DC detail:'
                        Write-Host $seedMsg -ForegroundColor Yellow
                    } else {
                        Write-Host '[+] seed-ap05: ESC1 template seeded on the DC.' -ForegroundColor Green
                    }
                }
            } else {
                Write-Warn 'AP05: outputs missing for the seed (incomplete apply?). Check terraform output.'
            }
        } else {
            Write-Warn 'AP05 disabled: seed-ap05 is not run.'
        }

        # AP06: seeds Entra Connect/Seamless SSO (AZUREADSSOACC$ + sync account
        # with DCSync) via az vm run-command (idempotent seed, mirror of
        # seed-ap05). Its OWN sentinel ap06_dc_vm_name. The run-command runs as
        # SYSTEM: the DOMAIN Administrator (EA) credential is passed to it.
        $dc06 = Get-Ap06Dc
        if ($dc06) {
            Write-Step "AP06 active - seeding Entra Connect/Seamless SSO on the DC (seed-ap06 via run-command)"
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
                # Arguments as an array: each 'key=value' travels as ONE argv token.
                # SsoAccountName fixed to 'AZUREADSSOACC' (real name, must match
                # the detections). -o json to inspect the result (run-command
                # returns exit 0 even if the script throws an exception on the DC).
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
                    Write-Warn "seed-ap06 (run-command) returned exit $LASTEXITCODE. VM deallocated by auto-shutdown? Run deploy during the day."
                } else {
                    $msg06 = ''
                    try {
                        $o06 = $raw06 | ConvertFrom-Json
                        $msg06 = ($o06.value | ForEach-Object { $_.message }) -join "`n"
                    } catch { $msg06 = [string]$raw06 }
                    if ($msg06 -match 'Exception|FullyQualifiedErrorId|\[AP06\]') {
                        Write-Warn 'seed-ap06 ran but the DC reported an ERROR (non-EA credential, DCSync ACL failure, or AZUREADSSOACC$ creation failure?). DC detail:'
                        Write-Host $msg06 -ForegroundColor Yellow
                    } else {
                        Write-Host '[+] seed-ap06: AZUREADSSOACC$ + sync account (DCSync) seeded on the DC.' -ForegroundColor Green
                    }
                }
            } else {
                Write-Warn 'AP06: outputs missing for the seed (incomplete apply?). Check terraform output.'
            }
        } else {
            Write-Warn 'AP06 disabled: seed-ap06 is not run.'
        }

        Write-Step 'Deployment complete. Next: ./azrange.ps1 verify'
    }

    'reset' {
        Assert-Prereqs
        $appId = Get-Ap01AppId
        if ($appId) {
            Write-Step 'Remediating AP01 (restores the safe user-consent policy)'
            & (Join-Path $Scripts 'seed-ap01.ps1') -AppId $appId -Remediate
        }
        # AP05 is NOT pre-remediated via run-command (deliberate divergence vs AP01):
        # the vuln lives on the VM and enable_ap05=false DESTROYS it entirely (the
        # template dies with the DC); also the VM may be deallocated by auto-shutdown.
        # The in-place "Remediate" exercise is seed-ap05.ps1 -Remediate (see doc).
        # AP06 is not pre-remediated either (same reason): AP05 and AP06 SHARE the DC,
        # so ONLY with BOTH flags false (enable_ap05=false AND enable_ap06=false)
        # need_dc=false -> count=0 -> the single DC is destroyed and with it AZUREADSSOACC$ +
        # the sync account + the DCSync ACEs (they live in the directory, not the state).
        # CAVEAT: turning off ONLY AP06 (enable_ap06=false, enable_ap05=true) leaves the DC
        # alive and the AP06 AD objects persist -> use seed-ap06.ps1 -Remediate for the
        # in-place "Remediate" (rotates the AZUREADSSOACC$ key 2x + removes DCSync +
        # disables the sync account).
        Write-Step 'Re-applying with the vulnerabilities disabled'
        # AP07 has no seed nor attacker action outside the state: enable_ap07=false
        # -> count=0 -> atomically destroys RG+account+containers+leaked blob+SAS+LAW
        # (zero out-of-state residue, cleaner than AP02).
        # AP08 has none either: it is declarative (no seed; the "gun" is fired by the
        # student, not the deploy). enable_ap08=false -> count=0 -> destroys the RG and WITH IT
        # the Automation Account + MI + runbook + LAW AND any role assignment created at RUNTIME
        # that is RG-scoped (the student's Owner self-grant). That is why the MI's role and the
        # escalation are RG-scoped ON PURPOSE: a subscription -Scope would survive the destroy
        # (out-of-state residue) -- a clean reset like AP05/AP07.
        $resetArgs = @('apply', '-input=false', '-var', 'enable_ap01=false', '-var', 'enable_ap02=false', '-var', 'enable_ap03=false', '-var', 'enable_ap04=false', '-var', 'enable_ap05=false', '-var', 'enable_ap06=false', '-var', 'enable_ap07=false', '-var', 'enable_ap08=false')
        if ($AutoApprove) { $resetArgs += '-auto-approve' }
        Invoke-Tf $resetArgs
        Write-Step 'Reset done: baseline intact, vulnerabilities removed (AP05+AP06: with both flags false need_dc=false -> the shared DC is destroyed, cost->0, and with it ESC1 + AZUREADSSOACC$ + the sync account; AP07: storage+credential destroyed; AP08: Automation Account+MI+runbook and every RG-scoped runtime role assignment destroyed).'
    }

    'destroy' {
        Assert-Prereqs
        Write-Warn 'This removes ALL of the range objects in the active tenant.'
        Write-Step 'terraform destroy'
        $destroyArgs = @('destroy', '-input=false')
        if ($AutoApprove) { $destroyArgs += '-auto-approve' }
        Invoke-Tf $destroyArgs
        Write-Step 'Range destroyed.'
    }

    'verify' {
        & (Join-Path $Scripts 'verify.ps1')
    }

    'status' {
        Invoke-Tf @('output')
    }
}
