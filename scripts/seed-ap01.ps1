<#
.SYNOPSIS
    Completes (or remediates) the AP01 vulnerable condition - illicit consent grant.

.DESCRIPTION
    Terraform creates the "NewsletterSync" app with dangerous delegated scopes, but the
    piece that makes it exploitable is the tenant's CONSENT POLICY:

      Vulnerable  -> any user can consent to any app (legacy policy).
      Safe        -> user consent is disabled (requires admin).

    Default mode  : leaves the tenant in the vulnerable state.
    -Remediate    : restores the safe state (used by `aether.ps1 reset`).
    -PreConsent   : additionally pre-creates the delegated grant for a victim user,
                    to demonstrate token abuse without repeating the consent phishing.

.NOTES
    Requires the Microsoft.Graph module. Scopes: Policy.ReadWrite.Authorization,
    DelegatedPermissionGrant.ReadWrite.All, Application.Read.All.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$AppId,
    [string]$TenantId,
    [switch]$Remediate,
    [switch]$PreConsent,
    [string]$VictimUpn
)

$ErrorActionPreference = 'Stop'

# Policy that represents "allow user consent to all apps" (legacy permissive state).
$LegacyUserConsent = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'

Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
Import-Module Microsoft.Graph.Applications   -ErrorAction Stop

# Pin the Graph connection to the lab tenant so this never changes the consent
# policy of a different (e.g. corporate) tenant. The Graph token cache is separate
# from az CLI, so without -TenantId it could land elsewhere. [SECURITY.md H-1]
$connectArgs = @{
    Scopes    = @('Policy.ReadWrite.Authorization', 'DelegatedPermissionGrant.ReadWrite.All', 'Application.Read.All')
    NoWelcome = $true
}
if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
Connect-MgGraph @connectArgs
if ($TenantId -and (Get-MgContext).TenantId -ne $TenantId) {
    throw "Microsoft Graph connected to tenant $((Get-MgContext).TenantId), not the expected $TenantId. Aborting so the wrong tenant's consent policy is not modified."
}

# Back up / restore the tenant's ORIGINAL consent policy so remediation restores it
# instead of wiping every assigned policy (which would also drop RSC/Teams grants). [SECURITY.md M-1]
$BackupFile = Join-Path $PSScriptRoot 'seed-output-ap01.json'   # gitignored
$current = @((Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)

if ($Remediate) {
    if (Test-Path $BackupFile) {
        $orig = @((Get-Content $BackupFile -Raw | ConvertFrom-Json).policies | Where-Object { $_ })
        Write-Host "[*] Remediating: restoring the original consent policy ($($orig.Count) assigned)..." -ForegroundColor Green
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ PermissionGrantPoliciesAssigned = $orig }
    }
    else {
        $kept = @($current | Where-Object { $_ -ne $LegacyUserConsent })
        Write-Host "[*] Remediating: removing the permissive legacy policy (no backup; keeping $($kept.Count) other policy/ies)..." -ForegroundColor Green
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ PermissionGrantPoliciesAssigned = $kept }
    }
    Write-Host '[+] user-consent restored to a safe state. AP01 remediated.' -ForegroundColor Green
    return
}

# Save the original ONCE, before we pollute it with the legacy policy.
if (-not (Test-Path $BackupFile) -and ($current -notcontains $LegacyUserConsent)) {
    @{ policies = $current } | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupFile -Encoding UTF8
    Write-Host "[i] Saved the original consent policy to $BackupFile (for clean remediation)." -ForegroundColor DarkGray
}
Write-Host '[*] Seeding VULNERABLE state: allowing user consent to all apps...' -ForegroundColor Yellow
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    PermissionGrantPoliciesAssigned = @($LegacyUserConsent)
}
Write-Host "[+] Permissive policy applied. Vulnerable app: $AppId" -ForegroundColor Yellow

if ($PreConsent) {
    if (-not $VictimUpn) { throw '-PreConsent requires -VictimUpn <user@tenant>.' }
    Write-Host "[*] Pre-consenting the app on behalf of $VictimUpn ..." -ForegroundColor Yellow

    $sp     = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
    $graph  = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $victim = Get-MgUser -UserId $VictimUpn

    New-MgOauth2PermissionGrant -BodyParameter @{
        clientId    = $sp.Id
        consentType = 'Principal'
        principalId = $victim.Id
        resourceId  = $graph.Id
        scope       = 'offline_access Mail.Read Files.Read.All'
    } | Out-Null
    Write-Host '[+] Delegated grant created: the app token can now read the victim''s mail/files.' -ForegroundColor Yellow
}

Write-Host "`n[i] Attack path in docs/attack-paths/AP01-illicit-consent.md" -ForegroundColor Cyan
