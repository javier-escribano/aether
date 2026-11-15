<#
.SYNOPSIS
    Completa (o remedia) la condición vulnerable de AP01 — illicit consent grant.

.DESCRIPTION
    Terraform crea el app "NewsletterSync" con scopes delegados peligrosos, pero la
    pieza que lo hace explotable es la POLÍTICA DE CONSENTIMIENTO del tenant:

      Vulnerable  -> cualquier usuario puede consentir cualquier app (policy legacy).
      Seguro      -> el consentimiento de usuario queda deshabilitado (requiere admin).

    Modo por defecto  : deja el tenant en estado vulnerable.
    -Remediate        : restaura el estado seguro (lo usa `caelum.ps1 reset`).
    -PreConsent       : además pre-crea el grant delegado para un usuario víctima,
                        para demostrar el abuso de token sin repetir el phishing de consent.

.NOTES
    Requiere el módulo Microsoft.Graph. Scopes: Policy.ReadWrite.Authorization,
    DelegatedPermissionGrant.ReadWrite.All, Application.Read.All.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$AppId,
    [switch]$Remediate,
    [switch]$PreConsent,
    [string]$VictimUpn
)

$ErrorActionPreference = 'Stop'

# Policy que representa "permitir consentimiento de usuario a todas las apps" (estado permisivo legacy).
$LegacyUserConsent = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'

Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
Import-Module Microsoft.Graph.Applications   -ErrorAction Stop

Connect-MgGraph -Scopes @(
    'Policy.ReadWrite.Authorization',
    'DelegatedPermissionGrant.ReadWrite.All',
    'Application.Read.All'
) -NoWelcome

if ($Remediate) {
    Write-Host '[*] Remediando: deshabilitando el consentimiento de usuario...' -ForegroundColor Green
    Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
        PermissionGrantPoliciesAssigned = @()   # vacío = ningún usuario puede consentir
    }
    Write-Host '[+] user-consent deshabilitado. AP01 remediado.' -ForegroundColor Green
    return
}

Write-Host '[*] Sembrando estado VULNERABLE: permitiendo consentimiento de usuario a todas las apps...' -ForegroundColor Yellow
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    PermissionGrantPoliciesAssigned = @($LegacyUserConsent)
}
Write-Host "[+] Policy permisiva aplicada. App vulnerable: $AppId" -ForegroundColor Yellow

if ($PreConsent) {
    if (-not $VictimUpn) { throw '-PreConsent requiere -VictimUpn <usuario@tenant>.' }
    Write-Host "[*] Pre-consintiendo el app en nombre de $VictimUpn ..." -ForegroundColor Yellow

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
    Write-Host '[+] Grant delegado creado: el token del app ya puede leer correo/ficheros de la víctima.' -ForegroundColor Yellow
}

Write-Host "`n[i] Ruta en docs/attack-paths/AP01-illicit-consent.md" -ForegroundColor Cyan
